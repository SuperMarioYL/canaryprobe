"""Regression / fuzz tests pinning the corrupt-input fail-soft path (v0.6.0).

These lock the two v0.6.0 fail-soft fixes against the *structural* valid-JSON-
wrong-shape hole the v0.5.0 surfacing itself left open, so a future narrowing of
the broadened except tuples / isinstance guards re-opens the denial-of-evidence
hole loudly here in CI rather than silently in the field.

* ``fix-corrupt-input-failsoft-misses-typeerror-attributeerror`` (audit side +
  manifest side) — a single attacker-tampered ``audit.jsonl`` line holding a
  non-dict JSON value (``null``/``[1]``/``5``/``"x"``/``true``) or a non-dict /
  non-list ``decoys.manifest.json`` value must surface as a corrupt line /
  manifest CORRUPT, never raise ``TypeError``/``AttributeError`` out of
  ``read()``/``build_report``/``verify``.
* ``fix-load-decoys-crash-on-corrupt`` — a corrupt/tampered ``decoys.json``
  must raise the typed :class:`DecoysCorruptError` (rendered by the CLI as
  "decoys.json corrupt — re-init") rather than a raw traceback out of
  ``watch``/``simulate-trip``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from typer.testing import CliRunner

from canaryprobe.alarm import AuditLog, SensorKind, TripEvent
from canaryprobe.cli import app
from canaryprobe.config import DeploymentConfig
from canaryprobe.decoy import (
    DecoysCorruptError,
    generate_decoys,
    load_decoys,
    load_manifest,
    write_decoys,
)
from canaryprobe.report import build_report, verify_report

runner = CliRunner()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _event(decoy_id="dcy_x", sensor=SensorKind.DNS, value="h.corp.local", ts=None):
    return TripEvent(
        decoy_id=decoy_id,
        sensor=sensor,
        observed_value=value,
        src="127.0.0.1:5555",
        ts=ts or datetime.now(timezone.utc),
    )


# Representative valid-JSON-but-non-dict audit lines plus a malformed-JSON control.
NON_DICT_AUDIT_LINES = ["null", "[1]", "5", '"x"', "true", '[{"decoy_id":"x"}]']
MALFORMED_JSON_LINE = "{{bad json"


# ---------------------------------------------------------------------------
# fix-corrupt-input-failsoft-misses-typeerror-attributeerror — audit side
# ---------------------------------------------------------------------------


def test_audit_log_non_dict_valid_json_lines_are_corrupt_not_crash(tmp_path):
    """Regression for fix-corrupt-input-failsoft-misses-typeerror-attributeerror.

    A valid-JSON-but-non-dict ``audit.jsonl`` line (``null``/``[1]``/``5``/
    ``"x"``/``true``/list-of-non-dict) made ``TripEvent.from_record``'s first
    access ``data["decoy_id"]`` raise ``TypeError`` — not a subclass of the
    v0.5.0 except tuple ``(JSONDecodeError, KeyError, ValueError)`` — so it
    propagated out of ``iter_events`` through ``read()`` -> ``build_report``
    and crashed ``canaryprobe report``/``verify`` with a traceback, BEFORE the
    v0.5.0 corrupt-line tally could fire. With the fix, ``TypeError`` is caught
    and the line is counted corrupt + surfaced, never raised.
    """
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append(_event(decoy_id="dcy_good"))
    with open(path, "a", encoding="utf-8") as fh:
        for bad in NON_DICT_AUDIT_LINES:
            fh.write(bad + "\n")
        fh.write(MALFORMED_JSON_LINE + "\n")  # control: malformed JSON, also corrupt

    # iter_events must NOT raise — only the good line is a trip.
    events = log.read()
    assert [e.decoy_id for e in events] == ["dcy_good"]
    # every non-dict line + the malformed line is counted corrupt.
    assert log.count_corrupt() == len(NON_DICT_AUDIT_LINES) + 1
    # the skipped set (iter_corrupt) stays consistent with the counted set.
    assert {raw.strip() for raw in log.iter_corrupt()} == {
        s.strip() for s in NON_DICT_AUDIT_LINES + [MALFORMED_JSON_LINE]
    }


def test_report_surfaces_non_dict_audit_line_as_evidence_incomplete(tmp_path):
    """A non-dict audit line surfaces 'Evidence incomplete' in the signed report
    body rather than crashing ``build_report`` (the read-side denial-of-evidence
    hole the v0.5.0 surfacing was built to close)."""
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    with open(cfg.audit_path, "a", encoding="utf-8") as fh:
        fh.write("null\n")  # a single valid-JSON-but-non-dict attacker line
    result = build_report(cfg)  # must not raise
    assert result.event_count == 0
    assert result.corrupt_lines == 1
    assert "Evidence incomplete" in result.markdown
    assert "corrupt audit line" in result.markdown.lower()
    assert verify_report(result.markdown, cfg.signing_key()) is True


# ---------------------------------------------------------------------------
# fix-corrupt-input-failsoft-misses-typeerror-attributeerror — manifest side
# ---------------------------------------------------------------------------


NON_DICT_MANIFEST_VALUES = ["null", "5", '"x"']


def test_load_manifest_non_dict_value_returns_none_not_crash(tmp_path):
    """Regression for fix-corrupt-input-failsoft-misses-typeerror-attributeerror
    (manifest side).

    A manifest whose top-level JSON value is a non-dict (``null``/``5``/``"x"``)
    made ``DecoyManifest.from_json``'s first access ``data.get("version", 1)``
    raise ``AttributeError`` — not in the v0.5.0 except tuple
    ``(ValidationError, KeyError, ValueError)`` — so ``load_manifest`` raised
    and ``build_report``/``cli.verify`` crashed instead of rendering manifest
    CORRUPT. With the fix, ``AttributeError`` is caught and ``load_manifest``
    returns ``None`` (manifest CORRUPT).
    """
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    for bad in NON_DICT_MANIFEST_VALUES:
        cfg.manifest_path.write_text(bad, encoding="utf-8")
        assert load_manifest(cfg) is None


@pytest.mark.parametrize("bad_decoys", [None, 5], ids=["decoys_null", "decoys_int"])
def test_load_manifest_non_list_decoys_returns_none_not_crash(tmp_path, bad_decoys):
    """A dict manifest whose ``decoys`` is a non-iterable (``null``/``5``) raises
    ``TypeError`` in the ``[Decoy.from_dict(d) for d in data["decoys"]]``
    comprehension — caught after the fix, surfaced as manifest CORRUPT."""
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    payload = {
        "version": 1,
        "zone": "corp.local",
        "created_at": "2026-01-01T00:00:00Z",
        "decoys": bad_decoys,
    }
    cfg.manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    assert load_manifest(cfg) is None


def test_load_manifest_list_of_non_dict_decoys_returns_none_not_crash(tmp_path):
    """A ``decoys`` list of non-dict elements (``[1,2]``) makes
    ``Decoy.from_dict(1)`` raise ``TypeError`` (``1["id"]``) — caught after the
    fix, surfaced as manifest CORRUPT."""
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    payload = {
        "version": 1,
        "zone": "corp.local",
        "created_at": "2026-01-01T00:00:00Z",
        "decoys": [1, 2],
    }
    cfg.manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    assert load_manifest(cfg) is None


def test_report_non_dict_manifest_surfaced_as_corrupt_not_crash(tmp_path):
    """A non-dict manifest value surfaces 'manifest CORRUPT' in the signed report
    body rather than crashing ``build_report`` (denial-of-evidence on a tampered
    manifest)."""
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    cfg.manifest_path.write_text("null", encoding="utf-8")
    result = build_report(cfg)  # must not raise
    assert result.manifest_corrupt is True
    assert "manifest CORRUPT" in result.markdown
    assert "Evidence incomplete" in result.markdown
    assert verify_report(result.markdown, cfg.signing_key()) is True


# ---------------------------------------------------------------------------
# fix-load-decoys-crash-on-corrupt — typed error + CLI surfacing
# ---------------------------------------------------------------------------


CORRUPT_DECOYS_JSON_CASES = [
    # (id, file content)
    ("malformed_json", "{not valid json"),
    (
        "decoy_missing_id",
        json.dumps(
            {
                "zone": "z",
                "decoys": [
                    {
                        "kind": "hostname",
                        "value": "h.z",
                        "planted_at": "2026-01-01T00:00:00Z",
                    }
                ],
            }
        ),
    ),
    (
        "decoy_missing_kind",
        json.dumps(
            {
                "zone": "z",
                "decoys": [
                    {
                        "id": "dcy_x",
                        "value": "h.z",
                        "planted_at": "2026-01-01T00:00:00Z",
                    }
                ],
            }
        ),
    ),
    (
        "decoy_missing_value",
        json.dumps(
            {
                "zone": "z",
                "decoys": [
                    {
                        "id": "dcy_x",
                        "kind": "hostname",
                        "planted_at": "2026-01-01T00:00:00Z",
                    }
                ],
            }
        ),
    ),
    ("non_list_decoys_null", json.dumps({"zone": "z", "decoys": None})),
    ("non_list_decoys_int", json.dumps({"zone": "z", "decoys": 5})),
    ("non_dict_element", json.dumps({"zone": "z", "decoys": [1, 2]})),
    ("non_dict_top_level_list", "[1, 2, 3]"),
    ("non_dict_top_level_null", "null"),
    ("non_dict_top_level_int", "5"),
]


@pytest.mark.parametrize(
    "content",
    [c[1] for c in CORRUPT_DECOYS_JSON_CASES],
    ids=[c[0] for c in CORRUPT_DECOYS_JSON_CASES],
)
def test_load_decoys_corrupt_raises_typed_error(tmp_path, content):
    """Regression for fix-load-decoys-crash-on-corrupt.

    ``load_decoys`` had zero error handling; a corrupt/tampered ``decoys.json``
    raised an uncaught ``JSONDecodeError``/``KeyError``/``TypeError``/
    ``ValueError``/``AttributeError`` that propagated out of ``canaryprobe
    watch`` (cli.py:195) and ``simulate-trip`` (cli.py:373) as a raw traceback —
    sensors never armed. With the fix it raises the typed
    :class:`DecoysCorruptError` the CLI renders as "decoys.json corrupt — re-init".
    """
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))  # a valid base + signing key
    cfg.decoys_path.write_text(content, encoding="utf-8")
    with pytest.raises(DecoysCorruptError):
        load_decoys(cfg)


def test_load_decoys_missing_file_returns_empty_not_corrupt(tmp_path):
    """Control: an ABSENT ``decoys.json`` is a genuine fresh install → ``[]``,
    NOT the typed corrupt error. Guards against over-broadening (a present-but-
    corrupt file must raise; an absent file must not)."""
    cfg = DeploymentConfig.default(tmp_path)
    assert not cfg.decoys_path.is_file()
    assert load_decoys(cfg) == []


def test_watch_corrupt_decoys_json_surfaces_reinit_not_crash(tmp_path):
    """``canaryprobe watch`` with a corrupt ``decoys.json`` prints a guided
    'decoys.json corrupt — re-init' message and exits (code 2) instead of
    crashing with a raw traceback before the sensors arm."""
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    cfg.decoys_path.write_text("{not valid json", encoding="utf-8")
    # --duration 0 is a hang-safety; the corrupt path exits before any sensor binds.
    result = runner.invoke(app, ["watch", "--dir", str(tmp_path), "--duration", "0"])
    assert result.exit_code == 2
    out = (result.stdout or "") + (result.stderr or "")
    assert "decoys.json corrupt" in out
    assert "re-init" in out.lower()


def test_simulate_trip_corrupt_decoys_json_surfaces_reinit_not_crash(tmp_path):
    """``canaryprobe simulate-trip`` with a corrupt ``decoys.json`` prints the
    guided 're-init' message and exits (code 2) instead of crashing."""
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    cfg.decoys_path.write_text('{"zone":"z","decoys":[1,2]}', encoding="utf-8")
    result = runner.invoke(app, ["simulate-trip", "--dir", str(tmp_path)])
    assert result.exit_code == 2
    out = (result.stdout or "") + (result.stderr or "")
    assert "decoys.json corrupt" in out
    assert "re-init" in out.lower()
