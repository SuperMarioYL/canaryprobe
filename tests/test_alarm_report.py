"""Tests for the audit trail (m2) and the evidence report (m3).

Covers the ``TripEvent`` JSONL round-trip, the append-only ``AuditLog``, and
both report states (clean + TRIPPED) with signature verification.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from canaryprobe.alarm import AuditLog, SensorKind, TripEvent
from canaryprobe.config import DeploymentConfig
from canaryprobe.decoy import generate_decoys, load_manifest, write_decoys
from canaryprobe.report import build_report, verify_report, write_report


# ---------------------------------------------------------------------------
# TripEvent + AuditLog
# ---------------------------------------------------------------------------


def _event(decoy_id="dcy_x", sensor=SensorKind.DNS, value="h.corp.local", ts=None):
    return TripEvent(
        decoy_id=decoy_id,
        sensor=sensor,
        observed_value=value,
        src="127.0.0.1:5555",
        ts=ts or datetime.now(timezone.utc),
    )


def test_tripevent_jsonl_roundtrip():
    ev = _event()
    line = ev.to_jsonl()
    data = json.loads(line)
    restored = TripEvent.from_record(data)
    assert restored.decoy_id == ev.decoy_id
    assert restored.sensor is ev.sensor
    assert restored.observed_value == ev.observed_value
    assert restored.verdict == "TRIPPED"


def test_audit_log_is_append_only(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append(_event(decoy_id="dcy_1"))
    log.append(_event(decoy_id="dcy_2"))
    events = log.read()
    assert [e.decoy_id for e in events] == ["dcy_1", "dcy_2"]
    # a third append does not rewrite the first two
    log.append(_event(decoy_id="dcy_3"))
    assert log.count() == 3


def test_audit_log_skips_corrupt_lines(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append(_event(decoy_id="dcy_good"))
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("this is not json\n")
        fh.write("\n")
    events = log.read()
    assert len(events) == 1
    assert events[0].decoy_id == "dcy_good"


def test_audit_log_missing_file_is_empty(tmp_path):
    log = AuditLog(tmp_path / "nope.jsonl")
    assert log.read() == []
    assert log.count() == 0


# ---------------------------------------------------------------------------
# report — clean
# ---------------------------------------------------------------------------


def test_clean_report_when_no_events(tmp_path):
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    result = build_report(cfg)
    assert result.tripped is False
    assert result.verdict == "CLEAN"
    assert result.event_count == 0
    assert "no covert egress observed" in result.markdown.lower()
    assert result.manifest_verified is True


def test_clean_report_signature_verifies(tmp_path):
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    result = build_report(cfg)
    assert result.signature
    assert verify_report(result.markdown, cfg.signing_key()) is True


# ---------------------------------------------------------------------------
# report — tripped
# ---------------------------------------------------------------------------


def _seed_events(cfg, n=2):
    log = AuditLog(cfg.audit_path)
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for i in range(n):
        log.append(
            _event(
                decoy_id=f"dcy_{i}",
                sensor=SensorKind.DNS if i % 2 == 0 else SensorKind.CONN,
                value=f"host-{i}.corp.local",
                ts=base + timedelta(minutes=i),
            )
        )


def test_tripped_report_enumerates_events(tmp_path):
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    _seed_events(cfg, n=3)
    result = build_report(cfg)
    assert result.tripped is True
    assert result.verdict == "TRIPPED"
    assert result.event_count == 3
    # each decoy id appears in the rendered table
    for i in range(3):
        assert f"dcy_{i}" in result.markdown
    assert "TRIPPED" in result.markdown


def test_tripped_report_signature_verifies(tmp_path):
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    _seed_events(cfg, n=2)
    result = build_report(cfg)
    assert verify_report(result.markdown, cfg.signing_key()) is True
    # a wrong key does not verify
    assert verify_report(result.markdown, "some-other-key") is False


def test_report_detects_body_tampering(tmp_path):
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    _seed_events(cfg, n=1)
    result = build_report(cfg)
    tampered = result.markdown.replace("TRIPPED", "CLEAN", 1)
    assert verify_report(tampered, cfg.signing_key()) is False


def test_write_report_creates_file(tmp_path):
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    _seed_events(cfg, n=1)
    path, result = write_report(cfg)
    assert path.is_file()
    assert path.name == "report.md"
    assert result.tripped is True
    # the written file is exactly the signed markdown
    assert path.read_text(encoding="utf-8") == result.markdown


def test_report_window_start_is_earliest_event(tmp_path):
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    _seed_events(cfg, n=3)
    result = build_report(cfg)
    assert result.window_start == datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_report_signature_is_deterministic_over_same_evidence(tmp_path):
    """Two runs over the SAME audit log produce the SAME signature.

    The volatile generation timestamp must live OUTSIDE the signed body so an
    auditor can reproduce the signature over identical evidence (the guarantee
    the module docstring documents).
    """
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    _seed_events(cfg, n=2)
    r1 = build_report(cfg)
    r2 = build_report(cfg)
    assert r1.signature == r2.signature
    assert r1.signature  # non-empty
    # the markdown may carry a different generated-at footer, but the signature
    # (over the body only) is stable.
    assert verify_report(r1.markdown, cfg.signing_key()) is True
    assert verify_report(r2.markdown, cfg.signing_key()) is True


def test_report_generated_at_is_present_but_unsigned(tmp_path):
    """The generation timestamp is shown in the report but excluded from the
    signed body — editing only the generated-at footer must NOT break the
    signature."""
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    _seed_events(cfg, n=1)
    result = build_report(cfg)
    assert "Generated at:" in result.markdown
    # mutate the generated-at footer only
    tampered_footer = result.markdown.replace("Generated at:", "Generated-at:", 1)
    assert verify_report(tampered_footer, cfg.signing_key()) is True


# ---------------------------------------------------------------------------
# on_trip — audit-append I/O failure must NOT silently drop the trip
# ---------------------------------------------------------------------------


def test_handle_trip_surfaces_audit_write_failure_not_silent(tmp_path):
    """Regression for fix-on-trip-silent-drop.

    ``on_trip`` appends to the audit log before rendering the alarm.  If the
    append raises (disk full / read-only fs / fsync error) the sensors wrap
    the callback in ``except Exception: pass``, which silently swallowed the
    failure → no audit line, no red panel, zero count, report reads CLEAN.
    For a security canary that is the worst failure mode (a silent miss).

    With the fix, an audit-append I/O failure is surfaced to stderr, the trip
    is still counted in memory, and the alarm is still rendered — the trip
    stays visible.  Without the fix (bare ``audit.append`` with no guard) this
    test fails: the OSError propagates, the count stays 0, no alarm renders.
    """

    from io import StringIO

    from rich.console import Console

    from canaryprobe.cli import _handle_trip

    class _FailingAudit:
        """Stand-in AuditLog whose append always raises an I/O error."""

        def __init__(self, path):
            self.path = path

        def append(self, event):
            raise OSError("disk full — simulated audit.append I/O failure")

    audit = _FailingAudit(tmp_path / "audit.jsonl")
    trip_count = {"n": 0}
    buf = StringIO()
    err = Console(file=buf, color_system=None, width=200)

    event = _event(decoy_id="dcy_x", sensor=SensorKind.DNS, value="h.corp.local")

    # Must NOT raise — the failure path is made non-silent, not crash-prone.
    _handle_trip(event, audit, trip_count, err)

    out = buf.getvalue()
    # the trip was still counted in memory (would be 0 if the raise aborted the callback)
    assert trip_count["n"] == 1
    # the alarm was still rendered live — the catch stays visible
    assert "TRIPPED" in out
    assert "dcy_x" in out
    # the audit-write failure was surfaced rather than swallowed
    assert "AUDIT WRITE FAILED" in out
    assert "disk full" in out


# ---------------------------------------------------------------------------
# v0.5.0 — corrupt audit line + corrupt manifest must surface, not silently
# read CLEAN / crash. (fix-report-silent-drop-on-corrupt-audit-line +
# fix-load-manifest-crash-on-corrupt)
# ---------------------------------------------------------------------------


def test_audit_log_count_corrupt_tallies_skipped_lines(tmp_path):
    """A corrupt line is still skipped (don't crash) but now also counted."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append(_event(decoy_id="dcy_good"))
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("this is not json\n")
        fh.write("\n")  # blank line is not counted as corrupt
        fh.write('{"decoy_id": "x"}\n')  # missing sensor -> KeyError -> corrupt
    assert log.count() == 1
    assert log.count_corrupt() == 2
    corrupt = list(log.iter_corrupt())
    assert "this is not json" in corrupt


def test_report_corrupt_line_alongside_trip_is_surfaced(tmp_path):
    """A corrupt line next to a real trip is surfaced in the signed body."""
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    log = AuditLog(cfg.audit_path)
    log.append(_event(decoy_id="dcy_real"))
    with open(cfg.audit_path, "a", encoding="utf-8") as fh:
        fh.write("this is not json\n")
    result = build_report(cfg)
    assert result.event_count == 1
    assert result.tripped is True
    assert result.corrupt_lines == 1
    assert "Evidence incomplete" in result.markdown
    assert verify_report(result.markdown, cfg.signing_key()) is True


def test_report_corrupt_only_line_does_not_silently_read_clean(tmp_path):
    """Regression for fix-report-silent-drop-on-corrupt-audit-line.

    A corrupt audit.jsonl line used to be silently skipped, so a single
    corrupted trip line could make report undercount to event_count=0 and read
    CLEAN (signed + VERIFIED) over a real trip. With the fix the corrupt-line
    count is surfaced in the signed body, so the report can never silently read
    CLEAN over a dropped trip.
    """
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    # ONLY a corrupt line — no parseable trip.
    with open(cfg.audit_path, "a", encoding="utf-8") as fh:
        fh.write("{{bad json\n")
    result = build_report(cfg)
    assert result.event_count == 0
    assert result.verdict == "CLEAN"  # no parseable trip
    # …but it is NOT a silent CLEAN: the gap is surfaced.
    assert result.corrupt_lines == 1
    assert "Evidence incomplete" in result.markdown
    assert "corrupt audit line" in result.markdown.lower()
    assert verify_report(result.markdown, cfg.signing_key()) is True


def test_load_manifest_fail_soft_on_corrupt_json(tmp_path):
    """Regression for fix-load-manifest-crash-on-corrupt."""
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    cfg.manifest_path.write_text("{not valid json", encoding="utf-8")
    # must NOT raise — fail-soft to None so report/verify surface it in-band.
    assert load_manifest(cfg) is None


def test_load_manifest_fail_soft_on_bad_version(tmp_path):
    """A manifest whose version the schema rejects fail-softs to None."""
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    m = json.loads(cfg.manifest_path.read_text(encoding="utf-8"))
    m["version"] = 2  # Literal[1] rejects this
    cfg.manifest_path.write_text(json.dumps(m), encoding="utf-8")
    assert load_manifest(cfg) is None


def test_report_corrupt_manifest_is_surfaced_not_crash(tmp_path):
    """A corrupt manifest is surfaced as 'manifest CORRUPT' in the signed body,
    not a traceback that denies the operator their evidence."""
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    _seed_events(cfg, n=1)
    cfg.manifest_path.write_text("{not valid json", encoding="utf-8")
    result = build_report(cfg)  # must not raise
    assert result.manifest_corrupt is True
    assert "manifest CORRUPT" in result.markdown
    assert "Evidence incomplete" in result.markdown
    assert verify_report(result.markdown, cfg.signing_key()) is True
