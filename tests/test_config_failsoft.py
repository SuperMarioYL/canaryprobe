"""Regression tests pinning the three v0.7.0 config.py correctness fixes.

``deployment.yaml`` loading was the last unhardened corrupt-input path (asymmetric
with the v0.5.0/v0.6.0 fail-soft on the sibling runtime files). These lock the
three fixes found by reading shipped v0.6.0 source so a future narrowing
re-opens the hole loudly here in CI rather than silently in the field.

* ``fix-deployment-yaml-load-no-failsoft`` (config.py:217) — a present-but-
  corrupt ``deployment.yaml`` (a bare scalar key the parser turns into a dict,
  or a ``null`` coerced to ``None``, failing pydantic's ``str`` field) must
  raise the typed :class:`DeploymentConfigCorruptError` (rendered by the CLI as
  "deployment.yaml corrupt — re-init", exit 2) instead of a raw
  ``ValidationError`` traceback out of every command.
* ``fix-yaml-unquoted-leading-hash-misparse`` (config.py:349) — an unquoted
  value that STARTS with ``#`` (``decoy_zone: # use default corp.local``) must
  be treated as comment-only/empty, never returned as the literal garbage
  string (which the dotted-only zone validator would accept, minting a decoy
  hostname containing spaces/``#`` and a DNS sensor zone no real query can
  match → trips silently never fire).
* ``fix-partial-sensor-bind-silent-port0`` (config.py:189) — a sensor block
  that sets ``host:`` but omits ``port:`` must inherit the documented bind port
  (5353/5443), not ``SensorBind.port``'s own default of 0 (which binds a random
  port the config reports as 0, pointing the armed banner at port 0 → the trip
  silently never fires).
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from canaryprobe.cli import app
from canaryprobe.config import (
    DEFAULT_DNS_BIND_PORT,
    DEFAULT_CONN_BIND_PORT,
    DeploymentConfig,
    DeploymentConfigCorruptError,
    _parse_yaml,
    _strip_inline_comment,
    load_or_default,
)

runner = CliRunner()


# ---------------------------------------------------------------------------
# fix-deployment-yaml-load-no-failsoft — typed error, not a raw traceback
# ---------------------------------------------------------------------------


# A bare scalar key (`audit_file:`) parses to a dict and `audit_file: null` to
# None; both fail pydantic's `str` field. These are the two repro cases the
# bug-hunter verified raise a raw ValidationError out of DeploymentConfig.load.
CORRUPT_DEPLOYMENT_YAML_CASES = [
    ("bare_scalar_key", "audit_file:\n"),
    ("null_value", "audit_file: null\n"),
    ("bare_decoys_file", "decoys_file:\n"),
    ("null_manifest_file", "manifest_file: null\n"),
]


@pytest.mark.parametrize(
    "content",
    [c[1] for c in CORRUPT_DEPLOYMENT_YAML_CASES],
    ids=[c[0] for c in CORRUPT_DEPLOYMENT_YAML_CASES],
)
def test_load_or_default_corrupt_deployment_yaml_raises_typed_error(tmp_path, content):
    """Regression for fix-deployment-yaml-load-no-failsoft.

    A present-but-corrupt ``deployment.yaml`` used to propagate a raw
    ``ValidationError`` out of ``load_or_default`` → every CLI command crashed
    with a traceback (``watch`` = no protection, ``report``/``verify`` =
    denial-of-evidence). With the fix, ``load_or_default`` raises the typed
    :class:`DeploymentConfigCorruptError` (a clean, catchable error) — never a
    raw ``ValidationError`` — so the CLI can render a guided "re-init" message.
    """
    (tmp_path / "deployment.yaml").write_text(content, encoding="utf-8")
    with pytest.raises(DeploymentConfigCorruptError) as exc_info:
        load_or_default(tmp_path)
    msg = str(exc_info.value)
    assert "deployment.yaml" in msg
    assert "re-init" in msg.lower()
    # the raw pydantic ValidationError must be chained, not propagated bare
    assert exc_info.value.__cause__ is not None


def test_load_or_default_missing_file_returns_default_not_corrupt(tmp_path):
    """Control: an ABSENT ``deployment.yaml`` is a genuine fresh install → the
    default config, NOT the typed corrupt error. Guards against over-broadening
    (a present-but-corrupt file must raise; an absent file must not)."""
    assert not (tmp_path / "deployment.yaml").is_file()
    cfg = load_or_default(tmp_path)
    assert isinstance(cfg, DeploymentConfig)
    assert cfg.base_dir == tmp_path


@pytest.mark.parametrize(
    "command",
    [["watch", "--duration", "0"], ["report"], ["verify"], ["simulate-trip"]],
    ids=["watch", "report", "verify", "simulate-trip"],
)
def test_command_corrupt_deployment_yaml_exits_clean_not_traceback(
    tmp_path, command
):
    """Every command that loads config surfaces a guided 'deployment.yaml
    corrupt — re-init' message and exits 2 instead of crashing with a raw
    ``ValidationError`` traceback before it can arm sensors / render evidence."""
    (tmp_path / "deployment.yaml").write_text("audit_file:\n", encoding="utf-8")
    result = runner.invoke(app, [command[0], "--dir", str(tmp_path), *command[1:]])
    assert result.exit_code == 2
    out = (result.stdout or "") + (result.stderr or "")
    assert "deployment.yaml" in out.lower()
    assert "corrupt" in out.lower()
    assert "re-init" in out.lower()


def test_init_corrupt_deployment_yaml_falls_back_and_overwrites(tmp_path):
    """``canaryprobe init`` IS the recovery command ("re-init with canaryprobe
    init"), so a present-but-corrupt ``deployment.yaml`` must not crash it: it
    falls back to a fresh default and overwrites the corrupt file, leaving the
    deployment loadable again (a subsequent command works)."""
    (tmp_path / "deployment.yaml").write_text("audit_file:\n", encoding="utf-8")
    result = runner.invoke(app, ["init", "--dir", str(tmp_path)])
    assert result.exit_code == 0
    # the corrupt file was overwritten with a valid config — load no longer raises
    cfg = load_or_default(tmp_path)
    assert isinstance(cfg, DeploymentConfig)
    # a subsequent report now runs clean (no traceback)
    report = runner.invoke(app, ["report", "--dir", str(tmp_path)])
    assert report.exit_code == 0


# ---------------------------------------------------------------------------
# fix-yaml-unquoted-leading-hash-misparse — comment-only, not the literal
# ---------------------------------------------------------------------------


def test_strip_inline_comment_unquoted_leading_hash_is_empty():
    """Regression for fix-yaml-unquoted-leading-hash-misparse.

    An unquoted value that STARTS with ``#`` (``decoy_zone: # use default``) is
    comment-only — the `` #`` (space-then-hash) lookup did not match it, so the
    whole ``# use default corp.local`` was returned as the literal value. With
    the fix it returns empty (the key carries no value), mirroring the v0.4.0
    quoted-value inline-comment fix.
    """
    assert _strip_inline_comment("# use default corp.local") == ""
    assert _strip_inline_comment("#note") == ""  # no space, still comment-only


def test_strip_inline_comment_space_hash_path_unchanged():
    """Guard: the existing `` #`` (space-then-hash) inline-comment strip the
    fix sits beside must still work, so the fix doesn't regress trailing
    comments on a real value."""
    assert _strip_inline_comment("corp.local # comment") == "corp.local"
    assert _strip_inline_comment("corp.local") == "corp.local"


def test_strip_inline_comment_quoted_leading_hash_is_literal():
    """Guard: a QUOTED value whose content starts with ``#`` is literal (the
    v0.4.0 quoted-value fix leaves in-quote ``#`` untouched). The leading-``#``
    fix must only apply to UNQUOTED values."""
    assert _strip_inline_comment('"# use default"') == '"# use default"'


def test_parse_yaml_unquoted_leading_hash_value_not_literal_garbage():
    """End-to-end parser pin: ``decoy_zone: # use default corp.local`` must NOT
    parse to the literal garbage string ``'# use default corp.local'`` (which
    the dotted-only zone validator would accept). With the fix the value
    becomes empty, so the key carries no value rather than the garbage."""
    parsed = _parse_yaml("decoy_zone: # use default corp.local\n")
    assert parsed.get("decoy_zone") != "# use default corp.local"
    # the value is now empty/comment-only, not the garbage string
    assert parsed.get("decoy_zone") == {}


def test_load_decoy_zone_unquoted_leading_hash_rejected_not_accepted(tmp_path):
    """The security property: a garbage zone born of an unquoted leading-``#``
    comment (with spaces/``#``) must be REJECTED by the load, not silently
    accepted as a valid zone (which would mint a detectable-as-fake decoy
    hostname and a DNS sensor zone no real query can match). With fix-2 the
    value becomes empty → a bare key → the load-level guard (fix-1) rejects it
    as :class:`DeploymentConfigCorruptError`."""
    (tmp_path / "deployment.yaml").write_text(
        "decoy_zone: # use default corp.local\n", encoding="utf-8"
    )
    with pytest.raises(DeploymentConfigCorruptError):
        load_or_default(tmp_path)


# ---------------------------------------------------------------------------
# fix-partial-sensor-bind-silent-port0 — omitted port inherits the default
# ---------------------------------------------------------------------------


def test_partial_dns_sensor_omitting_port_inherits_default_port():
    """Regression for fix-partial-sensor-bind-silent-port0.

    An operator who sets a sensor ``host:`` and omits ``port:`` used to silently
    get ``port=0`` (``SensorBind.port``'s own default) — the sensor bound a
    random port while the config reported 0, so the armed banner pointed the
    agent at port 0 and the trip silently never fired. With the fix the omitted
    port inherits the documented per-sensor default (5353 for DNS)."""
    cfg = DeploymentConfig.from_dict({"dns_sensor": {"host": "10.0.0.5"}})
    assert cfg.dns_sensor.host == "10.0.0.5"
    assert cfg.dns_sensor.port == DEFAULT_DNS_BIND_PORT  # 5353, not 0


def test_partial_conn_sensor_omitting_port_inherits_default_port():
    """The conn sensor equivalent: an omitted ``port:`` inherits 5443, not 0."""
    cfg = DeploymentConfig.from_dict({"conn_sensor": {"host": "10.0.0.5"}})
    assert cfg.conn_sensor.host == "10.0.0.5"
    assert cfg.conn_sensor.port == DEFAULT_CONN_BIND_PORT  # 5443, not 0


def test_partial_sensor_omitting_host_inherits_default_host_and_port():
    """Omitting ``host:`` (port only) likewise inherits the default host, not a
    blank — the partial-merge fix applies symmetrically to both keys."""
    cfg = DeploymentConfig.from_dict({"dns_sensor": {"port": 15353}})
    assert cfg.dns_sensor.port == 15353
    assert cfg.dns_sensor.host == "127.0.0.1"  # DEFAULT_DNS_BIND_HOST


def test_partial_sensor_explicit_port_zero_still_passes_through():
    """Guard: an explicit ``port: 0`` is an opt-in random bind and must still
    win (the merge puts the operator's value last). The fix only changes the
    OMITTED case; it must not force a non-zero port on an operator who chose 0."""
    cfg = DeploymentConfig.from_dict(
        {"conn_sensor": {"host": "10.0.0.5", "port": 0}}
    )
    assert cfg.conn_sensor.port == 0


def test_partial_sensor_round_trips_through_yaml(tmp_path):
    """A partial sensor block written by the operator and reloaded through the
    YAML round-trip resolves the omitted port to the documented default, so a
    config saved with a host-only bind still arms at a real port after reload."""
    cfg = DeploymentConfig.from_dict(
        {"dns_sensor": {"host": "10.0.0.5"}}, base_dir=tmp_path
    )
    cfg.save()
    reloaded = load_or_default(tmp_path)
    assert reloaded.dns_sensor.host == "10.0.0.5"
    assert reloaded.dns_sensor.port == DEFAULT_DNS_BIND_PORT
