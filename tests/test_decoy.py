"""Tests for milestone m1: decoy generation, the signed manifest, and config.

These exercise the core engine ``canaryprobe init`` is built on: decoys are
generated, persisted to ``decoys.json`` + a signed manifest, the signature
round-trips and catches tampering, and the operator gets clear injection
instructions.
"""

from __future__ import annotations

import json

import pytest

from canaryprobe.config import (
    DEFAULT_DECOY_ZONE,
    DeploymentConfig,
    SensorBind,
    ensure_signing_key,
    load_or_default,
)
from canaryprobe.decoy import (
    Decoy,
    DecoyKind,
    DecoyManifest,
    build_manifest,
    generate_credential_decoy,
    generate_decoys,
    generate_hostname_decoy,
    injection_instructions,
    load_decoys,
    load_manifest,
    write_decoys,
)


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


def test_default_config_zone_and_binds():
    cfg = DeploymentConfig.default()
    assert cfg.decoy_zone == DEFAULT_DECOY_ZONE
    assert cfg.dns_sensor.port == 5353
    assert cfg.conn_sensor.port == 5443


def test_zone_is_normalized():
    # The field validator strips whitespace / trailing dot and lowercases.
    cfg = DeploymentConfig(decoy_zone="  CORP.Local.  ")
    assert cfg.decoy_zone == "corp.local"


def test_zone_must_be_dotted():
    with pytest.raises(ValueError):
        DeploymentConfig(decoy_zone="notdotted")


def test_config_yaml_roundtrip(tmp_path):
    cfg = DeploymentConfig(
        decoy_zone="lab.internal",
        dns_sensor=SensorBind(host="0.0.0.0", port=15353),
        conn_sensor=SensorBind(host="127.0.0.1", port=15443),
        audit_file="events.jsonl",
        base_dir=tmp_path,
    )
    saved = cfg.save()
    assert saved.is_file()

    loaded = DeploymentConfig.load(saved)
    assert loaded.decoy_zone == "lab.internal"
    assert loaded.dns_sensor.host == "0.0.0.0"
    assert loaded.dns_sensor.port == 15353
    assert loaded.conn_sensor.port == 15443
    assert loaded.audit_file == "events.jsonl"
    # base_dir is derived from the file location, paths resolve under it
    assert loaded.audit_path == (tmp_path / "events.jsonl").resolve()


def test_load_or_default_without_file(tmp_path):
    cfg = load_or_default(tmp_path)
    assert cfg.decoy_zone == DEFAULT_DECOY_ZONE
    assert cfg.base_dir == tmp_path


def test_load_or_default_prefers_existing(tmp_path):
    DeploymentConfig(decoy_zone="picked.up", base_dir=tmp_path).save()
    cfg = load_or_default(tmp_path)
    assert cfg.decoy_zone == "picked.up"


def test_paths_resolve_absolute_untouched(tmp_path):
    abs_audit = tmp_path / "elsewhere" / "audit.jsonl"
    cfg = DeploymentConfig(audit_file=str(abs_audit), base_dir=tmp_path)
    assert cfg.audit_path == abs_audit


def test_signing_key_is_stable_and_persisted(tmp_path):
    k1 = ensure_signing_key(tmp_path)
    k2 = ensure_signing_key(tmp_path)
    assert k1 == k2
    assert len(k1) == 64  # token_hex(32)
    assert (tmp_path / ".canaryprobe.key").is_file()


def test_signing_key_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("CANARYPROBE_SIGNING_KEY", "operator-supplied-secret")
    cfg = DeploymentConfig.default(tmp_path)
    assert cfg.signing_key() == "operator-supplied-secret"
    # no key file was written because the env var short-circuits
    assert not (tmp_path / ".canaryprobe.key").is_file()


def test_signing_key_file_created_0600_with_no_0o644_window(tmp_path):
    """The signing key is the root of trust that signs the decoy manifest AND
    the evidence report, so its file must be created at 0o600 with no
    write-then-chmod (0o644) window that would leak it to a co-tenant of a
    traversable base_dir.
    """
    import os
    import stat

    key = ensure_signing_key(tmp_path)
    key_path = tmp_path / ".canaryprobe.key"
    assert key_path.is_file()
    mode = stat.S_IMODE(os.stat(key_path).st_mode)
    assert mode == 0o600, f"expected 0o600, got {oct(mode)}"
    # the persisted content is the returned key, and it round-trips on reload
    assert key_path.read_text(encoding="utf-8").strip() == key
    assert len(key) == 64  # token_hex(32)
    assert ensure_signing_key(tmp_path) == key


def test_quoted_value_with_trailing_inline_comment_parses():
    """Regression for fix-yaml-quoted-value-inline-comment: a quoted scalar
    followed by ' # comment' must parse to the bare value, not the literal
    '"value" # comment' string that broke audit_path / decoys loading / the
    DNS sensor zone.
    """
    from canaryprobe.config import _parse_yaml

    assert _parse_yaml('audit_file: "events.jsonl" # trail') == {
        "audit_file": "events.jsonl"
    }
    assert _parse_yaml('decoy_zone: "zone" # c') == {"decoy_zone": "zone"}
    # single-quoted values behave the same
    assert _parse_yaml("decoy_zone: 'zone' # c") == {"decoy_zone": "zone"}
    # a quoted value with no trailing comment still parses (no regression)
    assert _parse_yaml('audit_file: "events.jsonl"') == {
        "audit_file": "events.jsonl"
    }


def test_unquoted_value_inline_comment_still_strips():
    """The unquoted path is unchanged: a ' # comment' is stripped as before."""
    from canaryprobe.config import _strip_inline_comment

    assert _strip_inline_comment("foo # comment") == "foo"
    assert _strip_inline_comment("foo") == "foo"
    assert _strip_inline_comment("foo#bar") == "foo#bar"  # no space -> not a comment
    assert _strip_inline_comment("") == ""


# ---------------------------------------------------------------------------
# decoy generation
# ---------------------------------------------------------------------------


def test_hostname_decoy_is_in_zone():
    d = generate_hostname_decoy("corp.local")
    assert d.kind is DecoyKind.HOSTNAME
    assert d.value.endswith(".corp.local")
    assert d.id.startswith("dcy_")


def test_hostname_decoy_normalizes_zone():
    d = generate_hostname_decoy("  CORP.Local.  ")
    assert d.value.endswith(".corp.local")


def test_credential_decoy_shapes():
    aws = generate_credential_decoy("aws_access_key")
    assert aws.value.startswith("AKIA")
    api = generate_credential_decoy("api_token")
    assert api.value.startswith("cnp_")
    assert generate_credential_decoy("db_password").kind is DecoyKind.CREDENTIAL
    assert generate_credential_decoy("ssh_private_key_id").value.startswith("SHA256:")
    # v0.2 — broader bait surface
    imds = generate_credential_decoy("cloud_metadata_url")
    assert imds.kind is DecoyKind.CREDENTIAL
    assert "169.254.169.254" in imds.value
    assert imds.value.startswith("http://")
    pkg = generate_credential_decoy("package_index_token")
    assert pkg.kind is DecoyKind.CREDENTIAL
    assert pkg.value.startswith("npm_")


def test_new_credential_kinds_are_random_unique():
    a = generate_credential_decoy("cloud_metadata_url")
    b = generate_credential_decoy("cloud_metadata_url")
    assert a.value != b.value
    c = generate_credential_decoy("package_index_token")
    d = generate_credential_decoy("package_index_token")
    assert c.value != d.value


def test_cred_env_name_maps_new_kinds():
    from canaryprobe.decoy import _cred_env_name

    assert _cred_env_name(generate_credential_decoy("cloud_metadata_url")) == "CLOUD_METADATA_URL"
    assert _cred_env_name(generate_credential_decoy("package_index_token")) == "PACKAGE_INDEX_TOKEN"
    # existing mappings unchanged
    assert _cred_env_name(generate_credential_decoy("aws_access_key")) == "AWS_ACCESS_KEY_ID"


def test_unknown_credential_kind_raises():
    with pytest.raises(ValueError):
        generate_credential_decoy("totally_made_up")


def test_generate_decoys_counts():
    decoys = generate_decoys("corp.local", hostnames=2, credentials=3)
    hosts = [d for d in decoys if d.kind is DecoyKind.HOSTNAME]
    creds = [d for d in decoys if d.kind is DecoyKind.CREDENTIAL]
    assert len(hosts) == 2
    assert len(creds) == 3


def test_generate_decoys_never_empty():
    decoys = generate_decoys("corp.local", hostnames=0, credentials=0)
    assert len(decoys) >= 1


def test_generate_decoys_rejects_negative():
    with pytest.raises(ValueError):
        generate_decoys("corp.local", hostnames=-1)


def test_decoy_values_are_unique_across_a_set():
    decoys = generate_decoys("corp.local", hostnames=4, credentials=4)
    values = [d.value for d in decoys]
    ids = [d.id for d in decoys]
    assert len(set(values)) == len(values)
    assert len(set(ids)) == len(ids)


# ---------------------------------------------------------------------------
# manifest signing / verification
# ---------------------------------------------------------------------------


def test_manifest_signs_and_verifies():
    decoys = generate_decoys("corp.local")
    manifest = build_manifest(decoys, "corp.local", "secret-key")
    assert manifest.sig
    assert manifest.verify("secret-key") is True


def test_manifest_rejects_wrong_key():
    manifest = build_manifest(generate_decoys("corp.local"), "corp.local", "key-a")
    assert manifest.verify("key-b") is False


def test_unsigned_manifest_does_not_verify():
    manifest = DecoyManifest(zone="corp.local", decoys=generate_decoys("corp.local"))
    assert manifest.verify("any-key") is False


def test_manifest_detects_tampering():
    decoys = generate_decoys("corp.local", hostnames=1, credentials=1)
    manifest = build_manifest(decoys, "corp.local", "secret-key")
    assert manifest.verify("secret-key") is True
    # Tamper: swap a decoy value after signing.
    manifest.decoys[0].value = "attacker-changed-this.corp.local"
    assert manifest.verify("secret-key") is False


def test_manifest_json_roundtrip():
    decoys = generate_decoys("corp.local", hostnames=2, credentials=2)
    manifest = build_manifest(decoys, "corp.local", "secret-key")
    text = manifest.to_json()
    restored = DecoyManifest.from_json(text)
    assert restored.zone == "corp.local"
    assert len(restored.decoys) == 4
    assert restored.sig == manifest.sig
    # signature still valid after a full serialize/parse cycle
    assert restored.verify("secret-key") is True


def test_decoy_canonical_is_stable():
    d = Decoy(id="dcy_test", kind=DecoyKind.HOSTNAME, value="h.corp.local")
    c1 = d.canonical()
    c2 = Decoy.from_dict(c1).canonical()
    assert c1 == c2


# ---------------------------------------------------------------------------
# persistence + full init round trip
# ---------------------------------------------------------------------------


def test_write_and_load_decoys(tmp_path):
    cfg = DeploymentConfig.default(tmp_path)
    decoys = generate_decoys("corp.local", hostnames=1, credentials=1)
    decoys_path, manifest_path = write_decoys(cfg, decoys)

    assert decoys_path.is_file()
    assert manifest_path.is_file()

    loaded = load_decoys(cfg)
    assert len(loaded) == len(decoys)
    assert {d.value for d in loaded} == {d.value for d in decoys}


def test_written_manifest_verifies_with_deployment_key(tmp_path):
    cfg = DeploymentConfig.default(tmp_path)
    decoys = generate_decoys("corp.local")
    write_decoys(cfg, decoys)

    manifest = load_manifest(cfg)
    assert manifest is not None
    # The same deployment key that signed it verifies it.
    assert manifest.verify(cfg.signing_key()) is True


def test_decoys_json_is_well_formed(tmp_path):
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local", hostnames=1, credentials=1))
    data = json.loads(cfg.decoys_path.read_text())
    assert data["zone"] == "corp.local"
    assert isinstance(data["decoys"], list)
    for d in data["decoys"]:
        assert {"id", "kind", "value", "label", "planted_at"} <= set(d)


def test_load_decoys_missing_file_is_empty(tmp_path):
    cfg = DeploymentConfig.default(tmp_path)
    assert load_decoys(cfg) == []
    assert load_manifest(cfg) is None


# ---------------------------------------------------------------------------
# injection instructions (m1 "print what to inject where")
# ---------------------------------------------------------------------------


def test_injection_instructions_mentions_each_decoy():
    cfg = DeploymentConfig.default()
    decoys = generate_decoys("corp.local", hostnames=1, credentials=2)
    text = injection_instructions(decoys, cfg)
    for d in decoys:
        assert d.value in text
    # host + resolver guidance is present
    assert "/etc/hosts" in text
    assert "canaryprobe watch" in text


def test_injection_instructions_uses_env_exports_for_creds():
    cfg = DeploymentConfig.default()
    decoys = [generate_credential_decoy("aws_access_key")]
    text = injection_instructions(decoys, cfg)
    assert "export AWS_ACCESS_KEY_ID=" in text


def test_injection_instructions_names_resolver_path_and_warns_etc_hosts(tmp_path):
    """The DNS trip path must actually fire: the zone's resolver is pointed at
    the DNS sensor (a resolve IS a DNS query), and the operator is explicitly
    warned that a bare /etc/hosts entry does NOT trip the DNS sensor.  The
    connect-bait carries the conn sensor's port so a connect lands on the bind.
    """
    cfg = DeploymentConfig.default(tmp_path)
    decoys = generate_decoys("corp.local", hostnames=1, credentials=0)
    text = injection_instructions(decoys, cfg)

    # the DNS sensor host:port is named as the resolver target for the zone
    assert f"{cfg.dns_sensor.host}:{cfg.dns_sensor.port}" in text
    assert "resolver" in text.lower()
    # explicit /etc/hosts warning that it will not trip the DNS sensor
    assert "/etc/hosts" in text
    low = text.lower()
    assert "will not trip" in low or "does not trip" in low or "no dns query" in low
    # connect-bait carries the conn sensor's port
    assert f":{cfg.conn_sensor.port}" in text
    assert "http://" in text
