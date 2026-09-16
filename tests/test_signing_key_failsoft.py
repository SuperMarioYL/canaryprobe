"""Regressions for fix-signing-key-mint-crash-on-readonly-audit-path (v0.10.0).

At v0.9.0, ``canaryprobe verify`` routed its signing-key lookup through
``DeploymentConfig.signing_key()`` -> ``ensure_signing_key``, which MINTS AND
PERSISTS ``.canaryprobe.key`` when absent. Two defects, both reproduced at the
shipped tag:

1. verify (an audit command) created a new root-of-trust key as a write side
   effect when the key file was lost.
2. On a read-only deployment dir, both ``verify`` and ``report`` crashed with a
   raw PermissionError traceback from the key-mint ``os.open`` (denial of
   evidence — the audit loop cannot complete).

These tests pin the fail-soft: verify never mints (guided exit 2 instead),
verify/report exit 2 (never raise) when the deployment dir is unwritable, and
``lookup_signing_key`` resolves env > file > None without writing.
"""

from __future__ import annotations

import os

import pytest
from typer.testing import CliRunner

from canaryprobe.cli import app
from canaryprobe.config import SIGNING_KEY_ENV, ensure_signing_key, lookup_signing_key

runner = CliRunner()

#: chmod-based tests are meaningless (and the chmod 0o500 is a no-op) for root.
_run_as_root = getattr(os, "geteuid", lambda: 1000)() == 0


def _deploy(tmp_path) -> None:
    result = runner.invoke(app, ["init", "--dir", str(tmp_path)])
    assert result.exit_code == 0
    assert (tmp_path / ".canaryprobe.key").is_file()


# ---------------------------------------------------------------------------
# lookup_signing_key — the non-minting read path
# ---------------------------------------------------------------------------


def test_lookup_signing_key_env_beats_file(tmp_path, monkeypatch):
    ensure_signing_key(tmp_path)
    monkeypatch.setenv(SIGNING_KEY_ENV, "env-key")
    assert lookup_signing_key(tmp_path) == "env-key"


def test_lookup_signing_key_reads_existing_file(tmp_path, monkeypatch):
    monkeypatch.delenv(SIGNING_KEY_ENV, raising=False)
    key = ensure_signing_key(tmp_path)
    assert lookup_signing_key(tmp_path) == key


def test_lookup_signing_key_returns_none_when_absent(tmp_path, monkeypatch):
    monkeypatch.delenv(SIGNING_KEY_ENV, raising=False)
    assert lookup_signing_key(tmp_path) is None


def test_lookup_signing_key_never_writes(tmp_path, monkeypatch):
    monkeypatch.delenv(SIGNING_KEY_ENV, raising=False)
    assert lookup_signing_key(tmp_path) is None
    assert not (tmp_path / ".canaryprobe.key").exists()


# ---------------------------------------------------------------------------
# verify — guided exit, no mint, no crash
# ---------------------------------------------------------------------------


def test_verify_does_not_mint_signing_key(tmp_path):
    _deploy(tmp_path)
    key_file = tmp_path / ".canaryprobe.key"
    key_file.unlink()
    (tmp_path / "report.md").write_text("tampered body", encoding="utf-8")

    result = runner.invoke(app, ["verify", "--dir", str(tmp_path)])

    assert result.exit_code == 2
    assert "signing key" in (result.output or "").lower()
    # The audit command must not create trust anchors as a side effect.
    assert not key_file.exists()


def test_verify_surfaces_error_instead_of_crash_on_readonly_dir(tmp_path):
    if _run_as_root:
        pytest.skip("chmod 0o500 does not block root")
    _deploy(tmp_path)
    key_file = tmp_path / ".canaryprobe.key"
    key_file.unlink()
    (tmp_path / "report.md").write_text("body", encoding="utf-8")
    os.chmod(tmp_path, 0o500)
    try:
        result = runner.invoke(app, ["verify", "--dir", str(tmp_path)])
    finally:
        os.chmod(tmp_path, 0o755)

    # Guided exit 2 — NOT the raw PermissionError traceback (which CliRunner
    # would report as exit code 1 + a stored PermissionError exception).
    assert result.exit_code == 2
    assert not isinstance(result.exception, PermissionError)


def test_verify_still_verifies_with_env_key(tmp_path, monkeypatch):
    _deploy(tmp_path)
    key_file = tmp_path / ".canaryprobe.key"
    monkeypatch.setenv(SIGNING_KEY_ENV, key_file.read_text(encoding="utf-8").strip())
    key_file.unlink()
    runner.invoke(app, ["report", "--dir", str(tmp_path)])

    result = runner.invoke(app, ["verify", "--dir", str(tmp_path)])

    assert result.exit_code == 0
    assert "VERIFIED" in result.output


# ---------------------------------------------------------------------------
# report — guided exit instead of a raw traceback on an unwritable dir
# ---------------------------------------------------------------------------


def test_report_surfaces_error_instead_of_crash_on_readonly_dir(tmp_path):
    if _run_as_root:
        pytest.skip("chmod 0o500 does not block root")
    _deploy(tmp_path)
    (tmp_path / ".canaryprobe.key").unlink()
    os.chmod(tmp_path, 0o500)
    try:
        result = runner.invoke(app, ["report", "--dir", str(tmp_path)])
    finally:
        os.chmod(tmp_path, 0o755)

    assert result.exit_code == 2
    assert not isinstance(result.exception, PermissionError)


def test_report_surfaces_error_when_report_unwritable(tmp_path):
    if _run_as_root:
        pytest.skip("chmod 0o500 does not block root")
    _deploy(tmp_path)  # key present — minting not needed
    os.chmod(tmp_path, 0o500)
    try:
        result = runner.invoke(app, ["report", "--dir", str(tmp_path)])
    finally:
        os.chmod(tmp_path, 0o755)

    assert result.exit_code == 2
    assert not isinstance(result.exception, PermissionError)
