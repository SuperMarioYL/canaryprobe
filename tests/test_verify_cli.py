"""Tests for milestone m6: the `canaryprobe verify` audit-loop command.

Drives the Typer app with the CliRunner against a real deployment dir, asserting
VERIFIED for a genuine report and TAMPERED (non-zero exit) for an edited body.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from canaryprobe.cli import app
from canaryprobe.config import DeploymentConfig
from canaryprobe.decoy import generate_decoys, write_decoys
from canaryprobe.report import write_report

runner = CliRunner()


def _seed_clean_report(tmp_path: Path) -> tuple[DeploymentConfig, Path]:
    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    path, _ = write_report(cfg)
    return cfg, path


def test_verify_genuine_report(tmp_path):
    _cfg, _path = _seed_clean_report(tmp_path)
    result = runner.invoke(app, ["verify", "--dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "VERIFIED" in result.stdout


def test_verify_tampered_report(tmp_path):
    _cfg, path = _seed_clean_report(tmp_path)
    text = path.read_text(encoding="utf-8")
    # flip the verdict token in the SIGNED body — signature must no longer match
    tampered = text.replace("`CLEAN`", "`TRIPPED`", 1)
    path.write_text(tampered, encoding="utf-8")

    result = runner.invoke(app, ["verify", "--dir", str(tmp_path)])
    assert result.exit_code == 1
    assert "TAMPERED" in result.stdout


def test_verify_missing_report(tmp_path):
    cfg = DeploymentConfig.default(tmp_path)
    # plant decoys + key but never run `report` -> no report.md
    write_decoys(cfg, generate_decoys("corp.local"))
    result = runner.invoke(app, ["verify", "--dir", str(tmp_path)])
    # usage error: no report file present -> exit 2
    assert result.exit_code == 2
    out = (result.stdout or "") + (result.stderr or "")
    assert "not found" in out.lower()


def test_verify_tripped_report(tmp_path):
    """A TRIPPED report (events present) must also verify as genuine."""
    from canaryprobe.alarm import AuditLog, SensorKind, TripEvent
    from datetime import datetime, timezone

    cfg = DeploymentConfig.default(tmp_path)
    write_decoys(cfg, generate_decoys("corp.local"))
    AuditLog(cfg.audit_path).append(
        TripEvent(
            decoy_id="dcy_x",
            sensor=SensorKind.DNS,
            observed_value="h.corp.local",
            src="127.0.0.1:1",
            ts=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
    )
    write_report(cfg)
    result = runner.invoke(app, ["verify", "--dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "VERIFIED" in result.stdout


def test_verify_corrupt_manifest_surfaces_not_crash(tmp_path):
    """Regression for fix-load-manifest-crash-on-corrupt.

    A corrupt/tampered decoys.manifest.json used to crash `canaryprobe verify`
    (DecoyManifest.from_json raised, uncaught). With the fix, load_manifest
    fail-softs to None and verify surfaces 'manifest CORRUPT' + exits non-zero
    instead of dying with a traceback.
    """
    cfg, path = _seed_clean_report(tmp_path)
    # corrupt the manifest that write_decoys + write_report left behind
    cfg.manifest_path.write_text("{not valid json", encoding="utf-8")
    result = runner.invoke(app, ["verify", "--dir", str(tmp_path)])
    # the report signature is still valid, but the manifest is corrupt -> exit 1
    assert result.exit_code == 1
    out = (result.stdout or "") + (result.stderr or "")
    assert "CORRUPT" in out
