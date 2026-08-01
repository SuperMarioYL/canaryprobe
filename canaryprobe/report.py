"""Evidence report (milestone m3).

``canaryprobe report`` reads the audit trail and emits ``report.md``: either a
clean *"no covert egress observed over window T"* artifact, or a **TRIPPED**
artifact that enumerates every :class:`~canaryprobe.alarm.TripEvent` with its
timestamp, sensor, decoy and source.  This is the deliverable a compliance /
审计 reader consumes — the yes/no evidence that replaces a decompilation
project.

The report is *signed*: an HMAC-SHA256 over the canonical report body keyed by
the same per-deployment signing key that signs the decoy manifest.  A verifier
recomputes the signature to confirm the evidence was produced by this
deployment and has not been edited after the fact.  (v0.1 signs by default;
the report stays free — the paid seam is the batch/fleet 等保 edition, not the
signature itself.)
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from pydantic import BaseModel, Field

from .alarm import AuditLog, TripEvent
from .config import DeploymentConfig
from .decoy import DecoyManifest, load_manifest

_SIG_MARKER = "signature: "


class ReportResult(BaseModel):
    """The structured outcome of building a report, returned to the CLI."""

    tripped: bool
    event_count: int
    window_start: datetime | None = None
    window_end: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    manifest_verified: bool | None = None
    signature: str = ""
    markdown: str = ""

    @property
    def verdict(self) -> str:
        return "TRIPPED" if self.tripped else "CLEAN"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _sign(signing_key: str, body: str) -> str:
    return hmac.new(
        signing_key.encode("utf-8"), body.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def build_report(
    config: DeploymentConfig,
    *,
    now: datetime | None = None,
) -> ReportResult:
    """Read the audit log + manifest and produce a :class:`ReportResult`.

    The report is deterministic given the same audit log (aside from the
    ``generated_at`` line), so two runs over the same evidence produce the same
    signature — an auditor can reproduce it.
    """

    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    audit = AuditLog(config.audit_path)
    events = sorted(audit.read(), key=lambda e: e.ts)

    manifest = load_manifest(config)
    manifest_verified: bool | None = None
    if manifest is not None:
        manifest_verified = manifest.verify(config.signing_key())

    window_start = events[0].ts if events else None
    result = ReportResult(
        tripped=bool(events),
        event_count=len(events),
        window_start=window_start,
        window_end=now,
        manifest_verified=manifest_verified,
    )

    body = _render_body(config, events, result, manifest)
    signature = _sign(config.signing_key(), body)
    result.signature = signature
    # The signature is over the evidence BODY only.  The generation timestamp is
    # volatile report-metadata, so it is rendered AFTER the signature line as an
    # unsigned footer — two runs over the same audit log then yield the same
    # signature, which is the auditor-reproducibility guarantee this module
    # documents.  verify_report recomputes the hash over the body (everything
    # before the signature line) and ignores this unsigned footer.
    result.markdown = (
        body
        + f"\n{_SIG_MARKER}`{signature}`\n"
        + f"\nGenerated at: `{_iso(result.window_end)}`\n"
    )
    return result


def _render_body(
    config: DeploymentConfig,
    events: list[TripEvent],
    result: ReportResult,
    manifest: DecoyManifest | None,
) -> str:
    lines: list[str] = []
    verdict = result.verdict
    lines.append("# CanaryProbe — Covert-Egress Evidence Report")
    lines.append("")
    lines.append(f"**Verdict:** `{verdict}`")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Decoy zone | `{config.decoy_zone}` |")
    if result.window_start is not None:
        lines.append(f"| Window start | `{_iso(result.window_start)}` |")
    lines.append(f"| Trip events | {result.event_count} |")
    if manifest is not None:
        planted = len(manifest.decoys)
        verified = "verified" if result.manifest_verified else "UNVERIFIED (tampered or wrong key)"
        lines.append(f"| Decoys planted | {planted} ({verified}) |")
    lines.append(f"| DNS sensor bind | `{config.dns_sensor}` |")
    lines.append(f"| TCP sensor bind | `{config.conn_sensor}` |")
    lines.append("")

    if not events:
        lines.append("## No covert egress observed")
        lines.append("")
        lines.append(
            "No planted decoy was resolved or connected over the observation "
            "window. Every decoy hostname and fake credential remained "
            "untouched — no legitimate code path ever touches a decoy, so this "
            "is positive evidence that the monitored coding agent did not probe "
            "a host it had no business knowing about."
        )
        lines.append("")
        lines.append(
            "> Scope note: this attests to the decoys and sensors configured in "
            "this deployment over the window above. It is runtime evidence, not "
            "a certified compliance artifact."
        )
    else:
        lines.append("## TRIPPED — decoys were touched")
        lines.append("")
        lines.append(
            f"{result.event_count} trip event(s) were recorded. Each row below is "
            "an unambiguous probe of a planted decoy — a value no legitimate "
            "code path should ever touch."
        )
        lines.append("")
        lines.append("| # | Timestamp (UTC) | Sensor | Decoy | Observed | Source |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for i, ev in enumerate(events, start=1):
            lines.append(
                f"| {i} | `{_iso(ev.ts)}` | {ev.sensor.value.upper()} "
                f"| `{ev.decoy_id}` | `{ev.observed_value}` | `{ev.src}` |"
            )
        lines.append("")
        lines.append(
            "> Each event is also recorded as an immutable JSONL line in the "
            "audit trail; this report is a rendering of that trail, not a "
            "substitute for it."
        )

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(
        "This report is signed with the deployment's key (HMAC-SHA256). "
        "Recompute the signature over everything above the signature line to "
        "verify the evidence was produced by this deployment and not edited."
    )
    return "\n".join(lines) + "\n"


def write_report(
    config: DeploymentConfig,
    *,
    path: str | Path | None = None,
    now: datetime | None = None,
) -> tuple[Path, ReportResult]:
    """Build the report and write it to ``report.md`` (or ``path``)."""

    result = build_report(config, now=now)
    target = Path(path) if path is not None else (config.base_dir / "report.md")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(result.markdown, encoding="utf-8")
    return target, result


def verify_report(markdown: str, signing_key: str) -> bool:
    """Verify a rendered ``report.md``: recompute the signature over the body.

    Returns ``True`` iff the embedded signature matches an HMAC over the
    report body (everything before the ``signature:`` line).
    """

    marker = "\n" + _SIG_MARKER
    idx = markdown.rfind(marker)
    if idx == -1:
        return False
    # The signed content is exactly the body, which ends in its own newline;
    # ``build_report`` then appends ``"\n" + marker + sig``. So the body is
    # everything up to (and including) the newline before the extra separator.
    body = markdown[:idx]
    # The signature is the (backtick-wrapped) hex token on the signature line.
    # Anything after that line — e.g. the unsigned "Generated at" footer — is
    # ignored so it can never corrupt the extracted token.
    first_line = markdown[idx + len(marker):].split("\n", 1)[0].strip()
    embedded = first_line.strip("`").strip()
    expected = _sign(signing_key, body)
    return hmac.compare_digest(expected, embedded)


def summarize_events(events: Iterable[TripEvent]) -> str:
    events = list(events)
    if not events:
        return "clean — no decoy was touched"
    return f"TRIPPED — {len(events)} trip event(s) recorded"


__all__ = [
    "ReportResult",
    "build_report",
    "write_report",
    "verify_report",
    "summarize_events",
]
