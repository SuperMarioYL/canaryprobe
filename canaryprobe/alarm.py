"""Tripwire events and the append-only audit trail (milestone m2).

When a sensor sees a decoy resolved or connected, it raises a :class:`TripEvent`
— the unambiguous "the trap was sprung" signal from the plan's core primitive::

    TripEvent = { decoy_id, sensor: dns|conn, observed_value, src, ts, verdict: TRIPPED }

Every trip is (a) rendered as a red terminal alarm the operator sees live and
(b) appended as one immutable JSONL line to ``audit.jsonl`` — the audit-留痕
that a later ``canaryprobe report`` turns into evidence.  The audit file is
append-only by construction: :class:`AuditLog` never rewrites existing lines,
so the trail is tamper-evident by inspection.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Literal

from pydantic import BaseModel, Field
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .decoy import Decoy, DecoyKind


class SensorKind(str, Enum):
    """Which sensor observed the trip."""

    DNS = "dns"
    CONN = "conn"


class TripEvent(BaseModel):
    """The record written when a decoy is touched.

    ``verdict`` is always ``"TRIPPED"`` — the mere existence of the event *is*
    the alarm (no legitimate code path ever touches a decoy).  The field is
    kept explicit so the JSONL line is self-describing for an auditor reading
    it out of context.
    """

    decoy_id: str = Field(..., description="id of the decoy that was touched")
    sensor: SensorKind = Field(..., description="which sensor caught it")
    observed_value: str = Field(
        ..., description="the exact host/credential value that was seen"
    )
    src: str = Field(
        default="unknown", description="source of the probe, e.g. '127.0.0.1:54xxx'"
    )
    ts: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp the trip was observed",
    )
    verdict: Literal["TRIPPED"] = "TRIPPED"

    def to_record(self) -> dict[str, Any]:
        """A JSON-serialisable dict with a stable, sorted-key shape."""

        return {
            "ts": self.ts.astimezone(timezone.utc).isoformat(),
            "verdict": self.verdict,
            "sensor": self.sensor.value,
            "decoy_id": self.decoy_id,
            "observed_value": self.observed_value,
            "src": self.src,
        }

    def to_jsonl(self) -> str:
        return json.dumps(self.to_record(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_record(cls, data: dict[str, Any]) -> "TripEvent":
        return cls(
            decoy_id=data["decoy_id"],
            sensor=SensorKind(data["sensor"]),
            observed_value=data["observed_value"],
            src=data.get("src", "unknown"),
            ts=_parse_ts(data["ts"]),
            verdict="TRIPPED",
        )

    @classmethod
    def for_decoy(
        cls,
        decoy: Decoy,
        *,
        sensor: SensorKind,
        observed_value: str | None = None,
        src: str = "unknown",
    ) -> "TripEvent":
        return cls(
            decoy_id=decoy.id,
            sensor=sensor,
            observed_value=observed_value if observed_value is not None else decoy.value,
            src=src,
        )


class AuditLog:
    """Append-only writer/reader for ``audit.jsonl``.

    Writes are guarded by a lock so the two sensor threads never interleave a
    line, and every append is ``flush``+``fsync``'d so a trip survives an
    immediate crash — the audit trail must be durable to be evidence.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def append(self, event: TripEvent) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = event.to_jsonl() + "\n"
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())

    def read(self) -> list[TripEvent]:
        """Read every well-formed event; skip blank/corrupt lines rather than
        crash a report on one bad line."""

        return list(self.iter_events())

    def iter_events(self) -> Iterator[TripEvent]:
        if not self.path.is_file():
            return
        with open(self.path, "r", encoding="utf-8") as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    data = json.loads(raw)
                    yield TripEvent.from_record(data)
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue

    def count(self) -> int:
        return sum(1 for _ in self.iter_events())


# ---------------------------------------------------------------------------
# Terminal rendering — the visceral red TRIPPED alarm
# ---------------------------------------------------------------------------


def render_alarm(event: TripEvent, console: Console | None = None) -> None:
    """Print the red **TRIPPED** panel for a live trip.

    This is the screenshot-able moment: a bordered red panel naming the decoy,
    the sensor that caught it, the source, and the timestamp.
    """

    console = console or Console(stderr=True)

    body = Table.grid(padding=(0, 2))
    body.add_column(justify="right", style="bold red")
    body.add_column()
    body.add_row("decoy", Text(event.decoy_id, style="bold white"))
    body.add_row("observed", Text(event.observed_value, style="yellow"))
    body.add_row("sensor", Text(event.sensor.value.upper(), style="cyan"))
    body.add_row("source", Text(event.src, style="white"))
    body.add_row("time", Text(event.ts.astimezone(timezone.utc).isoformat(), style="white"))

    title = Text("  TRIPPED — decoy touched  ", style="bold white on red")
    console.print()
    console.print(
        Panel(
            body,
            title=title,
            border_style="red",
            expand=False,
            subtitle=Text("a coding agent probed a host it had no business knowing", style="dim"),
        )
    )


def render_armed(config_summary: str, console: Console | None = None) -> None:
    """Print the green 'armed' banner when ``watch`` binds the sensors."""

    console = console or Console(stderr=True)
    console.print(
        Panel(
            Text(config_summary),
            title=Text("  ARMED — sensors listening  ", style="bold white on green"),
            border_style="green",
            expand=False,
        )
    )


def describe_decoy_for_alarm(decoy: Decoy) -> str:
    kind = "host" if decoy.kind is DecoyKind.HOSTNAME else "credential"
    return f"{kind} decoy {decoy.id} ({decoy.value})"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(str(value))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


__all__ = [
    "SensorKind",
    "TripEvent",
    "AuditLog",
    "render_alarm",
    "render_armed",
    "describe_decoy_for_alarm",
]
