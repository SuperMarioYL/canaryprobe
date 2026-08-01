"""CanaryProbe command-line interface.

Four commands carry the whole happy path:

* ``canaryprobe init``   — generate decoys + a signed manifest, print what to inject.
* ``canaryprobe plant``  — alias of ``init`` (re-plant a fresh decoy set).
* ``canaryprobe watch``  — arm the DNS + TCP sensors; alarm + audit on a trip.
* ``canaryprobe report`` — emit the signed clean/TRIPPED evidence artifact.

A hidden ``simulate-trip`` command triggers a decoy resolve/connect against a
running ``watch`` so the demo (and the test suite) can produce the visceral
TRIPPED moment without pointing a real closed-source coding agent at a local
endpoint.
"""

from __future__ import annotations

import signal
import socket
import threading
import time
from pathlib import Path
from typing import Optional

import typer
from dnslib import DNSRecord
from rich.console import Console
from rich.table import Table

from . import __version__
from .alarm import AuditLog, render_alarm, render_armed
from .config import DeploymentConfig, load_or_default
from .decoy import (
    DecoyKind,
    generate_decoys,
    injection_instructions,
    load_decoys,
    load_manifest,
    write_decoys,
)
from .report import verify_report, write_report
from .sensor_conn import ConnSensor
from .sensor_dns import DnsSensor

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="A honeytoken tripwire that catches a closed-source coding agent probing planted decoys.",
)

_out = Console()
_err = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        _out.print(f"canaryprobe {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """CanaryProbe — plant decoys, arm sensors, prove no covert egress."""


# ---------------------------------------------------------------------------
# init / plant
# ---------------------------------------------------------------------------


def _do_init(
    dir_: Path,
    zone: Optional[str],
    hostnames: int,
    credentials: int,
) -> None:
    cfg = load_or_default(dir_)
    if zone:
        cfg = DeploymentConfig.from_dict(
            {**_config_to_dict(cfg), "decoy_zone": zone}, base_dir=dir_
        )
    # Persist the config so watch/report agree on zone + binds.
    config_path = cfg.save()

    decoys = generate_decoys(cfg.decoy_zone, hostnames=hostnames, credentials=credentials)
    decoys_path, manifest_path = write_decoys(cfg, decoys)

    table = Table(title="Planted decoys", show_lines=False, expand=False)
    table.add_column("id", style="cyan", no_wrap=True)
    table.add_column("kind", style="magenta")
    table.add_column("value", style="yellow", overflow="fold")
    for d in decoys:
        table.add_row(d.id, d.kind.value, d.value)
    _out.print(table)
    _out.print()
    _out.print(f"[green]decoys[/green]   {decoys_path}")
    _out.print(f"[green]manifest[/green] {manifest_path}  (signed)")
    _out.print(f"[green]config[/green]   {config_path}")
    _out.print()
    _out.print(injection_instructions(decoys, cfg))


def _config_to_dict(cfg: DeploymentConfig) -> dict:
    return {
        "decoy_zone": cfg.decoy_zone,
        "dns_sensor": {"host": cfg.dns_sensor.host, "port": cfg.dns_sensor.port},
        "conn_sensor": {"host": cfg.conn_sensor.host, "port": cfg.conn_sensor.port},
        "decoys_file": cfg.decoys_file,
        "manifest_file": cfg.manifest_file,
        "audit_file": cfg.audit_file,
    }


@app.command()
def init(
    directory: Path = typer.Option(
        Path.cwd, "--dir", "-d", help="Deployment directory (default: current)."
    ),
    zone: Optional[str] = typer.Option(
        None, "--zone", "-z", help="Decoy DNS zone (default: corp.local)."
    ),
    hostnames: int = typer.Option(1, "--hostnames", min=0, help="Decoy hostnames to mint."),
    credentials: int = typer.Option(1, "--credentials", min=0, help="Fake credentials to mint."),
) -> None:
    """Generate a decoy set + signed manifest and print what to inject where."""

    _do_init(Path(directory), zone, hostnames, credentials)


@app.command()
def plant(
    directory: Path = typer.Option(Path.cwd, "--dir", "-d", help="Deployment directory."),
    zone: Optional[str] = typer.Option(None, "--zone", "-z", help="Decoy DNS zone."),
    hostnames: int = typer.Option(1, "--hostnames", min=0),
    credentials: int = typer.Option(1, "--credentials", min=0),
) -> None:
    """Re-plant a fresh decoy set (alias of 'init')."""

    _do_init(Path(directory), zone, hostnames, credentials)


# ---------------------------------------------------------------------------
# watch
# ---------------------------------------------------------------------------


@app.command()
def watch(
    directory: Path = typer.Option(Path.cwd, "--dir", "-d", help="Deployment directory."),
    duration: Optional[float] = typer.Option(
        None,
        "--duration",
        help="Seconds to watch then exit (default: run until Ctrl-C).",
    ),
) -> None:
    """Arm the DNS + TCP sensors; alarm and audit the instant a decoy is touched."""

    cfg = load_or_default(Path(directory))
    decoys = load_decoys(cfg)
    if not decoys:
        _err.print(
            "[red]No decoys planted.[/red] Run [bold]canaryprobe init[/bold] first."
        )
        raise typer.Exit(code=2)

    audit = AuditLog(cfg.audit_path)
    trip_count = {"n": 0}

    def on_trip(event) -> None:  # noqa: ANN001
        audit.append(event)
        trip_count["n"] += 1
        render_alarm(event, console=_err)

    dns = DnsSensor(cfg, decoys, on_trip)
    conn = ConnSensor(cfg, decoys, on_trip)

    try:
        dns.start()
        conn.start()
    except OSError as exc:
        _err.print(f"[red]Failed to bind a sensor:[/red] {exc}")
        _err.print(
            "Another process may hold the port, or the DNS bind needs a higher "
            "port (default 5353 avoids privileged port 53)."
        )
        raise typer.Exit(code=1)

    n_hosts = sum(1 for d in decoys if d.kind is DecoyKind.HOSTNAME)
    n_creds = sum(1 for d in decoys if d.kind is DecoyKind.CREDENTIAL)
    summary = (
        f"zone      {cfg.decoy_zone}\n"
        f"DNS       {dns.bind}\n"
        f"TCP       {conn.bind}\n"
        f"decoys    {n_hosts} host(s), {n_creds} credential(s)\n"
        f"audit     {cfg.audit_path}"
    )
    render_armed(summary, console=_err)
    _err.print("[dim]Watching… trip a decoy to fire the alarm. Ctrl-C to stop.[/dim]")

    stop = threading.Event()

    def _handle_sigint(signum, frame):  # noqa: ANN001
        stop.set()

    previous = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, _handle_sigint)
    deadline = time.monotonic() + duration if duration is not None else None
    try:
        while not stop.is_set():
            if deadline is not None and time.monotonic() >= deadline:
                break
            time.sleep(0.1)
    finally:
        signal.signal(signal.SIGINT, previous)
        dns.stop()
        conn.stop()

    _err.print(
        f"\n[dim]Sensors stopped. {trip_count['n']} trip event(s) recorded to "
        f"{cfg.audit_path}.[/dim]"
    )


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


@app.command()
def report(
    directory: Path = typer.Option(Path.cwd, "--dir", "-d", help="Deployment directory."),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Where to write the report (default: report.md)."
    ),
) -> None:
    """Emit a signed clean/TRIPPED evidence artifact from the audit log."""

    cfg = load_or_default(Path(directory))
    path, result = write_report(cfg, path=output)

    if result.tripped:
        _out.print(
            f"[bold red]TRIPPED[/bold red] — {result.event_count} trip event(s). "
            f"Evidence: {path}"
        )
    else:
        _out.print(
            f"[bold green]CLEAN[/bold green] — no covert egress observed. "
            f"Evidence: {path}"
        )
    _out.print(f"[dim]signature {result.signature[:16]}…[/dim]")


# ---------------------------------------------------------------------------
# verify (audit loop — recompute the report + manifest signatures)
# ---------------------------------------------------------------------------


@app.command()
def verify(
    directory: Path = typer.Option(
        Path.cwd, "--dir", "-d", help="Deployment directory (holds the signing key)."
    ),
    report_path: Optional[Path] = typer.Option(
        None,
        "--report",
        "-r",
        help="Path to a report.md to verify (default: <dir>/report.md).",
    ),
) -> None:
    """Verify a report's signature and the decoy manifest signature (audit loop).

    Recomputes the report's HMAC-SHA256 over the signed body and (when a manifest
    is present) the manifest signature, printing VERIFIED or TAMPERED. Exits
    non-zero on a tamper or a missing report — the check an auditor runs to
    confirm the evidence was produced by this deployment and not edited.
    """

    cfg = load_or_default(Path(directory))
    target = Path(report_path) if report_path is not None else (cfg.base_dir / "report.md")
    if not target.is_file():
        _err.print(f"[red]report not found:[/red] {target}")
        _err.print("Run [bold]canaryprobe report[/bold] first.")
        raise typer.Exit(code=2)

    markdown = target.read_text(encoding="utf-8")
    key = cfg.signing_key()
    report_ok = verify_report(markdown, key)

    manifest = load_manifest(cfg)
    manifest_state = "absent"
    if manifest is not None:
        manifest_state = "verified" if manifest.verify(key) else "TAMPERED"

    manifest_ok = manifest_state != "TAMPERED"
    if report_ok and manifest_ok:
        _out.print(
            f"[bold green]VERIFIED[/bold green] — report signature matches the "
            f"deployment key."
        )
        if manifest is not None:
            _out.print(f"[green]manifest[/green] {manifest_state}")
        _out.print(f"[dim]{target}[/dim]")
    else:
        if not report_ok:
            _out.print(
                "[bold red]TAMPERED[/bold red] — the report body does not match its signature."
            )
        if manifest_state == "TAMPERED":
            _out.print("[red]manifest[/red] TAMPERED — the decoy set was edited.")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# simulate-trip (hidden helper for the demo / tests)
# ---------------------------------------------------------------------------


@app.command("simulate-trip", hidden=True)
def simulate_trip(
    directory: Path = typer.Option(Path.cwd, "--dir", "-d", help="Deployment directory."),
    sensor: str = typer.Option(
        "dns", "--sensor", help="Which sensor to hit: dns | conn."
    ),
) -> None:
    """Stand in for a coding agent: resolve/connect a planted decoy so a running
    ``watch`` fires the alarm. This is what the demo uses to produce the catch."""

    cfg = load_or_default(Path(directory))
    decoys = load_decoys(cfg)
    hosts = [d for d in decoys if d.kind is DecoyKind.HOSTNAME]
    if not hosts:
        _err.print("[red]No hostname decoy planted.[/red] Run init first.")
        raise typer.Exit(code=2)
    host = hosts[0].value

    if sensor == "dns":
        q = DNSRecord.question(host)
        try:
            q.send(cfg.dns_sensor.host, cfg.dns_sensor.port, timeout=3)
            _out.print(f"[yellow]resolved[/yellow] decoy {host} via the DNS sensor")
        except Exception as exc:  # pragma: no cover - network edge
            _err.print(f"[red]resolve failed:[/red] {exc}")
            raise typer.Exit(code=1)
    elif sensor == "conn":
        try:
            with socket.create_connection(
                (cfg.conn_sensor.host, cfg.conn_sensor.port), timeout=3
            ) as s:
                creds = [d for d in decoys if d.kind is DecoyKind.CREDENTIAL]
                if creds:
                    s.sendall(
                        f"GET / HTTP/1.1\r\nAuthorization: {creds[0].value}\r\n\r\n".encode()
                    )
            _out.print(
                f"[yellow]connected[/yellow] to the decoy bind {cfg.conn_sensor}"
            )
        except OSError as exc:
            _err.print(f"[red]connect failed:[/red] {exc}")
            raise typer.Exit(code=1)
    else:
        _err.print(f"[red]unknown sensor:[/red] {sensor} (use 'dns' or 'conn')")
        raise typer.Exit(code=2)


def main() -> None:  # pragma: no cover - console-script entry
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
