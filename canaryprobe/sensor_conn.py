"""TCP connect sensor (milestone m2).

The DNS sensor answers a decoy resolve with a loopback sinkhole, so an agent
that then *connects* the "resolved" host lands here.  This sensor is a plain
userspace TCP listener: **any accepted connection is a trip** — nothing
legitimate should ever dial the decoy's host:port.  It reads a small,
bounded first chunk of the connection so a fake credential the agent tries to
send (e.g. an ``Authorization`` header carrying a decoy token) can be recorded
as the observed value.

Userspace only, single host — no kernel/eBPF interception (out of scope).  Runs
in a background thread and fires a :class:`~canaryprobe.alarm.TripEvent` per
connection through the shared callback.
"""

from __future__ import annotations

import socket
import threading
from typing import Callable

from .alarm import SensorKind, TripEvent
from .config import DeploymentConfig
from .decoy import Decoy, DecoyKind

TripCallback = Callable[[TripEvent], None]

#: Cap on the bytes we peek from a connection to look for a decoy credential.
#: Small: we only want to fingerprint the probe, never proxy traffic.
_PEEK_BYTES = 2048
#: Short read timeout — the agent either sends immediately or we record the
#: bare connect.  We must not block the accept loop on a silent client.
_READ_TIMEOUT = 0.5


class ConnSensor:
    """Accepts TCP connections to the decoy bind and reports each as a trip."""

    def __init__(
        self,
        config: DeploymentConfig,
        decoys: list[Decoy],
        on_trip: TripCallback,
    ) -> None:
        self.config = config
        self._on_trip = on_trip
        self._host_decoys = [d for d in decoys if d.kind is DecoyKind.HOSTNAME]
        self._cred_decoys = [d for d in decoys if d.kind is DecoyKind.CREDENTIAL]
        # Any hostname decoy stands in as the decoy_id for a bare connect; the
        # connect itself is the signal (the agent dialed the sinkholed decoy).
        self._primary = self._host_decoys[0] if self._host_decoys else None
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    @property
    def bind(self) -> str:
        return f"{self.config.conn_sensor.host}:{self.config.conn_sensor.port}"

    def start(self) -> None:
        if self._sock is not None:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.config.conn_sensor.host, self.config.conn_sensor.port))
        sock.listen(16)
        sock.settimeout(0.25)  # so the accept loop can observe the stop flag
        self._sock = sock
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._serve, name="canaryprobe-conn-sensor", daemon=True
        )
        self._thread.start()

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._handle(conn, addr)
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def _handle(self, conn: socket.socket, addr) -> None:  # noqa: ANN001
        src = f"{addr[0]}:{addr[1]}"
        observed_value, decoy = self._sniff(conn)
        event = TripEvent(
            decoy_id=decoy.id if decoy is not None else "dcy_conn",
            sensor=SensorKind.CONN,
            observed_value=observed_value,
            src=src,
        )
        try:
            self._on_trip(event)
        except Exception:  # pragma: no cover - a callback bug must not kill the sensor
            pass

    def _sniff(self, conn: socket.socket) -> tuple[str, Decoy | None]:
        """Peek the first chunk; if it carries a decoy credential, report that
        credential, otherwise report the bare connect to the decoy bind."""

        payload = b""
        try:
            conn.settimeout(_READ_TIMEOUT)
            payload = conn.recv(_PEEK_BYTES)
        except (socket.timeout, OSError):
            payload = b""

        text = payload.decode("latin-1", errors="replace") if payload else ""
        for cred in self._cred_decoys:
            if cred.value and cred.value in text:
                return cred.value, cred

        # No credential in the payload: the connect itself is the trip.
        observed = f"connect->{self.bind}"
        return observed, self._primary

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


__all__ = ["ConnSensor", "TripCallback"]
