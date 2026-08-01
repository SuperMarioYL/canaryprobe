"""Authoritative DNS sensor (milestone m2).

``canaryprobe watch`` binds this small authoritative DNS server for the decoy
zone.  It answers queries so the agent's resolve *succeeds* (a decoy that fails
to resolve is a decoy the agent stops probing) — but the act of resolving a
decoy host **is** the trip.  Any query whose name matches a planted hostname
decoy (or falls inside the decoy zone) fires a :class:`~canaryprobe.alarm.TripEvent`
through the shared callback and gets answered with a sinkhole address.

Built on ``dnslib``'s ``DNSServer`` + a custom resolver.  Userspace only — no
kernel/eBPF interception (explicitly out of scope).  Binds a non-privileged
port by default (5353) so it runs without root; the operator points the agent
host's resolver (or an ``/etc/hosts`` entry) at this bind.
"""

from __future__ import annotations

import threading
from typing import Callable

from dnslib import QTYPE, RR, A, AAAA, DNSLabel, DNSRecord
from dnslib.server import BaseResolver, DNSLogger, DNSServer

from .alarm import SensorKind, TripEvent
from .config import DeploymentConfig
from .decoy import Decoy, DecoyKind

#: Address every decoy name resolves to.  A loopback sinkhole: the resolve
#: succeeds (so the agent believes the host exists and may go on to *connect*,
#: tripping the TCP sensor too) but no traffic leaves the box.
SINKHOLE_A = "127.0.0.1"
SINKHOLE_AAAA = "::1"

#: Callback invoked with a fully-formed TripEvent for every decoy resolve.
TripCallback = Callable[[TripEvent], None]


def _normalise(name: str) -> str:
    return name.rstrip(".").lower()


class DecoyResolver(BaseResolver):
    """Answers only for the decoy zone; every match is a trip.

    A query is a trip when its name is exactly a planted hostname decoy, or
    when it falls inside the authoritative decoy zone (so a decoy the agent
    mutates slightly — ``internal-prod-db-01.corp.local`` vs the planted
    ``…-42.corp.local`` — is still caught as "probing the decoy zone").
    """

    def __init__(
        self,
        *,
        zone: str,
        decoys: list[Decoy],
        on_trip: TripCallback,
    ) -> None:
        self.zone = _normalise(zone)
        self._on_trip = on_trip
        # Exact-match lookup: planted host value -> its decoy.
        self._by_host: dict[str, Decoy] = {
            _normalise(d.value): d
            for d in decoys
            if d.kind is DecoyKind.HOSTNAME
        }
        # A synthetic "zone" decoy so an in-zone name that is not an exact
        # planted host still records a trip with a stable decoy_id.
        self._zone_decoy = next(
            (d for d in decoys if d.kind is DecoyKind.HOSTNAME), None
        )

    def _match(self, qname: str) -> tuple[Decoy | None, bool]:
        """Return ``(decoy, is_trip)`` for a query name."""

        name = _normalise(qname)
        exact = self._by_host.get(name)
        if exact is not None:
            return exact, True
        # In-zone but not an exact planted host: still a probe of the decoy zone.
        if name == self.zone or name.endswith("." + self.zone):
            return self._zone_decoy, True
        return None, False

    def resolve(self, request: DNSRecord, handler) -> DNSRecord:  # noqa: ANN001
        reply = request.reply()
        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]
        decoy, is_trip = self._match(qname)

        if is_trip:
            src = "unknown"
            client = getattr(handler, "client_address", None)
            if client:
                src = f"{client[0]}:{client[1]}"
            observed = _normalise(qname)
            event = TripEvent(
                decoy_id=decoy.id if decoy is not None else "dcy_zone",
                sensor=SensorKind.DNS,
                observed_value=observed,
                src=src,
            )
            try:
                self._on_trip(event)
            except Exception:  # pragma: no cover - a callback bug must not kill the sensor
                pass
            # Answer with the sinkhole so the resolve succeeds.
            name = DNSLabel(qname)
            if qtype in ("AAAA",):
                reply.add_answer(RR(name, QTYPE.AAAA, rdata=AAAA(SINKHOLE_AAAA), ttl=30))
            else:
                reply.add_answer(RR(name, QTYPE.A, rdata=A(SINKHOLE_A), ttl=30))
            return reply

        # Not our zone: NXDOMAIN-ish empty reply (we are not a recursive resolver).
        return reply


class DnsSensor:
    """Runs the authoritative DNS server in a background thread."""

    def __init__(
        self,
        config: DeploymentConfig,
        decoys: list[Decoy],
        on_trip: TripCallback,
    ) -> None:
        self.config = config
        self.resolver = DecoyResolver(
            zone=config.decoy_zone, decoys=decoys, on_trip=on_trip
        )
        self._server: DNSServer | None = None
        self._started = threading.Event()

    @property
    def bind(self) -> str:
        return f"{self.config.dns_sensor.host}:{self.config.dns_sensor.port}"

    def start(self) -> None:
        """Bind + serve in a daemon thread.  Idempotent."""

        if self._server is not None:
            return
        # A silent logger: dnslib's default prints every request/reply to the
        # terminal, which would drown out CanaryProbe's own TRIPPED alarm. We
        # own the operator-facing output (the Rich alarm + the JSONL audit line).
        quiet = DNSLogger(log="", prefix=False)
        self._server = DNSServer(
            self.resolver,
            address=self.config.dns_sensor.host,
            port=self.config.dns_sensor.port,
            logger=quiet,
        )
        # dnslib's DNSServer.start_thread() runs the UDP server on its own thread.
        self._server.start_thread()
        self._started.set()

    def stop(self) -> None:
        if self._server is not None:
            self._server.stop()
            self._server = None
            self._started.clear()

    def is_running(self) -> bool:
        # dnslib's DNSServer exposed the thread-alive check as isAlive() (the
        # deprecated threading alias) in older builds and is_alive() in newer
        # ones — probe for both so this stays robust across versions.
        if self._server is None:
            return False
        alive = getattr(self._server, "is_alive", None) or getattr(
            self._server, "isAlive", None
        )
        return bool(alive()) if callable(alive) else False


__all__ = [
    "DecoyResolver",
    "DnsSensor",
    "SINKHOLE_A",
    "SINKHOLE_AAAA",
    "TripCallback",
]
