"""Tests for milestone m2: the DNS + TCP sensors.

These bind a real (loopback, ephemeral-port) DNS sensor and TCP sensor and
drive a real resolve / connect at them, asserting a ``TripEvent`` is produced
with the right decoy, sensor, and observed value. Ports are chosen high and
per-test to avoid collisions and privilege.
"""

from __future__ import annotations

import socket
import time

from dnslib import DNSRecord

from canaryprobe.alarm import SensorKind, TripEvent
from canaryprobe.config import DeploymentConfig, SensorBind
from canaryprobe.decoy import generate_decoys, generate_hostname_decoy
from canaryprobe.sensor_conn import ConnSensor
from canaryprobe.sensor_dns import SINKHOLE_A, DecoyResolver, DnsSensor


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _cfg(tmp_path, dns_port: int, conn_port: int) -> DeploymentConfig:
    return DeploymentConfig(
        decoy_zone="corp.local",
        dns_sensor=SensorBind(host="127.0.0.1", port=dns_port),
        conn_sensor=SensorBind(host="127.0.0.1", port=conn_port),
        base_dir=tmp_path,
    )


# ---------------------------------------------------------------------------
# DecoyResolver matching (no socket)
# ---------------------------------------------------------------------------


def test_resolver_matches_exact_planted_host():
    host = generate_hostname_decoy("corp.local")
    events = []
    resolver = DecoyResolver(zone="corp.local", decoys=[host], on_trip=events.append)
    decoy, is_trip = resolver._match(host.value)
    assert is_trip is True
    assert decoy is not None and decoy.id == host.id


def test_resolver_matches_anything_in_zone():
    host = generate_hostname_decoy("corp.local")
    resolver = DecoyResolver(zone="corp.local", decoys=[host], on_trip=lambda e: None)
    _, is_trip = resolver._match("some-other-name.corp.local")
    assert is_trip is True


def test_resolver_ignores_out_of_zone():
    host = generate_hostname_decoy("corp.local")
    resolver = DecoyResolver(zone="corp.local", decoys=[host], on_trip=lambda e: None)
    decoy, is_trip = resolver._match("example.com")
    assert is_trip is False
    assert decoy is None


# ---------------------------------------------------------------------------
# Live DNS sensor
# ---------------------------------------------------------------------------


def test_dns_sensor_trips_on_resolve(tmp_path):
    dns_port = _free_udp_port()
    conn_port = _free_port()
    cfg = _cfg(tmp_path, dns_port, conn_port)
    decoys = generate_decoys("corp.local", hostnames=1, credentials=0)
    host = decoys[0].value

    events: list[TripEvent] = []
    sensor = DnsSensor(cfg, decoys, events.append)
    sensor.start()
    try:
        # give the UDP server a moment to bind
        time.sleep(0.3)
        reply = DNSRecord.question(host).send("127.0.0.1", dns_port, timeout=3)
        # the resolve succeeds with the sinkhole address
        parsed = DNSRecord.parse(reply)
        answers = [str(rr.rdata) for rr in parsed.rr]
        assert SINKHOLE_A in answers
    finally:
        sensor.stop()

    assert len(events) == 1
    ev = events[0]
    assert ev.sensor is SensorKind.DNS
    assert ev.observed_value == host.lower()
    assert ev.verdict == "TRIPPED"


def test_dns_sensor_ignores_out_of_zone(tmp_path):
    dns_port = _free_udp_port()
    conn_port = _free_port()
    cfg = _cfg(tmp_path, dns_port, conn_port)
    decoys = generate_decoys("corp.local", hostnames=1, credentials=0)

    events: list[TripEvent] = []
    sensor = DnsSensor(cfg, decoys, events.append)
    sensor.start()
    try:
        time.sleep(0.3)
        DNSRecord.question("totally-unrelated.example.org").send(
            "127.0.0.1", dns_port, timeout=3
        )
    finally:
        sensor.stop()

    assert events == []


# ---------------------------------------------------------------------------
# Live TCP connect sensor
# ---------------------------------------------------------------------------


def test_conn_sensor_trips_on_bare_connect(tmp_path):
    dns_port = _free_udp_port()
    conn_port = _free_port()
    cfg = _cfg(tmp_path, dns_port, conn_port)
    decoys = generate_decoys("corp.local", hostnames=1, credentials=0)

    events: list[TripEvent] = []
    sensor = ConnSensor(cfg, decoys, events.append)
    sensor.start()
    try:
        time.sleep(0.2)
        with socket.create_connection(("127.0.0.1", conn_port), timeout=3):
            pass
        _wait_for(lambda: len(events) >= 1)
    finally:
        sensor.stop()

    assert len(events) == 1
    assert events[0].sensor is SensorKind.CONN
    assert "connect->" in events[0].observed_value


def test_conn_sensor_captures_decoy_credential(tmp_path):
    dns_port = _free_udp_port()
    conn_port = _free_port()
    cfg = _cfg(tmp_path, dns_port, conn_port)
    decoys = generate_decoys("corp.local", hostnames=1, credentials=1)
    cred = next(d for d in decoys if d.kind.value == "credential")

    events: list[TripEvent] = []
    sensor = ConnSensor(cfg, decoys, events.append)
    sensor.start()
    try:
        time.sleep(0.2)
        with socket.create_connection(("127.0.0.1", conn_port), timeout=3) as s:
            s.sendall(f"Authorization: {cred.value}\r\n".encode())
        _wait_for(lambda: len(events) >= 1)
    finally:
        sensor.stop()

    assert len(events) == 1
    ev = events[0]
    assert ev.sensor is SensorKind.CONN
    assert ev.observed_value == cred.value
    assert ev.decoy_id == cred.id


def test_conn_sensor_bind_reports_actual_port_on_port0(tmp_path):
    """Regression for fix-port0-random-bind-banner-reports-zero (v0.10.0).

    An explicit ``port: 0`` is the documented random-bind opt-in (config.py's
    merge keeps it). The ``bind`` property — what the armed banner renders —
    must report the port the sensor ACTUALLY bound, never the configured 0:
    an armed banner pointing at ":0" is a bind nothing can dial, so the trip
    silently never fires.
    """
    cfg = _cfg(tmp_path, dns_port=_free_udp_port(), conn_port=0)
    sensor = ConnSensor(cfg, [], lambda e: None)
    try:
        sensor.start()
        actual = sensor._sock.getsockname()[1]
        assert actual != 0
        assert sensor.bind == f"127.0.0.1:{actual}"
    finally:
        sensor.stop()


def test_dns_sensor_bind_reports_actual_port_on_port0(tmp_path):
    """Same lockstep as the conn sensor: port-0 DNS bind reports the real port."""
    cfg = _cfg(tmp_path, dns_port=0, conn_port=_free_port())
    sensor = DnsSensor(cfg, [], lambda e: None)
    try:
        sensor.start()
        udp = getattr(sensor._server, "server", None) or getattr(
            sensor._server, "udp_server", None
        )
        actual = udp.socket.getsockname()[1]
        assert actual != 0
        assert sensor.bind == f"127.0.0.1:{actual}"
    finally:
        sensor.stop()


def test_bind_reports_configured_port_when_fixed(tmp_path):
    """A fixed (non-zero) configured port still reports verbatim."""
    cfg = _cfg(tmp_path, dns_port=_free_udp_port(), conn_port=_free_port())
    sensor = ConnSensor(cfg, [], lambda e: None)
    try:
        sensor.start()
        assert sensor.bind == (
            f"127.0.0.1:{cfg.conn_sensor.port}"
        )
    finally:
        sensor.stop()


def _wait_for(pred, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return
        time.sleep(0.02)
