"""Exercise a real local DNS trip and HMAC report; no agent is launched."""
from pathlib import Path
from tempfile import TemporaryDirectory
import json, socket, threading
from dnslib import DNSRecord
from canaryprobe.config import DeploymentConfig
from canaryprobe.decoy import generate_decoys, write_decoys, DecoyKind
from canaryprobe.alarm import AuditLog
from canaryprobe.sensor_dns import DnsSensor
from canaryprobe.report import build_report, verify_report

with TemporaryDirectory(prefix="canaryprobe-demo-") as folder:
    cfg = DeploymentConfig.default(folder)
    # Ask the OS for an available local UDP port, then give that bind to the sensor.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        cfg.dns_sensor.port = sock.getsockname()[1]
    cfg.save()
    decoys = generate_decoys("corp.local", hostnames=1, credentials=1)
    write_decoys(cfg, decoys)
    audit = AuditLog(cfg.audit_path)
    observed = threading.Event()
    def record(event):
        audit.append(event)
        observed.set()
    sensor = DnsSensor(cfg, decoys, record)
    sensor.start()
    try:
        hostname = next(d.value for d in decoys if d.kind is DecoyKind.HOSTNAME)
        response = DNSRecord.parse(DNSRecord.question(hostname).send("127.0.0.1", cfg.dns_sensor.port, timeout=3))
        assert observed.wait(3), "DNS trip was not recorded"
    finally:
        sensor.stop()
    report = build_report(cfg)
    print(json.dumps({"dns_answer": str(response.rr[0].rdata), "verdict": report.verdict, "events": report.event_count, "manifest_verified": report.manifest_verified, "report_verified": verify_report(report.markdown, cfg.signing_key())}, indent=2))
