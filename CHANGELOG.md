# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-08-02

Iteration over v0.1.0 — defends the two load-bearing value claims (audit-reproducibility
and the visceral trip demo) and broadens the bait surface the roadmap promised.

### Fixed

- **Deterministic, reproducible evidence report** — the report HMAC signature was
  non-deterministic over identical audit evidence because the volatile "Generated at"
  timestamp lived inside the signed body (contradicting the module's own
  auditor-reproducibility guarantee). The generation timestamp is now rendered as an
  unsigned footer outside the signed body, so two runs over the same audit log yield the
  same signature while `verify_report` still recomputes the body hash unchanged.
- **Correct operator trip-wiring guidance** — the "Simplest" `/etc/hosts` path in
  `injection_instructions` could not trip the DNS sensor (libc resolves `/etc/hosts`
  with no DNS query, so the UDP sensor on `127.0.0.1:5353` was never queried), and a
  connect to the resolved decoy hit port 80/443 — not the conn sensor's bind — so neither
  alarm fired. The guidance now points the decoy zone's resolver at the DNS sensor (a
  resolve IS a trip), plants connect-bait as a URL carrying the conn sensor's port, and
  warns explicitly that a bare `/etc/hosts` entry does NOT trip the DNS sensor. Also
  switched `DnsSensor.is_running` off the deprecated `isAlive()` alias.

### Added

- **`canaryprobe verify`** — a new subcommand that recomputes the report signature (and
  the decoy manifest signature) and prints `VERIFIED` / `TAMPERED`, exiting non-zero on a
  tamper or a missing report. This closes the audit loop an auditor runs to confirm the
  evidence was produced by this deployment and not edited.
- **More decoy shapes** — two new credential kinds broaden the bait surface for
  cloud-native coding agents: `cloud_metadata_url` (an IMDS-style URL bait) and
  `package_index_token` (an npm-style registry token), wired into generation and the
  injection env-var mapping.

### Changed

- License aligned to Apache-2.0 (copyright `2026 SuperMarioYL`) across `LICENSE`,
  `pyproject.toml`, and both README badges/footers.

## [0.1.0] - 2026-07-03

Initial release — the honeytoken tripwire for a coding-agent binary you can't read.

### Added

- **Plant decoys** (`canaryprobe init` / `canaryprobe plant`) — generate a plausible
  decoy hostname and a fake credential, write `decoys.json` plus a signed manifest,
  and print exactly what to inject where in the coding agent's environment.
- **Arm sensors** (`canaryprobe watch`) — run an authoritative DNS sensor for the
  decoy zone and a TCP connect sensor concurrently; a resolve or a connect to a decoy
  produces a `TripEvent`, a red terminal alarm, and an immutable JSONL audit line.
- **Emit report** (`canaryprobe report`) — read `audit.jsonl` and produce a
  `report.md` evidence artifact stating a clean "no covert egress observed over
  window T" or a TRIPPED artifact enumerating each `TripEvent` with timestamps.
- Deployment configuration via `deployment.yaml` (decoy zone, sensor binds, audit path).
- Bilingual README (简体中文 primary + English sibling) and a 10-minute local-agent
  reproduce-the-catch walkthrough.

[Unreleased]: https://github.com/SuperMarioYL/canaryprobe/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/SuperMarioYL/canaryprobe/releases/tag/v0.2.0
[0.1.0]: https://github.com/SuperMarioYL/canaryprobe/releases/tag/v0.1.0
