# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/SuperMarioYL/canaryprobe/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SuperMarioYL/canaryprobe/releases/tag/v0.1.0
