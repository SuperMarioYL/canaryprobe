# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-08-17

Two evidence-honesty fixes that close denial-of-evidence holes the v0.5.0
corrupt-input surfacing itself left open — a single attacker-tampered
`audit.jsonl` line or `decoys.manifest.json`/`decoys.json` holding a
valid-JSON-but-wrong-shape value no longer crashes `report`/`verify`/`watch`/
`simulate-trip` before the corrupt-line tally / CORRUPT-manifest / re-init
surfacing can fire — plus a regression/fuzz test pinning the fail-soft path.

### Fixed

- **Valid-JSON-wrong-shape audit lines and manifests fail soft, not crash** —
  the v0.5.0 fail-soft `except` tuples caught only `JSONDecodeError`/`KeyError`/
  `ValueError` (audit) and `ValidationError`/`KeyError`/`ValueError` (manifest).
  A valid-JSON-but-non-dict audit line (`null`, `[1]`, `5`, `"x"`, `true`)
  raised `TypeError` at `data["decoy_id"]`; a non-dict manifest value raised
  `AttributeError` at `data.get(...)`; a non-iterable or list-of-non-dict
  `decoys` raised `TypeError` in the `Decoy.from_dict` comprehension — none
  caught, so they propagated out of `read()`/`build_report`/`verify` as a
  traceback, and the v0.5.0 corrupt-line tally / CORRUPT-manifest surfacing
  never fired because the crash preceded it. This was exactly the attacker-tamper
  threat model the v0.5.0 fixes targeted — a denial-of-evidence hole punched
  through the v0.5.0 surfacing itself. `TypeError` is now caught in
  `AuditLog.iter_events`/`iter_corrupt` (`alarm.py`) and `TypeError` +
  `AttributeError` in `load_manifest` (`decoy.py`); `read()`/`count()`/
  `count_corrupt()` signatures are unchanged — the new shapes fold into the
  existing skip/corrupt-yield + return-`None` path.
- **Corrupt/tampered `decoys.json` fails soft, not crash** — `load_decoys`
  (`decoy.py`) had no error handling at all (unlike its hardened sibling
  `load_manifest` in the same module); `json.loads` + the `Decoy.from_dict`
  loop raised uncaught on a corrupt/tampered `decoys.json` (malformed JSON, a
  decoy missing `id`/`kind`/`value`, a non-list `decoys`, a non-dict element, a
  non-dict top-level value), propagating out of `canaryprobe watch` and
  `simulate-trip` as a raw traceback — sensors never armed (no protection) and
  the operator saw a stack trace. `load_decoys` now wraps the parse in
  `try/except` and raises a typed `DecoysCorruptError` the CLI renders as
  "decoys.json corrupt — re-init with `canaryprobe init`" (exit 2) rather than
  returning `[]` silently, so a corruption is not mislabelled as a fresh
  install. An absent file still returns `[]` (genuine fresh install).

### Tests

- **Corrupt-input fail-soft path pinned** — `tests/test_corrupt_input_failsoft.py`
  feeds a representative set of valid-JSON-wrong-shape values into each fail-soft
  boundary (audit non-dict lines, non-dict/non-list manifests, corrupt
  `decoys.json`) and asserts surfacing rather than an uncaught exception, so a
  future narrowing of the broadened `except` tuples re-opens the
  denial-of-evidence hole in CI, not the field.

## [0.5.0] - 2026-08-14

Two evidence-honesty fixes that close read-side gaps a security canary cannot
leave open: a corrupt audit line can no longer make `report` silently read CLEAN
over a dropped trip, and a corrupt/tampered decoy manifest is surfaced as an
unverifiable report instead of crashing the evidence command.

### Fixed

- **Corrupt audit lines are surfaced, not silently dropped** —
  `AuditLog.iter_events` (`alarm.py`) swallowed `JSONDecodeError`/`KeyError`/
  `ValueError` and skipped a corrupt `audit.jsonl` line, and `read()`/`count()`
  inherited the silent skip with nothing tallied or surfaced in `canaryprobe
  report`. So a single corrupted trip line (disk bit-rot, a partial write, or
  tampering of `audit.jsonl`) could make `report` undercount to `event_count=0`
  and read CLEAN — signed and VERIFIED — over a real trip. This was the read-side
  silent-CLEAN-miss, the mirror of the v0.3.0 write-side
  `fix-on-trip-silent-drop`. `AuditLog` now also exposes
  `iter_corrupt()`/`count_corrupt()`, and `report` renders "Evidence incomplete —
  N corrupt audit line(s) skipped; inspect audit.jsonl" in the signed body
  whenever N>0, so a non-zero corrupt count can never render a silent CLEAN.
  `read()`/`count()` signatures are unchanged.
- **Corrupt/tampered decoy manifest fails soft, not crash** — `load_manifest`
  (`decoy.py`) returned `None` only when the file was absent; it did not catch
  `DecoyManifest.from_json`'s raise paths (`json.loads` `JSONDecodeError`, the
  `version=Literal[1]` `ValidationError`, `KeyError` on a manifest missing
  `zone`/`created_at`/`decoys`). These propagated out of `build_report`
  (`report.py`) and `canaryprobe verify` (`cli.py`), so a corrupt or
  attacker-tampered `decoys.manifest.json` made `report`/`verify` crash with a
  traceback instead of rendering an unverifiable artifact — a denial-of-evidence
  vector, asymmetric with the audit-log fail-soft path. `load_manifest` now
  wraps `from_json` in `try/except` and returns `None`; `report` renders
  "manifest CORRUPT/unparseable" and `verify` surfaces `manifest CORRUPT` +
  exits non-zero instead of dying.

## [0.4.0] - 2026-08-11

Two integrity fixes: the signing key is no longer briefly group/world-readable
on creation, and operator-edited quoted config values with a trailing inline
comment now parse correctly.

### Fixed

- **Atomic signing-key file permissions** — `ensure_signing_key` created
  `.canaryprobe.key` with `write_text` (default mode `0o644` after umask) and
  only afterwards tightened it with `os.chmod(..., 0o600)`. The
  create-then-chmod window leaked the root-of-trust signing key — which signs
  both the decoy manifest and the evidence report — to any co-tenant of a
  group/world-traversable `base_dir` (a team workspace, `/opt`, `/tmp`, a CI
  workdir), who could read it in that window and later forge a CLEAN report.
  The key file is now created with `0o600` at open time
  (`os.open` with `O_WRONLY | O_CREAT | O_TRUNC` and mode `0o600`, plus an
  `os.fchmod` to defeat any permissive umask), eliminating the `0o644` window
  entirely.
- **Quoted YAML values with trailing inline comments** —
  `_strip_inline_comment` short-circuited for any value whose first char is a
  quote, so a trailing ` # comment` after the closing quote was never stripped;
  `_coerce` then failed its quote match and returned the whole string (quotes
  + comment) as the scalar. `audit_file: "events.jsonl" # trail` parsed to the
  literal `"events.jsonl" # trail`, silently breaking the audit path, decoys
  loading ("No decoys planted"), and — critically — making the DNS sensor's
  `decoy_zone` string garbage so no resolve query ever matched and the DNS
  sensor never tripped. The parser now scans to the matching closing quote
  (honoring backslash escapes) and drops the trailing comment, returning just
  the quoted value; the unquoted path is unchanged.

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

[Unreleased]: https://github.com/SuperMarioYL/canaryprobe/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/SuperMarioYL/canaryprobe/releases/tag/v0.6.0
[0.5.0]: https://github.com/SuperMarioYL/canaryprobe/releases/tag/v0.5.0
[0.4.0]: https://github.com/SuperMarioYL/canaryprobe/releases/tag/v0.4.0
[0.2.0]: https://github.com/SuperMarioYL/canaryprobe/releases/tag/v0.2.0
[0.1.0]: https://github.com/SuperMarioYL/canaryprobe/releases/tag/v0.1.0
