# Reproduce the catch in 10 minutes — point a coding agent at a local endpoint, watch a decoy trip

This is the whole pitch in one screenshot: plant a decoy, arm the sensors, let a
**coding agent** run against a local model endpoint, and watch the moment its
binary resolves or connects a host it had no business knowing about — a red
`TRIPPED` alarm and an immutable audit line.

You do **not** need a real closed-source agent to see the catch. Step 4 shows the
one-command simulator (`canaryprobe simulate-trip`) that stands in for the agent;
step 5 shows how to wire a real local-endpoint agent when you want the live demo.

---

## 0. Install

```bash
pip install canaryprobe
```

## 1. Plant a decoy

```bash
mkdir demo && cd demo
canaryprobe init
```

`init` mints a decoy hostname (e.g. `internal-prod-db-42.corp.local`) plus a fake
credential, writes `decoys.json` + a **signed manifest**, and prints exactly what
to inject where. You'll see something like:

```
Planted decoys
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ id           ┃ kind       ┃ value                                    ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ dcy_ab12cd34 │ hostname   │ internal-prod-db-42.corp.local           │
│ dcy_9e3f4ee8 │ credential │ cnp_… (fake API token)                   │
└──────────────┴────────────┴──────────────────────────────────────────┘

Plant these decoys where the coding agent can reach them:
  Make the agent host resolve the decoy zone to the DNS sensor.
  Simplest: add a line to /etc/hosts on the agent box:
      127.0.0.1   internal-prod-db-42.corp.local
```

## 2. Point the agent's resolver at the sensor

The DNS sensor is **authoritative only for the decoy zone**. The simplest way to
make a resolve reach it is an `/etc/hosts` entry on the agent host (copy the exact
line `init` printed):

```bash
echo "127.0.0.1   internal-prod-db-42.corp.local" | sudo tee -a /etc/hosts
```

Or, if you run a resolver, forward just the `corp.local` zone to
`127.0.0.1:5353` (the default DNS sensor bind — non-privileged, no root needed).

## 3. Arm the sensors

In one terminal:

```bash
canaryprobe watch
```

You'll see a green **ARMED** banner listing the zone, the DNS bind (`127.0.0.1:5353`),
the TCP bind (`127.0.0.1:5443`), and the audit path. Leave it running.

## 4. Trip the decoy (simulated agent — no real agent needed)

In a second terminal, stand in for the agent's binary:

```bash
# a decoy DNS resolve — what a probing agent does first
canaryprobe simulate-trip --sensor dns

# a decoy connect that even carries the fake credential
canaryprobe simulate-trip --sensor conn
```

Back in the `watch` terminal, a red panel fires **instantly**:

```
╭──────────  TRIPPED — decoy touched  ──────────╮
│    decoy  dcy_ab12cd34                         │
│ observed  internal-prod-db-42.corp.local       │
│   sensor  DNS                                  │
│   source  127.0.0.1:60809                      │
│     time  2026-07-03T11:22:35.467097+00:00     │
╰─ a coding agent probed a host it had no busin ─╯
```

and one immutable JSONL line lands in `audit.jsonl`:

```json
{"decoy_id":"dcy_ab12cd34","observed_value":"internal-prod-db-42.corp.local","sensor":"dns","src":"127.0.0.1:60809","ts":"2026-07-03T11:22:35.467097+00:00","verdict":"TRIPPED"}
```

## 5. (Optional) wire a real local-endpoint coding agent

To catch a *real* closed-source agent instead of the simulator, run it against a
local model endpoint and make the decoy reachable in its environment:

```bash
# a coding agent pointed at a local Qwen/GLM/DeepSeek endpoint
export ANTHROPIC_BASE_URL=http://localhost:11434
export INTERNAL_API_TOKEN=cnp_…            # the fake credential `init` printed
# …with the /etc/hosts decoy line from step 2 in place, run the agent
```

If the binary ever resolves or connects the decoy — the exact behaviour the
XOR-91 teardown found by hand-decompiling a hostname blocklist — the alarm fires
the same way. You just turned "did it exfiltrate?" from a decompilation project
into a checkable yes/no event.

## 6. Emit the evidence

Stop `watch` (Ctrl-C), then:

```bash
canaryprobe report
```

`report` reads the audit log and writes a **signed** `report.md`: a clean
"no covert egress observed over window T" artifact, or — as here — a `TRIPPED`
artifact enumerating each event with its timestamp, sensor, decoy, and source.
That signed Markdown is the evidence a compliance / 审计 reader consumes.

---

**That's the loop:** `init` → paste decoy → `watch` → **TRIPPED** → `report`. One
paste, one screenshot, one signed artifact.
