# CanaryProbe demo — the 30s happy path: init -> watch -> TRIPPED -> report
# Rendered by `vhs docs/demo.tape` into assets/demo.gif (CI: .github/workflows/demo.yml).
# The tape drives the REAL binary via a scripted "agent" that trips a decoy.

Output assets/demo.gif

Set Shell "bash"
Set FontSize 17
Set Width 1200
Set Height 720
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

# --- setup: a clean deployment dir + the simulated-agent tripper ------------
Hide
Type "cd $(mktemp -d) && clear" Enter
Sleep 400ms
Show

# --- 1. plant a decoy -------------------------------------------------------
Type "canaryprobe init" Sleep 500ms Enter
Sleep 2.5s

# --- 2. arm the sensors in the background -----------------------------------
Type "canaryprobe watch --duration 12 &" Sleep 400ms Enter
Sleep 2.5s

# --- 3. a coding agent probes the decoy (DNS resolve, then a connect) --------
Type "canaryprobe simulate-trip --sensor dns" Sleep 400ms Enter
Sleep 1.8s
Type "canaryprobe simulate-trip --sensor conn" Sleep 400ms Enter
Sleep 2.5s

# --- 4. wait for watch to finish, then emit the signed evidence -------------
Type "wait" Sleep 300ms Enter
Sleep 1s
Type "canaryprobe report" Sleep 400ms Enter
Sleep 2.5s
Type "head -20 report.md" Sleep 300ms Enter
Sleep 3s
