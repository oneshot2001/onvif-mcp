# Build packet: `commission` — commissioning-as-code with signed handoff (Phase 1)

Claude plans → Codex builds → Claude reviews + live-verifies on the 3 lab cams. This packet is the plan.
Decision record: vault `08-Agent-Output/2026-08-29-vapix-agent-roundtable/00-roundtable.md`.

## Goal
Add commissioning to onvif-mcp: a **desired-state spec** (`camspec.yaml`) is planned, applied,
verified, and rolled back on failure, and every run emits a **signed handoff artifact**
(`handoff/<camera>-<ts>.json`) proving the camera matches spec and the agent stayed in policy.
Phase 1 = VAPIX `param.cgi` parameters + PTZ presets only. AOA scenarios, MQTT/Scene-Metadata
observation, and the PDF render are Phase 2 (PDF is Claude's, not yours).

Style: match index.ts exactly — terse, no speculative abstraction, minimum lines. New module
`commission.ts` imported by index.ts; do not restructure existing code. Reuse the existing
`vapix()` fetch, `receipt()`, policy lookup, and `config_*` param parsing (extract a shared
helper only if it removes duplication).

## Design (settled — do not re-litigate)

### camspec.yaml
```yaml
spec: camspec/0.1
name: loading-dock-east
applies_to: { models: ["AXIS Q6358-LE", "AXIS Q6325-LE"] }   # optional; device info must match if present
params:                       # Full.Param.Name → value; groups must be in agent policy config.groups
  Time.NTP.Enabled: "yes"
  Time.NTP.Server: "192.168.1.1"
  ImageSource.I0.Sensor.WDR: "on"
presets:                      # PTZ only; name → {pan,tilt,zoom} absolute; skipped on non-PTZ
  Gate: { pan: 12.5, tilt: -8.0, zoom: 1200 }
```
Parse with `Bun.YAML` (Bun ≥1.2.x ships it) — no new dependency. Unknown top-level keys → error exit, not ignored.

### Policy
Reuse the existing `config` block; **no new policy keys**. `commission_apply` requires
`config.remediate: true`; `commission_plan`/`commission_verify` require only `config.groups`.
Every param in the spec must fall inside `config.groups` AND outside the server-side
denylist from the drift executor (`Network`, `System.BoxRebootAction`, `RemoteService`, names
containing `Password`/`User`/`Root`) — a spec touching those is **denied whole**, receipted,
before any write.

### Tools
**commission_plan** `{ camera, spec }` — spec = path relative to ROOT/specs/. Read live params
for spec groups, return diff `{ param, current, desired }[]` + preset list; no writes.
Receipt observation, `result_sha256` = hash of plan JSON.

**commission_apply** `{ camera, spec, approve: boolean }` — `approve:false` = plan only (same
output as commission_plan). `approve:true`: snapshot pre-state (the plan's `current` values are
the rollback set), write each param via `param.cgi?action=update`, set presets via
`com/ptz.cgi?setserverpresetname=<name>` after `pan=..&tilt=..&zoom=..` absolute move, then
**verify** (re-read; every value must equal desired). On ANY verify mismatch: roll back every
param written in this run to its pre-state, re-verify rollback, and report
`{ passed:false, failed:[...], rolled_back:true }`. Receipt `action_attempt`,
`outcome_evidence: "device_acknowledged"` for writes, plus one final receipt whose
`result_sha256` = hash of the handoff JSON.

**commission_verify** `{ camera, spec }` — read-only conformance check; same output shape as
the verify step; emits a handoff artifact too (so a re-verify weeks later is a first-class
receipt).

### Handoff artifact `handoff/<camera>-<ISO ts>.json`
```json
{ "artifact": "camspec-handoff/0.1", "spec": {name, sha256}, "camera": {id, model, firmware, serial},
  "agent": "<AGENT_ID>", "policy_sha256": "...", "run": {started, finished},
  "plan": [...], "applied": [...], "verify": {passed, failed:[{param, desired, observed}]},
  "rollback": {performed, verified} | null,
  "receipts": {first_seq, last_seq, chain_head_hash},
  "sig": "<ed25519 over sha256 of everything above, same key as the chain>" }
```
Commit `handoff/` (like `baselines/`). `bun index.ts --verify` must also verify handoff signatures.

### Fixtures
`specs/lab-baseline.yaml` — Time.NTP + one Image param; `specs/lab-ptz.yaml` — one preset
`Home` on q6358. Values must be safe to apply repeatedly (idempotent) on the lab cams.

## Acceptance (Claude runs these live; you run them too if creds resolve)
1. `commission_plan lab-baseline` on each of q6358/q6325/p3285 returns a diff with no writes and a receipt.
2. `commission_apply approve:true` → `passed:true`, handoff JSON written and signed; second run → empty plan, `passed:true`.
3. Mutate one param out-of-band (`config_remediate` in reverse is fine) → `commission_verify` → `passed:false` with the exact param.
4. Force a verify failure (test hook: env `COMMISSION_FAIL_PARAM=<name>` makes verify treat that param as mismatched) → rollback performed, re-verify OK, `rolled_back:true`, artifact still signed.
5. Spec touching `Network.*` → denied whole, deny receipt, no writes.
6. `bun index.ts --verify` OK incl. handoff signatures. README: one paragraph + tools table rows.

## Honesty Ledger (fill in your report)
built / verified-live / verified-unit-only / not-done / verification_gap (missing cam, cred, env).
