# Build packet: config-drift executor (bet #6 first unit)

Claude plans → Codex builds → Claude reviews + live-verifies. This packet is the plan.

## Goal
Extend onvif-mcp with three MCP tools that make it a config-drift detect + safe-remediate
executor: `config_baseline`, `config_drift`, `config_remediate`. Read-only by default,
dry-run + explicit approval for mutations, postcondition verification, receipt per action
(including denials). Match the existing code style in index.ts exactly — terse, no
speculative abstraction, minimum lines. Do NOT restructure existing code or split files
unless index.ts would exceed ~450 lines; a single new module `drift.ts` imported by
index.ts is acceptable if cleaner.

## Design (settled — do not re-litigate)

### Transport
Config read/write uses VAPIX `param.cgi` on ALL cameras (all lab cams are Axis; ONVIF has
no generic param surface). This is a documented gap: add one README line under Features —
config tools are VAPIX-only for now.
- Read: `/axis-cgi/param.cgi?action=list&group=<G1>,<G2>` (repeatable groups, comma-joined)
- Write: `/axis-cgi/param.cgi?action=update&<Full.Param.Name>=<value>` (URL-encode value)

### Baselines
- Dir: `baselines/<camera>.json` (gitignored? NO — commit them; baselines are the point).
- Format: `{ camera, captured: ISO ts, groups: [...], params: { "Full.Param.Name": "value", ... }, sha256: <hash of sorted params JSON> }`
- Parse param.cgi output lines `root.Group.Sub=value` → key `Group.Sub` (strip leading `root.`), value = rest after first `=` (values may contain `=`).

### Policy extension (policy.json)
Per-agent optional block:
```json
"config": { "groups": ["ImageSource", "Time", "Image"], "remediate": true }
```
- `groups` = param groups this agent may baseline/diff/remediate. Fail closed: no block
  → all three config tools denied.
- `remediate: true` required for config_remediate; absent → dry-run-only agent.
- HARD server-side denylist regardless of policy (safety, non-negotiable):
  groups `Network`, `System.BoxRebootAction`, `RemoteService`, and any param name
  containing `Password`, `User`, `Root`. Deny + receipt if a remediation targets these.
- Give `claude-main` the config block with groups `["ImageSource", "Time", "Image"]` and
  `remediate: true` in policy.json.

### Tools

**config_baseline** `{ camera }`
- Policy check (tool + camera + config block). Fetch allowed groups via param.cgi,
  parse, write `baselines/<camera>.json`, receipt as `node_kind: "observation"`,
  `result_sha256` = params hash, `outcome_evidence: "independently_sensed"`.
- Overwrites existing baseline (re-baselining is explicit and receipted — fine).

**config_drift** `{ camera }`
- Requires existing baseline (else text: "no baseline — run config_baseline"; receipt allow, detail "no baseline").
- Fetch live params for the SAME groups recorded in the baseline (intersected with the
  agent's currently-allowed groups — policy may have shrunk).
- Diff: report `added` / `removed` / `changed` (param, baseline value, live value).
- Output: human-readable list + summary line `drift: N changed, N added, N removed`.
- Receipt observation, detail = summary, result_sha256 = hash of the diff JSON.

**config_remediate** `{ camera, param, approve?: boolean }`
- Remediates ONE param per call back to its BASELINE value (the only supported direction —
  no arbitrary value writes; that keeps this an executor, not a config editor).
- Checks in order, each failure → deny receipt with reason:
  1. policy (tool, camera, config block)
  2. param's group ∈ agent's allowed groups
  3. hard denylist
  4. baseline exists and contains param
  5. live value actually differs (no-op → text "no drift on <param>", allow receipt, detail "no-op")
- `approve` absent/false → DRY RUN: report `would set <param>: <live> → <baseline>`,
  receipt `node_kind: "action_attempt"`, detail prefixed `dry-run:`, no device write.
- `approve: true` → perform param.cgi update, then POSTCONDITION: re-read the param and
  compare to baseline value. Receipt detail `remediated` with
  `outcome_evidence: "independently_sensed"` and result_sha256 = hash of re-read value
  ONLY if postcondition passes; if re-read mismatches, detail `write acked but postcondition FAILED (live=<v>)`,
  outcome_evidence `device_acknowledged`.

### Receipts
Reuse existing `receipt()`. Add to NODE_KIND map: config_baseline/config_drift =
"observation", config_remediate = "action_attempt".

### test-client.ts
Extend with a drift scenario the reviewer can run:
baseline q6358 → drift (expect none) → remediate without approve on an undrifted param
(expect no-op) → attempt remediate on denylisted param `Network.Bonjour.FriendlyName`
(expect DENY). Live-drift injection is done manually by the reviewer, not in the client.

## Acceptance (Claude will verify on live cams)
1. `bun index.ts --verify` chain still OK after all new receipts.
2. Baseline all 3 cams succeeds; files well-formed.
3. Manually change a param on q6358 (e.g. Image.I0.Text.String) → config_drift reports
   exactly that change.
4. Dry-run remediate shows correct would-set; device unchanged.
5. approve:true remediate restores baseline value; postcondition passes; receipt shows
   independently_sensed.
6. Denylist + off-group + unknown-agent paths all deny with receipts.
7. No secrets in any file, log, or receipt.
