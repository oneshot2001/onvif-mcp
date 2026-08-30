# Build packet: commission Phase 2 — AOA scenarios + event observation

Claude plans → Codex builds → Claude reviews + live-verifies (Q6358/Q6325 run AOA). PDF render is Claude's — do NOT build it.
Phase 1 (`docs/commission-packet.md`) shipped `a224086`; keep its style and structure. Extend `commission.ts`; new module `aoa.ts` only if it removes duplication.

## Goal
`camspec.yaml` gains a `scenarios:` block. apply deploys AOA scenarios via VAPIX, reads them back (diff must be empty), then **observes** the camera's event stream for a window and records which scenarios actually fired. The handoff gains `scenarios` + `observation` sections. Presets also get a readback in verify (Phase 1 open item).

## Design (settled)

### camspec additions
```yaml
scenarios:                       # AOA; skipped with a warning if AOA app not installed
  - name: dock-motion
    type: motion                 # Phase 2: motion | crosslinecounting only; others → error exit
    objects: [human, vehicle]
    area: [[-0.9,-0.9],[0.9,-0.9],[0.9,0.9],[-0.9,0.9]]     # normalized -1..1, AOA convention
  - name: gate-line
    type: crosslinecounting
    objects: [vehicle]
    line: [[-0.5,0.0],[0.5,0.0]]
observe: { seconds: 60 }         # default 60 if scenarios present; 0 = skip observation
```

### AOA transport (VAPIX, JSON-RPC)
`POST /local/objectanalytics/control.cgi` body `{"apiVersion":"1.0","method":"getConfiguration"}` / `setConfiguration` with `params` = full configuration (AOA replaces whole config — read, merge our scenarios by `name`, write back; never drop scenarios not in the spec). `getSupportedVersions` first; map `type` to AOA `type` names (`motion`, `crosslinecounting`) and objects to AOA `objectClassifications`. Scenario `id` assigned by us = max existing+1. Readback: getConfiguration → diff our scenarios' name/type/objects/geometry only. Existing `vapix()` is GET-only via curl — add a `vapixPost(camera, path, body)` in index.ts using the same curl args + `-H content-type: application/json -d @-`.

### Presets readback (Phase 1 gap)
After preset save, `GET /axis-cgi/com/ptz.cgi?query=presetposition` (or `query=position` after `gotoserverpresetname`) — verify the preset name exists in `query=presetposition` output. Include `presets` in `verify.failed` shape as `param: "preset:<name>"`.

### Observation
Subscribe to `wss://<cam>/vapix/ws-data-stream?sources=events` (digest → use Basic over TLS with `-k` equivalent: Bun `WebSocket` with `Authorization` header; if the camera rejects, fall back to HTTP long-poll `/vapix/services` event pull — pick whichever works on Q6358 and document). Filter topics `tnsaxis:CameraApplicationPlatform/ObjectAnalytics/Device1Scenario<ID>`. Record per scenario: `fired_count`, `first_fired`, `last_fired`. Window = `observe.seconds`. No broker, no MQTT in Phase 2.

### Handoff additions
```json
"scenarios": [{ "name", "id", "type", "deployed": true, "readback_diff": [] }],
"observation": { "window_seconds": 60, "started", "finished", "fired": { "dock-motion": { "count": 3, "first": "...", "last": "..." } }, "warnings": ["gate-line: 0 events in window"] }
```
`verify.passed` is NOT affected by zero events (an empty lot is not a config failure) — warnings carry it. Receipts per scenario write (`device_acknowledged`) and one per observation window (`independently_sensed`, result_sha256 = hash of observation JSON).

### Policy
`config.aoa: true` required for scenario writes; absent → scenarios in a spec are denied whole (same pattern as denylist). Add to `claude-main`.

### Fixtures
`specs/lab-aoa.yaml` — one `motion` scenario `lab-motion` objects [human], full-frame area, `observe: {seconds: 30}`, `applies_to` Q6358-LE + Q6325-LE.

## Acceptance (Claude runs live)
1. `commission_plan lab-aoa` on q6358 lists scenario as to-deploy; no writes.
2. `commission_apply approve:true` → scenario exists in AOA UI/getConfiguration, readback_diff empty, observation block present, handoff signed; second run → no scenario changes (idempotent by name).
3. Walk in front of the camera during the window → `fired["lab-motion"].count ≥ 1`.
4. Spec with `type: fence` → error exit, no writes. Agent without `config.aoa` → denied whole.
5. Preset readback: `lab-ptz` apply now verifies preset `Home` exists; delete it out-of-band → verify fails on `preset:Home`.
6. `bun test` green, `tsc` clean, `--verify` OK.

## Honesty Ledger — same 5 fields as Phase 1.
