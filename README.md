<div align="center">

# onvif-mcp

<img src="docs/banner.png" alt="onvif-mcp — a governed doorway between AI agents and video infrastructure" width="100%">

### The governed doorway between AI agents and video infrastructure.

Every tool call passes a **fail-closed policy gate** and emits a **hash-chained,
signed receipt — including denials**.<br>
The audit trail records what agents *tried*, not just what they did.

<p>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://bun.sh"><img src="https://img.shields.io/badge/runtime-Bun-f9f1e1.svg?logo=bun" alt="Runtime: Bun"></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/protocol-MCP-8A2BE2.svg" alt="Protocol: MCP"></a>
  <a href="#transports"><img src="https://img.shields.io/badge/transports-VAPIX%20%7C%20ONVIF%20SOAP-1d3648.svg" alt="Transports: VAPIX | ONVIF SOAP"></a>
  <a href="https://github.com/oneshot2001/aar"><img src="https://img.shields.io/badge/receipts-AAR%20v0.2%20vocabulary-3ec9a7.svg" alt="Receipts: AAR v0.2 vocabulary"></a>
  <a href="#status"><img src="https://img.shields.io/badge/status-experimental-d98e3b.svg" alt="Status: experimental"></a>
</p>

<a href="https://github.com/oneshot2001/aar">AAR specification</a> ·
<a href="docs/aar-alignment.md">Conformance plan</a> ·
<a href="#quick-start">Quick start</a> ·
<a href="https://github.com/oneshot2001/onvif-mcp/issues">Report an issue</a>

</div>

---

Agents are getting wired into everything. Nobody has shipped agent access to
cameras and video systems that a security director could approve. This is that
attempt.

## Features

- **Config drift executor** — baseline, diff, and safe remediation tools are VAPIX-only for now
- **MCP tools** over stdio: `list_cameras`, `get_snapshot`, `ptz_move`, `ptz_preset`, `get_receipts`, plus the config-drift trio
- **Fail-closed per-agent policy** — tool allowlist, camera allowlist, PTZ step
  bounds per agent identity; unknown agents get nothing
- **Signed receipts on every call** — hash-chained JSONL, ed25519-signed,
  produced frames content-hashed into the receipt; one altered byte is detected
  at the exact sequence number
- **Dual transport** — AXIS VAPIX and ONVIF SOAP behind one tool contract,
  selected per camera
- **No secrets on disk** — camera credentials resolve from a local credential
  store at startup and are never written or logged

Commissioning-as-code turns a `specs/*.yaml` desired-state file into a read-only plan, an explicitly approved and postcondition-verified apply, or a later conformance check. Applies snapshot every changed parameter for rollback, verify PTZ presets by name, and merge named AXIS Object Analytics scenarios without removing unmanaged scenarios. Approved AOA writes require `config.aoa: true`; after readback, apply observes filtered AOA topics with a Bun WebSocket using Basic authentication over TLS (accepting the camera's self-signed certificate, like `curl -k`) and records counts and warnings in the signed handoff. Apply/verify runs emit signed JSON handoffs in `handoff/`, while parameter access stays inside the existing config grant and hard denylist.

## Quick start

```bash
bun install
```

Describe your cameras in `cameras.json`:

```json
{
  "lobby": { "base": "http://192.168.1.33", "user": "root", "credKey": "cam-lobby",
             "ptz": true, "protocol": "vapix" },
  "gate":  { "base": "http://192.168.1.32", "user": "root", "credKey": "cam-gate",
             "ptz": true, "protocol": "onvif", "profile": "profile_1_jpeg" }
}
```

Grant agents authority in `policy.json` (anything not granted is denied):

```json
{
  "agents": {
    "claude-main": {
      "tools": ["list_cameras", "get_snapshot", "ptz_move", "get_receipts"],
      "cameras": ["lobby", "gate"],
      "ptz": { "maxStep": 30 }
    }
  }
}
```

Register with an MCP client (Claude Code shown):

```bash
claude mcp add cameras -- env AGENT_ID=claude-main bun /path/to/onvif-mcp/index.ts
```

Audit the receipt chain any time:

```bash
bun index.ts --verify
# chain OK — every hash linked + signature valid
```

## Tools

| Tool | Does | Policy checks |
|---|---|---|
| `list_cameras` | Live device info for cameras this agent may see | agent known, tool granted |
| `get_snapshot` | Capture a JPEG, return path + SHA-256 | + camera granted |
| `ptz_move` | Relative pan/tilt/zoom in degrees | + camera granted, camera is PTZ, step within `maxStep` |
| `ptz_preset` | Recall a named PTZ preset (VAPIX); emits an AAR wire bundle | + camera granted, camera is PTZ, ptz grant |
| `commission_plan` | Diff parameters and named AOA scenarios; list applicable presets; no writes | + camera granted, config groups granted, all params allowed, AOA grant for scenario specs |
| `commission_apply` | Dry-run unless `approve:true`; apply, read back, observe AOA events, roll back parameters on failure, emit signed handoff | + plan checks, config remediation grant for approved writes, `config.aoa` for scenarios |
| `commission_verify` | Check parameter, preset-name, and AOA scenario conformance; emit a signed handoff | + camera granted, config groups granted, all params allowed, AOA grant for scenarios |
| `get_receipts` | Tail the signed receipt chain | agent known, tool granted |

Every call — allowed or denied — appends a receipt. A denial looks like this:

```json
{ "seq": 19, "profile": "aar-0.2-draft-alignment",
  "principal": { "role": "agent", "type": "service", "id": "claude-main" },
  "enforcement_point": "onvif-mcp/0.1.0", "node_kind": "authorization",
  "action": { "tool": "ptz_move", "params": { "camera": "gate", "pan": 90 } },
  "decision": "deny", "detail": "step exceeds policy maxStep 30°",
  "prev": "8fb7…", "hash": "8322…", "sig": "jRld…" }
```

## Receipts and the AAR spec

Receipt semantics follow the [Agent Action Receipts (AAR)](https://github.com/oneshot2001/aar)
v0.2 vocabulary: principals, enforcement points, node kinds (`observation`,
`action_attempt`, `authorization`), and calibrated outcome-evidence levels
(`device_acknowledged`, `independently_sensed`, `unknown`).

**Honesty note:** wire conformance to AAR v0.2 (deterministic CBOR, detached
COSE_Sign1 ES256) is **not claimed yet**. The current chain is a draft
transport. The gap analysis and conformance plan live in
[`docs/aar-alignment.md`](docs/aar-alignment.md).

## Transports

Set `protocol` per camera: `"vapix"` (AXIS HTTP CGI) or `"onvif"` (SOAP
services). Verified live against AXIS hardware: on AXIS OS 12.9.57 the admin
user works for ONVIF over HTTP digest; older 12.x firmware requires a separate
ONVIF account provisioned in the web UI. ONVIF `RelativeMove` uses the generic
translation space — pan converts as degrees/360 (measured exact on hardware);
tilt/zoom mapping is linear-approximate.

## Status

Experimental (v0.1.0). Verified live against three AXIS cameras (two PTZ, one
fixed dome) through real MCP client round-trips: physical PTZ motion with
before/after frame proof, all denial paths exercised and receipted, and
tamper-detection confirmed by mutating a receipt and watching `--verify` flag
the exact sequence. Not production software — see the roadmap.

## Roadmap

- ~~AAR v0.2 wire-conformant receipt producer~~ **SHIPPED 2026-08-15** — `receipts-aar/`
  emits deterministic-CBOR + COSE_Sign1 ES256 bundles for the pinned-ontology
  actions (`camera.stream.view`, `camera.ptz.preset`), offline-verified conformant
  by the spec's independent pyref verifier: `bun index.ts --verify-aar`.
  A conformant verdict proves wire integrity + binding, not receipt-body truth — scope, remaining narrative residue, and same-operator disclosures: `docs/aar-alignment.md`. Policy denials wire-emit too
  (decision deny, real refusal reason); receipt bodies carry real narrative (timestamps,
  agent identity, policy.json digest)
- Per-agent signing keys and signed policy objects (agent commissioning)
- Clip/recording export
- Non-AXIS ONVIF hardware validation
- Align to MCP spec 2026-07-28 once official SDK support lands — the stateless
  request/response core removes session plumbing and opens a serverless/edge
  deploy path for the gateway

## Trademark note

ONVIF® is a trademark of ONVIF, Inc. This project is not affiliated with,
endorsed by, or certified by ONVIF, Inc. The name is purely descriptive — this
server speaks the ONVIF protocol as published in the open specifications.
**No ONVIF conformance is claimed or implied.** No ONVIF logos are used and no
WSDL files are redistributed; the SOAP envelopes are hand-authored.

## License

[MIT](LICENSE) © 2026 Matthew Visher.

The [AAR specification](https://github.com/oneshot2001/aar) this project
aligns with is separately licensed: spec text CC BY 4.0, reference code
Apache-2.0.

Render a handoff for the customer: `bun render-handoff.ts handoff/<file>.json --pdf` (HTML + PDF next to the JSON; JSON stays the signed source of truth).

Known device quirk (AXIS Q6358-LE, OS 12.9.57): `ptz.cgi?setserverpresetname=<new>` returns 204 but the preset is not persisted; `commission_verify` catches this via `query=presetposcam` readback and reports `preset:<name>` as failed — which is the reason readback exists.

VAPIX OpenAPI + llms.txt (the quirks this server learned the hard way): https://github.com/oneshot2001/vapix-openapi
