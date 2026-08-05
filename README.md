# onvif-mcp

Governed MCP server over AXIS VAPIX. Spike / kill test, 2026-08-04.

The thesis: agent access to video infrastructure that a security director could
approve. Not a naked API wrapper — every tool call passes a fail-closed policy
gate and emits a hash-chained, ed25519-signed receipt, **including denials**.

## What it does

- `list_cameras` · `get_snapshot` · `ptz_move` · `get_receipts` over MCP (stdio)
- Per-agent policy (`policy.json`): tool allowlist, camera allowlist, PTZ step
  bounds. Unknown agent → every call denied (fail closed).
- Receipts (`receipts/chain.jsonl`): AAR v0.2-aligned semantics — principal,
  enforcement point, node kind (`observation` / `action_attempt` /
  `authorization` for denials), outcome-evidence level, content hash of produced
  frames — on a hash-chained, ed25519-signed JSONL draft transport.
  `bun index.ts --verify` recomputes the chain + checks every signature; a
  single altered byte flags the exact receipt. Wire conformance to the AAR spec
  (deterministic CBOR + detached COSE_Sign1 ES256) is NOT claimed yet — the gap
  and build packet live in `docs/aar-alignment.md`.
- Camera passwords fetched from the local `cred` store at startup; never on disk.

## Run

```
bun install      # deps
AGENT_ID=claude-main bun index.ts            # serve (stdio MCP)
bun test-client.ts claude-main '[["list_cameras",{}]]'   # exercise via real MCP client
bun index.ts --verify                        # audit the receipt chain
```

Register for Claude Code: `claude mcp add onvif -- env AGENT_ID=claude-main bun /path/to/index.ts`

## Trademark note

ONVIF® is a trademark of ONVIF, Inc. This project is not affiliated with,
endorsed by, or certified by ONVIF, Inc. The name is purely descriptive — this
server speaks the ONVIF protocol (SOAP services as published in the open
specifications). **No ONVIF conformance is claimed or implied.** No ONVIF
logos are used, and no WSDL files are redistributed (the SOAP envelopes are
hand-authored against the public specs).

## Kill-test results (2026-08-04)

- Live PTZ move + snapshot round-trip against AXIS Q6358-LE through the real MCP
  protocol — before/after frames prove physical motion.
- Policy: oversize step denied, non-PTZ camera denied, scoped agent denied
  off-list camera + tool, unknown agent fully denied. All denials receipted.
- Tamper test: one edited field → `--verify` flags the exact seq, exit 1.

## ONVIF leg (2026-08-04, same day)

Dual transport, one tool contract: `protocol` per camera in `cameras.json`.
Verified live on AXIS Q6325-LE via ONVIF SOAP at `/onvif/services`:
GetDeviceInformation, GetProfiles, GetSnapshotUri (+ authenticated fetch), and
RelativeMove — requested +10° pan, measured +10.0° (generic translation space
maps pan°/360). AXIS OS 12.9.57 accepts the admin user over HTTP digest for
ONVIF; on older 12.x (e.g. P3285 @ 12.7.61) a separate ONVIF account must be
provisioned via web UI.

Known gaps (spike, not product): no clip export, relative PTZ doesn't
round-trip at high zoom (use absolute position restore), ONVIF tilt/zoom
degree mapping is approximate (generic space), receipts key is per-install not
per-agent persona, policy file is unsigned (should be a signed policy object —
the commissioning-registry concept), AAR wire conformance pending
(`docs/aar-alignment.md`).
