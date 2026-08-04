# onvif-mcp

Governed MCP server over AXIS VAPIX. Spike / kill test, 2026-08-04.

The thesis: agent access to video infrastructure that a security director could
approve. Not a naked API wrapper — every tool call passes a fail-closed policy
gate and emits a hash-chained, ed25519-signed receipt, **including denials**.

## What it does

- `list_cameras` · `get_snapshot` · `ptz_move` · `get_receipts` over MCP (stdio)
- Per-agent policy (`policy.json`): tool allowlist, camera allowlist, PTZ step
  bounds. Unknown agent → every call denied (fail closed).
- Receipts (`receipts/chain.jsonl`): seq, ts, agent, tool, params, decision,
  detail, result hash (snapshots are content-hashed), prev-hash chain, ed25519
  signature. `bun index.ts --verify` recomputes the chain + checks every
  signature; a single altered byte flags the exact receipt.
- Camera passwords fetched from the local `cred` store at startup; never on disk.

## Run

```
bun install      # deps
AGENT_ID=claude-main bun index.ts            # serve (stdio MCP)
bun test-client.ts claude-main '[["list_cameras",{}]]'   # exercise via real MCP client
bun index.ts --verify                        # audit the receipt chain
```

Register for Claude Code: `claude mcp add onvif -- env AGENT_ID=claude-main bun /path/to/index.ts`

## Kill-test results (2026-08-04)

- Live PTZ move + snapshot round-trip against AXIS Q6358-LE through the real MCP
  protocol — before/after frames prove physical motion.
- Policy: oversize step denied, non-PTZ camera denied, scoped agent denied
  off-list camera + tool, unknown agent fully denied. All denials receipted.
- Tamper test: one edited field → `--verify` flags the exact seq, exit 1.

Known gaps (spike, not product): VAPIX only (no ONVIF SOAP yet — name is the
ambition), no clip export, relative PTZ doesn't round-trip at high zoom (use
absolute position restore), receipts key is per-install not per-agent persona,
policy file is unsigned (should be a signed policy object — see the
commissioning-registry concept).
