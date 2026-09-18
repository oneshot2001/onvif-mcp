# BACKLOG — nightly Astra loop input (Claude writes, Matthew edits)

Rules: loop takes the TOP Ready item only. No `accept:` line → loop does not fire.
Branch `night/YYYY-MM-DD` off `main`. Never push. No live camera calls (192.168.1.x) — tests run offline.

## Ready
- [ ] Add an offline test for `render-handoff.ts` using an existing `handoff/*.json` fixture: HTML output contains the scenario rows and the receipt hash — accept: `bun test` exits 0 with the new test; no `--pdf` path exercised.

## Blocked / needs Matthew

## Done
- [x] `commission.test.ts` AOA-absence test: no fix needed — test already expects verify failure per 34119cc; `bun test` 13 pass 0 fail (2026-09-18; original accept hardcoded 8 pass).
