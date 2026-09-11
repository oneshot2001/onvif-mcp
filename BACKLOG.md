# BACKLOG — nightly Astra loop input (Claude writes, Matthew edits)

Rules: loop takes the TOP Ready item only. No `accept:` line → loop does not fire.
Branch `night/YYYY-MM-DD` off `main`. Never push. No live camera calls (192.168.1.x) — tests run offline.

## Ready
- [ ] Fix the failing test `commission.test.ts` "AOA absence warns without failing and preset verification detects deletion" (assertion at line ~147). Decide whether the test or `commission.ts` is wrong by reading `docs/commission-phase2-packet.md` (AOA-unavailable = verify failure per commit 34119cc) and fix the wrong side — accept: `bun test` exits 0, 8 pass 0 fail, no network calls in tests.
- [ ] Add an offline test for `render-handoff.ts` using an existing `handoff/*.json` fixture: HTML output contains the scenario rows and the receipt hash — accept: `bun test` exits 0 with the new test; no `--pdf` path exercised.

## Blocked / needs Matthew

## Done
