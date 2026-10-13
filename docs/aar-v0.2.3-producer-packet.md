# Build packet: AAR producer → v0.2.3 (commit the attempt before the camera send)

Claude plans → Codex builds → Claude reviews + live-verifies. This packet is the plan. 2026-10-12, revised after the
Astra premise review (GO-WITH-CHANGES, all seven findings folded in).

## Why
onvif-mcp is the named reference producer for AAR, but it pins `aar-kat-harness@github:oneshot2001/aar#e763b78`
(2026-08-15, pre-v0.2.0), and its bundles fail the released verifier. Probed 2026-10-12 against v0.2.3 (`26e77fb`)
offline, in a scratch worktree with a fake dispatch and scratch keys:

| Check | August pin | Pin bump only |
|---|---|---|
| prior-state.json parse | `prior_emissions must be strictly sorted and unique` (the producer appends; D-76 needs CBOR-key order) | same: producer bug |
| step 6 schema | `schema/enum-unknown` (verifier-trust credential `principal_type: authority_source`) | fixed upstream; `producer.ts` compiles unchanged |
| D-66, AAR-3 (CONFORMANCE step 13) | n/a | **`journal/uncommitted-dispatch`** whenever the bundle's commit time is later than the recorded dispatch time, assuming earlier checks pass. In practice: any call whose start and finish fall in different seconds, which includes every successful `ptz_preset` (the settle poll sleeps ≥ 1 s) |
| denial bundle | n/a | conformant AAR-3 |

The D-66 result is a correct verdict, not a verifier bug:
- onvif-mcp sends the camera command first and signs the whole chain afterwards (`producer.ts:167` records
  `startedAt` as the dispatch time).
- D-66 requires a durable commit of the `action_attempt` before an AAR-3 action-bearing send. The only bypass is the
  policy-bound life-safety exception (`spec/DECISIONS.md` ~1035), which doesn't apply to these actions.
- The fix is to sign **and durably journal** the attempt before the send, the way the upstream demo producer does
  (`demo/ep/producer.ts` `beforeDispatch`).

## Non-negotiables
- **Event times are real; validity bounds are disclosed.**
  - Every *event* time must be a reading of this process's clock taken when that event happened: observation
    `observed_at`, `dispatched_at`, outcome `observed_at`, each receipt's `emission.committed_at`, and
    `evidence.time.wall_time` plus `monotonic_ns`. Post-send receipts get fresh post-send monotonic readings, and
    the anchor observation happens after the send.
  - Never set an event time earlier than when the event happened to satisfy D-66, and never label a pre-build
    reading as the fsync-completion time.
  - Some fields stay demo-synthetic: freshness `issued_at`, trust-store `created_at`, `expires_at`, and the existing
    legal and purpose residue. These are *validity bounds*, not event times. List them in `docs/aar-alignment.md`
    (that doc already has a "placeholder residue" disclosure; extend it).
  - If an honest timeline can't be built, emission fails loudly. Examples: T1 − T0 outside the builder's bound, or
    the clock goes backwards. Fail as `aar-emit FAILED: …` in the tool output plus the existing JSONL `aar_emit`
    failure receipt; never clamp or patch the times.
- **Fail closed on the journal.** If the attempt can't be durably appended (append + fsync) before the send, there
  is **no action-bearing send**. The bundle is a signed `not_dispatched` attempt with
  `refusal_reason: "journal/unavailable"` (CONFORMANCE refusal codes). The device-metadata read happens before
  journaling and is not action-bearing. If storage is down too, the refusal bundle may fail to write, and that
  surfaces as `aar-emit FAILED`.
- **No spec, verifier, KAT or CDDL change in the aar repo.** Wire bytes for existing inputs stay byte-identical:
  `bun test demo/ep/wire-builder.golden.test.ts` and `scripts/release-check.sh` pass unchanged.
- **Never rewrite signed history.** Existing bundles under `receipts/aar/*/` stay byte-for-byte as they are.
  - They're on the August pre-release wire and will keep failing v0.2.3; the site already says so.
  - Existing `prior-state.json` history entries are kept (re-sorted, not dropped).
- **Pin:** don't change `aar-kat-harness` in `package.json` / `bun.lock`. Claude repins to the aar commit once it's
  on aar `main` (see Workspace).
- **Offline only:** no live camera calls, no network. Tests run with no camera, no listener and no `.keys/`, and
  write nothing under the repo's `receipts/`. Use temp dirs and a temp `HOME` for keys.

## Part 1: aar repo, demo layer only (`demo/ep/wire-builder.ts` + tests)
Add an opt-in two-phase real-clock path for producers that dispatch inside `beforeDispatch`. When it isn't used, the
bytes stay exactly as they are today.

- **Pre-send, frozen at T0:** pre-send envelopes (observation, inference, authorization, `action_attempt`) carry
  `committed_at = T0`. Credentials, the request, and delegation windows are minted at T0 and stay unchanged:
  never regenerate a signed ancestor using T1. Delegation validity is checked against the attempt's commit time
  (`pyref/verifier.py` ~1620).
- **Post-send, at T1:**
  - post-send receipts (dispatch, outcome_observation and anything after) carry `committed_at = T1`;
  - epoch closure (`closed_at` must cover every commitment, `verifier.py` ~1758), the selector, bundle `created_at`,
    trust `evaluation_time` and the returned verification metadata all use T1.
- **Times from the callback:** `beforeDispatch`'s success result carries the producer-measured times, at least
  `dispatchedAt` (right before the send), `outcomeObservedAt` (after readback) and T1. Exact shape: your call, at
  minimum lines. Document it next to `RealNarrative`.
- **Validate both phases (throw, don't clamp):**
  - `T0 ≤ dispatchedAt ≤ outcomeObservedAt ≤ T1`;
  - `0 ≤ T1 − T0 ≤ 60`, the retained builder/selector bound (`wire-builder.ts` ~78). Export the bound so onvif-mcp
    can use it.
  - Mixed `committed_at` values within one bundle are already supported by the verifier's index ordering
    (`verifier.py` ~1783).

Tests first:
- (a) the golden tests stay byte-identical;
- (b) a bundle built through `beforeDispatch` with `dispatchedAt = T0+1`, `outcomeObservedAt = T0+5`, `T1 = T0+6`
  → `python3 -B -m pyref verify … --at T1 --trust-policy … --prior-state …` → `Result: conformant`,
  `evaluated_profile: AAR-3`;
- (c) the same timeline committed entirely after the send (today's single-`committedAt` narrative) →
  `journal/uncommitted-dispatch`;
- (d) T1 − T0 = 60 passes and 61 throws; T1 < T0 throws; each ordering violation throws.

## Part 2: onvif-mcp
1. **`receipts-aar/producer.ts`**
   - `emit()` takes `send: () => Promise<{ dispatch: WireDispatch; dispatchedAt: number; outcomeObservedAt: number }>`
     in place of a precomputed `dispatch`. `refusal` stays as today for policy denials.
   - Order:
     1. Read T0.
     2. **Reserve the epoch durably** (write `next_epoch` before building, so a crash can't reuse an epoch).
     3. Build through `beforeDispatch`.
     4. Inside the callback, append + fsync an `attempt_committed` line to `receipts/aar/journal.jsonl`
        (`invocation_id`, `receipt_id`, envelope digest + envelope CBOR hex, a clock reading taken *after* the
        fsync returns).
     5. Only then call `send()`, then append `dispatch_completed`.
     6. Read T1.
   - If the journal append or fsync throws, return `{ refusalReason: "journal/unavailable" }`; `send()` is never
     called.
   - **Serialize** `emit()` calls within the process (MCP tool calls can overlap). The single-writer assumption
     across processes stays and now also covers `journal.jsonl`; update the header comment.
2. **When `send()` fails.**
   - `not_dispatched` only for a refusal proven before any bytes went to the device.
   - A device request that fails *after* the attempt is journaled **resolves** `send()` with what's true:
     `status: 0`, outcome `unknown` (today's `ptz_preset` transport-error shape). The snapshot path now does the
     same, where today it returns "capture failed" with no bundle.
   - A `send()` that **throws** is ambiguous:
     - no bundle is written;
     - the journal keeps the eligible attempt plus a `dispatch_ambiguous` line, if the journal is writable;
     - the tool output says `aar-emit FAILED: dispatch outcome ambiguous`;
     - nothing is ever retried automatically.
3. **Startup recovery** (pattern of `lastReceiptFrom` and the startup chain check, `index.ts` before
   `server.connect`):
   - A torn or unparseable last line in `journal.jsonl` → print `aar journal corrupt: …` plus the path, and exit
     non-zero. Never repair or truncate it.
   - An `attempt_committed` with no completion line → print a warning naming the invocation and start normally.
     Never redispatch.
4. **Prior state.** Sort `prior_emissions` on every write with upstream's key (`demo/run-scenario.ts`
   `advancePriorState`: a CBOR array of the 7 fields, compared with `Buffer.compare`), and reject duplicates. Each
   bundle dir's `prior-state.json` snapshot is written sorted.
5. **`index.ts` call sites** (`get_snapshot`, `ptz_preset`): move the device calls into `send`.
   - For the snapshot, `send` covers the capture.
   - For the preset, `send` covers recall + settle readback.
   - The settle loop stops early when one more poll (curl timeout `curl-args.ts` ~15 + 1 s sleep) could push T1
     past the exported bound; the outcome is then `unknown`. Today the loop can run to ~88 s.
   - `deviceMeta` (a read) runs before `emit`, because the observation receipt carries it.
   - The JSONL chain receipts, the denial paths, tool output text and `aar-emit FAILED` handling stay as they are.
6. **`--verify-aar [dir]`** stays per-bundle. Don't relabel or silently skip pre-bump bundles.
7. **Docs.**
   - `docs/aar-alignment.md`: add a dated 2026-10 section covering the v0.2.3 wire, commit-before-send, the journal
     and recovery, event times vs validity bounds, and old bundles staying on the August wire.
   - README: one line, if it states the AAR version.

Tests first (bun, offline, fake `send`, temp root + temp `HOME`):
- **Timelines:**
  - a fast send (same second) and a slow send (≥ 2 s across a second boundary; fake clock or real sleep) each give a
    bundle that pyref v0.2.3 calls `conformant`, `AAR-3`, checked against that bundle's own `prior-state.json`;
  - three bundles in sequence: each prior-state snapshot is non-empty and sorted.
- **Journal:**
  - journal append failure and fsync failure → `send` never called, and the bundle is conformant with a
    `not_dispatched` attempt carrying `journal/unavailable`;
  - the `attempt_committed` line holds that bundle's `action_attempt` envelope digest;
  - a crash after the append and before the send (journal holds `attempt_committed` only) → startup warning, no
    redispatch;
  - a torn last line → startup exits non-zero with `aar journal corrupt`.
- **Failure shapes:**
  - recall succeeds but readback fails → dispatch receipt, outcome `unknown`;
  - transport failure after the attempt is journaled → `status: 0`, `unknown`;
  - snapshot failure → same shape;
  - `send` throws → no bundle, `dispatch_ambiguous`, no retry.
- **Bounds and concurrency:**
  - T1 − T0 > 60 or a backwards clock → `aar-emit FAILED`, no bundle;
  - the settle loop stops before the bound;
  - two overlapping `emit()` calls → distinct epochs, both bundles conformant.
- **Policy denial:** a conformant bundle; `send` never called.
- **Cred leak:** with a stand-in camera password (pattern of `curl-args.test.ts:87`), the password never appears in
  `journal.jsonl`, any bundle file, `meta.json` or tool output.
- The existing suite stays green.

## Workspace (important: the nightly loops run at 01:00 in the main checkouts)
Work only in the two worktrees Claude created:
- aar: `~/Projects/.wt/aar-realclock`, branch `realclock-predispatch` (base `26e77fb`);
- onvif-mcp: `~/Projects/.wt/onvif-mcp-aar-v023`, branch `aar-v0.2.3-producer`. Its `node_modules/aar-kat-harness`
  is a symlink to the aar worktree, so Part 2 sees Part 1 live.

Don't run `bun install` or `bun add` in the onvif-mcp worktree (that would replace the symlink); if you need to,
say so in the report.

Commit on each branch: one commit for Part 1, and one or two for Part 2. Messages end with
`Co-Authored-By: Codex (GPT-6 Astra) <noreply@openai.com>`. Never push, tag or touch `main`.

## Accept
- **aar worktree:** `scripts/release-check.sh` → `release-check: PASS`, and the new Part 1 tests pass.
- **onvif-mcp worktree:** `bun test` exits 0 with the new tests, `bunx tsc --noEmit` is clean, and
  `git diff --stat main -- receipts/` is empty.
- **Report:**
  - each material choice left open here (timing-API shape, journal format, epoch reservation, serialization,
    settle-loop stop rule) as gap → choice + alternative → consequence → file:line;
  - the exact pyref output lines for the slow-send bundle;
  - anything you couldn't satisfy.
