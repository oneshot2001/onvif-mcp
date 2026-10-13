# AAR v0.2 Alignment — status + build packet

2026-08-04. Decision: onvif-mcp receipts align to the AAR spec before publish, and
onvif-mcp becomes AAR's first public reference producer.

## What is aligned today (semantic layer)

Receipt bodies use AAR v0.2 vocabulary:

| onvif-mcp field | AAR concept |
|---|---|
| `principal {role: "agent", type: "service", id}` | principal-role / principal-type |
| `enforcement_point` | principal-role `enforcement_point` (this server) |
| `node_kind` | `observation` (snapshot/list) · `action_attempt` (ptz) · `authorization` (denials) |
| `outcome_evidence` | outcome-evidence-level: `device_acknowledged` (VAPIX/ONVIF 200 on move) · `independently_sensed` (content-hashed frame) · `unknown` |
| `result_sha256` | digest binding of the produced artifact |
| `prev`/`hash`/`sig` | draft transport chain (NOT the AAR wire) |

`profile: "aar-0.2-draft-alignment"` marks these receipts as vocabulary-aligned,
**explicitly not conformance-claiming**.

## What conformance requires (the gap — build packet for the systems lane)

Per `aar-core.cddl` (v0.2-rc7):

1. Deterministic CBOR encoding (RFC 8949 §4.2.1): definite lengths, shortest ints,
   deterministic key order, closed maps, no tags, no floats.
2. Detached COSE_Sign1, ES256 (P-256, RFC 6979 deterministic, 64-byte P1363 r||s,
   low-S), protected headers with the −70000..−70006 AAR label allocation
   (principal-type, tenant_id, site_id, epoch_id, epoch_seq, issuer_seq, role).
3. Key discipline: kid = SHA-256 of DER SubjectPublicKeyInfo; per-principal keys
   (today's chain key is per-install — must become per-agent, which is the
   commissioning-registry tie-in).
4. Epoch machinery: epoch events + manifests; receipts carry epoch_id/epoch_seq.
5. Verify against the byte-pinned KATs in the AAR repo (`kats/`), not self-tests.

Estimated shape: a `receipts-aar` module producing `receipt-envelope` bytes +
KAT-driven tests. Two-model process per AAR repo README: Claude plans/gates,
Codex builds.

## 2026-08-15 — wire-conformant producer SHIPPED (`receipts-aar/`)

onvif-mcp now emits real AAR v0.2 wire bundles, offline-verified conformant by the
spec's independent pyref verifier (`bun index.ts --verify-aar`, exit 0, all 20 steps,
`evaluated_profile: AAR-3`, `coverage: complete`). Live-proven against AXIS Q6358-LE.

How: the AAR reference demo-EP wire machinery (`buildDemoBundle`, keys, RFC 6962
anchor log) is consumed as a pinned dependency (`aar-kat-harness@github:oneshot2001/aar`),
so the bundle bytes come from the code the AAR gates verified. Byte tampering on an
emitted bundle flips pyref to nonconformant (verified).

Honest scope boundary:

- **Real narrative (2026-08-15, upstream `RealNarrative`).** Receipt-body timestamps
  (`observed_at`, `dispatched_at`, outcome `observed_at`, epoch window, `committed_at`)
  come from this process's clock; the inference model record names the actual MCP agent
  (`provider: mcp-client`); the authorization decision and `policy_set_root` (digest of
  `policy.json`) reflect the evaluation this server actually performed; and **policy
  denials are wire-emitted** as decision `deny` + `not_dispatched` attempts carrying the
  real refusal reason (denial bundles never contact the device — metadata `not-queried`).
  `evidence.time` carries a genuine monotonic reading (`process.hrtime`) and a boot id
  derived from the real macOS boot time (`sysctl kern.boottime`).
  **Remaining placeholder residue** (upstream demo-layer constants): the legal block
  (purpose `incident-response`, jurisdiction `US-CO`), delegation `purpose_ids`,
  freshness `issued_at` (pinned to `evaluatedAt - 60`, not a real issuance time),
  correlation `peer_binding_digest`, decision `evaluated_inputs`, and the
  request/consumption framing. A pyref `conformant` verdict still proves wire-format
  integrity and binding — not the truth of body fields (G4).
- **Single-writer assumption.** `producer-state.json` / `prior-state.json` /
  `anchor.jsonl` are read-modify-write with no locking — run one server process per
  receipts directory (same race class as the JSONL chain, wider surface). The
  two-agent demo (`claude-main` then `untrusted-demo`) must run its legs
  sequentially, never in parallel.

- **Only pinned-ontology actions are wire-emitted:** `get_snapshot` →
  `camera.stream.view`, new `ptz_preset` tool → `camera.ptz.preset`. `ptz_move`
  (relative — not in the v0.2 ontology) and `config_*` stay on the draft JSONL chain.
- **Denials ARE wire-emitted** (2026-08-15) for the two pinned-ontology actions;
  denials of off-ontology tools stay on the draft JSONL chain only.
- **Same-operator disclosures apply (F22):** one process holds every key role
  (per-agent key dirs under `~/.aar-onvif-mcp/<agent>/`, self-issued delegation),
  the anchor log is local, identity is self-asserted. A verdict proves artifact
  integrity/binding, not process honesty (G4).
- Per-bundle evidence dirs under `receipts/aar/`: `bundle.cbor`, pinned
  `trust-policy.json`, pre-emission `prior-state.json` snapshot, `meta.json`.

## 2026-10-12 — v0.2.3 wire, durable attempt before send

Part 2 uses the upstream two-phase `realClock` builder completed in aar
`96fb57b`. Offline tests verify new snapshot, preset, refusal, fast-send and
slow-send bundles as `conformant`, `evaluated_profile: AAR-3`, against each
bundle's own prior-state snapshot. The worktree dependency is a symlink to
Part 1; `package.json` and `bun.lock` are deliberately unchanged. Claude will
repin after the upstream commit reaches aar main. This is offline validation,
not a new live-camera conformance claim.

Device metadata is read before emission, and its observation time is recorded
when the read completes. `emit()` accepts a deferred `send(T0)` returning the
actual dispatch and outcome-observation readings. It reserves `next_epoch`
through a file fsync, atomic rename and directory fsync before reading the
epoch-open time. Prior-state updates use the same atomic write pattern.
Reservations are never rolled back: a crash or failed emission can leave a
gap, but cannot reuse an epoch. All producer instances serialize emissions
through one process-wide promise queue; failed calls do not poison the queue.
The **single-writer process assumption** still covers `producer-state.json`,
`prior-state.json`, `anchor.jsonl`, and now `journal.jsonl`.

The journal is append-only JSONL. `attempt_envelope` holds the invocation ID,
receipt ID, signed envelope digest and envelope CBOR hex. After that append
and fsync return, a fresh clock reading becomes `envelope_synced_at` in an
`attempt_committed` marker carrying the same envelope identifiers and bytes.
The marker is also appended and fsynced before `send()` can run. Two records
are necessary: a record cannot contain a reading taken after its own fsync.
The marker's timestamp describes the **envelope record's completed fsync**;
it does not claim to time its own fsync. No credentials, transport responses,
or exception details are journaled.

A journal append/fsync failure prevents the send and produces a signed
`not_dispatched` attempt with `journal/unavailable` only if the refusal is
decided within T0's second. A later refusal fails loudly without a bundle.
If bundle storage also fails, tool output contains `aar-emit FAILED` and the
existing JSONL chain gets an `aar_emit` failure receipt. Camera actions are
blocked whenever wire emission fails before send; preset output then says
`preset not dispatched`, without a false transport-error receipt.
A returned transport failure records status 0
and outcome `unknown`, including failed snapshots. A successful recall with
failed readback retains its dispatch receipt and an unknown outcome. A thrown
`send()` is ambiguous: no bundle, an attempted `dispatch_ambiguous` journal
append, and `aar-emit FAILED: dispatch outcome ambiguous`. No automatic retry
occurs. Failed completion journaling also fails emission without retrying.

Startup examines the journal before credentials, signing-key setup or MCP
connection. A torn, unparseable or invalid record produces
`aar journal corrupt: … (path)` and a nonzero exit; nothing is repaired or
truncated. An envelope/committed attempt lacking a completion produces a
warning naming its invocation and startup continues. It is never redispatched.
A `dispatch_ambiguous` record terminates recovery bookkeeping but does not
assert a known device result. Recovery does not reconstruct missing bundles.
After saving a journal refusal bundle, a best-effort `refusal_persisted` marker
clears any pending attempt for that invocation. Appends check only that the
journal is empty or ends with a newline; full validation occurs at startup.

Event times come from clock readings, never arithmetic backdating: metadata
observation; dispatch immediately before the device operation; outcome after
capture/readback; T0 for pre-send receipts; T1 after send and completion
journaling for post-send receipts; fresh post-send monotonic evidence and
anchor observation. The epoch-open reading is taken before T0 and emission
waits for the next clock second, because v0.2.3 requires epoch open strictly
before close even for a same-second send or denial. This adds up to one second
before T0; an early timer wake sleeps again for the remainder. T0 is a phase
commitment reading, **not** an fsync-completion claim.
The upstream builder freezes pre-send ancestors, credentials and the request
at T0 and uses T1 for descendants, closure, selector, bundle creation and
verification metadata. Backwards clocks or a span beyond the exported
60-second bound fail loudly; timestamps are never clamped.

Preset settlement keeps the eight-poll cap and stops before another 10-second
curl timeout plus one-second sleep can reach the bound. Its deadline is
based on T0, so metadata and queue time do not consume the budget. Scheduler
or fsync stalls can still exceed the bound, in which case emission fails.
Successful recall plus a successful last readback gives evidence level
`device_acknowledged`; equal consecutive reads only stop polling early.
The readback is from the same device channel, so outcome state stays `unknown`:
it cannot establish the preset's independently known target position.

**Validity bounds and placeholder residue remain disclosed.** Freshness
`issued_at` is the builder phase time minus 60 seconds and `expires_at` is
phase time plus 3600; trust-store `created_at` is T0 minus 3600. Credentials use
`valid_from = T0 - 3600`, `valid_until = T0 + 86400`; delegation bounds are
T0 minus 60 through T0 plus 3600. These demo validity bounds are not event or
issuance observations. The existing legal block (`incident-response`, `US-CO`,
`security-sensitive`, demo retention), delegation purposes, correlation peer
binding, decision inputs/counters, and request/consumption framing remain
demo residue. Same-operator trust and self-asserted evidence limits still apply.

Every prior-state write uses the upstream seven-field CBOR key ordering and
rejects duplicate entries. Historical entries are retained and re-sorted;
bundle snapshots capture the sorted history before that bundle. A brand-new
producer necessarily has an empty first snapshot; subsequent snapshots are
nonempty. **Existing `receipts/aar/*/` bundles are never rewritten.** They stay
on the August pre-release wire and continue to fail v0.2.3 verification.
`--verify-aar [dir]` remains per-bundle and reports those failures, without
skipping or relabeling old bundles; it now runs before camera/key setup.

## Sequencing constraint (flagged 2026-08-04)

The AAR repo is PRIVATE until launch. onvif-mcp going public with AAR references
pre-announces the spec — so onvif-mcp's public flip is coupled to (or follows)
the AAR license/go-public call, which is already an open decision on the AAR
pickup. Until then the repo stays local/private-remote.
