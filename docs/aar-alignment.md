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

- **⚠️ Demo-narrative placeholders in receipt bodies.** `buildDemoBundle` authors the
  observation/inference/authorization receipt bodies from its fixed Gate-5 scenario:
  synthetic offsets on internal timestamps (`observed_at`, `dispatched_at`, epoch
  `opened_at`, monotonic/boot ids), a fictional "scripted-agent" model record, and a
  synthetic demo trust-policy decision that does **not** restate this server's
  `policy.json` evaluation. **What is real in each bundle:** evaluation time, action
  name, target, parameters, command manifest, dispatch status + response-body digest,
  outcome level/state + observation digest, and device metadata. A pyref `conformant`
  verdict proves wire-format integrity and binding — not the truth of the narrative
  fields. Making those fields real requires generalizing the upstream wire-builder
  (open item, with denial emission below).
- **Single-writer assumption.** `producer-state.json` / `prior-state.json` /
  `anchor.jsonl` are read-modify-write with no locking — run one server process per
  receipts directory (same race class as the JSONL chain, wider surface).

- **Only pinned-ontology actions are wire-emitted:** `get_snapshot` →
  `camera.stream.view`, new `ptz_preset` tool → `camera.ptz.preset`. `ptz_move`
  (relative — not in the v0.2 ontology) and `config_*` stay on the draft JSONL chain.
- **Denials are not wire-emitted yet** — the reference wire-builder only models
  delegation-expiry refusals; policy denials need a small upstream generalization.
- **Same-operator disclosures apply (F22):** one process holds every key role
  (per-agent key dirs under `~/.aar-onvif-mcp/<agent>/`, self-issued delegation),
  the anchor log is local, identity is self-asserted. A verdict proves artifact
  integrity/binding, not process honesty (G4).
- Per-bundle evidence dirs under `receipts/aar/`: `bundle.cbor`, pinned
  `trust-policy.json`, pre-emission `prior-state.json` snapshot, `meta.json`.

## Sequencing constraint (flagged 2026-08-04)

The AAR repo is PRIVATE until launch. onvif-mcp going public with AAR references
pre-announces the spec — so onvif-mcp's public flip is coupled to (or follows)
the AAR license/go-public call, which is already an open decision on the AAR
pickup. Until then the repo stays local/private-remote.
