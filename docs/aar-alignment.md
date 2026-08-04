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

## Sequencing constraint (flagged 2026-08-04)

The AAR repo is PRIVATE until launch. onvif-mcp going public with AAR references
pre-announces the spec — so onvif-mcp's public flip is coupled to (or follows)
the AAR license/go-public call, which is already an open decision on the AAR
pickup. Until then the repo stays local/private-remote.
