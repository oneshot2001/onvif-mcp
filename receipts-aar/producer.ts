// AAR v0.2 wire-conformant receipt producer for onvif-mcp.
// Reuses the AAR reference demo EP wire machinery (aar-kat-harness, Apache-2.0,
// pinned by commit in bun.lock) so the bundle bytes come from the same code the
// spec's gates verified against pyref. This module only maps onvif-mcp calls
// onto that machinery.
//
// Scope (honest boundary — see docs/aar-alignment.md):
// - Only actions expressible in the v0.2 pinned ontology get wire bundles:
//   get_snapshot → camera.stream.view, ptz_preset → camera.ptz.preset.
//   ptz_move (relative) and config_* stay on the draft JSONL chain.
// - Denials are NOT wire-emitted yet: the reference wire-builder only models
//   delegation-expiry refusals; policy-denial receipts need a small upstream
//   generalization first.
// - Same-operator disclosure applies: one process holds every key role, the
//   anchor log is local, and identity is self-asserted (F22).
// - REAL NARRATIVE (upstream RealNarrative, 2026-08-15): timestamps come from
//   this process's clock, the model record names the actual MCP agent, the
//   decision + policy_set_root reflect the policy.json evaluation this server
//   actually performed, and policy denials are wire-emitted as decision "deny"
//   with the real refusal reason. Remaining placeholder residue (upstream
//   demo-layer constants): the legal block (purpose incident-response,
//   jurisdiction US-CO), delegation purpose_ids, and the request/consumption
//   framing — see docs/aar-alignment.md.
// - SINGLE-WRITER ASSUMPTION: producer-state.json, prior-state.json, and
//   anchor.jsonl are read-modify-write with no locking. Run ONE server process
//   per receipts directory; concurrent writers can fork epochs and drop
//   prior-state entries (same class of race as the JSONL chain, wider surface).
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { AdapterId, LogicalTargetName } from "aar-kat-harness/adapters/shared/types";
import { encodeCbor, toHex } from "aar-kat-harness/harness/cbor";
import { hash } from "aar-kat-harness/harness/crypto";
import { LocalRfc6962Log } from "aar-kat-harness/demo/anchor/log";
import { buildCommandManifest } from "aar-kat-harness/demo/ep/command-manifest";
import { buildDemoBundle, type WireBuildResult } from "aar-kat-harness/demo/ep/wire-builder";
import { generateDemoKeys, loadDemoKeys, type DemoKey, type DemoKeyRole } from "aar-kat-harness/demo/keys/keys";

export type WireAction = "camera.stream.view" | "camera.ptz.preset";

export interface WireDispatch {
  readonly status: number;
  readonly responseBody: Uint8Array;
  readonly outcomeLevel: "device_acknowledged" | "contradicted" | "unknown";
  readonly outcomeState: "consistent" | "contradicted" | "unknown";
  // Outcome-observation bytes. NOT independent of the dispatch channel: the
  // snapshot observation is the produced frame itself; the preset observation
  // is a settled-position readback over the same VAPIX session.
  readonly observation: Uint8Array;
}

export interface WireEmitInput {
  readonly agentId: string;
  readonly camera: string;
  readonly cameraPtz: boolean;
  readonly protocol: string;
  readonly deviceMetadata: { manufacturer: string; model: string; firmware: string };
  readonly actionName: WireAction;
  readonly parameters: Readonly<Record<string, string | number | boolean>>;
  readonly startedAt: number; // unix seconds when the tool call began
  // Exactly one of: a dispatch result, or a policy refusal reason (denial —
  // wire-emitted as authorization decision "deny", attempt not_dispatched).
  readonly dispatch?: WireDispatch;
  readonly refusal?: string;
}

const id16 = (label: string) => hash(new TextEncoder().encode(`onvif-mcp-id:${label}`)).slice(0, 16);

interface ProducerState { next_epoch: number }
interface PriorState {
  prior_emissions: Array<{ issuer_kid: string; issuer_seq: number; epoch_owner_kid: string; epoch_id: number; epoch_seq: number; receipt_id: string; envelope_digest: string }>;
  entries: Array<{ replay_domain: string; invocation_id: string; content_digest: string }>;
}

// Real monotonic clock reading (ns) and a boot id derived from the actual
// macOS boot time — evidence.time fields carry genuine values, not synthetics.
const bootId = hash(new TextEncoder().encode(
  `boot:${Bun.spawnSync(["sysctl", "-n", "kern.boottime"]).stdout.toString().trim()}`)).slice(0, 16);

export class AarWireProducer {
  private readonly aarDir: string;
  private readonly keyDir: string;
  // Digest of the EXACT policy bytes the server parsed at startup — the policy
  // actually evaluated. Never re-read from disk (TOCTOU: an edited policy.json
  // would sign a digest of a policy that was not the one enforced).
  private readonly policyRoot: Uint8Array;

  constructor(private readonly root: string, private readonly agentId: string, policyBytes: Uint8Array) {
    this.policyRoot = hash(policyBytes);
    this.aarDir = join(root, "receipts", "aar");
    // Private keys stay outside the repository (AAR demo-kit convention).
    this.keyDir = join(process.env.HOME!, ".aar-onvif-mcp", agentId);
    mkdirSync(this.aarDir, { recursive: true });
  }

  private async keys(): Promise<Readonly<Record<DemoKeyRole, DemoKey>>> {
    // Gate on the LAST role file generateDemoKeys writes ("verifier-trust"),
    // so a crash mid-generation doesn't leave a half-populated dir that would
    // EEXIST forever; a partial dir is a hard error the operator must clear.
    if (!existsSync(join(this.keyDir, "verifier-trust.private.json"))) {
      if (existsSync(join(this.keyDir, "agent.private.json"))) {
        throw new Error(`partially generated key dir ${this.keyDir} — remove it and retry`);
      }
      return generateDemoKeys(this.keyDir, join(this.aarDir, `public-keys-${this.agentId}.json`));
    }
    return loadDemoKeys(this.keyDir);
  }

  private stateFile = () => join(this.aarDir, "producer-state.json");
  private priorFile = () => join(this.aarDir, "prior-state.json");

  private readJson<T>(path: string, fallback: T): T {
    return existsSync(path) ? (JSON.parse(readFileSync(path, "utf8")) as T) : fallback;
  }

  async emit(input: WireEmitInput): Promise<{ dir: string; bundlePath: string; evaluatedAt: number }> {
    if (!input.dispatch === !input.refusal) throw new Error("emit() requires exactly one of dispatch or refusal");
    const evaluatedAt = Math.floor(Date.now() / 1000);
    const state = this.readJson<ProducerState>(this.stateFile(), { next_epoch: 1 });
    const epochId = state.next_epoch;
    const prior = this.readJson<PriorState>(this.priorFile(), { prior_emissions: [], entries: [] });

    const invocationId = new Uint8Array(randomBytes(16));
    const command = buildCommandManifest({
      actionName: input.actionName,
      targetId: id16(`camera:${input.camera}`),
      targetLogicalName: (input.cameraPtz ? "ptz-primary" : "fixed-primary") as LogicalTargetName,
      parameters: input.parameters,
      invocationId,
    }, input.protocol as AdapterId, "onvif-mcp/0.1.0");

    const dir = join(this.aarDir, `${evaluatedAt}-${input.actionName.replaceAll(".", "-")}-${input.camera}-${toHex(invocationId).slice(0, 8)}`);
    mkdirSync(dir, { recursive: true });
    // Snapshot the prior state BEFORE this bundle so verification replays cleanly.
    writeFileSync(join(dir, "prior-state.json"), `${JSON.stringify(prior, null, 2)}\n`);

    const wire = await buildDemoBundle({
      scenarioId: "S1",
      evaluatedAt,
      epochId,
      invocationId,
      correlationId: new Uint8Array(randomBytes(16)),
      tenantId: id16("tenant:matthew-lab"),
      siteId: id16("site:home-lan"),
      targetId: id16(`camera:${input.camera}`),
      targetLogicalName: (input.cameraPtz ? "ptz-primary" : "fixed-primary") as LogicalTargetName,
      actionName: input.actionName,
      parameters: input.parameters,
      sourceDeviceMetadata: input.deviceMetadata,
      adapterId: input.protocol as AdapterId,
      command,
      // Self-issued delegation: this process is authority and EP (same-operator
      // demo trust). notBefore covers startedAt so a slow call (>60s of camera
      // stalls) can't sign a dispatch that predates its own delegation window.
      delegationWindows: [{ notBefore: Math.min(input.startedAt, evaluatedAt - 60) - 1, notAfter: evaluatedAt + 3600 }],
      dispatch: input.dispatch ? {
        status: input.dispatch.status,
        responseBodyDigest: hash(input.dispatch.responseBody),
        outcomeLevel: input.dispatch.outcomeLevel,
        outcomeState: input.dispatch.outcomeState,
        observationDigest: hash(input.dispatch.observation),
      } : undefined,
      refusalReason: input.refusal,
      // Real narrative: this process's clock, actual agent identity, and the
      // digest of the policy.json evaluation this server actually performed.
      narrative: {
        committedAt: evaluatedAt,
        observedAt: input.startedAt,
        dispatchedAt: input.startedAt,
        outcomeObservedAt: evaluatedAt,
        epochOpenedAt: Math.min(input.startedAt, evaluatedAt) - 1,
        epochClosedAt: evaluatedAt,
        monotonicNs: Number(process.hrtime.bigint()),
        bootId,
        transportId: "mcp:onvif-mcp/0.1.0",
        model: { provider: "mcp-client", model: input.agentId, version: "onvif-mcp/0.1.0" },
        decision: input.refusal ? "deny" : "permit",
        policySetRoot: this.policyRoot,
      },
      keys: await this.keys(),
      anchorLog: new LocalRfc6962Log(join(this.aarDir, "anchor.jsonl")),
      anchorObservedAt: evaluatedAt,
    });

    const bundlePath = join(dir, "bundle.cbor");
    writeFileSync(bundlePath, wire.bundle);
    writeFileSync(join(dir, "trust-policy.json"), `${JSON.stringify(wire.trustPolicy, null, 2)}\n`);
    writeFileSync(join(dir, "meta.json"), `${JSON.stringify({ evaluated_at: evaluatedAt, tool_action: input.actionName, camera: input.camera, agent: this.agentId, agent_keys: `public-keys-${this.agentId}.json` }, null, 2)}\n`);
    this.advance(prior, wire, epochId);
    writeFileSync(this.stateFile(), `${JSON.stringify({ next_epoch: epochId + 1 }, null, 2)}\n`);
    return { dir, bundlePath, evaluatedAt };
  }

  private advance(prior: PriorState, wire: WireBuildResult, epochId: number): void {
    for (const receipt of wire.receipts) {
      const binding = (receipt.fields as Record<string, unknown>).binding as Record<string, unknown>;
      prior.prior_emissions.push({
        issuer_kid: toHex(receipt.issuerKid),
        issuer_seq: receipt.issuerSeq,
        epoch_owner_kid: toHex(binding.epoch_owner_kid as Uint8Array),
        epoch_id: epochId,
        epoch_seq: receipt.epochSeq,
        receipt_id: toHex(receipt.id),
        envelope_digest: toHex(hash(receipt.signed.envelopeBytes)),
      });
    }
    writeFileSync(this.priorFile(), `${JSON.stringify(prior, null, 2)}\n`);
  }
}

// Offline verification of an emitted bundle directory via pyref (from the
// pinned aar-kat-harness dependency): exit 0 = conformant.
export function verifyBundleDir(root: string, dir: string): { conformant: boolean; output: string } {
  const meta = JSON.parse(readFileSync(join(dir, "meta.json"), "utf8")) as { evaluated_at: number };
  const proc = Bun.spawnSync([
    "python3", "-m", "pyref", "verify", join(dir, "bundle.cbor"),
    "--at", String(meta.evaluated_at),
    "--trust-policy", join(dir, "trust-policy.json"),
    "--prior-state", join(dir, "prior-state.json"),
  ], { cwd: join(root, "node_modules", "aar-kat-harness") });
  const output = proc.stdout.toString() + proc.stderr.toString();
  return { conformant: proc.exitCode === 0 && output.includes("Result: conformant"), output };
}

export const jsonBytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
export { encodeCbor, hash, toHex };
