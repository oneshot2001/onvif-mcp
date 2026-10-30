// AAR v0.2.3 wire-conformant receipt producer for onvif-mcp.
// Reuses the AAR reference demo EP wire machinery (aar-kat-harness, Apache-2.0,
// pinned by commit in bun.lock) so the bundle bytes come from the same code the
// spec's gates verified against pyref. This module only maps onvif-mcp calls
// onto that machinery.
//
// Scope (honest boundary — see docs/aar-alignment.md):
// - Only actions expressible in the v0.2 pinned ontology get wire bundles:
//   get_snapshot → camera.stream.view, ptz_preset → camera.ptz.preset.
//   ptz_move (relative) and config_* stay on the draft JSONL chain.
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
// - SINGLE-WRITER ASSUMPTION: one server process per receipts directory,
//   covering producer-state.json, prior-state.json, anchor.jsonl and journal.jsonl.
//   emit() calls (including separate producer instances) serialize in-process.
import { randomBytes } from "node:crypto";
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { AdapterId, LogicalTargetName } from "aar-kat-harness/adapters/shared/types";
import { encodeCbor, fromHex, toHex } from "aar-kat-harness/harness/cbor";
import { hash } from "aar-kat-harness/harness/crypto";
import { LocalRfc6962Log } from "aar-kat-harness/demo/anchor/log";
import { buildCommandManifest } from "aar-kat-harness/demo/ep/command-manifest";
import { buildDemoBundle, REAL_CLOCK_BOUND_SECONDS, type WireBuildResult } from "aar-kat-harness/demo/ep/wire-builder";
import { generateDemoKeys, loadDemoKeys, type DemoKey, type DemoKeyRole } from "aar-kat-harness/demo/keys/keys";
import { appendJournal } from "./journal";

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

export interface WireSendResult {
  readonly dispatch: WireDispatch;
  readonly dispatchedAt: number;
  readonly outcomeObservedAt: number;
}

export interface WireEmitInput {
  // Trusted internal correlation ID, never an MCP argument.
  readonly invocationId?: Uint8Array;
  readonly agentId: string;
  readonly camera: string;
  readonly cameraPtz: boolean;
  readonly protocol: string;
  readonly deviceMetadata: { manufacturer: string; model: string; firmware: string };
  readonly actionName: WireAction;
  readonly parameters: Readonly<Record<string, string | number | boolean>>;
  readonly startedAt: number; // unix seconds when the tool call began
  readonly observedAt: number; // clock reading after device metadata was read
  // Exactly one of: a deferred send, or a policy refusal reason (denial —
  // wire-emitted as authorization decision "deny", attempt not_dispatched).
  readonly send?: (t0: number, commandDigest: string) => Promise<WireSendResult>;
  readonly refusal?: string;
}

const id16 = (label: string) => hash(new TextEncoder().encode(`onvif-mcp-id:${label}`)).slice(0, 16);

type CommandInput = Pick<WireEmitInput, "actionName" | "camera" | "cameraPtz" | "parameters" | "protocol">;

function commandManifest(input: CommandInput, invocationId: Uint8Array) {
  return buildCommandManifest({
    actionName: input.actionName,
    targetId: id16(`camera:${input.camera}`),
    targetLogicalName: (input.cameraPtz ? "ptz-primary" : "fixed-primary") as LogicalTargetName,
    parameters: input.parameters,
    invocationId,
  }, input.protocol as AdapterId, "onvif-mcp/0.1.0");
}

export function commandDigestHex(input: CommandInput): string {
  return toHex(commandManifest(input, new Uint8Array(16)).command_digest);
}

interface ProducerState { next_epoch: number }
interface PriorState {
  prior_emissions: Array<{ issuer_kid: string; issuer_seq: number; epoch_owner_kid: string; epoch_id: number; epoch_seq: number; receipt_id: string; envelope_digest: string }>;
  entries: Array<{ replay_domain: string; invocation_id: string; content_digest: string }>;
}

// The producer is a single writer even when MCP handlers overlap.
let emissionQueue: Promise<unknown> = Promise.resolve();
const seconds = () => Math.floor(Date.now() / 1000);

function sortPrior(prior: PriorState): void {
  const key = (e: PriorState["prior_emissions"][number]) => Buffer.from(encodeCbor([
    fromHex(e.issuer_kid), e.issuer_seq, fromHex(e.epoch_owner_kid),
    e.epoch_id, e.epoch_seq, fromHex(e.receipt_id), fromHex(e.envelope_digest),
  ]));
  prior.prior_emissions.sort((a, b) => Buffer.compare(key(a), key(b)));
  for (let i = 1; i < prior.prior_emissions.length; i++) {
    if (Buffer.compare(key(prior.prior_emissions[i - 1]!), key(prior.prior_emissions[i]!)) === 0) {
      throw Error("duplicate prior emission");
    }
  }
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

  emit(input: WireEmitInput): Promise<{ dir: string; bundlePath: string; evaluatedAt: number }> {
    const invocationId = input.invocationId;
    if (invocationId !== undefined && invocationId.length !== 16) {
      return Promise.reject(new Error("invocationId must be 16 bytes"));
    }
    const queued = { ...input, invocationId: invocationId === undefined ? undefined : Uint8Array.from(invocationId) };
    const result = emissionQueue.then(() => this.emitOne(queued));
    emissionQueue = result.catch(() => {});
    return result;
  }

  private reserveEpoch(): number {
    const state = this.readJson<ProducerState>(this.stateFile(), { next_epoch: 1 });
    const epochId = state.next_epoch;
    if (!Number.isSafeInteger(epochId) || epochId < 1 || !Number.isSafeInteger(epochId + 1)) throw Error("invalid next_epoch");
    const temporary = `${this.stateFile()}.tmp`;
    const fd = openSync(temporary, "w", 0o600);
    try {
      writeFileSync(fd, `${JSON.stringify({ next_epoch: epochId + 1 }, null, 2)}\n`);
      fsyncSync(fd);
    } finally { closeSync(fd); }
    renameSync(temporary, this.stateFile());
    // Persist rename and, on first use, the newly created ancestor directories.
    for (const path of [this.aarDir, join(this.root, "receipts"), this.root]) {
      const directory = openSync(path, "r");
      try { fsyncSync(directory); } finally { closeSync(directory); }
    }
    return epochId;
  }

  private async emitOne(input: WireEmitInput): Promise<{ dir: string; bundlePath: string; evaluatedAt: number }> {
    if ((input.send === undefined) === (input.refusal === undefined)) throw Error("emit() requires exactly one of send or refusal");
    const epochId = this.reserveEpoch();
    const epochOpenedAt = seconds();
    let previousTime = epochOpenedAt;
    const readTime = () => {
      const value = seconds();
      if (value < previousTime) throw Error("invalid real-clock timeline: clock went backwards");
      previousTime = value;
      return value;
    };
    // D-73 requires open < close. An early timer wake must wait the remainder.
    let evaluatedAt: number; // T0, never labeled as fsync completion.
    do {
      await Bun.sleep(1000 - Date.now() % 1000);
      evaluatedAt = readTime();
    } while (evaluatedAt === epochOpenedAt);
    if (input.observedAt > evaluatedAt || input.startedAt > evaluatedAt) throw Error("invalid real-clock timeline: clock went backwards before T0");
    const prior = this.readJson<PriorState>(this.priorFile(), { prior_emissions: [], entries: [] });
    sortPrior(prior);

    const invocationId = input.invocationId ?? new Uint8Array(randomBytes(16));
    const journal = join(this.aarDir, "journal.jsonl");
    let journalUnavailable = false;
    const refuseJournal = () => {
      if (readTime() > evaluatedAt) throw Error("invalid real-clock timeline: journal refusal decided after T0");
      journalUnavailable = true;
      return { refusalReason: "journal/unavailable" as const };
    };
    const command = commandManifest(input, invocationId);

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
      // Validity bounds, not event times. Ancestors remain fixed at T0.
      delegationWindows: [{ notBefore: evaluatedAt - 60, notAfter: evaluatedAt + 3600 }],
      beforeDispatch: async (attempt) => {
        const entry = {
          invocation_id: toHex(invocationId), receipt_id: toHex(attempt.id),
          envelope_digest: toHex(hash(attempt.signed.envelopeBytes)),
          envelope_cbor: toHex(attempt.signed.envelopeBytes),
        };
        try {
          appendJournal(journal, { event: "attempt_envelope", ...entry });
        } catch {
          return refuseJournal();
        }
        const envelopeSyncedAt = readTime();
        try {
          appendJournal(journal, { event: "attempt_committed", ...entry, envelope_synced_at: envelopeSyncedAt });
        } catch {
          return refuseJournal();
        }
        const beforeSend = readTime();
        if (beforeSend < evaluatedAt || beforeSend - evaluatedAt > REAL_CLOCK_BOUND_SECONDS) {
          throw Error("invalid real-clock timeline before send");
        }
        let sent: WireSendResult;
        try { sent = await input.send!(evaluatedAt, toHex(command.command_digest)); }
        catch {
          try { appendJournal(journal, { event: "dispatch_ambiguous", invocation_id: entry.invocation_id, observed_at: seconds() }); }
          catch { /* Keep the durable eligible attempt; recovery will warn. */ }
          throw Error("dispatch outcome ambiguous");
        }
        appendJournal(journal, { event: "dispatch_completed", invocation_id: entry.invocation_id, observed_at: readTime() });
        const committedAt = readTime(); // T1, after send/readback and completion append.
        return {
          dispatch: {
            status: sent.dispatch.status, responseBodyDigest: hash(sent.dispatch.responseBody),
            outcomeLevel: sent.dispatch.outcomeLevel, outcomeState: sent.dispatch.outcomeState,
            observationDigest: hash(sent.dispatch.observation),
          },
          timing: { dispatchedAt: sent.dispatchedAt, outcomeObservedAt: sent.outcomeObservedAt,
            committedAt, monotonicNs: Number(process.hrtime.bigint()), anchorObservedAt: readTime() },
        };
      },
      refusalReason: input.refusal,
      // Real narrative: this process's clock, actual agent identity, and the
      // digest of the policy.json evaluation this server actually performed.
      narrative: {
        realClock: true,
        committedAt: evaluatedAt,
        observedAt: input.observedAt,
        epochOpenedAt,
        epochClosedAt: evaluatedAt,
        monotonicNs: Number(process.hrtime.bigint()),
        bootId,
        transportId: "mcp:onvif-mcp/0.1.0",
        model: { provider: "mcp-client", model: input.agentId, version: "onvif-mcp/0.1.0" },
        decision: input.refusal !== undefined ? "deny" : "permit",
        policySetRoot: this.policyRoot,
      },
      keys: await this.keys(),
      anchorLog: new LocalRfc6962Log(join(this.aarDir, "anchor.jsonl")),
      anchorObservedAt: evaluatedAt,
    });

    const cameraLabel = input.camera.replace(/[^A-Za-z0-9_-]/g, "_");
    const dir = join(this.aarDir, `${evaluatedAt}-${input.actionName.replaceAll(".", "-")}-${cameraLabel}-${toHex(invocationId).slice(0, 8)}`);
    mkdirSync(dir, { recursive: true });
    // First-ever snapshot is empty; subsequent snapshots preserve all history.
    writeFileSync(join(dir, "prior-state.json"), `${JSON.stringify(prior, null, 2)}\n`);
    const bundlePath = join(dir, "bundle.cbor");
    writeFileSync(bundlePath, wire.bundle);
    writeFileSync(join(dir, "trust-policy.json"), `${JSON.stringify(wire.trustPolicy, null, 2)}\n`);
    writeFileSync(join(dir, "meta.json"), `${JSON.stringify({ evaluated_at: wire.evaluatedAt, tool_action: input.actionName, camera: input.camera, agent: this.agentId, agent_keys: `public-keys-${this.agentId}.json` }, null, 2)}\n`);
    this.advance(prior, wire, epochId);
    if (journalUnavailable) {
      try { appendJournal(journal, { event: "refusal_persisted", invocation_id: toHex(invocationId), observed_at: seconds() }); }
      catch { /* Refusal bundle is saved; recovery may still warn about the attempt. */ }
    }
    return { dir, bundlePath, evaluatedAt: wire.evaluatedAt };
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
    sortPrior(prior);
    const temporary = `${this.priorFile()}.tmp`;
    const fd = openSync(temporary, "w", 0o600);
    try {
      writeFileSync(fd, `${JSON.stringify(prior, null, 2)}\n`);
      fsyncSync(fd);
    } finally { closeSync(fd); }
    renameSync(temporary, this.priorFile());
    const directory = openSync(this.aarDir, "r");
    try { fsyncSync(directory); } finally { closeSync(directory); }
  }
}

// Offline verification of an emitted bundle directory via pyref (from the
// pinned aar-kat-harness dependency): exit 0 = conformant.
export function verifyBundleDir(root: string, dir: string): { conformant: boolean; output: string } {
  const meta = JSON.parse(readFileSync(join(dir, "meta.json"), "utf8")) as { evaluated_at: number };
  const proc = Bun.spawnSync([
    "python3", "-B", "-m", "pyref", "verify", join(dir, "bundle.cbor"),
    "--at", String(meta.evaluated_at),
    "--trust-policy", join(dir, "trust-policy.json"),
    "--prior-state", join(dir, "prior-state.json"),
  ], { cwd: join(root, "node_modules", "aar-kat-harness") });
  const output = proc.stdout.toString() + proc.stderr.toString();
  return { conformant: proc.exitCode === 0 && output.includes("Result: conformant"), output };
}

export const jsonBytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
export { encodeCbor, hash, toHex };
