// onvif-mcp — governed MCP server over AXIS VAPIX. Spike / kill test 2026-08-04.
// Every tool call — allowed or denied — emits a hash-chained, ed25519-signed receipt.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { gatewayConfigFromEnv, serveGateway } from "./gateway-listen";
import { createVaultClient, curlVaultCall, VaultWithheld, type Signer } from "./vault-client";
import { z } from "zod";
import { cameraId, presetName, paramName } from "./schemas";
import { generateKeyPairSync, sign as edSign, createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync, statSync, openSync, appendFileSync, fsyncSync, closeSync } from "node:fs";
import { join } from "node:path";
import { AarWireProducer, verifyBundleDir, type WireEmitInput } from "./receipts-aar/producer";
import { checkAarJournal } from "./receipts-aar/journal";
import { sendPreset, sendSnapshot } from "./receipts-aar/actions";
import { handoffHeads, hardDenied, registerCommission, verifyHandoffs } from "./commission";
import { snapshotContent } from "./snapshot-content";
import { parseParams } from "./vapix-params";
import { parseEventMessage } from "./event-parse";
import { openEventWebSocket } from "./event-websocket";
import { deviceText } from "./device-text";
import { clockCheck, clockReceipt, formatClock } from "./clock";
import { formatDeviceInfo, parseDeviceMeta, parseSnapshotUri, snapshotPath } from "./device-info";
import { formatPresetRecall } from "./ptz-output";
import { formatDriftLines, type ConfigDiff } from "./config-drift";
import { appendLocked, emptyChainConflict, formatReceiptsText, lastReceiptFrom, missingHandoffHeads, outcomeEvidence, selectReceipts, verifyChain } from "./receipt-chain";
import { curlRequest } from "./curl-args";
import { claimInvocationForAar, currentCommandDigest, currentInvocationId, runAsDispatch, setInvocationRecorder, withInvocations } from "./invocation";
import { cameraPinProblem } from "./camera-pins";
import { accountFor, type CameraAccounts } from "./account-for";
import { keyModeProblem } from "./key-perms";
import { missingPasswords } from "./creds-check";
import { makeLimiter } from "./rate-limit";
import { allowed as policyAllowed, baselineDenied, configDenied as policyConfigDenied, ptzBound, type Policy } from "./policy-check";

const ROOT = import.meta.dir;
const KEYDIR = join(ROOT, ".keys");
const LOG = join(ROOT, "receipts", "chain.jsonl");

// --verify: read-only verification, before credentials or signing-key setup.
if (process.argv.includes("--verify")) {
  const publicKey = readFileSync(join(KEYDIR, "receipt.pub"), "utf8");
  const text = existsSync(LOG) ? readFileSync(LOG, "utf8").trim() : "";
  const lines = text ? text.split("\n") : [];
  const chain = verifyChain(lines, publicKey);
  for (const { seq, reason } of chain.bad) console.log(`BROKEN at seq ${seq}: ${reason}`);
  const chainHashes = new Set<string>();
  for (const line of lines) {
    try {
      const hash = JSON.parse(line)?.hash;
      if (typeof hash === "string") chainHashes.add(hash);
    } catch { /* Invalid JSON is already reported by verifyChain. */ }
  }
  const handoffs = verifyHandoffs(ROOT, publicKey);
  const missing = missingHandoffHeads(chainHashes, handoffs.heads);
  if (missing.length) console.log(`handoff head missing — chain truncated? ${missing.join(", ")}`);
  const bad = chain.bad.length + handoffs.bad.length + missing.length;
  console.log(bad === 0 ? `chain OK — ${chain.count} receipts, every hash linked + signature valid; ${handoffs.count} handoff signatures valid, heads present` : `${bad} broken receipts or handoffs${handoffs.bad.length ? ` (${handoffs.bad.join(", ")})` : ""}`);
  process.exit(bad === 0 ? 0 : 1);
}

// --verify-aar [dir]: offline pyref verification of emitted AAR wire bundles
if (process.argv.includes("--verify-aar")) {
  const { readdirSync } = await import("node:fs");
  const { resolve } = await import("node:path");
  const arg = process.argv[process.argv.indexOf("--verify-aar") + 1];
  const base = join(ROOT, "receipts", "aar");
  const dirs = arg ? [resolve(arg)] : existsSync(base)
    ? readdirSync(base).filter((d) => existsSync(join(base, d, "bundle.cbor"))).map((d) => join(base, d))
    : [];
  if (dirs.length === 0) { console.log("no AAR bundles found"); process.exit(1); }
  let bad = 0;
  for (const dir of dirs) {
    try {
      const { conformant, output } = verifyBundleDir(ROOT, dir);
      console.log(`${conformant ? "CONFORMANT" : "NONCONFORMANT"}  ${dir}`);
      if (!conformant) { bad++; console.log(output); }
    } catch (error) {
      bad++;
      console.log(`NONCONFORMANT  ${dir}\nverification error: ${String(error)}`);
    }
  }
  console.log(bad === 0 ? `${dirs.length} bundle(s) conformant (pyref offline verify)` : `${bad}/${dirs.length} bundles FAILED`);
  process.exit(bad === 0 ? 0 : 1);
}

// Recovery is read-only and precedes credentials, key setup and MCP connect.
try { checkAarJournal(join(ROOT, "receipts", "aar", "journal.jsonl")); }
catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}

const AGENT = process.env.AGENT_ID ?? "unknown";
const cameras: Record<string, CameraAccounts & { base: string; pin?: string; auth?: "digest" | "any"; ptz: boolean; protocol: "vapix" | "onvif"; profile?: string }> =
  JSON.parse(readFileSync(join(ROOT, "cameras.json"), "utf8"));
const pinProblem = cameraPinProblem(cameras);
if (pinProblem !== null) {
  console.error(pinProblem);
  process.exit(1);
}
// Gateway mode (P1): GATEWAY_LISTEN=<port> serves Streamable HTTP behind a
// bearer token bound to AGENT_ID. Camera calls then go through the witness's
// unix socket (it owns TLS and the pins; the URL names the camera by id) and
// credentials plus receipt signing come from the vault's unix socket.
const gateway = gatewayConfigFromEnv(process.env);
const WITNESS = gateway === null ? undefined : process.env.GATEWAY_WITNESS_SOCKET;
const VAULT = gateway === null ? undefined : process.env.GATEWAY_VAULT_SOCKET;
if (gateway !== null && (!WITNESS || !VAULT)) {
  console.error("gateway mode needs GATEWAY_WITNESS_SOCKET and GATEWAY_VAULT_SOCKET");
  process.exit(1);
}
if (WITNESS !== undefined) {
  for (const [id, cam] of Object.entries(cameras)) { cam.base = `http://${id}`; delete cam.pin; }
}
// Stdio must never inherit a stray witness socket: the helpers read it inline.
if (gateway === null) delete process.env.GATEWAY_WITNESS_SOCKET;
const vault = VAULT === undefined ? null : createVaultClient(curlVaultCall(VAULT));
// Gateway mode: the actor's ownership claim is durable before the tool runs (C4).
// If the record cannot be written the tool body never runs and no receipt is
// written either: that call left no trace by design, and the gateway's drift
// check stops the listener when the receipts volume is unwritable.
const INVOCATIONS = join(ROOT, "receipts", "invocations.jsonl");
if (gateway !== null) {
  // The journal and its directory entry are durable before the first call:
  // a first-record fsync alone does not persist a freshly created file name.
  mkdirSync(join(ROOT, "receipts"), { recursive: true });
  closeSync(openSync(INVOCATIONS, "a", 0o640));
  const dir = openSync(join(ROOT, "receipts"), "r");
  try { fsyncSync(dir); } finally { closeSync(dir); }
  setInvocationRecorder((entry) => {
    const fd = openSync(INVOCATIONS, "a", 0o640);
    try { appendFileSync(fd, `${JSON.stringify({ ...entry, agent: AGENT })}\n`); fsyncSync(fd); } finally { closeSync(fd); }
  });
}
// Raw bytes kept: the AAR producer signs the digest of the EXACT policy the
// server evaluates (parsed once here) — never a fresh disk read (TOCTOU).
const policyBytes = readFileSync(join(ROOT, "policy.json"));
const policy: Policy =
  JSON.parse(policyBytes.toString("utf8")).agents;
const limiter = makeLimiter(Date.now);
function rateDenied(key: "actuation" | "snapshot"): string | null {
  const perMinute = policy[AGENT]?.rate?.[key === "actuation" ? "actuationPerMin" : "snapshotPerMin"];
  return perMinute === undefined ? null : limiter.check(key, perMinute);
}

// --- credentials: fetched at startup, never persisted. Stdio: the cred store.
// Gateway: the vault, per tier; a withheld tier (admin until P4) is recorded by
// reason and every tool that needs it gets a receipted deny instead.
const credentials = Object.entries(cameras).flatMap(([id, cam]) =>
  [{ id, credKey: cam.credKey, tier: "admin" as const },
   ...(["viewer", "operator"] as const).flatMap((tier) => cam.accounts?.[tier] ? [{ id, credKey: cam.accounts[tier]!.credKey, tier }] : [])]);
const passwords: Record<string, string> = Object.create(null);
const withheld: Record<string, string> = Object.create(null);
if (vault === null) {
  for (const credKey of new Set(credentials.map((account) => account.credKey))) {
    const p = Bun.spawnSync([`${process.env.HOME}/.claude/bin/cred`, "get", credKey]);
    passwords[credKey] = p.stdout.toString().trim();
  }
} else {
  for (const { id, credKey, tier } of credentials) {
    if (passwords[credKey] !== undefined || withheld[credKey] !== undefined) continue;
    try { passwords[credKey] = vault.credential(id, tier); }
    catch (error) {
      if (!(error instanceof VaultWithheld)) { console.error(error instanceof Error ? error.message : String(error)); process.exit(1); }
      withheld[credKey] = error.message;
    }
  }
}
function tierDenied(tool: string, camera: string): string | null {
  const cam = cameras[camera];
  if (!cam) return null;
  const reason = withheld[accountFor(tool, cam).credKey];
  return reason === undefined ? null : `credential tier for '${tool}' withheld by the vault: ${reason}`;
}
const missing = missingPasswords(passwords);
if (missing.length > 0) {
  console.error(`Missing camera passwords: ${credentials.filter(({ credKey }) => missing.includes(credKey)).map(({ id, credKey }) => `${id} (credKey: ${credKey})`).join(", ")}`);
  process.exit(1);
}

// --- receipts: hash chain + ed25519 signature. Stdio: a local key. Gateway:
// the vault signs, and only receipts the witness log does not contradict.
mkdirSync(KEYDIR, { recursive: true });
mkdirSync(join(ROOT, "receipts"), { recursive: true });
let signer: Signer;
let PRIV = "";
if (vault === null) {
  if (!existsSync(join(KEYDIR, "receipt.key"))) {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    writeFileSync(join(KEYDIR, "receipt.key"), privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
    writeFileSync(join(KEYDIR, "receipt.pub"), publicKey.export({ type: "spki", format: "pem" }));
  }
  PRIV = readFileSync(join(KEYDIR, "receipt.key"), "utf8");
  const keyProblem = keyModeProblem(statSync(join(KEYDIR, "receipt.key")).mode);
  if (keyProblem !== null) {
    console.error(keyProblem);
    process.exit(1);
  }
  const localKey = PRIV;
  signer = {
    publicKeyPem: readFileSync(join(KEYDIR, "receipt.pub"), "utf8"),
    sign: (_kind, body) => edSign(null, Buffer.from(createHash("sha256").update(JSON.stringify(body)).digest("hex")), localKey).toString("base64"),
  };
} else {
  signer = vault.signer();
  // --verify reads the public key from here; the vault's is public. A ROOT that
  // already holds a chain under another key must not be silently re-keyed.
  const pubFile = join(KEYDIR, "receipt.pub");
  if (existsSync(pubFile) && readFileSync(pubFile, "utf8") !== signer.publicKeyPem) {
    console.error(`${pubFile} differs from the vault's public key; this ROOT holds a chain signed by another key. Use a fresh ROOT for gateway mode.`);
    process.exit(1);
  }
  writeFileSync(pubFile, signer.publicKeyPem);
}
const PUB = signer.publicKeyPem;

function lastReceipt(): { seq: number; hash: string } {
  return lastReceiptFrom(existsSync(LOG) ? readFileSync(LOG, "utf8") : "");
}

// Receipt semantics follow AAR v0.2 vocabulary (node kinds, principal roles,
// outcome-evidence levels). Wire conformance (deterministic CBOR + detached
// COSE_Sign1 ES256) is NOT claimed — this JSONL+ed25519 chain is a draft
// transport; the conformant producer is scoped in docs/aar-alignment.md.
const NODE_KIND: Record<string, string> = { ptz_move: "action_attempt", ptz_preset: "action_attempt", get_snapshot: "observation", clock_check: "observation", list_cameras: "observation", get_receipts: "observation", config_baseline: "observation", config_drift: "observation", config_remediate: "action_attempt", commission_plan: "observation", commission_apply: "action_attempt", commission_verify: "observation" };
function receipt(tool: string, params: unknown, decision: "allow" | "deny", detail: string, resultHash?: string, evidence?: string) {
  appendLocked(LOG, (prev) => {
    const body = {
      seq: prev.seq + 1, ts: new Date().toISOString(),
      invocation_id: currentInvocationId() ?? null,
      profile: "aar-0.2-draft-alignment",
      principal: { role: "agent", type: "service", id: AGENT },
      enforcement_point: "onvif-mcp/0.1.0",
      node_kind: decision === "deny" ? "authorization" : NODE_KIND[tool] ?? "action_attempt",
      action: { tool, params },
      decision, detail,
      outcome_evidence: outcomeEvidence(tool, decision, detail, resultHash, evidence),
      result_sha256: resultHash ?? null, prev: prev.hash,
    };
    const hash = createHash("sha256").update(JSON.stringify(body)).digest("hex");
    const sig = signer.sign("receipt", body);
    return JSON.stringify({ ...body, hash, sig });
  });
}

function allowed(tool: string, camera?: string): string | null {
  return policyAllowed(policy, AGENT, tool, camera) ?? (camera === undefined ? null : tierDenied(tool, camera));
}

function camOf(id: string) {
  const cam = cameras[id];
  if (!cam) throw new Error(`unknown camera '${id}'`);
  return cam;
}

// Digest auth via curl — it does the digest dance; native fetch can't.
// GATEWAY_WITNESS_SOCKET (set only by the gateway unit) routes every call
// through the witness's unix socket; read inline so the sliced test harnesses
// see no new free name.
async function vapix(tool: string, camera: string, path: string, outFile?: string): Promise<{ ok: boolean; body: string }> {
  const cam = camOf(camera);
  const account = accountFor(tool, cam);
  if (passwords[account.credKey] === undefined) return { ok: false, body: "credential tier withheld by the vault" };
  const { args, stdin } = curlRequest({ ...cam, user: account.user }, passwords[account.credKey]!, path, { outFile, invocationId: currentInvocationId(), commandDigest: currentCommandDigest(), unixSocket: process.env.GATEWAY_WITNESS_SOCKET });
  const p = Bun.spawnSync(args, { stdin: Buffer.from(stdin) });
  return { ok: p.exitCode === 0, body: p.stdout.toString() };
}

async function vapixPost(tool: string, camera: string, path: string, body: unknown): Promise<{ ok: boolean; body: string }> {
  const cam = camOf(camera);
  const account = accountFor(tool, cam);
  if (passwords[account.credKey] === undefined) return { ok: false, body: "credential tier withheld by the vault" };
  const { args, stdin } = curlRequest({ ...cam, user: account.user }, passwords[account.credKey]!, path, { jsonBody: body, maxTime: 15, invocationId: currentInvocationId(), unixSocket: process.env.GATEWAY_WITNESS_SOCKET });
  const p = Bun.spawnSync(args, { stdin: Buffer.from(stdin) });
  return { ok: p.exitCode === 0, body: p.stdout.toString() };
}

async function observeEvents(tool: string, camera: string, topics: string[], seconds: number): Promise<{ events: Array<{ topic: string; timestamp?: string | number; message?: { data?: Record<string, unknown> } }>; warnings: string[] }> {
  const cam = camOf(camera);
  const events: Array<{ topic: string; timestamp?: string | number; message?: { data?: Record<string, unknown> } }> = [];
  const warnings: string[] = [];
  if (process.env.GATEWAY_WITNESS_SOCKET !== undefined) return { events, warnings: ["event observation unavailable in gateway mode: the witness carries HTTP only (P1)"] };
  return await new Promise((resolve) => {
    let opened = false, done = false;
    let windowTimer: ReturnType<typeof setTimeout> | undefined;
    const finish = (warning?: string) => {
      if (done) return;
      done = true;
      clearTimeout(openTimer);
      if (windowTimer) clearTimeout(windowTimer);
      if (warning) warnings.push(warning);
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) ws.close();
      resolve({ events, warnings });
    };
    const ws = openEventWebSocket(cam, () => {
      const account = accountFor(tool, cam);
      return { user: account.user, password: passwords[account.credKey]! };
    });
    const openTimer = setTimeout(() => finish("event WebSocket connection timed out"), 10_000);
    ws.addEventListener("open", () => {
      opened = true;
      clearTimeout(openTimer);
      ws.send(JSON.stringify({ apiVersion: "1.0", method: "events:configure", params: { eventFilterList: topics.map((topicFilter) => ({ topicFilter })) } }));
      windowTimer = setTimeout(() => finish(), seconds * 1000);
    });
    ws.addEventListener("message", ({ data }) => {
      const { event, warning } = parseEventMessage(data);
      if (warning) warnings.push(warning);
      if (event) events.push(event);
    });
    ws.addEventListener("error", () => finish("event WebSocket failed"));
    ws.addEventListener("close", () => { if (!done) finish(opened ? "event WebSocket closed before the observation window finished" : "event WebSocket connection rejected"); });
  });
}

type Baseline = { camera: string; captured: string; groups: string[]; params: Record<string, string>; sha256: string };
const BASELINES = join(ROOT, "baselines");
const sha256 = (value: unknown) => createHash("sha256").update(typeof value === "string" ? value : JSON.stringify(value)).digest("hex");
const inGroup = (param: string, groups: string[]) => groups.some((g) => param === g || param.startsWith(`${g}.`));
const baselineFile = (camera: string) => join(BASELINES, `${camera}.json`);

function readBaseline(file: string): Pick<Baseline, "groups" | "params"> | null {
  try {
    if (!statSync(file).isFile()) return null;
    const baseline = JSON.parse(readFileSync(file, "utf8"));
    if (!baseline || typeof baseline !== "object" || Array.isArray(baseline)
      || !Array.isArray(baseline.groups) || !baseline.groups.every((g: unknown) => typeof g === "string")
      || !baseline.params || typeof baseline.params !== "object" || Array.isArray(baseline.params)
      || !Object.values(baseline.params).every((value) => typeof value === "string")) return null;
    return baseline;
  } catch {
    return null;
  }
}

function configDenied(tool: string, camera: string, approve = false): string | null {
  return policyConfigDenied(policy, AGENT, tool, camera, approve);
}

async function configParams(tool: string, camera: string, groups: string[]): Promise<{ ok: boolean; params: Record<string, string> }> {
  if (!groups.length) return { ok: true, params: {} };
  const r = await vapix(tool, camera, `/axis-cgi/param.cgi?action=list&group=${groups.map(encodeURIComponent).join(",")}`);
  return { ok: r.ok && !/^(# )?Error/m.test(r.body), params: parseParams(r.body) };
}

// ONVIF SOAP call. AXIS serves every ONVIF service at /onvif/services (per GetServices).
async function soap(tool: string, camera: string, body: string): Promise<{ ok: boolean; body: string }> {
  const cam = camOf(camera);
  const account = accountFor(tool, cam);
  if (passwords[account.credKey] === undefined) return { ok: false, body: "credential tier withheld by the vault" };
  const { args, stdin } = curlRequest({ ...cam, user: account.user }, passwords[account.credKey]!, "/onvif/services", {
    invocationId: currentInvocationId(), unixSocket: process.env.GATEWAY_WITNESS_SOCKET,
    soapBody: `<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>${body}</s:Body></s:Envelope>`,
  });
  const p = Bun.spawnSync(args, { stdin: Buffer.from(stdin) });
  const out = p.stdout.toString();
  return { ok: p.exitCode === 0 && !out.includes("s:Fault") && !out.includes("SOAP-ENV:Fault"), body: out };
}

// Transport dispatch: same tool contract (degrees, jpeg) over either protocol.
async function deviceInfo(tool: string, camera: string): Promise<string> {
  if (camOf(camera).protocol === "onvif") {
    const r = await soap(tool, camera, '<tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>');
    return formatDeviceInfo("onvif", r);
  }
  const r = await vapix(tool, camera, "/axis-cgi/param.cgi?action=list&group=Brand.ProdShortName,Properties.PTZ.PTZ");
  return formatDeviceInfo("vapix", r);
}

async function snapshot(tool: string, camera: string, outFile: string): Promise<boolean> {
  if (camOf(camera).protocol === "onvif") {
    const cam = camOf(camera);
    const r = await soap(tool, camera, `<trt:GetSnapshotUri xmlns:trt="http://www.onvif.org/ver10/media/wsdl"><trt:ProfileToken>${cam.profile ?? "profile_1_jpeg"}</trt:ProfileToken></trt:GetSnapshotUri>`);
    const uri = parseSnapshotUri(r);
    if (!uri) return false;
    const path = snapshotPath(uri);
    if (path === null) return false;
    return (await vapix(tool, camera, path, outFile)).ok;
  }
  return (await vapix(tool, camera, "/axis-cgi/jpg/image.cgi", outFile)).ok;
}

async function ptzMove(tool: string, camera: string, pan: number, tilt: number, zoom: number): Promise<boolean> {
  if (camOf(camera).protocol === "onvif") {
    // Generic translation space is -1..1 over the mechanical range; pan spans 360°.
    // Tilt/zoom use the same linear mapping — approximate, noted in README.
    const cam = camOf(camera);
    const r = await soap(tool, camera, `<tptz:RelativeMove xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema"><tptz:ProfileToken>${cam.profile ?? "profile_1_jpeg"}</tptz:ProfileToken><tptz:Translation><tt:PanTilt x="${pan / 360}" y="${tilt / 360}"/><tt:Zoom x="${zoom / 100}"/></tptz:Translation></tptz:RelativeMove>`);
    return r.ok && r.body.includes("RelativeMoveResponse");
  }
  const r = await vapix(tool, camera, `/axis-cgi/com/ptz.cgi?rpan=${pan}&rtilt=${tilt}&rzoom=${zoom * 100}`);
  return r.ok && !/^Error/m.test(r.body);
}

// AXIS firmware version + product number for AAR source-device metadata.
async function deviceMeta(tool: string, camera: string): Promise<{ manufacturer: string; model: string; firmware: string }> {
  if (camOf(camera).protocol === "onvif") {
    const r = await soap(tool, camera, '<tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>');
    return parseDeviceMeta("onvif", camera, r);
  }
  const r = await vapix(tool, camera, "/axis-cgi/param.cgi?action=list&group=Brand.ProdNbr,Properties.Firmware.Version");
  return parseDeviceMeta("vapix", camera, r);
}

// AAR wire emission for the two pinned-ontology actions — successes AND policy
// denials (decision "deny", attempt not_dispatched, real refusal reason).
// Failures surface in the tool response and the existing JSONL chain.
// Denials never contact the device (metadata not-queried).
const aarProducer = new AarWireProducer(ROOT, AGENT, policyBytes);
async function emitAar(tool: string, camera: string, actionName: "camera.stream.view" | "camera.ptz.preset",
  parameters: Record<string, string | number | boolean>, startedAt: number,
  outcome: { send: NonNullable<WireEmitInput["send"]> } | { refusal: string }): Promise<string> {
  try {
    const invocationId = Buffer.from(claimInvocationForAar(), "hex");
    const cam = cameras[camera];
    const deviceMetadata = "refusal" in outcome
      ? { manufacturer: "not-queried", model: cam ? camera : `unknown:${camera}`, firmware: "not-queried" }
      : await deviceMeta(tool, camera);
    const observedAt = Math.floor(Date.now() / 1000);
    const { dir } = await aarProducer.emit({
      agentId: AGENT, camera, cameraPtz: cam?.ptz ?? false, protocol: cam?.protocol ?? "vapix",
      invocationId, deviceMetadata, observedAt, actionName, parameters, startedAt, ...outcome,
    });
    return `\naar-bundle: ${dir}`;
  } catch (error) {
    // Durable record: wire-emission failures land on the JSONL chain too,
    // not just the ephemeral tool response.
    const detail = error instanceof Error ? error.message : String(error);
    receipt("aar_emit", { camera, action: actionName }, "allow", `wire emission FAILED: ${detail}`);
    return `\naar-emit FAILED: ${detail}`;
  }
}

const server = new McpServer({ name: "onvif-mcp", version: "0.1.0" });
withInvocations(server);
registerCommission(server, { root: ROOT, agent: AGENT, policy, policyBytes, cameras, privateKey: PRIV, signer, tierDenied, vapix, vapixPost, observeEvents, configParams, parseParams, inGroup, sha256, receipt, lastReceipt, snapshot, checkSnapshot: () => rateDenied("snapshot"), checkActuation: () => rateDenied("actuation"), clockCheck: (tool, camera) => clockCheck(tool, camera, { now: Date.now, vapixPost }) });

server.tool("list_cameras", "List cameras this agent may access, with live device info", {}, async () => {
  const deny = allowed("list_cameras");
  if (deny) { receipt("list_cameras", {}, "deny", deny); return { content: [{ type: "text", text: `DENIED: ${deny}` }] }; }
  const visible = policy[AGENT]!.cameras;
  const out: string[] = [];
  for (const id of visible) out.push(`${id}: ${await deviceInfo("list_cameras", id)}`);
  receipt("list_cameras", {}, "allow", `returned ${visible.length} cameras`);
  return { content: [{ type: "text", text: out.join("\n") }] };
});

server.tool("clock_check", "Read the camera clock offset against this host (host sync not checked) and device-reported NTP status",
  { camera: cameraId.describe("camera id from list_cameras") }, async ({ camera }) => {
  const deny = allowed("clock_check", camera);
  if (deny) { receipt("clock_check", { camera }, "deny", deny); return { content: [{ type: "text", text: `DENIED: ${deny}` }] }; }
  const result = await clockCheck("clock_check", camera, { now: Date.now, vapixPost });
  const text = formatClock(camera, result);
  const { detail, resultHash, evidence } = clockReceipt(camera, result);
  receipt("clock_check", { camera }, "allow", detail, resultHash, evidence);
  return { content: [{ type: "text", text }] };
});

server.tool("get_snapshot", "Capture a JPEG snapshot from a camera; returns the image plus saved file path and sha256",
  { camera: cameraId.describe("camera id from list_cameras") }, async ({ camera }) => {
  const startedAt = Math.floor(Date.now() / 1000);
  const deny = allowed("get_snapshot", camera) ?? rateDenied("snapshot");
  if (deny) {
    receipt("get_snapshot", { camera }, "deny", deny);
    const aar = await emitAar("get_snapshot", camera, "camera.stream.view", {}, startedAt, { refusal: deny });
    return { content: [{ type: "text", text: `DENIED: ${deny}${aar}` }] };
  }
  const file = join(ROOT, "receipts", `snap-${camera}-${Date.now()}.jpg`);
  const parameters = { file: file.split("/").pop()! };
  let jpeg: Buffer | undefined;
  let sent = false;
  const aar = await emitAar("get_snapshot", camera, "camera.stream.view", parameters, startedAt, { send: async (_t0, commandDigest) => {
    sent = true;
    return sendSnapshot(async () => {
      const ok = await runAsDispatch(commandDigest, () => snapshot("get_snapshot", camera, file));
      if (ok && existsSync(file)) jpeg = readFileSync(file);
      return jpeg;
    });
  } });
  if (!jpeg) {
    receipt("get_snapshot", { camera }, "allow", sent ? "capture FAILED" : "capture not dispatched");
    return { content: [{ type: "text", text: (sent ? "capture failed" : "capture not dispatched") + aar }] };
  }
  const h = createHash("sha256").update(jpeg).digest("hex");
  receipt("get_snapshot", { camera }, "allow", `saved ${file}`, h, "device_acknowledged");
  return { content: snapshotContent(jpeg, file, h, aar) };
});

server.tool("ptz_preset", "Send a PTZ camera to a named preset (VAPIX cameras only)",
  { camera: cameraId, preset: presetName.default("Home") }, async ({ camera, preset }) => {
  const startedAt = Math.floor(Date.now() / 1000);
  const deny = allowed("ptz_preset", camera);
  const cam = cameras[camera];
  const bound = !deny && (!cam?.ptz ? `camera '${camera}' is not PTZ` :
    !policy[AGENT]?.ptz ? "agent has no ptz grant" :
    cam.protocol !== "vapix" ? "preset recall implemented for vapix protocol only" : null);
  const reason = deny ?? bound ?? rateDenied("actuation");
  if (reason) {
    receipt("ptz_preset", { camera, preset }, "deny", reason);
    const aar = await emitAar("ptz_preset", camera, "camera.ptz.preset", { preset }, startedAt, { refusal: reason });
    return { content: [{ type: "text", text: `DENIED: ${reason}${aar}` }] };
  }
  let result: Awaited<ReturnType<typeof sendPreset>> | undefined;
  let sent = false;
  const parameters = { preset };
  const aar = await emitAar("ptz_preset", camera, "camera.ptz.preset", parameters, startedAt, { send: async (t0, commandDigest) => {
    sent = true;
    result = await sendPreset(t0,
      () => runAsDispatch(commandDigest, () => vapix("ptz_preset", camera, `/axis-cgi/com/ptz.cgi?gotoserverpresetname=${encodeURIComponent(preset)}`)),
      () => vapix("ptz_preset", camera, "/axis-cgi/com/ptz.cgi?query=position"));
    return result;
  } });
  if (!sent) {
    receipt("ptz_preset", { camera, preset }, "allow", "preset not dispatched");
    return { content: [{ type: "text", text: "preset not dispatched" + aar }] };
  }
  const ok = result?.ok ?? false;
  receipt("ptz_preset", { camera, preset }, "allow", ok ? "preset recalled (vapix)" : "transport error", undefined, ok ? "device_acknowledged" : "unknown");
  return { content: [{ type: "text", text: (ok ? formatPresetRecall(camera, preset, result!.pos) : "preset recall failed") + aar }] };
});

server.tool("ptz_move", "Relative PTZ move (degrees pan/tilt, zoom steps), bounded by policy",
  { camera: cameraId, pan: z.number().default(0), tilt: z.number().default(0), zoom: z.number().default(0) },
  async ({ camera, pan, tilt, zoom }) => {
  const deny = allowed("ptz_move", camera);
  const cam = cameras[camera];
  const bound = !deny && (!cam?.ptz ? `camera '${camera}' is not PTZ` :
    ptzBound(policy[AGENT]?.ptz, pan, tilt, zoom));
  const reason = deny ?? bound ?? rateDenied("actuation");
  if (reason) { receipt("ptz_move", { camera, pan, tilt, zoom }, "deny", reason); return { content: [{ type: "text", text: `DENIED: ${reason}` }] }; }
  const ok = await ptzMove("ptz_move", camera, pan, tilt, zoom);
  receipt("ptz_move", { camera, pan, tilt, zoom }, "allow", ok ? `moved via ${camOf(camera).protocol}` : "transport error");
  return { content: [{ type: "text", text: ok ? `moved ${camera} pan=${pan}° tilt=${tilt}° zoom=${zoom} (${camOf(camera).protocol})` : "move failed" }] };
});

server.tool("config_baseline", "Capture allowed VAPIX parameters as the camera config baseline",
  { camera: cameraId }, async ({ camera }) => {
  const params = { camera };
  const file = baselineFile(camera);
  const config = { agent: AGENT, rebaseline: policy[AGENT]?.config?.rebaseline };
  const deny = configDenied("config_baseline", camera) ?? baselineDenied(config, existsSync(file));
  if (deny) { receipt("config_baseline", params, "deny", deny); return { content: [{ type: "text", text: `DENIED: ${deny}` }] }; }
  const groups = policy[AGENT]!.config!.groups;
  const live = await configParams("config_baseline", camera, groups);
  if (!live.ok) { receipt("config_baseline", params, "allow", "fetch FAILED"); return { content: [{ type: "text", text: "baseline fetch failed" }] }; }
  const hash = sha256(live.params);
  const baseline: Baseline = { camera, captured: new Date().toISOString(), groups, params: live.params, sha256: hash };
  mkdirSync(BASELINES, { recursive: true });
  try {
    // Exclusive creation also protects against another caller baselining during the fetch.
    writeFileSync(file, JSON.stringify(baseline, null, 2) + "\n", { flag: config.rebaseline === true ? "w" : "wx" });
  } catch (error) {
    const deny = (error as NodeJS.ErrnoException).code === "EEXIST" ? baselineDenied(config, true) : null;
    if (!deny) throw error;
    receipt("config_baseline", params, "deny", deny);
    return { content: [{ type: "text", text: `DENIED: ${deny}` }] };
  }
  receipt("config_baseline", params, "allow", `baselined ${Object.keys(live.params).length} params`, hash, "device_acknowledged");
  return { content: [{ type: "text", text: `baselined ${camera}: ${Object.keys(live.params).length} params sha256:${hash}` }] };
});

server.tool("config_drift", "Compare live VAPIX parameters with the saved config baseline",
  { camera: cameraId }, async ({ camera }) => {
  const params = { camera };
  const deny = configDenied("config_drift", camera);
  if (deny) { receipt("config_drift", params, "deny", deny); return { content: [{ type: "text", text: `DENIED: ${deny}` }] }; }
  const file = baselineFile(camera);
  if (!existsSync(file)) { receipt("config_drift", params, "allow", "no baseline"); return { content: [{ type: "text", text: "no baseline — run config_baseline" }] }; }
  const baseline = readBaseline(file);
  if (!baseline) { receipt("config_drift", params, "allow", "baseline unreadable"); return { content: [{ type: "text", text: "baseline unreadable" }] }; }
  const groups = baseline.groups.filter((g) => policy[AGENT]!.config!.groups.includes(g));
  const base = Object.fromEntries(Object.entries(baseline.params).filter(([param]) => inGroup(param, groups)));
  const live = await configParams("config_drift", camera, groups);
  if (!live.ok) { receipt("config_drift", params, "allow", "fetch FAILED"); return { content: [{ type: "text", text: "drift fetch failed" }] }; }
  const diff: ConfigDiff = { changed: [], added: [], removed: [] };
  for (const param of [...new Set([...Object.keys(base), ...Object.keys(live.params)])].sort()) {
    if (!(param in base)) diff.added.push({ param, live: live.params[param]! });
    else if (!(param in live.params)) diff.removed.push({ param, baseline: base[param]! });
    else if (base[param] !== live.params[param]) diff.changed.push({ param, baseline: base[param]!, live: live.params[param]! });
  }
  const summary = `drift: ${diff.changed.length} changed, ${diff.added.length} added, ${diff.removed.length} removed`;
  const lines = [...formatDriftLines(diff), summary];
  receipt("config_drift", params, "allow", summary, sha256(diff), "device_acknowledged");
  return { content: [{ type: "text", text: lines.join("\n") }] };
});

server.tool("config_remediate", "Restore one drifted VAPIX parameter to its baseline value",
  { camera: cameraId, param: paramName, approve: z.boolean().optional() }, async ({ camera, param, approve }) => {
  const params = { camera, param, approve };
  const deny = configDenied("config_remediate", camera, approve) ?? tierDenied("config_remediate", camera) ?? (approve ? rateDenied("actuation") : null);
  if (deny) { receipt("config_remediate", params, "deny", deny); return { content: [{ type: "text", text: `DENIED: ${deny}` }] }; }
  const groups = policy[AGENT]!.config!.groups;
  const offGroup = !inGroup(param, groups) ? `param '${param}' is outside allowed config groups` : null;
  const hard = hardDenied(param, inGroup) ? `param '${param}' is hard-denied` : null;
  const reason = offGroup ?? hard;
  if (reason) { receipt("config_remediate", params, "deny", reason); return { content: [{ type: "text", text: `DENIED: ${reason}` }] }; }
  const file = baselineFile(camera);
  if (!existsSync(file)) { const reason = "no baseline"; receipt("config_remediate", params, "deny", reason); return { content: [{ type: "text", text: `DENIED: ${reason}` }] }; }
  const baseline = readBaseline(file);
  if (!baseline) { receipt("config_remediate", params, "deny", "baseline unreadable"); return { content: [{ type: "text", text: "baseline unreadable" }] }; }
  if (!(param in baseline.params)) { const reason = `param '${param}' not in baseline`; receipt("config_remediate", params, "deny", reason); return { content: [{ type: "text", text: `DENIED: ${reason}` }] }; }
  const live = await configParams("config_remediate", camera, [param]);
  if (!live.ok) { receipt("config_remediate", params, "allow", "read FAILED"); return { content: [{ type: "text", text: "live config read failed" }] }; }
  const before = live.params[param];
  const target = baseline.params[param]!;
  if (before === target) { receipt("config_remediate", params, "allow", "no-op"); return { content: [{ type: "text", text: `no drift on ${param}` }] }; }
  const change = `${param}: ${before ?? "(missing)"} → ${target}`;
  const displayChange = `${param}: ${deviceText(before ?? "(missing)")} → ${deviceText(target)}`;
  if (!approve) { receipt("config_remediate", params, "allow", `dry-run: would set ${change}`); return { content: [{ type: "text", text: `would set ${displayChange}` }] }; }
  const write = await vapix("config_remediate", camera, `/axis-cgi/param.cgi?action=update&${encodeURIComponent(param)}=${encodeURIComponent(target)}`);
  const after = await configParams("config_remediate", camera, [param]);
  if (after.ok && after.params[param] === target) {
    const hash = sha256(target);
    receipt("config_remediate", params, "allow", "remediated", hash, "device_acknowledged");
    return { content: [{ type: "text", text: `remediated ${displayChange}` }] };
  }
  const value = after.ok ? after.params[param] ?? "(missing)" : "(read failed)";
  const acknowledged = write.ok && !/^(# )?Error/m.test(write.body);
  const detail = acknowledged ? `write acked but postcondition FAILED (live=${value})` : `write FAILED (live=${value})`;
  receipt("config_remediate", params, "allow", detail, undefined, acknowledged ? "device_acknowledged" : "unknown");
  return { content: [{ type: "text", text: acknowledged ? `write acked but postcondition FAILED (live=${deviceText(value)})` : `write FAILED (live=${deviceText(value)})` }] };
});

server.tool("get_receipts", "Return the caller's last N signed receipts from the chain",
  { n: z.number().int().min(1).max(100).default(5) }, async ({ n }) => {
  const deny = allowed("get_receipts");
  if (deny) { receipt("get_receipts", { n }, "deny", deny); return { content: [{ type: "text", text: `DENIED: ${deny}` }] }; }
  const lines = existsSync(LOG) ? selectReceipts(readFileSync(LOG, "utf8").trim().split("\n"), AGENT, n) : [];
  receipt("get_receipts", { n }, "allow", `returned ${lines.length}`);
  return { content: [{ type: "text", text: formatReceiptsText(lines) }] };
});



try {
  const head = lastReceipt();
  const conflict = emptyChainConflict(head, handoffHeads(join(ROOT, "handoff")));
  if (conflict !== null) throw new Error(conflict);
} catch (error) {
  console.error(`${error instanceof Error ? error.message : String(error)} (${LOG})`);
  process.exit(1);
}
// Gateway mode (P1): GATEWAY_LISTEN=<port> serves Streamable HTTP behind a
// bearer token bound to AGENT_ID; otherwise stdio as before.
if (gateway !== null) serveGateway(server, gateway);
else await server.connect(new StdioServerTransport());
