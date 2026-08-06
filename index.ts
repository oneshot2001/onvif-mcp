// onvif-mcp — governed MCP server over AXIS VAPIX. Spike / kill test 2026-08-04.
// Every tool call — allowed or denied — emits a hash-chained, ed25519-signed receipt.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { generateKeyPairSync, sign as edSign, verify as edVerify, createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

const ROOT = import.meta.dir;
const AGENT = process.env.AGENT_ID ?? "unknown";
const cameras: Record<string, { base: string; user: string; credKey: string; ptz: boolean; protocol: "vapix" | "onvif"; profile?: string }> =
  JSON.parse(readFileSync(join(ROOT, "cameras.json"), "utf8"));
const policy: Record<string, { tools: string[]; cameras: string[]; ptz?: { maxStep: number }; config?: { groups: string[]; remediate?: boolean } }> =
  JSON.parse(readFileSync(join(ROOT, "policy.json"), "utf8")).agents;

// --- credentials: fetched from the cred store at startup, never persisted ---
const passwords: Record<string, string> = {};
for (const [id, cam] of Object.entries(cameras)) {
  const p = Bun.spawnSync([`${process.env.HOME}/.claude/bin/cred`, "get", cam.credKey]);
  passwords[id] = p.stdout.toString().trim();
}

// --- receipts: hash chain + ed25519 signature ---
const KEYDIR = join(ROOT, ".keys");
const LOG = join(ROOT, "receipts", "chain.jsonl");
mkdirSync(KEYDIR, { recursive: true });
mkdirSync(join(ROOT, "receipts"), { recursive: true });
if (!existsSync(join(KEYDIR, "receipt.key"))) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  writeFileSync(join(KEYDIR, "receipt.key"), privateKey.export({ type: "pkcs8", format: "pem" }));
  writeFileSync(join(KEYDIR, "receipt.pub"), publicKey.export({ type: "spki", format: "pem" }));
}
const PRIV = readFileSync(join(KEYDIR, "receipt.key"), "utf8");
const PUB = readFileSync(join(KEYDIR, "receipt.pub"), "utf8");

function lastReceipt(): { seq: number; hash: string } {
  if (!existsSync(LOG)) return { seq: 0, hash: "genesis" };
  const lines = readFileSync(LOG, "utf8").trim().split("\n");
  const last = JSON.parse(lines[lines.length - 1]);
  return { seq: last.seq, hash: last.hash };
}

// Receipt semantics follow AAR v0.2 vocabulary (node kinds, principal roles,
// outcome-evidence levels). Wire conformance (deterministic CBOR + detached
// COSE_Sign1 ES256) is NOT claimed — this JSONL+ed25519 chain is a draft
// transport; the conformant producer is scoped in docs/aar-alignment.md.
const NODE_KIND: Record<string, string> = { ptz_move: "action_attempt", get_snapshot: "observation", list_cameras: "observation", get_receipts: "observation", config_baseline: "observation", config_drift: "observation", config_remediate: "action_attempt" };
function receipt(tool: string, params: unknown, decision: "allow" | "deny", detail: string, resultHash?: string, evidence?: string) {
  const prev = lastReceipt();
  const body = {
    seq: prev.seq + 1, ts: new Date().toISOString(),
    profile: "aar-0.2-draft-alignment",
    principal: { role: "agent", type: "service", id: AGENT },
    enforcement_point: "onvif-mcp/0.1.0",
    node_kind: decision === "deny" ? "authorization" : NODE_KIND[tool] ?? "action_attempt",
    action: { tool, params },
    decision, detail,
    outcome_evidence: decision === "deny" ? null : evidence ?? (tool === "ptz_move" ? (detail.startsWith("moved") ? "device_acknowledged" : "unknown") : resultHash ? "independently_sensed" : null),
    result_sha256: resultHash ?? null, prev: prev.hash,
  };
  const hash = createHash("sha256").update(JSON.stringify(body)).digest("hex");
  const sig = edSign(null, Buffer.from(hash), PRIV).toString("base64");
  appendFileSync(LOG, JSON.stringify({ ...body, hash, sig }) + "\n");
}

function allowed(tool: string, camera?: string): string | null {
  const p = policy[AGENT];
  if (!p) return `agent '${AGENT}' not in policy (fail closed)`;
  if (!p.tools.includes(tool)) return `tool '${tool}' not allowlisted for agent '${AGENT}'`;
  if (camera && !p.cameras.includes(camera)) return `camera '${camera}' not allowlisted for agent '${AGENT}'`;
  return null;
}

// Digest auth via curl — it does the digest dance; native fetch can't.
async function vapix(camera: string, path: string, outFile?: string): Promise<{ ok: boolean; body: string }> {
  const cam = cameras[camera];
  const args = ["curl", "-sk", "--digest", "-u", `${cam.user}:${passwords[camera]}`, "--max-time", "10", `${cam.base}${path}`];
  if (outFile) args.push("-o", outFile);
  const p = Bun.spawnSync(args);
  return { ok: p.exitCode === 0, body: p.stdout.toString() };
}

type Baseline = { camera: string; captured: string; groups: string[]; params: Record<string, string>; sha256: string };
const BASELINES = join(ROOT, "baselines");
const HARD_DENY = ["Network", "System.BoxRebootAction", "RemoteService"];
const sha256 = (value: unknown) => createHash("sha256").update(typeof value === "string" ? value : JSON.stringify(value)).digest("hex");
const inGroup = (param: string, groups: string[]) => groups.some((g) => param === g || param.startsWith(`${g}.`));
const baselineFile = (camera: string) => join(BASELINES, `${camera}.json`);

function configDenied(tool: string, camera: string, approve = false): string | null {
  const deny = allowed(tool, camera);
  if (deny) return deny;
  const config = policy[AGENT]?.config;
  if (!config) return `agent '${AGENT}' has no config grant`;
  if (tool === "config_remediate" && approve && !config.remediate) return `agent '${AGENT}' has no config remediation grant`;
  return null;
}

function parseParams(body: string): Record<string, string> {
  const params: Record<string, string> = {};
  for (const line of body.split(/\r?\n/)) {
    // Firmware quirk (AXIS OS 12.x): group listings prefix lines with "root.",
    // exact-param queries don't. Accept both.
    const key = line.startsWith("root.") ? line.slice(5) : line;
    const i = key.indexOf("=");
    if (i > 0 && /^[A-Za-z]/.test(key)) params[key.slice(0, i)] = key.slice(i + 1);
  }
  return Object.fromEntries(Object.entries(params).sort(([a], [b]) => a.localeCompare(b)));
}

async function configParams(camera: string, groups: string[]): Promise<{ ok: boolean; params: Record<string, string> }> {
  if (!groups.length) return { ok: true, params: {} };
  const r = await vapix(camera, `/axis-cgi/param.cgi?action=list&group=${groups.map(encodeURIComponent).join(",")}`);
  return { ok: r.ok, params: parseParams(r.body) };
}

// ONVIF SOAP call. AXIS serves every ONVIF service at /onvif/services (per GetServices).
async function soap(camera: string, body: string): Promise<{ ok: boolean; body: string }> {
  const cam = cameras[camera];
  const p = Bun.spawnSync(["curl", "-sk", "--digest", "-u", `${cam.user}:${passwords[camera]}`,
    "-H", "Content-Type: application/soap+xml", "--data",
    `<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>${body}</s:Body></s:Envelope>`,
    "--max-time", "10", `${cam.base}/onvif/services`]);
  const out = p.stdout.toString();
  return { ok: p.exitCode === 0 && !out.includes("s:Fault") && !out.includes("SOAP-ENV:Fault"), body: out };
}

// Transport dispatch: same tool contract (degrees, jpeg) over either protocol.
async function deviceInfo(camera: string): Promise<string> {
  if (cameras[camera].protocol === "onvif") {
    const r = await soap(camera, '<tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>');
    const g = (tag: string) => r.body.match(new RegExp(`<tds:${tag}>([^<]+)`))?.[1] ?? "?";
    return `Model=${g("Manufacturer")} ${g("Model")} | Firmware=${g("FirmwareVersion")} | protocol=onvif`;
  }
  const r = await vapix(camera, "/axis-cgi/param.cgi?action=list&group=Brand.ProdShortName,Properties.PTZ.PTZ");
  return `${r.body.trim().replace(/\n/g, " | ")} | protocol=vapix`;
}

async function snapshot(camera: string, outFile: string): Promise<boolean> {
  if (cameras[camera].protocol === "onvif") {
    const cam = cameras[camera];
    const r = await soap(camera, `<trt:GetSnapshotUri xmlns:trt="http://www.onvif.org/ver10/media/wsdl"><trt:ProfileToken>${cam.profile ?? "profile_1_jpeg"}</trt:ProfileToken></trt:GetSnapshotUri>`);
    const uri = r.body.match(/<tt:Uri>([^<]+)/)?.[1]?.replace(/&amp;/g, "&");
    if (!uri) return false;
    const path = uri.replace(/^https?:\/\/[^/]+/, "");
    return (await vapix(camera, path, outFile)).ok;
  }
  return (await vapix(camera, "/axis-cgi/jpg/image.cgi", outFile)).ok;
}

async function ptzMove(camera: string, pan: number, tilt: number, zoom: number): Promise<boolean> {
  if (cameras[camera].protocol === "onvif") {
    // Generic translation space is -1..1 over the mechanical range; pan spans 360°.
    // Tilt/zoom use the same linear mapping — approximate, noted in README.
    const cam = cameras[camera];
    const r = await soap(camera, `<tptz:RelativeMove xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema"><tptz:ProfileToken>${cam.profile ?? "profile_1_jpeg"}</tptz:ProfileToken><tptz:Translation><tt:PanTilt x="${pan / 360}" y="${tilt / 360}"/><tt:Zoom x="${zoom / 100}"/></tptz:Translation></tptz:RelativeMove>`);
    return r.ok && r.body.includes("RelativeMoveResponse");
  }
  return (await vapix(camera, `/axis-cgi/com/ptz.cgi?rpan=${pan}&rtilt=${tilt}&rzoom=${zoom * 100}`)).ok;
}

const server = new McpServer({ name: "onvif-mcp", version: "0.1.0" });

server.tool("list_cameras", "List cameras this agent may access, with live device info", {}, async () => {
  const deny = allowed("list_cameras");
  if (deny) { receipt("list_cameras", {}, "deny", deny); return { content: [{ type: "text", text: `DENIED: ${deny}` }] }; }
  const visible = policy[AGENT].cameras;
  const out: string[] = [];
  for (const id of visible) out.push(`${id}: ${await deviceInfo(id)}`);
  receipt("list_cameras", {}, "allow", `returned ${visible.length} cameras`);
  return { content: [{ type: "text", text: out.join("\n") }] };
});

server.tool("get_snapshot", "Capture a JPEG snapshot from a camera; returns saved file path",
  { camera: z.string().describe("camera id from list_cameras") }, async ({ camera }) => {
  const deny = allowed("get_snapshot", camera);
  if (deny) { receipt("get_snapshot", { camera }, "deny", deny); return { content: [{ type: "text", text: `DENIED: ${deny}` }] }; }
  const file = join(ROOT, "receipts", `snap-${camera}-${Date.now()}.jpg`);
  const ok = await snapshot(camera, file);
  if (!ok || !existsSync(file)) { receipt("get_snapshot", { camera }, "allow", "capture FAILED"); return { content: [{ type: "text", text: "capture failed" }] }; }
  const h = createHash("sha256").update(readFileSync(file)).digest("hex");
  receipt("get_snapshot", { camera }, "allow", `saved ${file}`, h);
  return { content: [{ type: "text", text: `${file} sha256:${h.slice(0, 16)}…` }] };
});

server.tool("ptz_move", "Relative PTZ move (degrees pan/tilt, zoom steps), bounded by policy",
  { camera: z.string(), pan: z.number().default(0), tilt: z.number().default(0), zoom: z.number().default(0) },
  async ({ camera, pan, tilt, zoom }) => {
  const deny = allowed("ptz_move", camera);
  const cam = cameras[camera];
  const max = policy[AGENT]?.ptz?.maxStep ?? 0;
  const bound = !deny && (!cam?.ptz ? `camera '${camera}' is not PTZ` :
    !policy[AGENT]?.ptz ? "agent has no ptz grant" :
    Math.abs(pan) > max || Math.abs(tilt) > max ? `step exceeds policy maxStep ${max}°` : null);
  const reason = deny ?? bound;
  if (reason) { receipt("ptz_move", { camera, pan, tilt, zoom }, "deny", reason); return { content: [{ type: "text", text: `DENIED: ${reason}` }] }; }
  const ok = await ptzMove(camera, pan, tilt, zoom);
  receipt("ptz_move", { camera, pan, tilt, zoom }, "allow", ok ? `moved via ${cameras[camera].protocol}` : "transport error");
  return { content: [{ type: "text", text: ok ? `moved ${camera} pan=${pan}° tilt=${tilt}° zoom=${zoom} (${cameras[camera].protocol})` : "move failed" }] };
});

server.tool("config_baseline", "Capture allowed VAPIX parameters as the camera config baseline",
  { camera: z.string() }, async ({ camera }) => {
  const params = { camera };
  const deny = configDenied("config_baseline", camera);
  if (deny) { receipt("config_baseline", params, "deny", deny); return { content: [{ type: "text", text: `DENIED: ${deny}` }] }; }
  const groups = policy[AGENT]!.config!.groups;
  const live = await configParams(camera, groups);
  if (!live.ok) { receipt("config_baseline", params, "allow", "fetch FAILED"); return { content: [{ type: "text", text: "baseline fetch failed" }] }; }
  const hash = sha256(live.params);
  const baseline: Baseline = { camera, captured: new Date().toISOString(), groups, params: live.params, sha256: hash };
  mkdirSync(BASELINES, { recursive: true });
  writeFileSync(baselineFile(camera), JSON.stringify(baseline, null, 2) + "\n");
  receipt("config_baseline", params, "allow", `baselined ${Object.keys(live.params).length} params`, hash);
  return { content: [{ type: "text", text: `baselined ${camera}: ${Object.keys(live.params).length} params sha256:${hash}` }] };
});

server.tool("config_drift", "Compare live VAPIX parameters with the saved config baseline",
  { camera: z.string() }, async ({ camera }) => {
  const params = { camera };
  const deny = configDenied("config_drift", camera);
  if (deny) { receipt("config_drift", params, "deny", deny); return { content: [{ type: "text", text: `DENIED: ${deny}` }] }; }
  const file = baselineFile(camera);
  if (!existsSync(file)) { receipt("config_drift", params, "allow", "no baseline"); return { content: [{ type: "text", text: "no baseline — run config_baseline" }] }; }
  const baseline: Baseline = JSON.parse(readFileSync(file, "utf8"));
  const groups = baseline.groups.filter((g) => policy[AGENT]!.config!.groups.includes(g));
  const base = Object.fromEntries(Object.entries(baseline.params).filter(([param]) => inGroup(param, groups)));
  const live = await configParams(camera, groups);
  if (!live.ok) { receipt("config_drift", params, "allow", "fetch FAILED"); return { content: [{ type: "text", text: "drift fetch failed" }] }; }
  const diff: { changed: Array<{ param: string; baseline: string; live: string }>; added: Array<{ param: string; live: string }>; removed: Array<{ param: string; baseline: string }> } = { changed: [], added: [], removed: [] };
  for (const param of [...new Set([...Object.keys(base), ...Object.keys(live.params)])].sort()) {
    if (!(param in base)) diff.added.push({ param, live: live.params[param]! });
    else if (!(param in live.params)) diff.removed.push({ param, baseline: base[param]! });
    else if (base[param] !== live.params[param]) diff.changed.push({ param, baseline: base[param]!, live: live.params[param]! });
  }
  const summary = `drift: ${diff.changed.length} changed, ${diff.added.length} added, ${diff.removed.length} removed`;
  const lines = [
    ...diff.changed.map((d) => `changed ${d.param}: ${d.baseline} → ${d.live}`),
    ...diff.added.map((d) => `added ${d.param}: ${d.live}`),
    ...diff.removed.map((d) => `removed ${d.param}: ${d.baseline}`), summary,
  ];
  receipt("config_drift", params, "allow", summary, sha256(diff));
  return { content: [{ type: "text", text: lines.join("\n") }] };
});

server.tool("config_remediate", "Restore one drifted VAPIX parameter to its baseline value",
  { camera: z.string(), param: z.string(), approve: z.boolean().optional() }, async ({ camera, param, approve }) => {
  const params = { camera, param, approve };
  const deny = configDenied("config_remediate", camera, approve);
  if (deny) { receipt("config_remediate", params, "deny", deny); return { content: [{ type: "text", text: `DENIED: ${deny}` }] }; }
  const groups = policy[AGENT]!.config!.groups;
  const offGroup = !inGroup(param, groups) ? `param '${param}' is outside allowed config groups` : null;
  const hard = HARD_DENY.some((g) => inGroup(param, [g])) || /Password|User|Root/.test(param) ? `param '${param}' is hard-denied` : null;
  const reason = offGroup ?? hard;
  if (reason) { receipt("config_remediate", params, "deny", reason); return { content: [{ type: "text", text: `DENIED: ${reason}` }] }; }
  const file = baselineFile(camera);
  if (!existsSync(file)) { const reason = "no baseline"; receipt("config_remediate", params, "deny", reason); return { content: [{ type: "text", text: `DENIED: ${reason}` }] }; }
  const baseline: Baseline = JSON.parse(readFileSync(file, "utf8"));
  if (!(param in baseline.params)) { const reason = `param '${param}' not in baseline`; receipt("config_remediate", params, "deny", reason); return { content: [{ type: "text", text: `DENIED: ${reason}` }] }; }
  const live = await configParams(camera, [param]);
  if (!live.ok) { receipt("config_remediate", params, "allow", "read FAILED"); return { content: [{ type: "text", text: "live config read failed" }] }; }
  const before = live.params[param];
  const target = baseline.params[param]!;
  if (before === target) { receipt("config_remediate", params, "allow", "no-op"); return { content: [{ type: "text", text: `no drift on ${param}` }] }; }
  const change = `${param}: ${before ?? "(missing)"} → ${target}`;
  if (!approve) { receipt("config_remediate", params, "allow", `dry-run: would set ${change}`); return { content: [{ type: "text", text: `would set ${change}` }] }; }
  const write = await vapix(camera, `/axis-cgi/param.cgi?action=update&${encodeURIComponent(param)}=${encodeURIComponent(target)}`);
  const after = await configParams(camera, [param]);
  if (after.ok && after.params[param] === target) {
    const hash = sha256(target);
    receipt("config_remediate", params, "allow", "remediated", hash);
    return { content: [{ type: "text", text: `remediated ${change}` }] };
  }
  const value = after.ok ? after.params[param] ?? "(missing)" : "(read failed)";
  const detail = write.ok ? `write acked but postcondition FAILED (live=${value})` : `write FAILED (live=${value})`;
  receipt("config_remediate", params, "allow", detail, undefined, write.ok ? "device_acknowledged" : "unknown");
  return { content: [{ type: "text", text: detail }] };
});

server.tool("get_receipts", "Return the last N signed receipts from the chain",
  { n: z.number().default(5) }, async ({ n }) => {
  const deny = allowed("get_receipts");
  if (deny) { receipt("get_receipts", { n }, "deny", deny); return { content: [{ type: "text", text: `DENIED: ${deny}` }] }; }
  const lines = existsSync(LOG) ? readFileSync(LOG, "utf8").trim().split("\n").slice(-n) : [];
  receipt("get_receipts", { n }, "allow", `returned ${lines.length}`);
  return { content: [{ type: "text", text: lines.join("\n") || "(empty chain)" }] };
});

// --verify: recompute the hash chain + check every signature, then exit
if (process.argv.includes("--verify")) {
  const lines = readFileSync(LOG, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  let prev = "genesis", bad = 0;
  for (const r of lines) {
    const { hash, sig, ...body } = r;
    const expect = createHash("sha256").update(JSON.stringify(body)).digest("hex");
    const okHash = expect === hash && body.prev === prev;
    const okSig = edVerify(null, Buffer.from(hash), PUB, Buffer.from(sig, "base64"));
    if (!okHash || !okSig) { bad++; console.log(`BROKEN at seq ${r.seq}: hash=${okHash} sig=${okSig}`); }
    prev = hash;
  }
  console.log(bad === 0 ? `chain OK — ${lines.length} receipts, every hash linked + signature valid` : `${bad} broken receipts`);
  process.exit(bad === 0 ? 0 : 1);
}

await server.connect(new StdioServerTransport());
