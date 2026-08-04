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
const cameras: Record<string, { base: string; user: string; credKey: string; ptz: boolean }> =
  JSON.parse(readFileSync(join(ROOT, "cameras.json"), "utf8"));
const policy: Record<string, { tools: string[]; cameras: string[]; ptz?: { maxStep: number } }> =
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

function receipt(tool: string, params: unknown, decision: "allow" | "deny", detail: string, resultHash?: string) {
  const prev = lastReceipt();
  const body = { seq: prev.seq + 1, ts: new Date().toISOString(), agent: AGENT, tool, params, decision, detail, resultHash: resultHash ?? null, prev: prev.hash };
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

// VAPIX over digest auth — curl does the digest dance; native fetch can't.
async function vapix(camera: string, path: string, outFile?: string): Promise<{ ok: boolean; body: string }> {
  const cam = cameras[camera];
  const args = ["curl", "-sk", "--digest", "-u", `${cam.user}:${passwords[camera]}`, "--max-time", "10", `${cam.base}${path}`];
  if (outFile) args.push("-o", outFile);
  const p = Bun.spawnSync(args);
  return { ok: p.exitCode === 0, body: p.stdout.toString() };
}

const server = new McpServer({ name: "onvif-mcp", version: "0.0.1" });

server.tool("list_cameras", "List cameras this agent may access, with live device info", {}, async () => {
  const deny = allowed("list_cameras");
  if (deny) { receipt("list_cameras", {}, "deny", deny); return { content: [{ type: "text", text: `DENIED: ${deny}` }] }; }
  const visible = policy[AGENT].cameras;
  const out: string[] = [];
  for (const id of visible) {
    const r = await vapix(id, "/axis-cgi/param.cgi?action=list&group=Brand.ProdShortName,Properties.PTZ.PTZ");
    out.push(`${id}: ${r.body.trim().replace(/\n/g, " | ")}`);
  }
  receipt("list_cameras", {}, "allow", `returned ${visible.length} cameras`);
  return { content: [{ type: "text", text: out.join("\n") }] };
});

server.tool("get_snapshot", "Capture a JPEG snapshot from a camera; returns saved file path",
  { camera: z.string().describe("camera id from list_cameras") }, async ({ camera }) => {
  const deny = allowed("get_snapshot", camera);
  if (deny) { receipt("get_snapshot", { camera }, "deny", deny); return { content: [{ type: "text", text: `DENIED: ${deny}` }] }; }
  const file = join(ROOT, "receipts", `snap-${camera}-${Date.now()}.jpg`);
  const r = await vapix(camera, "/axis-cgi/jpg/image.cgi", file);
  if (!r.ok || !existsSync(file)) { receipt("get_snapshot", { camera }, "allow", "capture FAILED"); return { content: [{ type: "text", text: "capture failed" }] }; }
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
  const r = await vapix(camera, `/axis-cgi/com/ptz.cgi?rpan=${pan}&rtilt=${tilt}&rzoom=${zoom * 100}`);
  receipt("ptz_move", { camera, pan, tilt, zoom }, "allow", r.ok ? "moved" : "vapix error");
  return { content: [{ type: "text", text: r.ok ? `moved ${camera} pan=${pan}° tilt=${tilt}° zoom=${zoom}` : "move failed" }] };
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
