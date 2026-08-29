import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { sign as edSign, verify as edVerify } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, writeFileSync } from "node:fs";
import { basename, join, resolve, sep } from "node:path";

type Policy = { tools: string[]; cameras: string[]; config?: { groups: string[]; remediate?: boolean } };
type Camera = { ptz: boolean };
type Preset = { name: string; pan: number; tilt: number; zoom: number };
type Spec = { spec: "camspec/0.1"; name: string; applies_to?: { models: string[] }; params: Record<string, string>; presets: Preset[] };
type Diff = { param: string; current: string | null; desired: string };
type Failure = { param: string; desired: string; observed: string | null };
type Applied = { param: string; previous: string; desired: string } | { preset: string; pan: number; tilt: number; zoom: number };
type ReceiptHead = { seq: number; hash: string };
type Handoff = {
  artifact: "camspec-handoff/0.1";
  spec: { name: string; sha256: string };
  camera: { id: string; model: string; firmware: string; serial: string };
  agent: string;
  policy_sha256: string;
  run: { started: string; finished: string };
  plan: Diff[];
  applied: Applied[];
  verify: { passed: boolean; failed: Failure[] };
  rollback: { performed: boolean; verified: boolean } | null;
  receipts: { first_seq: number; last_seq: number; chain_head_hash: string };
};

export type CommissionDeps = {
  root: string;
  agent: string;
  policy: Record<string, Policy>;
  policyBytes: Uint8Array;
  cameras: Record<string, Camera>;
  privateKey: string;
  vapix: (camera: string, path: string) => Promise<{ ok: boolean; body: string }>;
  configParams: (camera: string, groups: string[]) => Promise<{ ok: boolean; params: Record<string, string> }>;
  parseParams: (body: string) => Record<string, string>;
  inGroup: (param: string, groups: string[]) => boolean;
  sha256: (value: unknown) => string;
  receipt: (tool: string, params: unknown, decision: "allow" | "deny", detail: string, resultHash?: string, evidence?: string) => void;
  lastReceipt: () => ReceiptHead;
};

const TOP_KEYS = ["spec", "name", "applies_to", "params", "presets"];
const HARD_DENY = ["Network", "System.BoxRebootAction", "RemoteService"];
export const hardDenied = (param: string, inGroup: (param: string, groups: string[]) => boolean) => HARD_DENY.some((group) => inGroup(param, [group])) || /Password|User|Root/.test(param);

export function readCommissionSpec(root: string, ref: string): { spec: Spec; sha256: string } {
  const dir = resolve(root, "specs");
  const file = resolve(dir, /\.ya?ml$/.test(ref) ? ref : `${ref}.yaml`);
  if (file !== dir && !file.startsWith(`${dir}${sep}`)) throw new Error(`spec '${ref}' is outside specs/`);
  if (!existsSync(file)) throw new Error(`spec '${ref}' not found`);
  const realDir = realpathSync(dir);
  const realFile = realpathSync(file);
  if (!realFile.startsWith(`${realDir}${sep}`)) throw new Error(`spec '${ref}' is outside specs/`);
  const bytes = readFileSync(realFile);
  const raw = Bun.YAML.parse(bytes.toString()) as unknown;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("spec must be a YAML object");
  const doc = raw as Record<string, unknown>;
  const unknown = Object.keys(doc).filter((key) => !TOP_KEYS.includes(key));
  if (unknown.length) throw new Error(`unknown top-level key(s): ${unknown.join(", ")}`);
  if (doc.spec !== "camspec/0.1") throw new Error("spec must be 'camspec/0.1'");
  if (typeof doc.name !== "string" || !doc.name) throw new Error("name must be a non-empty string");
  const params = doc.params ?? {};
  if (!params || typeof params !== "object" || Array.isArray(params) || Object.values(params).some((v) => typeof v !== "string")) throw new Error("params must map parameter names to string values");
  const applies = doc.applies_to;
  if (applies !== undefined && (!applies || typeof applies !== "object" || Array.isArray(applies) || Object.keys(applies).some((key) => key !== "models") || !Array.isArray((applies as { models?: unknown }).models) || (applies as { models: unknown[] }).models.some((v) => typeof v !== "string"))) throw new Error("applies_to must contain only a string models list");
  const presetMap = doc.presets ?? {};
  if (!presetMap || typeof presetMap !== "object" || Array.isArray(presetMap)) throw new Error("presets must map names to absolute positions");
  const presets = Object.entries(presetMap).map(([name, value]) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`preset '${name}' must be an object`);
    const p = value as Record<string, unknown>;
    if (Object.keys(p).some((key) => !["pan", "tilt", "zoom"].includes(key)) || ![p.pan, p.tilt, p.zoom].every((v) => typeof v === "number" && Number.isFinite(v))) throw new Error(`preset '${name}' requires finite pan, tilt, and zoom numbers`);
    return { name, pan: p.pan as number, tilt: p.tilt as number, zoom: p.zoom as number };
  });
  return { spec: { spec: "camspec/0.1", name: doc.name, ...(applies ? { applies_to: applies as { models: string[] } } : {}), params: params as Record<string, string>, presets }, sha256: new Bun.CryptoHasher("sha256").update(bytes).digest("hex") };
}

export function verifyHandoffs(root: string, publicKey: string): { count: number; bad: string[] } {
  const dir = join(root, "handoff");
  const files = existsSync(dir) ? readdirSync(dir).filter((file) => file.endsWith(".json")) : [];
  const bad: string[] = [];
  for (const file of files) {
    try {
      const { sig, ...body } = JSON.parse(readFileSync(join(dir, file), "utf8"));
      const hash = new Bun.CryptoHasher("sha256").update(JSON.stringify(body)).digest("hex");
      if (typeof sig !== "string" || !edVerify(null, Buffer.from(hash), publicKey, Buffer.from(sig, "base64"))) bad.push(file);
    } catch { bad.push(file); }
  }
  return { count: files.length, bad };
}

export function registerCommission(server: McpServer, d: CommissionDeps) {
  const denied = (tool: string, camera: string, approve = false): string | null => {
    const p = d.policy[d.agent];
    if (!p) return `agent '${d.agent}' not in policy (fail closed)`;
    if (!p.tools.includes(tool)) return `tool '${tool}' not granted to agent '${d.agent}'`;
    if (!p.cameras.includes(camera)) return `camera '${camera}' not allowlisted for agent '${d.agent}'`;
    if (!d.cameras[camera]) return `unknown camera '${camera}'`;
    if (!p.config?.groups) return `agent '${d.agent}' has no config grant`;
    if (tool === "commission_apply" && approve && !p.config.remediate) return `agent '${d.agent}' has no config remediation grant`;
    return null;
  };
  const validateParams = (spec: Spec): string | null => {
    const groups = d.policy[d.agent]!.config!.groups;
    for (const param of Object.keys(spec.params)) {
      if (!d.inGroup(param, groups)) return `param '${param}' is outside allowed config groups`;
      if (hardDenied(param, d.inGroup)) return `param '${param}' is hard-denied`;
    }
    return null;
  };
  const meta = async (camera: string) => {
    const r = await d.vapix(camera, "/axis-cgi/param.cgi?action=list&group=Brand.ProdShortName,Brand.ProdFullName,Brand.ProdNbr,Properties.Firmware.Version,Properties.System.SerialNumber");
    const p = d.parseParams(r.body);
    if (!r.ok) throw new Error("device metadata fetch failed");
    return { id: camera, model: p["Brand.ProdShortName"] ?? p["Brand.ProdFullName"] ?? (p["Brand.ProdNbr"] ? `AXIS ${p["Brand.ProdNbr"]}` : "unknown"), firmware: p["Properties.Firmware.Version"] ?? "unknown", serial: p["Properties.System.SerialNumber"] ?? "unknown" };
  };
  const prepare = async (camera: string, ref: string) => {
    const loaded = readCommissionSpec(d.root, ref);
    const reason = validateParams(loaded.spec);
    if (reason) throw new Error(`DENIED: ${reason}`);
    const cameraMeta = await meta(camera);
    if (loaded.spec.applies_to && !loaded.spec.applies_to.models.includes(cameraMeta.model)) throw new Error(`spec does not apply to model '${cameraMeta.model}'`);
    const groups = [...new Set(Object.keys(loaded.spec.params).map((param) => param.split(".")[0]!))];
    const live = await d.configParams(camera, groups);
    if (!live.ok) throw new Error("live config fetch failed");
    const plan = Object.entries(loaded.spec.params).filter(([param, desired]) => live.params[param] !== desired).map(([param, desired]) => ({ param, current: live.params[param] ?? null, desired }));
    return { ...loaded, cameraMeta, plan, presets: d.cameras[camera]!.ptz ? loaded.spec.presets : [] };
  };
  const check = async (camera: string, spec: Spec, force = false): Promise<{ passed: boolean; failed: Failure[] }> => {
    const groups = [...new Set(Object.keys(spec.params).map((param) => param.split(".")[0]!))];
    const live = await d.configParams(camera, groups);
    const failed: Failure[] = [];
    for (const [param, desired] of Object.entries(spec.params)) {
      const observed = live.ok ? live.params[param] ?? null : null;
      if (!live.ok || observed !== desired || (force && process.env.COMMISSION_FAIL_PARAM === param)) failed.push({ param, desired, observed });
    }
    return { passed: failed.length === 0, failed };
  };
  const writeHandoff = (handoff: Handoff) => {
    const hash = d.sha256(handoff);
    const signed = { ...handoff, sig: edSign(null, Buffer.from(hash), d.privateKey).toString("base64") };
    const bytes = JSON.stringify(signed, null, 2) + "\n";
    const dir = join(d.root, "handoff");
    mkdirSync(dir, { recursive: true });
    const file = join(dir, `${handoff.camera.id}-${handoff.run.finished}.json`);
    writeFileSync(file, bytes);
    return { file, hash: d.sha256(bytes) };
  };
  const finish = (tool: "commission_apply" | "commission_verify", params: unknown, started: string, firstSeq: number, prepared: Awaited<ReturnType<typeof prepare>>, applied: Applied[], verify: { passed: boolean; failed: Failure[] }, rollback: Handoff["rollback"]) => {
    d.receipt(tool, params, "allow", verify.passed ? "verification passed" : "verification FAILED", d.sha256(verify));
    const head = d.lastReceipt();
    const finished = new Date().toISOString();
    const handoff: Handoff = {
      artifact: "camspec-handoff/0.1", spec: { name: prepared.spec.name, sha256: prepared.sha256 }, camera: prepared.cameraMeta,
      agent: d.agent, policy_sha256: d.sha256(Buffer.from(d.policyBytes).toString()), run: { started, finished }, plan: prepared.plan, applied, verify, rollback,
      receipts: { first_seq: firstSeq, last_seq: head.seq, chain_head_hash: head.hash },
    };
    const artifact = writeHandoff(handoff);
    d.receipt(tool, params, "allow", `handoff ${basename(artifact.file)}`, artifact.hash);
    return artifact.file;
  };
  const error = (tool: string, params: unknown, value: unknown) => {
    const message = value instanceof Error ? value.message : String(value);
    const deny = message.startsWith("DENIED: ");
    d.receipt(tool, params, deny ? "deny" : "allow", deny ? message.slice(8) : `FAILED: ${message}`);
    return { content: [{ type: "text" as const, text: message }], isError: !deny };
  };

  server.tool("commission_plan", "Plan a camspec against live VAPIX parameters without writes",
    { camera: z.string(), spec: z.string() }, async ({ camera, spec: ref }) => {
    const params = { camera, spec: ref };
    const reason = denied("commission_plan", camera);
    if (reason) { d.receipt("commission_plan", params, "deny", reason); return { content: [{ type: "text", text: `DENIED: ${reason}` }] }; }
    try {
      const p = await prepare(camera, ref);
      const out = { diff: p.plan, presets: p.presets };
      d.receipt("commission_plan", params, "allow", `planned ${p.plan.length} params and ${p.presets.length} presets`, d.sha256(out));
      return { content: [{ type: "text", text: JSON.stringify(out, null, 2) }] };
    } catch (e) { return error("commission_plan", params, e); }
  });

  server.tool("commission_apply", "Plan or explicitly apply a camspec, verify, and roll back parameters on failure",
    { camera: z.string(), spec: z.string(), approve: z.boolean() }, async ({ camera, spec: ref, approve }) => {
    const params = { camera, spec: ref, approve };
    const reason = denied("commission_apply", camera, approve);
    if (reason) { d.receipt("commission_apply", params, "deny", reason); return { content: [{ type: "text", text: `DENIED: ${reason}` }] }; }
    const started = new Date().toISOString();
    const firstSeq = d.lastReceipt().seq + 1;
    try {
      const p = await prepare(camera, ref);
      if (!approve) {
        const out = { diff: p.plan, presets: p.presets };
        d.receipt("commission_apply", params, "allow", `dry-run: planned ${p.plan.length} params and ${p.presets.length} presets`, d.sha256(out));
        return { content: [{ type: "text", text: JSON.stringify(out, null, 2) }] };
      }
      const applied: Applied[] = [];
      let writeFailed: Failure | null = null;
      for (const item of p.plan) {
        if (item.current === null) { writeFailed = { param: item.param, desired: item.desired, observed: null }; break; }
        const r = await d.vapix(camera, `/axis-cgi/param.cgi?action=update&${encodeURIComponent(item.param)}=${encodeURIComponent(item.desired)}`);
        const ok = r.ok && !/^Error/m.test(r.body);
        d.receipt("commission_apply", { ...params, param: item.param }, "allow", ok ? `wrote ${item.param}` : `write FAILED ${item.param}`, undefined, ok ? "device_acknowledged" : "unknown");
        if (!ok) { writeFailed = { param: item.param, desired: item.desired, observed: item.current }; break; }
        applied.push({ param: item.param, previous: item.current, desired: item.desired });
      }
      if (!writeFailed) for (const preset of p.presets) {
        const move = await d.vapix(camera, `/axis-cgi/com/ptz.cgi?pan=${preset.pan}&tilt=${preset.tilt}&zoom=${preset.zoom}`);
        const moved = move.ok && !/^Error/m.test(move.body);
        d.receipt("commission_apply", { ...params, preset: preset.name, operation: "move" }, "allow", moved ? `moved for preset ${preset.name}` : `move FAILED for preset ${preset.name}`, undefined, moved ? "device_acknowledged" : "unknown");
        if (!moved) { writeFailed = { param: `preset:${preset.name}`, desired: JSON.stringify(preset), observed: null }; break; }
        const set = await d.vapix(camera, `/axis-cgi/com/ptz.cgi?setserverpresetname=${encodeURIComponent(preset.name)}`);
        const saved = set.ok && !/^Error/m.test(set.body);
        d.receipt("commission_apply", { ...params, preset: preset.name, operation: "save" }, "allow", saved ? `saved preset ${preset.name}` : `save FAILED for preset ${preset.name}`, undefined, saved ? "device_acknowledged" : "unknown");
        if (!saved) { writeFailed = { param: `preset:${preset.name}`, desired: JSON.stringify(preset), observed: null }; break; }
        applied.push({ preset: preset.name, pan: preset.pan, tilt: preset.tilt, zoom: preset.zoom });
      }
      const verify = writeFailed ? { passed: false, failed: [writeFailed] } : await check(camera, p.spec, true);
      let rollback: Handoff["rollback"] = null;
      if (!verify.passed) {
        let rollbackWrites = true;
        for (const item of applied.filter((a): a is Extract<Applied, { param: string }> => "param" in a).reverse()) {
          const r = await d.vapix(camera, `/axis-cgi/param.cgi?action=update&${encodeURIComponent(item.param)}=${encodeURIComponent(item.previous)}`);
          const ok = r.ok && !/^Error/m.test(r.body);
          rollbackWrites &&= ok;
          d.receipt("commission_apply", { ...params, rollback: item.param }, "allow", ok ? `rolled back ${item.param}` : `rollback FAILED ${item.param}`, undefined, ok ? "device_acknowledged" : "unknown");
        }
        const rollbackSpec: Spec = { ...p.spec, params: Object.fromEntries(applied.filter((a): a is Extract<Applied, { param: string }> => "param" in a).map((item) => [item.param, item.previous])) };
        rollback = { performed: true, verified: rollbackWrites && (await check(camera, rollbackSpec)).passed };
      }
      const file = finish("commission_apply", params, started, firstSeq, p, applied, verify, rollback);
      const out = { ...verify, rolled_back: rollback?.performed ?? false, rollback_verified: rollback?.verified ?? null, handoff: file };
      return { content: [{ type: "text", text: JSON.stringify(out, null, 2) }] };
    } catch (e) { return error("commission_apply", params, e); }
  });

  server.tool("commission_verify", "Verify live conformance to a camspec and emit a signed handoff",
    { camera: z.string(), spec: z.string() }, async ({ camera, spec: ref }) => {
    const params = { camera, spec: ref };
    const reason = denied("commission_verify", camera);
    if (reason) { d.receipt("commission_verify", params, "deny", reason); return { content: [{ type: "text", text: `DENIED: ${reason}` }] }; }
    const started = new Date().toISOString();
    const firstSeq = d.lastReceipt().seq + 1;
    try {
      const p = await prepare(camera, ref);
      const verify = await check(camera, p.spec);
      const file = finish("commission_verify", params, started, firstSeq, p, [], verify, null);
      return { content: [{ type: "text", text: JSON.stringify({ ...verify, handoff: file }, null, 2) }] };
    } catch (e) { return error("commission_verify", params, e); }
  });
}
