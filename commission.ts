import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { sign as edSign, verify as edVerify } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, writeFileSync } from "node:fs";
import { basename, join, resolve, sep } from "node:path";

type Policy = { tools: string[]; cameras: string[]; config?: { groups: string[]; remediate?: boolean; aoa?: boolean } };
type Camera = { ptz: boolean };
type Preset = { name: string; pan: number; tilt: number; zoom: number };
type Point = [number, number];
type Scenario = { name: string; type: "motion"; objects: string[]; area: Point[] } | { name: string; type: "crosslinecounting"; objects: string[]; line: Point[] };
type Spec = { spec: "camspec/0.1"; name: string; applies_to?: { models: string[] }; params: Record<string, string>; presets: Preset[]; scenarios: Scenario[]; observe: { seconds: number } };
type Diff = { param: string; current: string | null; desired: string };
type Failure = { param: string; desired: string; observed: string | null };
type Applied = { param: string; previous: string; desired: string } | { preset: string; pan: number; tilt: number; zoom: number } | { scenario: string; id: number; type: Scenario["type"] };
type AoaScenario = Record<string, unknown> & { id: number; name: string; type: string };
type AoaConfiguration = Record<string, unknown> & { devices?: Array<{ id?: unknown }>; scenarios: AoaScenario[] };
type ScenarioPlan = { name: string; id: number; type: Scenario["type"]; action: "deploy" };
type ScenarioResult = { name: string; id: number | null; type: Scenario["type"]; deployed: boolean; readback_diff: string[] };
type EventNotification = { topic: string; timestamp?: string | number; message?: { data?: Record<string, unknown> } };
type Observation = { window_seconds: number; started: string; finished: string; fired: Record<string, { count: number; first: string | null; last: string | null }>; warnings: string[] };
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
  scenarios: ScenarioResult[];
  observation: Observation | null;
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
  vapixPost: (camera: string, path: string, body: unknown) => Promise<{ ok: boolean; body: string }>;
  observeEvents: (camera: string, topics: string[], seconds: number) => Promise<{ events: EventNotification[]; warnings: string[] }>;
  configParams: (camera: string, groups: string[]) => Promise<{ ok: boolean; params: Record<string, string> }>;
  parseParams: (body: string) => Record<string, string>;
  inGroup: (param: string, groups: string[]) => boolean;
  sha256: (value: unknown) => string;
  receipt: (tool: string, params: unknown, decision: "allow" | "deny", detail: string, resultHash?: string, evidence?: string) => void;
  lastReceipt: () => ReceiptHead;
};

const TOP_KEYS = ["spec", "name", "applies_to", "params", "presets", "scenarios", "observe"];
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
  const scenarioList = doc.scenarios ?? [];
  if (!Array.isArray(scenarioList)) throw new Error("scenarios must be a list");
  const names = new Set<string>();
  const points = (value: unknown, label: string, minimum: number): Point[] => {
    if (!Array.isArray(value) || value.length < minimum || value.some((point) => !Array.isArray(point) || point.length !== 2 || point.some((n) => typeof n !== "number" || !Number.isFinite(n) || n < -1 || n > 1))) throw new Error(`${label} must contain at least ${minimum} normalized [x,y] points`);
    return value as Point[];
  };
  const scenarios = scenarioList.map((value, i): Scenario => {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`scenario ${i + 1} must be an object`);
    const s = value as Record<string, unknown>;
    if (typeof s.name !== "string" || !s.name) throw new Error(`scenario ${i + 1} name must be a non-empty string`);
    if (names.has(s.name)) throw new Error(`duplicate scenario name '${s.name}'`);
    names.add(s.name);
    if (s.type !== "motion" && s.type !== "crosslinecounting") throw new Error(`scenario '${s.name}' has unsupported type '${String(s.type)}'`);
    const allowed = s.type === "motion" ? ["name", "type", "objects", "area"] : ["name", "type", "objects", "line"];
    const extra = Object.keys(s).filter((key) => !allowed.includes(key));
    if (extra.length) throw new Error(`scenario '${s.name}' has unknown key(s): ${extra.join(", ")}`);
    if (!Array.isArray(s.objects) || !s.objects.length || s.objects.some((object) => typeof object !== "string" || !object)) throw new Error(`scenario '${s.name}' objects must be a non-empty string list`);
    return s.type === "motion"
      ? { name: s.name, type: s.type, objects: s.objects as string[], area: points(s.area, `scenario '${s.name}' area`, 3) }
      : { name: s.name, type: s.type, objects: s.objects as string[], line: points(s.line, `scenario '${s.name}' line`, 2) };
  });
  const observeValue = doc.observe;
  if (observeValue !== undefined && (!observeValue || typeof observeValue !== "object" || Array.isArray(observeValue) || Object.keys(observeValue).some((key) => key !== "seconds") || typeof (observeValue as { seconds?: unknown }).seconds !== "number" || !Number.isFinite((observeValue as { seconds: number }).seconds) || (observeValue as { seconds: number }).seconds < 0)) throw new Error("observe must contain only a non-negative seconds number");
  const observe = { seconds: observeValue ? (observeValue as { seconds: number }).seconds : scenarios.length ? 60 : 0 };
  return { spec: { spec: "camspec/0.1", name: doc.name, ...(applies ? { applies_to: applies as { models: string[] } } : {}), params: params as Record<string, string>, presets, scenarios, observe }, sha256: new Bun.CryptoHasher("sha256").update(bytes).digest("hex") };
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
  type PreparedAoa = { installed: boolean; warning?: string; config: AoaConfiguration | null; merged: AoaConfiguration | null; desired: AoaScenario[]; plan: ScenarioPlan[] };
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
    if (spec.scenarios.length && !d.policy[d.agent]!.config!.aoa) return `agent '${d.agent}' has no AOA config grant`;
    return null;
  };
  const parseRpc = (body: string, method: string): Record<string, unknown> => {
    let value: unknown;
    try { value = JSON.parse(body); } catch { throw new Error(`AOA ${method} returned invalid JSON`); }
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`AOA ${method} returned an invalid response`);
    const rpc = value as Record<string, unknown>;
    if (rpc.error) {
      const message = typeof rpc.error === "object" && rpc.error && typeof (rpc.error as { message?: unknown }).message === "string" ? (rpc.error as { message: string }).message : "unknown error";
      throw new Error(`AOA ${method} failed: ${message}`);
    }
    return rpc;
  };
  const readAoaConfiguration = async (camera: string): Promise<AoaConfiguration> => {
    const r = await d.vapixPost(camera, "/local/objectanalytics/control.cgi", { apiVersion: "1.0", method: "getConfiguration" });
    if (!r.ok) throw new Error("AOA getConfiguration transport failed");
    const data = parseRpc(r.body, "getConfiguration").data;
    if (!data || typeof data !== "object" || Array.isArray(data) || !Array.isArray((data as { scenarios?: unknown }).scenarios)) throw new Error("AOA getConfiguration returned an invalid configuration");
    return data as AoaConfiguration;
  };
  const viewDesired = (scenario: Scenario) => ({
    name: scenario.name, type: scenario.type, objects: [...scenario.objects].sort(),
    geometry: scenario.type === "motion" ? scenario.area : scenario.line,
  });
  const viewLive = (scenario: AoaScenario) => {
    const classes = Array.isArray(scenario.objectClassifications) ? scenario.objectClassifications : [];
    const objects = classes.map((value) => value && typeof value === "object" && typeof (value as { type?: unknown }).type === "string" ? (value as { type: string }).type : null).filter((value): value is string => value !== null).sort();
    const triggers = Array.isArray(scenario.triggers) ? scenario.triggers : [];
    const triggerType = scenario.type === "motion" ? "includeArea" : "countingLine";
    const trigger = triggers.find((value) => value && typeof value === "object" && (value as { type?: unknown }).type === triggerType) as { vertices?: unknown } | undefined;
    return { name: scenario.name, type: scenario.type, objects, geometry: trigger?.vertices ?? null };
  };
  const scenarioDiff = (desired: Scenario, observed: AoaScenario | undefined): string[] => {
    if (!observed) return ["scenario missing"];
    const want = viewDesired(desired);
    const got = viewLive(observed);
    return (Object.keys(want) as Array<keyof typeof want>).filter((key) => JSON.stringify(want[key]) !== JSON.stringify(got[key])).map((key) => `${key}: desired ${JSON.stringify(want[key])}, observed ${JSON.stringify(got[key])}`);
  };
  const buildAoa = (config: AoaConfiguration, scenarios: Scenario[]): Pick<PreparedAoa, "merged" | "desired" | "plan"> => {
    const existing = new Map(config.scenarios.map((scenario) => [scenario.name, scenario]));
    const used = config.scenarios.map((scenario) => scenario.id).filter(Number.isFinite);
    let nextId = Math.max(0, ...used) + 1;
    const firstDevice = config.devices?.find((device) => typeof device.id === "number")?.id;
    const desired = scenarios.map((spec) => {
      const current = existing.get(spec.name);
      const id = current?.id ?? nextId++;
      const devices = Array.isArray(current?.devices) && current.devices.length ? current.devices : typeof firstDevice === "number" ? [{ id: firstDevice }] : null;
      if (!devices) throw new Error("AOA configuration has no device for a new scenario");
      const trigger = spec.type === "motion"
        ? { type: "includeArea", vertices: spec.area }
        : { type: "countingLine", countingDirection: "leftToRight", vertices: spec.line };
      const base = current?.type === spec.type ? current : {};
      return { filters: [], ...base, id, name: spec.name, type: spec.type, devices, triggers: [trigger], objectClassifications: spec.objects.map((type) => ({ type })) } as AoaScenario; // AOA rejects a motion scenario without a filters array (error 2003)
    });
    const managed = new Map(desired.map((scenario) => [scenario.name, scenario]));
    const mergedScenarios = config.scenarios.map((scenario) => managed.get(scenario.name) ?? scenario);
    for (const scenario of desired) if (!existing.has(scenario.name)) mergedScenarios.push(scenario);
    const plan = scenarios.flatMap((scenario, i) => scenarioDiff(scenario, existing.get(scenario.name)).length ? [{ name: scenario.name, id: desired[i]!.id, type: scenario.type, action: "deploy" as const }] : []);
    return { desired, plan, merged: { ...config, scenarios: mergedScenarios } };
  };
  const loadAoa = async (camera: string, scenarios: Scenario[]): Promise<PreparedAoa> => {
    if (!scenarios.length) return { installed: false, config: null, merged: null, desired: [], plan: [] };
    const versions = await d.vapixPost(camera, "/local/objectanalytics/control.cgi", { method: "getSupportedVersions" });
    if (!versions.ok) return { installed: false, warning: "AOA application unavailable; scenarios skipped", config: null, merged: null, desired: [], plan: [] };
    let rpc: Record<string, unknown>;
    try { rpc = parseRpc(versions.body, "getSupportedVersions"); } catch {
      return { installed: false, warning: "AOA application unavailable; scenarios skipped", config: null, merged: null, desired: [], plan: [] };
    }
    const apiVersions = rpc.data && typeof rpc.data === "object" && Array.isArray((rpc.data as { apiVersions?: unknown }).apiVersions) ? (rpc.data as { apiVersions: unknown[] }).apiVersions.map(String) : [];
    if (!apiVersions.includes("1.0")) return { installed: false, warning: "AOA API 1.0 unavailable; scenarios skipped", config: null, merged: null, desired: [], plan: [] };
    const config = await readAoaConfiguration(camera);
    return { installed: true, warning: undefined, config, ...buildAoa(config, scenarios) };
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
    const aoa = await loadAoa(camera, loaded.spec.scenarios);
    return { ...loaded, cameraMeta, plan, presets: d.cameras[camera]!.ptz ? loaded.spec.presets : [], aoa };
  };
  const checkParams = async (camera: string, spec: Spec, force = false): Promise<Failure[]> => {
    const groups = [...new Set(Object.keys(spec.params).map((param) => param.split(".")[0]!))];
    const live = await d.configParams(camera, groups);
    const failed: Failure[] = [];
    for (const [param, desired] of Object.entries(spec.params)) {
      const observed = live.ok ? live.params[param] ?? null : null;
      if (!live.ok || observed !== desired || (force && process.env.COMMISSION_FAIL_PARAM === param)) failed.push({ param, desired, observed });
    }
    return failed;
  };
  const check = async (camera: string, prepared: Awaited<ReturnType<typeof prepare>>, force = false) => {
    const failed = await checkParams(camera, prepared.spec, force);
    if (prepared.presets.length) {
      const r = await d.vapix(camera, "/axis-cgi/com/ptz.cgi?query=presetposcam");
      const names = r.ok ? r.body.split(/\r?\n/).map((line) => line.slice(line.indexOf("=") + 1).trim()).filter(Boolean) : [];
      for (const preset of prepared.presets) if (!r.ok || !names.some((name) => name === preset.name || name.endsWith(`,${preset.name}`))) failed.push({ param: `preset:${preset.name}`, desired: preset.name, observed: null });
    }
    const warnings = prepared.aoa.warning ? [prepared.aoa.warning] : [];
    const scenarios: ScenarioResult[] = [];
    if (!prepared.aoa.installed) for (const scenario of prepared.spec.scenarios) scenarios.push({ name: scenario.name, id: null, type: scenario.type, deployed: false, readback_diff: [] });
    else {
      let config: AoaConfiguration;
      try { config = await readAoaConfiguration(camera); } catch (e) {
        for (const scenario of prepared.spec.scenarios) {
          const detail = e instanceof Error ? e.message : String(e);
          scenarios.push({ name: scenario.name, id: null, type: scenario.type, deployed: false, readback_diff: [detail] });
          failed.push({ param: `scenario:${scenario.name}`, desired: JSON.stringify(viewDesired(scenario)), observed: null });
        }
        return { verify: { passed: false, failed }, scenarios, warnings };
      }
      for (const scenario of prepared.spec.scenarios) {
        const observed = config.scenarios.find((value) => value.name === scenario.name);
        const diff = scenarioDiff(scenario, observed);
        scenarios.push({ name: scenario.name, id: observed?.id ?? null, type: scenario.type, deployed: !!observed, readback_diff: diff });
        if (diff.length) failed.push({ param: `scenario:${scenario.name}`, desired: JSON.stringify(viewDesired(scenario)), observed: observed ? JSON.stringify(viewLive(observed)) : null });
      }
    }
    return { verify: { passed: failed.length === 0, failed }, scenarios, warnings };
  };
  const observe = async (camera: string, prepared: Awaited<ReturnType<typeof prepare>>, scenarios: ScenarioResult[], canObserve: boolean): Promise<Observation | null> => {
    if (!prepared.spec.scenarios.length) return null;
    const started = new Date().toISOString();
    const fired = Object.fromEntries(prepared.spec.scenarios.map((scenario) => [scenario.name, { count: 0, first: null as string | null, last: null as string | null }]));
    const warnings = prepared.aoa.warning ? [prepared.aoa.warning] : [];
    if (!prepared.spec.observe.seconds) warnings.push("observation skipped by observe.seconds=0");
    else if (!canObserve || !prepared.aoa.installed) warnings.push("observation skipped because scenarios were not deployed and verified");
    else {
      const deployed = scenarios.filter((scenario): scenario is ScenarioResult & { id: number } => scenario.deployed && scenario.id !== null);
      const byTopic = new Map(deployed.map((scenario) => [`tnsaxis:CameraApplicationPlatform/ObjectAnalytics/Device1Scenario${scenario.id}`, scenario.name]));
      let sensed: Awaited<ReturnType<CommissionDeps["observeEvents"]>>;
      try { sensed = await d.observeEvents(camera, [...byTopic.keys()], prepared.spec.observe.seconds); }
      catch (e) { sensed = { events: [], warnings: [`event observation failed: ${e instanceof Error ? e.message : String(e)}`] }; }
      warnings.push(...sensed.warnings);
      for (const event of sensed.events) {
        const name = byTopic.get(event.topic);
        if (!name) continue;
        const data = event.message?.data ?? {};
        const active = data.active ?? data.state;
        if (active !== undefined && ![true, 1, "1", "true"].includes(active as never)) continue;
        const raw = event.timestamp;
        const at = typeof raw === "number" ? new Date(raw < 100_000_000_000 ? raw * 1000 : raw).toISOString() : typeof raw === "string" && !Number.isNaN(Date.parse(raw)) ? new Date(raw).toISOString() : new Date().toISOString();
        const item = fired[name]!;
        item.count++;
        item.first ??= at;
        item.last = at;
      }
    }
    for (const [name, item] of Object.entries(fired)) if (!item.count) warnings.push(`${name}: 0 events in window`);
    const observation = { window_seconds: prepared.spec.observe.seconds, started, finished: new Date().toISOString(), fired, warnings };
    if (prepared.spec.observe.seconds && canObserve && prepared.aoa.installed) d.receipt("commission_apply", { camera, spec: prepared.spec.name, observation: true }, "allow", `observed ${prepared.spec.observe.seconds}s AOA event window`, d.sha256(observation), "independently_sensed");
    return observation;
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
  const finish = (tool: "commission_apply" | "commission_verify", params: unknown, started: string, firstSeq: number, prepared: Awaited<ReturnType<typeof prepare>>, applied: Applied[], verify: { passed: boolean; failed: Failure[] }, rollback: Handoff["rollback"], scenarios: ScenarioResult[], observation: Observation | null) => {
    d.receipt(tool, params, "allow", verify.passed ? "verification passed" : "verification FAILED", d.sha256(verify));
    const head = d.lastReceipt();
    const finished = new Date().toISOString();
    const handoff: Handoff = {
      artifact: "camspec-handoff/0.1", spec: { name: prepared.spec.name, sha256: prepared.sha256 }, camera: prepared.cameraMeta,
      agent: d.agent, policy_sha256: d.sha256(Buffer.from(d.policyBytes).toString()), run: { started, finished }, plan: prepared.plan, applied, verify, rollback, scenarios, observation,
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
  const planOutput = (prepared: Awaited<ReturnType<typeof prepare>>) => ({ diff: prepared.plan, presets: prepared.presets, scenarios: prepared.aoa.plan, warnings: prepared.aoa.warning ? [prepared.aoa.warning] : [] });

  server.tool("commission_plan", "Plan a camspec against live VAPIX parameters without writes",
    { camera: z.string(), spec: z.string() }, async ({ camera, spec: ref }) => {
    const params = { camera, spec: ref };
    const reason = denied("commission_plan", camera);
    if (reason) { d.receipt("commission_plan", params, "deny", reason); return { content: [{ type: "text", text: `DENIED: ${reason}` }] }; }
    try {
      const p = await prepare(camera, ref);
      const out = planOutput(p);
      d.receipt("commission_plan", params, "allow", `planned ${p.plan.length} params, ${p.presets.length} presets, and ${p.aoa.plan.length} scenarios`, d.sha256(out));
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
        const out = planOutput(p);
        d.receipt("commission_apply", params, "allow", `dry-run: planned ${p.plan.length} params, ${p.presets.length} presets, and ${p.aoa.plan.length} scenarios`, d.sha256(out));
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
      if (!writeFailed && p.aoa.installed && p.aoa.plan.length) {
        const r = await d.vapixPost(camera, "/local/objectanalytics/control.cgi", { apiVersion: "1.0", method: "setConfiguration", params: p.aoa.merged });
        let ok = r.ok, why = r.ok ? "" : "transport failed";
        if (ok) try { parseRpc(r.body, "setConfiguration"); } catch (e) { ok = false; why = e instanceof Error ? e.message : String(e); }
        for (const scenario of p.aoa.plan) d.receipt("commission_apply", { ...params, scenario: scenario.name }, "allow", ok ? `deployed scenario ${scenario.name}` : `scenario write FAILED ${scenario.name}: ${why}`, undefined, ok ? "device_acknowledged" : "unknown");
        if (!ok) writeFailed = { param: `scenario:${p.aoa.plan[0]!.name}`, desired: JSON.stringify(viewDesired(p.spec.scenarios.find((scenario) => scenario.name === p.aoa.plan[0]!.name)!)), observed: null };
        else for (const scenario of p.aoa.plan) applied.push({ scenario: scenario.name, id: scenario.id, type: scenario.type });
      }
      const checked = await check(camera, p, true);
      if (writeFailed && !checked.verify.failed.some((failure) => failure.param === writeFailed!.param)) checked.verify.failed.unshift(writeFailed);
      checked.verify.passed = checked.verify.failed.length === 0;
      const observation = await observe(camera, p, checked.scenarios, checked.verify.passed);
      let rollback: Handoff["rollback"] = null;
      if (!checked.verify.passed) {
        let rollbackWrites = true;
        for (const item of applied.filter((a): a is Extract<Applied, { param: string }> => "param" in a).reverse()) {
          const r = await d.vapix(camera, `/axis-cgi/param.cgi?action=update&${encodeURIComponent(item.param)}=${encodeURIComponent(item.previous)}`);
          const ok = r.ok && !/^Error/m.test(r.body);
          rollbackWrites &&= ok;
          d.receipt("commission_apply", { ...params, rollback: item.param }, "allow", ok ? `rolled back ${item.param}` : `rollback FAILED ${item.param}`, undefined, ok ? "device_acknowledged" : "unknown");
        }
        const rollbackSpec: Spec = { ...p.spec, params: Object.fromEntries(applied.filter((a): a is Extract<Applied, { param: string }> => "param" in a).map((item) => [item.param, item.previous])) };
        rollback = { performed: true, verified: rollbackWrites && (await checkParams(camera, rollbackSpec)).length === 0 };
      }
      const file = finish("commission_apply", params, started, firstSeq, p, applied, checked.verify, rollback, checked.scenarios, observation);
      const out = { ...checked.verify, rolled_back: rollback?.performed ?? false, rollback_verified: rollback?.verified ?? null, scenarios: checked.scenarios, observation, handoff: file };
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
      const checked = await check(camera, p);
      const file = finish("commission_verify", params, started, firstSeq, p, [], checked.verify, null, checked.scenarios, null);
      return { content: [{ type: "text", text: JSON.stringify({ ...checked.verify, scenarios: checked.scenarios, observation: null, handoff: file }, null, 2) }] };
    } catch (e) { return error("commission_verify", params, e); }
  });
}
