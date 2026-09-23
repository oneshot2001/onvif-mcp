import { afterEach, describe, expect, test } from "bun:test";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readCommissionSpec, registerCommission, verifyHandoffs, type CommissionDeps } from "./commission";

const roots: string[] = [];
afterEach(() => {
  delete process.env.COMMISSION_FAIL_PARAM;
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function harness(options: { ptz?: boolean; aoa?: boolean; aoaInstalled?: boolean } = {}) {
  const root = mkdtempSync(join(tmpdir(), "onvif-commission-"));
  roots.push(root);
  mkdirSync(join(root, "specs"));
  const state: Record<string, string> = { "Time.NTP.Server": "old", "Image.I0.Appearance.Rotation": "0" };
  const writes: string[] = [];
  const posts: unknown[] = [];
  const receipts: Array<{ tool: string; decision: string; detail: string; resultHash?: string; evidence?: string }> = [];
  const presets = new Set<string>();
  let aoa = { devices: [{ id: 1 }], scenarios: [{ id: 4, name: "keep-me", type: "motion", devices: [{ id: 1 }], triggers: [{ type: "includeArea", vertices: [[-0.5, -0.5], [0.5, -0.5], [0.5, 0.5]] }], objectClassifications: [{ type: "vehicle" }] }] };
  let seq = 0;
  const handlers: Record<string, (args: Record<string, unknown>) => Promise<{ content: Array<{ text: string }> }>> = {};
  const server = { tool(name: string, _description: string, _schema: unknown, handler: (args: Record<string, unknown>) => Promise<{ content: Array<{ text: string }> }>) { handlers[name] = handler; } };
  const parseParams = (body: string) => Object.fromEntries(body.trim().split(/\r?\n/).filter(Boolean).map((line) => {
    const raw = line.startsWith("root.") ? line.slice(5) : line;
    const i = raw.indexOf("=");
    return [raw.slice(0, i), raw.slice(i + 1)];
  }));
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const deps: CommissionDeps = {
    root, agent: "claude-main",
    policy: { "claude-main": { tools: ["commission_plan", "commission_apply", "commission_verify"], cameras: ["cam"], config: { groups: ["Time", "Image", "Network"], remediate: true, aoa: options.aoa ?? true } } },
    policyBytes: Buffer.from("policy"), cameras: { cam: { ptz: options.ptz ?? false } },
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    parseParams,
    inGroup: (param, groups) => groups.some((group) => param === group || param.startsWith(`${group}.`)),
    sha256: (value) => createHash("sha256").update(typeof value === "string" ? value : JSON.stringify(value)).digest("hex"),
    lastReceipt: () => ({ seq, hash: seq ? `hash-${seq}` : "genesis" }),
    receipt: (tool, _params, decision, detail, resultHash, evidence) => { seq++; receipts.push({ tool, decision, detail, resultHash, evidence }); },
    configParams: async (_camera, groups) => ({ ok: true, params: Object.fromEntries(Object.entries(state).filter(([param]) => groups.some((group) => param === group || param.startsWith(`${group}.`)))) }),
    vapix: async (_camera, path) => {
      if (path.includes("Brand.ProdShortName")) return { ok: true, body: "root.Brand.ProdShortName=AXIS TEST\nroot.Properties.Firmware.Version=1.2.3\nroot.Properties.System.SerialNumber=serial\n" };
      if (path.includes("query=presetposcam")) return { ok: true, body: [...presets].map((name, i) => `presetposno${i + 1}=${name}`).join("\n") };
      if (path.includes("setserverpresetname=")) presets.add(decodeURIComponent(path.split("setserverpresetname=")[1]!));
      if (path.includes("action=update")) {
        writes.push(path);
        const query = new URL(`http://camera${path}`).searchParams;
        for (const [param, value] of query) if (param !== "action") state[param] = value;
      }
      return { ok: true, body: "OK" };
    },
    vapixPost: async (_camera, _path, body) => {
      posts.push(structuredClone(body));
      const request = body as { method?: string; params?: typeof aoa };
      if (request.method === "getSupportedVersions") return options.aoaInstalled === false ? { ok: true, body: "not installed" } : { ok: true, body: JSON.stringify({ apiVersion: "1.0", method: request.method, data: { apiVersions: ["1.0"] } }) };
      if (request.method === "getConfiguration") return { ok: true, body: JSON.stringify({ apiVersion: "1.0", method: request.method, data: aoa }) };
      if (request.method === "setConfiguration") {
        aoa = structuredClone(request.params!);
        writes.push("AOA:setConfiguration");
        return { ok: true, body: JSON.stringify({ apiVersion: "1.0", method: request.method, data: {} }) };
      }
      return { ok: false, body: "" };
    },
    observeEvents: async (_camera, topics) => ({ events: topics.length ? [{ topic: topics[0]!, timestamp: 1_700_000_000_000, message: { data: { active: "1" } } }] : [], warnings: [] }),
  };
  registerCommission(server as never, deps);
  return { root, state, writes, posts, receipts, presets, handlers, aoa: () => aoa, privateKey, publicKey: publicKey.export({ type: "spki", format: "pem" }).toString() };
}

describe("commission specs", () => {
  test("loads the committed fixtures and rejects unknown top-level keys", () => {
    expect(readCommissionSpec(import.meta.dir, "lab-baseline").spec.params).toEqual({ "Image.I0.Appearance.Rotation": "0" });
    expect(readCommissionSpec(import.meta.dir, "lab-aoa").spec).toMatchObject({ scenarios: [{ name: "lab-motion", type: "motion", objects: ["human"] }], observe: { seconds: 30 } });
    const { root } = harness();
    writeFileSync(join(root, "specs", "bad.yaml"), "spec: camspec/0.1\nname: bad\nextra: true\n");
    expect(() => readCommissionSpec(root, "bad")).toThrow("unknown top-level key(s): extra");
    expect(() => readCommissionSpec(root, "../bad")).toThrow("outside specs/");
  });

  test("denies a protected parameter before any write", async () => {
    const h = harness();
    writeFileSync(join(h.root, "specs", "deny.yaml"), "spec: camspec/0.1\nname: deny\nparams:\n  Network.HostName: camera\n");
    const result = await h.handlers.commission_apply!({ camera: "cam", spec: "deny", approve: true });
    expect(result.content[0]!.text).toContain("DENIED: param 'Network.HostName' is hard-denied");
    expect(h.writes).toEqual([]);
    expect(h.receipts.at(-1)).toMatchObject({ decision: "deny" });
  });

  test("denies clock parameters despite a Time config grant before any write", async () => {
    const h = harness();
    writeFileSync(join(h.root, "specs", "clock.yaml"), "spec: camspec/0.1\nname: clock\nparams:\n  Time.NTP.Server: new\n");
    const result = await h.handlers.commission_apply!({ camera: "cam", spec: "clock", approve: true });
    expect(result.content[0]!.text).toBe("DENIED: param 'Time.NTP.Server' is hard-denied");
    expect(h.writes).toEqual([]);
    expect(h.receipts.at(-1)).toMatchObject({ decision: "deny" });
  });

  test("denies lowercase password parameters before any write", async () => {
    const h = harness();
    writeFileSync(join(h.root, "specs", "password.yaml"), "spec: camspec/0.1\nname: password\nparams:\n  Image.I0.password: new\n");
    const result = await h.handlers.commission_apply!({ camera: "cam", spec: "password", approve: true });
    expect(result.content[0]!.text).toBe("DENIED: param 'Image.I0.password' is hard-denied");
    expect(h.writes).toEqual([]);
    expect(h.receipts.at(-1)).toMatchObject({ decision: "deny" });
  });

  test("plan and unapproved apply are identical read-only diffs", async () => {
    const h = harness();
    writeFileSync(join(h.root, "specs", "plan.yaml"), "spec: camspec/0.1\nname: plan\nparams:\n  Image.I0.Appearance.Rotation: \"180\"\npresets:\n  Home: { pan: 0, tilt: 0, zoom: 1 }\n");
    const plan = await h.handlers.commission_plan!({ camera: "cam", spec: "plan" });
    const dry = await h.handlers.commission_apply!({ camera: "cam", spec: "plan", approve: false });
    expect(JSON.parse(dry.content[0]!.text)).toEqual(JSON.parse(plan.content[0]!.text));
    expect(JSON.parse(plan.content[0]!.text)).toEqual({ diff: [{ param: "Image.I0.Appearance.Rotation", current: "0", desired: "180" }], presets: [], scenarios: [], warnings: [] });
    expect(h.writes).toEqual([]);
  });

  test("forced verify failure rolls back and emits a verifiable signed handoff", async () => {
    const h = harness();
    writeFileSync(join(h.root, "specs", "apply.yaml"), "spec: camspec/0.1\nname: apply\nparams:\n  Image.I0.Appearance.Rotation: \"180\"\n");
    process.env.COMMISSION_FAIL_PARAM = "Image.I0.Appearance.Rotation";
    const result = await h.handlers.commission_apply!({ camera: "cam", spec: "apply", approve: true, notes: "Readback failed; rolled back." });
    const out = JSON.parse(result.content[0]!.text);
    expect(out).toMatchObject({ passed: false, rolled_back: true, rollback_verified: true });
    expect(out.failed).toEqual([{ param: "Image.I0.Appearance.Rotation", desired: "180", observed: "180" }]);
    expect(h.state["Image.I0.Appearance.Rotation"]).toBe("0");
    expect(h.writes).toHaveLength(2);
    expect(JSON.parse(readFileSync(out.handoff, "utf8")).notes).toBe("Readback failed; rolled back.");
    expect(verifyHandoffs(h.root, h.publicKey)).toEqual({ count: 1, bad: [] });
  });

  test("verify records signed notes immediately after observation", async () => {
    const h = harness();
    writeFileSync(join(h.root, "specs", "verify.yaml"), "spec: camspec/0.1\nname: verify\n");
    const notes = "walk test at 10:41, two zone entries, count stayed 0";
    const result = await h.handlers.commission_verify!({ camera: "cam", spec: "verify", notes });
    const out = JSON.parse(result.content[0]!.text);
    const handoff = JSON.parse(readFileSync(out.handoff, "utf8"));
    expect(handoff.notes).toBe(notes);
    expect(Object.keys(handoff)).toEqual(["artifact", "spec", "camera", "agent", "policy_sha256", "run", "plan", "applied", "verify", "rollback", "scenarios", "observation", "notes", "receipts", "sig"]);
    expect(verifyHandoffs(h.root, h.publicKey)).toEqual({ count: 1, bad: [] });
  });

  test("verify without notes records null", async () => {
    const h = harness();
    writeFileSync(join(h.root, "specs", "verify.yaml"), "spec: camspec/0.1\nname: verify\n");
    const result = await h.handlers.commission_verify!({ camera: "cam", spec: "verify" });
    const out = JSON.parse(result.content[0]!.text);
    expect(JSON.parse(readFileSync(out.handoff, "utf8")).notes).toBeNull();
    expect(verifyHandoffs(h.root, h.publicKey)).toEqual({ count: 1, bad: [] });
  });

  test("verifies a legacy handoff signed without the notes key", () => {
    const h = harness();
    const handoff = {
      artifact: "camspec-handoff/0.1", spec: { name: "legacy", sha256: "spec-hash" },
      camera: { id: "cam", model: "AXIS TEST", firmware: "1.2.3", serial: "serial" },
      agent: "claude-main", policy_sha256: "policy-hash",
      run: { started: "2026-01-01T00:00:00.000Z", finished: "2026-01-01T00:00:01.000Z" },
      plan: [], applied: [], verify: { passed: true, failed: [] }, rollback: null,
      scenarios: [], observation: null,
      receipts: { first_seq: 1, last_seq: 1, chain_head_hash: "hash-1" },
    };
    const hash = createHash("sha256").update(JSON.stringify(handoff)).digest("hex");
    const sig = sign(null, Buffer.from(hash), h.privateKey).toString("base64");
    mkdirSync(join(h.root, "handoff"));
    writeFileSync(join(h.root, "handoff", "legacy.json"), JSON.stringify({ ...handoff, sig }, null, 2) + "\n");
    expect(verifyHandoffs(h.root, h.publicKey)).toEqual({ count: 1, bad: [] });
  });

  test("rejects unsupported scenario types and missing AOA grants before device calls", async () => {
    const h = harness({ aoa: false });
    writeFileSync(join(h.root, "specs", "fence.yaml"), "spec: camspec/0.1\nname: fence\nscenarios:\n  - name: bad\n    type: fence\n    objects: [human]\n    line: [[-0.5, 0], [0.5, 0]]\n");
    const invalid = await h.handlers.commission_apply!({ camera: "cam", spec: "fence", approve: true });
    expect(invalid.content[0]!.text).toContain("unsupported type 'fence'");
    writeFileSync(join(h.root, "specs", "aoa.yaml"), "spec: camspec/0.1\nname: aoa\nscenarios:\n  - name: motion\n    type: motion\n    objects: [human]\n    area: [[-0.9,-0.9],[0.9,-0.9],[0.9,0.9],[-0.9,0.9]]\n");
    const denied = await h.handlers.commission_apply!({ camera: "cam", spec: "aoa", approve: true });
    expect(denied.content[0]!.text).toContain("DENIED: agent 'claude-main' has no AOA config grant");
    expect(h.writes).toEqual([]);
    expect(h.posts).toEqual([]);
  });

  test("plans, merges, verifies, observes, and then no-ops an AOA scenario by name", async () => {
    const h = harness();
    writeFileSync(join(h.root, "specs", "aoa.yaml"), "spec: camspec/0.1\nname: aoa\nscenarios:\n  - name: lab-motion\n    type: motion\n    objects: [human]\n    area: [[-0.9,-0.9],[0.9,-0.9],[0.9,0.9],[-0.9,0.9]]\nobserve: { seconds: 1 }\n");
    const plan = JSON.parse((await h.handlers.commission_plan!({ camera: "cam", spec: "aoa" })).content[0]!.text);
    expect(plan.scenarios).toEqual([{ name: "lab-motion", id: 5, type: "motion", action: "deploy" }]);
    expect(h.writes).toEqual([]);
    const applied = JSON.parse((await h.handlers.commission_apply!({ camera: "cam", spec: "aoa", approve: true })).content[0]!.text);
    expect(applied).toMatchObject({ passed: true, scenarios: [{ name: "lab-motion", id: 5, deployed: true, readback_diff: [] }], observation: { window_seconds: 1, fired: { "lab-motion": { count: 1 } }, warnings: [] } });
    expect(h.aoa().scenarios.map((scenario) => scenario.name)).toEqual(["keep-me", "lab-motion"]);
    expect(h.receipts.some((receipt) => receipt.detail === "deployed scenario lab-motion" && receipt.evidence === "device_acknowledged")).toBeTrue();
    expect(h.receipts.some((receipt) => receipt.detail === "observed 1s AOA event window" && receipt.evidence === "independently_sensed" && receipt.resultHash)).toBeTrue();
    const second = JSON.parse((await h.handlers.commission_apply!({ camera: "cam", spec: "aoa", approve: true })).content[0]!.text);
    expect(second).toMatchObject({ passed: true, scenarios: [{ name: "lab-motion", id: 5, readback_diff: [] }], observation: { fired: { "lab-motion": { count: 1 } } } });
    expect(h.writes).toEqual(["AOA:setConfiguration"]);
  });

  test("AOA absence fails verification with a warning and preset verification detects deletion", async () => {
    const unavailable = harness({ aoaInstalled: false });
    writeFileSync(join(unavailable.root, "specs", "aoa.yaml"), "spec: camspec/0.1\nname: aoa\nscenarios:\n  - name: motion\n    type: motion\n    objects: [human]\n    area: [[-0.9,-0.9],[0.9,-0.9],[0.9,0.9],[-0.9,0.9]]\nobserve: { seconds: 0 }\n");
    const skipped = JSON.parse((await unavailable.handlers.commission_apply!({ camera: "cam", spec: "aoa", approve: true })).content[0]!.text);
    expect(skipped.passed).toBeFalse();
    expect(skipped.failed).toMatchObject([{ param: "scenario:motion", observed: null }]);
    expect(skipped.observation.warnings).toContain("AOA application unavailable; scenarios skipped");

    const ptz = harness({ ptz: true });
    writeFileSync(join(ptz.root, "specs", "preset.yaml"), "spec: camspec/0.1\nname: preset\npresets:\n  Home: { pan: 0, tilt: 0, zoom: 1 }\n");
    expect(JSON.parse((await ptz.handlers.commission_apply!({ camera: "cam", spec: "preset", approve: true })).content[0]!.text).passed).toBeTrue();
    ptz.presets.delete("Home");
    const verify = JSON.parse((await ptz.handlers.commission_verify!({ camera: "cam", spec: "preset" })).content[0]!.text);
    expect(verify).toMatchObject({ passed: false, failed: [{ param: "preset:Home", desired: "Home", observed: null }] });
  });

  test("maps crosslinecounting geometry and classifications to AOA", async () => {
    const h = harness();
    writeFileSync(join(h.root, "specs", "line.yaml"), "spec: camspec/0.1\nname: line\nscenarios:\n  - name: gate-line\n    type: crosslinecounting\n    objects: [vehicle]\n    line: [[-0.5, 0], [0.5, 0]]\nobserve: { seconds: 0 }\n");
    const result = JSON.parse((await h.handlers.commission_apply!({ camera: "cam", spec: "line", approve: true })).content[0]!.text);
    expect(result.passed).toBeTrue();
    expect(h.aoa().scenarios.find((scenario) => scenario.name === "gate-line")).toMatchObject({
      id: 5, type: "crosslinecounting", objectClassifications: [{ type: "vehicle" }],
      triggers: [{ type: "countingLine", countingDirection: "leftToRight", vertices: [[-0.5, 0], [0.5, 0]] }],
    });
  });
});
