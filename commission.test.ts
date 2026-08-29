import { afterEach, describe, expect, test } from "bun:test";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readCommissionSpec, registerCommission, verifyHandoffs, type CommissionDeps } from "./commission";

const roots: string[] = [];
afterEach(() => {
  delete process.env.COMMISSION_FAIL_PARAM;
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function harness() {
  const root = mkdtempSync(join(tmpdir(), "onvif-commission-"));
  roots.push(root);
  mkdirSync(join(root, "specs"));
  const state: Record<string, string> = { "Time.NTP.Server": "old", "Image.I0.Appearance.Rotation": "0" };
  const writes: string[] = [];
  const receipts: Array<{ tool: string; decision: string; detail: string }> = [];
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
    policy: { "claude-main": { tools: [], cameras: ["cam"], config: { groups: ["Time", "Image", "Network"], remediate: true } } },
    policyBytes: Buffer.from("policy"), cameras: { cam: { ptz: false } },
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    parseParams,
    inGroup: (param, groups) => groups.some((group) => param === group || param.startsWith(`${group}.`)),
    sha256: (value) => createHash("sha256").update(typeof value === "string" ? value : JSON.stringify(value)).digest("hex"),
    lastReceipt: () => ({ seq, hash: seq ? `hash-${seq}` : "genesis" }),
    receipt: (tool, _params, decision, detail) => { seq++; receipts.push({ tool, decision, detail }); },
    configParams: async (_camera, groups) => ({ ok: true, params: Object.fromEntries(Object.entries(state).filter(([param]) => groups.some((group) => param === group || param.startsWith(`${group}.`)))) }),
    vapix: async (_camera, path) => {
      if (path.includes("Brand.ProdShortName")) return { ok: true, body: "root.Brand.ProdShortName=AXIS TEST\nroot.Properties.Firmware.Version=1.2.3\nroot.Properties.System.SerialNumber=serial\n" };
      if (path.includes("action=update")) {
        writes.push(path);
        const query = new URL(`http://camera${path}`).searchParams;
        for (const [param, value] of query) if (param !== "action") state[param] = value;
      }
      return { ok: true, body: "OK" };
    },
  };
  registerCommission(server as never, deps);
  return { root, state, writes, receipts, handlers, publicKey: publicKey.export({ type: "spki", format: "pem" }).toString() };
}

describe("commission specs", () => {
  test("loads the committed fixtures and rejects unknown top-level keys", () => {
    expect(readCommissionSpec(import.meta.dir, "lab-baseline").spec.params["Time.NTP.Server"]).toBe("0.0.0.0");
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

  test("plan and unapproved apply are identical read-only diffs", async () => {
    const h = harness();
    writeFileSync(join(h.root, "specs", "plan.yaml"), "spec: camspec/0.1\nname: plan\nparams:\n  Time.NTP.Server: new\npresets:\n  Home: { pan: 0, tilt: 0, zoom: 1 }\n");
    const plan = await h.handlers.commission_plan!({ camera: "cam", spec: "plan" });
    const dry = await h.handlers.commission_apply!({ camera: "cam", spec: "plan", approve: false });
    expect(JSON.parse(dry.content[0]!.text)).toEqual(JSON.parse(plan.content[0]!.text));
    expect(JSON.parse(plan.content[0]!.text)).toEqual({ diff: [{ param: "Time.NTP.Server", current: "old", desired: "new" }], presets: [] });
    expect(h.writes).toEqual([]);
  });

  test("forced verify failure rolls back and emits a verifiable signed handoff", async () => {
    const h = harness();
    writeFileSync(join(h.root, "specs", "apply.yaml"), "spec: camspec/0.1\nname: apply\nparams:\n  Time.NTP.Server: new\n");
    process.env.COMMISSION_FAIL_PARAM = "Time.NTP.Server";
    const result = await h.handlers.commission_apply!({ camera: "cam", spec: "apply", approve: true });
    const out = JSON.parse(result.content[0]!.text);
    expect(out).toMatchObject({ passed: false, rolled_back: true, rollback_verified: true });
    expect(out.failed).toEqual([{ param: "Time.NTP.Server", desired: "new", observed: "new" }]);
    expect(h.state["Time.NTP.Server"]).toBe("old");
    expect(h.writes).toHaveLength(2);
    expect(verifyHandoffs(h.root, h.publicKey)).toEqual({ count: 1, bad: [] });
  });
});
