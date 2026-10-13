import { afterEach, beforeEach, expect, spyOn, test } from "bun:test";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { decodeCbor } from "aar-kat-harness/harness/cbor";
import { AarWireProducer, verifyBundleDir } from "./producer";
import { sendPreset, sendSnapshot } from "./actions";
import { cameraId, presetName } from "../schemas";
import { formatPresetRecall } from "../ptz-output";
import { snapshotContent } from "../snapshot-content";
import { curlRequest } from "../curl-args";

// Execute the actual index.ts wrapper and registrations with fake transports.
// Importing index.ts itself would fetch credentials, create .keys and connect MCP.
const repo = resolve(import.meta.dir, "..");
const source = fs.readFileSync(join(repo, "index.ts"), "utf8");
const wrapper = source.slice(source.indexOf("const aarProducer ="), source.indexOf("const server = new McpServer"));
const registrations = source.slice(source.indexOf('server.tool("get_snapshot"'), source.indexOf('server.tool("ptz_move"'));
const code = new Bun.Transpiler({ loader: "ts" }).transformSync(wrapper + registrations);
let root: string, now: number;
const home = process.env.HOME;
const spies: Array<{ mockRestore(): void }> = [];
beforeEach(() => {
  root = fs.mkdtempSync(join(tmpdir(), "aar-tools-test-"));
  process.env.HOME = join(root, "home");
  now = 1_800_000_000_000;
  spies.push(spyOn(Date, "now").mockImplementation(() => now));
  spies.push(spyOn(Bun, "sleep").mockImplementation(async ms => { now += Number(ms); }));
});
afterEach(() => {
  for (const spy of spies.splice(0).reverse()) spy.mockRestore();
  process.env.HOME = home;
  fs.rmSync(root, { recursive: true, force: true });
});
function harness(mode: string, password = "fake-password") {
  const calls: string[] = [], chain: any[] = [];
  const handlers: Record<string, (input: any) => Promise<any>> = {};
  const credentialChannel = (path: string) => {
    const request = curlRequest({ base: "https://camera.invalid", user: "test" }, password, path);
    expect(request.args.join(" ")).not.toContain(password);
    expect(request.stdin).toContain("user ="); // Fake transport consumes stdin; no process/network.
  };
  const dependencies = {
    AarWireProducer, sendPreset, sendSnapshot, createHash, join, cameraId, presetName, formatPresetRecall, snapshotContent,
    ROOT: root, AGENT: "test-agent", policyBytes: Buffer.from("policy"),
    cameras: { cam: { ptz: true, protocol: "vapix" } }, policy: { "test-agent": { ptz: true } },
    existsSync: fs.existsSync, readFileSync: fs.readFileSync,
    allowed: () => mode === "deny" ? "agent has no grant" : null, rateDenied: () => null,
    deviceMeta: async () => { calls.push("metadata"); return { manufacturer: "AXIS", model: "test", firmware: "0" }; },
    receipt: (...args: any[]) => chain.push(args),
    server: { tool: (name: string, _description: string, _schema: unknown, handler: any) => { handlers[name] = handler; } },
    snapshot: async (_tool: string, _camera: string, path: string) => {
      calls.push("snapshot");
      credentialChannel("/axis-cgi/jpg/image.cgi");
      if (mode === "throws") throw Error("stand-in-camera-password");
      if (mode === "snapshot-failure") return false;
      fs.writeFileSync(path, Buffer.from([255, 216, 255, 217]));
      return true;
    },
    vapix: async (_tool: string, _camera: string, path: string) => {
      credentialChannel(path);
      const readback = path.includes("query=position");
      calls.push(readback ? "readback" : "recall");
      const journal = fs.readFileSync(join(root, "receipts", "aar", "journal.jsonl"), "utf8");
      expect(journal).toContain('"event":"attempt_committed"');
      if (mode === "throws") throw Error("stand-in-camera-password");
      if (mode === "overrun") now += 61_000;
      if (mode === "backwards") now -= 1000;
      if (mode === "transport-failure" || (readback && mode === "readback-failure")) return { ok: false, body: "" };
      return { ok: true, body: readback ? "pan=1" : "OK" };
    },
  };
  new Function(...Object.keys(dependencies), code)(...Object.values(dependencies));
  return { handlers, calls, chain };
}
function bundle(output: any) {
  const text = output.content.filter((c: any) => c.type === "text").map((c: any) => c.text).join("\n");
  const dir = text.match(/aar-bundle: (.+)/)?.[1];
  expect(dir).toBeDefined();
  const result = verifyBundleDir(repo, dir!);
  expect(result.output).toContain("Result: conformant");
  const wire = decodeCbor(fs.readFileSync(join(dir!, "bundle.cbor"))) as any;
  return wire.artifacts.receipts.map((e: any[]) => decodeCbor(e[0] as Uint8Array)) as any[];
}

for (const [mode, tool, status] of [
  ["readback-failure", "ptz_preset", 200], ["transport-failure", "ptz_preset", 0], ["snapshot-failure", "get_snapshot", 0],
] as const) {
  test(`actual ${tool} handler: ${mode} emits conformant unknown outcome`, async () => {
    const h = harness(mode);
    const output = await h.handlers[tool]!({ camera: "cam", preset: "Home" });
    const rs = bundle(output);
    expect(h.calls[0]).toBe("metadata");
    expect(rs.find(r => r.kind === "dispatch").body.target_status).toBe(status);
    expect(rs.find(r => r.kind === "outcome_observation")).toMatchObject({ body: { state: "unknown" }, evidence: { outcome: { level: "unknown" } } });
    expect(h.chain.some(r => r[0] === tool)).toBe(true);
  });
}
for (const mode of ["throws", "overrun", "backwards"]) {
  test(`actual handler ${mode}: loud failure and JSONL aar_emit, no bundle`, async () => {
    const h = harness(mode);
    const output = await h.handlers.ptz_preset!({ camera: "cam", preset: "Home" });
    const text = JSON.stringify(output);
    expect(text).toContain("aar-emit FAILED:");
    if (mode === "throws") expect(text).toContain("aar-emit FAILED: dispatch outcome ambiguous");
    expect(text).not.toContain("stand-in-camera-password");
    expect(h.chain.some(r => r[0] === "aar_emit" && r[3].includes("wire emission FAILED:"))).toBe(true);
    expect(fs.readdirSync(join(root, "receipts", "aar")).some(name => fs.existsSync(join(root, "receipts", "aar", name, "bundle.cbor")))).toBe(false);
  });
}

test("actual denial handlers never query metadata or send, and both verify", async () => {
  const h = harness("deny");
  for (const tool of ["get_snapshot", "ptz_preset"]) {
    const output = await h.handlers[tool]!({ camera: "cam", preset: "Home" });
    expect(bundle(output).find(r => r.kind === "action_attempt").body.disposition).toBe("not_dispatched");
  }
  expect(h.calls).toEqual([]);
});

test("actual handler on journal append failure does metadata only and writes refusal", async () => {
  const h = harness("ok");
  spies.push(spyOn(fs, "appendFileSync").mockImplementation(() => { throw Error("unavailable"); }));
  const output = await h.handlers.get_snapshot!({ camera: "cam" });
  expect(h.calls).toEqual(["metadata"]);
  expect(bundle(output).find(r => r.kind === "action_attempt").body).toMatchObject({ disposition: "not_dispatched", refusal_reason: "journal/unavailable" });
});

test("actual preset handler on journal failure never recalls or records transport error", async () => {
  const h = harness("ok");
  spies.push(spyOn(fs, "appendFileSync").mockImplementation(() => { throw Error("unavailable"); }));
  const output = await h.handlers.ptz_preset!({ camera: "cam", preset: "Home" });
  expect(h.calls).toEqual(["metadata"]);
  expect(JSON.stringify(h.chain)).not.toContain("transport error");
  expect(JSON.stringify(output)).toContain("preset not dispatched");
  expect(bundle(output).find(r => r.kind === "action_attempt").body).toMatchObject({ disposition: "not_dispatched", refusal_reason: "journal/unavailable" });
});

test("actual preset handler late journal refusal fails loudly with JSONL aar_emit and no send", async () => {
  const h = harness("ok");
  spies.push(spyOn(fs, "appendFileSync").mockImplementation(() => { now += 1000; throw Error("unavailable"); }));
  const output = await h.handlers.ptz_preset!({ camera: "cam", preset: "Home" });
  expect(h.calls).toEqual(["metadata"]);
  expect(JSON.stringify(output)).toContain("aar-emit FAILED: invalid real-clock timeline: journal refusal decided after T0");
  expect(JSON.stringify(output)).toContain("preset not dispatched");
  expect(h.chain.some(r => r[0] === "aar_emit" && r[3].includes("journal refusal decided after T0"))).toBe(true);
  expect(JSON.stringify(h.chain)).not.toContain("transport error");
  expect(fs.readdirSync(join(root, "receipts", "aar")).some(name => fs.existsSync(join(root, "receipts", "aar", name, "bundle.cbor")))).toBe(false);
});

test("actual preset handler uses T0 for readback budget after waiting to emit", async () => {
  const h = harness("ok");
  const emit = AarWireProducer.prototype.emit;
  spies.push(spyOn(AarWireProducer.prototype, "emit").mockImplementation(function (this: AarWireProducer, input) {
    now += 61_000;
    return emit.call(this, input);
  }));
  const output = await h.handlers.ptz_preset!({ camera: "cam", preset: "Home" });
  expect(h.calls).toEqual(["metadata", "recall", "readback", "readback"]);
  expect(bundle(output).find(r => r.kind === "outcome_observation").evidence.outcome.level).toBe("device_acknowledged");
});

test("stand-in camera password stays out of journal, all bundle files, metadata and tool output", async () => {
  const password = 'stand-in-camera-password\\"quote';
  const request = curlRequest({ base: "https://camera.invalid", user: "test" }, password, "/axis-cgi/com/ptz.cgi");
  expect(request.args.join(" ")).not.toContain(password);
  expect(request.stdin).toContain("stand-in-camera-password"); // Only credential-bearing channel; never spawned.
  const h = harness("ok", password);
  for (const tool of ["get_snapshot", "ptz_preset"]) {
    const output = await h.handlers[tool]!({ camera: "cam", preset: "Home" });
    bundle(output);
    expect(JSON.stringify(output)).not.toContain("stand-in-camera-password");
  }
  const walk = (dir: string): string[] => fs.readdirSync(dir).flatMap(name => {
    const path = join(dir, name);
    return fs.statSync(path).isDirectory() ? walk(path) : [path];
  });
  for (const path of walk(join(root, "receipts"))) {
    expect(fs.readFileSync(path).includes(Buffer.from("stand-in-camera-password"))).toBe(false);
  }
  expect(JSON.stringify(h.chain)).not.toContain("stand-in-camera-password");
});
