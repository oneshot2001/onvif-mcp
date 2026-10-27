import { afterEach, beforeEach, expect, spyOn, test } from "bun:test";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createHash, generateKeyPairSync, sign as edSign } from "node:crypto";
import { decodeCbor, toHex } from "aar-kat-harness/harness/cbor";
import { AarWireProducer, commandDigestHex, verifyBundleDir } from "./producer";
import { sendPreset, sendSnapshot } from "./actions";
import { cameraId, presetName } from "../schemas";
import { formatPresetRecall } from "../ptz-output";
import { snapshotContent } from "../snapshot-content";
import { curlRequest } from "../curl-args";
import { z } from "zod";
import { allowed as policyAllowed, ptzBound, type Policy } from "../policy-check";
import { clockReceipt, formatClock, type ClockResult } from "../clock";
import { appendLocked, outcomeEvidence, verifyChain, formatReceiptsText, selectReceipts } from "../receipt-chain";

import { claimInvocationForAar, currentCommandDigest, currentInvocationId, runAsDispatch, runWithInvocation } from "../invocation";
import { checkAarJournal } from "./journal";

// Execute the actual index.ts wrapper and registrations with fake transports.
// Importing index.ts itself would fetch credentials, create .keys and connect MCP.
const repo = resolve(import.meta.dir, "..");
const source = fs.readFileSync(join(repo, "index.ts"), "utf8");
const wrapper = source.slice(source.indexOf("const aarProducer ="), source.indexOf("const server = new McpServer"));
const registrations = source.slice(source.indexOf('server.tool("get_snapshot"'), source.indexOf('server.tool("ptz_move"'));
const writer = source.slice(source.indexOf("const NODE_KIND:"), source.indexOf("function allowed("));
const code = new Bun.Transpiler({ loader: "ts" }).transformSync(writer + wrapper + registrations);
const gateCode = new Bun.Transpiler({ loader: "ts" }).transformSync(
  source.slice(source.indexOf('server.tool("list_cameras"'), source.indexOf('server.tool("get_snapshot"'))
  + source.slice(source.indexOf('server.tool("ptz_move"'), source.indexOf('server.tool("config_baseline"'))
  + source.slice(source.indexOf('server.tool("get_receipts"'), source.indexOf('\n\n\ntry {', source.indexOf('server.tool("get_receipts"'))),
);
const agent = "test-agent";
function freshPolicy(): Policy {
  return { [agent]: {
    tools: ["list_cameras", "clock_check", "get_snapshot", "ptz_preset", "ptz_move", "get_receipts"],
    cameras: ["cam"], ptz: { maxStep: 30 },
  } };
}
type HarnessOptions = {
  policy?: Policy;
  rateDenied?: (key: "snapshot" | "actuation") => string | null;
  camera?: { ptz: boolean; protocol: string };
};
let root: string, now: number;
const home = process.env.HOME;
const spies: Array<{ mockRestore(): void }> = [];
// Keep tests serial: HOME, Date.now, Bun.sleep and fs spies are process-global.
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
function harness(mode: string, password = "fake-password", options: HarnessOptions = {}) {
  const policy = options.policy ?? freshPolicy();
  const calls: string[] = [];
  const dispatchScopes: Array<{ call: string; digest: string | undefined }> = [];
  const recordCall = (call: string) => {
    calls.push(call);
    dispatchScopes.push({ call, digest: currentCommandDigest() });
  };
  const log = join(root, "chain.jsonl");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const lines = () => fs.existsSync(log) ? fs.readFileSync(log, "utf8").trim().split("\n") : [];
  const signedReceipts = () => lines().map(line => JSON.parse(line));
  const durable = new Set<string>();
  let journalFd: number | undefined;
  const open = fs.openSync, sync = fs.fsyncSync;
  spies.push(spyOn(fs, "openSync").mockImplementation((...args: Parameters<typeof open>) => {
    const fd = open(...args);
    if (args[0] === join(root, "receipts", "aar", "journal.jsonl")) journalFd = fd;
    return fd;
  }));
  spies.push(spyOn(fs, "fsyncSync").mockImplementation(fd => {
    sync(fd);
    if (journalFd === fd) {
      for (const record of journalRecords()) {
        if (record.event === "attempt_committed") durable.add(record.invocation_id);
      }
      journalFd = undefined;
    }
  }));
  const assertCommitted = () => {
    const id = currentInvocationId()!;
    expect(id).toMatch(/^[0-9a-f]{32}$/);
    const records = fs.readFileSync(join(root, "receipts", "aar", "journal.jsonl"), "utf8").trim().split("\n").map(line => JSON.parse(line));
    expect(records.some(r => r.event === "attempt_committed" && r.invocation_id === id)).toBe(true);
    expect(durable.has(id)).toBe(true);
  };
  const handlers: Record<string, (input: any) => Promise<any>> = {};
  const rawHandlers: typeof handlers = {};
  const credentialChannel = (path: string) => {
    const request = curlRequest({ base: "https://camera.invalid", user: "test" }, password, path, {
      invocationId: currentInvocationId(), commandDigest: currentCommandDigest(),
    });
    expect(request.args.join(" ")).not.toContain(password);
    expect(request.stdin).toContain(password.replace(/\\/g, "\\\\").replace(/"/g, '\\"')); // Only credential channel; no process/network.
  };
  const dependencies = {
    AarWireProducer, commandDigestHex, runAsDispatch, sendPreset, sendSnapshot, createHash, join, cameraId, presetName, formatPresetRecall, snapshotContent,
    claimInvocationForAar, currentInvocationId, appendLocked, outcomeEvidence, edSign, LOG: log, PRIV: privateKey,
    ROOT: root, AGENT: "test-agent", policyBytes: Buffer.from("policy"),
    cameras: { cam: options.camera ?? { ptz: true, protocol: "vapix" } }, policy,
    existsSync: fs.existsSync, readFileSync: fs.readFileSync,
    allowed: (tool: string, camera?: string) => mode === "deny" ? "agent has no grant" : policyAllowed(policy, agent, tool, camera),
    rateDenied: options.rateDenied ?? (() => null),
    deviceMeta: async () => { recordCall("metadata"); return { manufacturer: "AXIS", model: "test", firmware: "0" }; },
    server: { tool: (name: string, _description: string, _schema: unknown, handler: any) => { rawHandlers[name] = handler; handlers[name] = input => runWithInvocation(() => handler(input)); } },
    snapshot: async (_tool: string, _camera: string, path: string) => {
      assertCommitted();
      recordCall("snapshot");
      credentialChannel("/axis-cgi/jpg/image.cgi");
      if (mode === "throws") throw Error("stand-in-camera-password");
      if (mode === "snapshot-failure") return false;
      fs.writeFileSync(path, Buffer.from([255, 216, 255, 217]));
      return true;
    },
    vapix: async (_tool: string, _camera: string, path: string) => {
      credentialChannel(path);
      const readback = path.includes("query=position");
      recordCall(readback ? "readback" : "recall");
      assertCommitted();
      if (mode === "throws") throw Error("stand-in-camera-password");
      if (mode === "overrun") now += 61_000;
      if (mode === "backwards") now -= 1000;
      if (mode === "transport-failure" || (readback && mode === "readback-failure")) return { ok: false, body: "" };
      return { ok: true, body: readback ? "pan=1" : "OK" };
    },
  };
  const emitAar = new Function(...Object.keys(dependencies), code + "\nreturn emitAar;")(...Object.values(dependencies));
  return { handlers, rawHandlers, calls, dispatchScopes, emitAar, lines, signedReceipts, assertCommitted,
    publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(),
    get chain(): any[][] { return signedReceipts().map(r => [r.action.tool, r.action.params, r.decision, r.detail]); },
  };
}
function bundle(output: any) {
  const text = output.content.filter((c: any) => c.type === "text").map((c: any) => c.text).join("\n");
  const dir = text.match(/aar-bundle: (.+)/)?.[1];
  expect(dir).toBeDefined();
  const result = verifyBundleDir(repo, dir!);
  expect(result.output).toContain("Result: conformant");
  expect(result.conformant).toBe(true);
  const wire = decodeCbor(fs.readFileSync(join(dir!, "bundle.cbor"))) as any;
  return wire.artifacts.receipts.map((e: any[]) => decodeCbor(e[0] as Uint8Array)) as any[];
}

for (const [tool, protocol, ptz, preset] of [
  ["get_snapshot", "vapix", false, "Home"],
  ["get_snapshot", "onvif", true, "Home"],
  ["ptz_preset", "vapix", true, "Home"],
  ["ptz_preset", "vapix", true, "Side & Gate"],
] as const) {
  test(`W2a dispatch wiring: ${tool} ${protocol} ${preset} scopes the bundle's exact command digest`, async () => {
    const password = "stand-in-w2a-camera-password";
    const h = harness("ok", password, { camera: { protocol, ptz } });
    const output = await h.handlers[tool]!({ camera: "cam", preset });
    const receipts = bundle(output); // Actual bundle.cbor decoded and pyref-conformant.
    const attempt = receipts.find(r => r.kind === "action_attempt");
    const digest = toHex(attempt.body.command.command_digest);
    expect(digest).toMatch(/^[0-9a-f]{64}$/);
    expect(h.dispatchScopes).toEqual(tool === "get_snapshot" ? [
      { call: "metadata", digest: undefined }, { call: "snapshot", digest },
    ] : [
      { call: "metadata", digest: undefined }, { call: "recall", digest },
      { call: "readback", digest: undefined }, { call: "readback", digest: undefined },
    ]);
    const file = fs.readdirSync(join(root, "receipts")).find(name => name.endsWith(".jpg"));
    if (tool === "get_snapshot") expect(file).toMatch(/^snap-cam-\d+\.jpg$/);
    expect(digest).toBe(commandDigestHex({
      actionName: tool === "get_snapshot" ? "camera.stream.view" : "camera.ptz.preset",
      camera: "cam", cameraPtz: ptz, protocol,
      parameters: tool === "get_snapshot" ? { file: file! } : { preset },
    }));
    expect(currentCommandDigest()).toBeUndefined();
    expect(JSON.stringify(output)).not.toContain(password);
    expect(h.lines().join("\n")).not.toContain(password);
    expect(verifyChain(h.lines(), h.publicKey).bad).toEqual([]);
    const checkFiles = (dir: string) => {
      for (const name of fs.readdirSync(dir)) {
        const path = join(dir, name);
        if (fs.statSync(path).isDirectory()) checkFiles(path);
        else expect(fs.readFileSync(path).includes(Buffer.from(password))).toBe(false);
      }
    };
    checkFiles(join(root, "receipts"));
  });
}

function gateHarness(options: HarnessOptions = {}, caller = agent) {
  const policy = options.policy ?? freshPolicy();
  const calls: any[][] = [], chain: any[][] = [];
  const handlers: Record<string, (input: any) => Promise<any>> = {};
  const log = join(fs.mkdtempSync(join(root, "gates-")), "chain.jsonl");
  const cameras = { cam: { ptz: true, protocol: "vapix" }, other: { ptz: true, protocol: "vapix" } };
  const clock: ClockResult = {
    state: "ok", camera_time: "2027-01-15T08:00:00Z", host_before: "2027-01-15T08:00:00Z",
    host_after: "2027-01-15T08:00:00Z", offset_s: 0, uncertainty_s: 0,
    reference: "host system clock, sync not checked", ntp: null,
  };
  const dependencies = {
    z, cameraId, ptzBound, clockReceipt, formatClock, selectReceipts, formatReceiptsText,
    policy, cameras, AGENT: caller, LOG: log,
    existsSync: fs.existsSync, readFileSync: fs.readFileSync,
    allowed: (tool: string, camera?: string) => policyAllowed(policy, caller, tool, camera),
    rateDenied: options.rateDenied ?? (() => null),
    camOf: (camera: keyof typeof cameras) => cameras[camera],
    deviceInfo: async (...args: any[]) => { calls.push(["deviceInfo", ...args]); return "test device"; },
    clockCheck: async (tool: string, camera: string) => { calls.push(["clockCheck", tool, camera]); return clock; },
    ptzMove: async (...args: any[]) => { calls.push(["ptzMove", ...args]); return true; },
    vapixPost: () => { throw Error("unexpected transport"); },
    receipt: (...args: any[]) => {
      chain.push(args);
      fs.appendFileSync(log, JSON.stringify({ principal: { id: caller }, tool: args[0], decision: args[2] }) + "\n");
    },
    server: { tool: (name: string, _description: string, _schema: unknown, handler: any) => { handlers[name] = input => runWithInvocation(() => handler(input)); } },
  };
  new Function(...Object.keys(dependencies), gateCode)(...Object.values(dependencies));
  return { handlers, calls, chain, log };
}

function outputText(output: any): string {
  return output.content.filter((c: any) => c.type === "text").map((c: any) => c.text).join("\n");
}
function denial(h: { chain: any[][] }, output: any, tool: string, params: object, reason: string) {
  expect(outputText(output).split("\n")[0]).toBe(`DENIED: ${reason}`);
  expect(h.chain).toEqual([[tool, params, "deny", reason]]);
}

test("tool gate wiring: ptz_move enforces maxStep before dispatch", async () => {
  const h = gateHarness();
  const params = { camera: "cam", pan: 31, tilt: 0, zoom: 0 };
  denial(h, await h.handlers.ptz_move!(params), "ptz_move", params, "step exceeds policy maxStep 30°");
  expect(h.calls).toEqual([]);
});

test("tool gate wiring: ptz_move enforces actuation rate before dispatch", async () => {
  const rates: string[] = [];
  const h = gateHarness({ rateDenied: key => { rates.push(key); return "actuation rate exhausted"; } });
  const params = { camera: "cam", pan: 1, tilt: 0, zoom: 0 };
  denial(h, await h.handlers.ptz_move!(params), "ptz_move", params, "actuation rate exhausted");
  expect(h.calls).toEqual([]);
  expect(rates).toEqual(["actuation"]);
});

test("tool gate wiring: ptz_move permits a step at maxStep", async () => {
  const h = gateHarness();
  const params = { camera: "cam", pan: 30, tilt: 0, zoom: 0 };
  expect(outputText(await h.handlers.ptz_move!(params))).toBe("moved cam pan=30° tilt=0° zoom=0 (vapix)");
  expect(h.calls).toEqual([["ptzMove", "ptz_move", "cam", 30, 0, 0]]);
  expect(h.chain).toEqual([["ptz_move", params, "allow", "moved via vapix"]]);
});

test("tool gate wiring: ptz_preset requires an agent ptz grant", async () => {
  const policy = freshPolicy();
  delete policy[agent]!.ptz;
  const h = harness("ok", undefined, { policy });
  const params = { camera: "cam", preset: "Home" };
  const output = await h.handlers.ptz_preset!(params);
  denial(h, output, "ptz_preset", params, "agent has no ptz grant");
  expect(h.calls).toEqual([]);
  expect(bundle(output).find(r => r.kind === "action_attempt").body.disposition).toBe("not_dispatched");
});

test("tool gate wiring: get_snapshot enforces snapshot rate before capture", async () => {
  const rates: string[] = [];
  const h = harness("ok", undefined, { rateDenied: key => { rates.push(key); return "snapshot rate exhausted"; } });
  const params = { camera: "cam" };
  const output = await h.handlers.get_snapshot!(params);
  denial(h, output, "get_snapshot", params, "snapshot rate exhausted");
  expect(h.calls).toEqual([]);
  expect(rates).toEqual(["snapshot"]);
  expect(bundle(output).find(r => r.kind === "action_attempt").body.disposition).toBe("not_dispatched");
});

for (const tool of ["ptz_preset", "get_snapshot"]) {
  test(`tool gate wiring: ${tool} permits a granted call`, async () => {
    const h = harness("ok");
    const output = await h.handlers[tool]!({ camera: "cam", preset: "Home" });
    expect(outputText(output)).not.toContain("DENIED:");
    expect(h.calls).toEqual(tool === "ptz_preset" ? ["metadata", "recall", "readback", "readback"] : ["metadata", "snapshot"]);
    expect(h.chain).toHaveLength(1);
    expect(h.chain[0]!.slice(0, 3)).toEqual([tool, tool === "ptz_preset" ? { camera: "cam", preset: "Home" } : { camera: "cam" }, "allow"]);
    expect(bundle(output).find(r => r.kind === "dispatch")).toBeDefined();
  });
}

for (const blocked of ["tool", "camera"]) {
  test(`tool gate wiring: clock_check denies a disallowed ${blocked}`, async () => {
    const policy = freshPolicy();
    if (blocked === "tool") policy[agent]!.tools = [];
    else policy[agent]!.cameras = [];
    const h = gateHarness({ policy });
    const params = { camera: "cam" };
    const reason = `${blocked} '${blocked === "tool" ? "clock_check" : "cam"}' not allowlisted for agent '${agent}'`;
    denial(h, await h.handlers.clock_check!(params), "clock_check", params, reason);
    expect(h.calls).toEqual([]);
  });
}

test("tool gate wiring: clock_check permits a granted camera", async () => {
  const h = gateHarness();
  const output = await h.handlers.clock_check!({ camera: "cam" });
  expect(outputText(output)).toContain("cam clock: observed +0 s");
  expect(h.calls).toEqual([["clockCheck", "clock_check", "cam"]]);
  expect(h.chain).toHaveLength(1);
  expect(h.chain[0]!.slice(0, 3)).toEqual(["clock_check", { camera: "cam" }, "allow"]);
});

test("tool gate wiring: list_cameras denies a disallowed tool", async () => {
  const policy = freshPolicy();
  policy[agent]!.tools = [];
  const h = gateHarness({ policy });
  denial(h, await h.handlers.list_cameras!({}), "list_cameras", {}, `tool 'list_cameras' not allowlisted for agent '${agent}'`);
  expect(h.calls).toEqual([]);
});

test("tool gate wiring: list_cameras returns only granted cameras", async () => {
  const h = gateHarness();
  expect(outputText(await h.handlers.list_cameras!({}))).toBe("cam: test device");
  expect(h.calls).toEqual([["deviceInfo", "list_cameras", "cam"]]);
  expect(h.chain).toEqual([["list_cameras", {}, "allow", "returned 1 cameras"]]);
});

test("tool gate wiring: list_cameras succeeds with an empty camera grant", async () => {
  const policy = freshPolicy();
  policy[agent]!.cameras = [];
  const h = gateHarness({ policy });
  expect(outputText(await h.handlers.list_cameras!({}))).toBe("");
  expect(h.calls).toEqual([]);
  expect(h.chain).toEqual([["list_cameras", {}, "allow", "returned 0 cameras"]]);
});

for (const caller of [agent, "other-agent"]) {
  test(`tool gate wiring: get_receipts isolates ${caller} in an interleaved chain`, async () => {
    const policy = freshPolicy();
    policy["other-agent"] = structuredClone(policy[agent]!);
    const h = gateHarness({ policy }, caller);
    const lines = [agent, "other-agent", agent, "other-agent", agent, "other-agent"].map((id, i) =>
      JSON.stringify({ seq: i + 1, principal: { id }, tool: "clock_check", decision: "allow", detail: `receipt ${i + 1}` }));
    fs.writeFileSync(h.log, lines.join("\n") + "\n");
    const output = await h.handlers.get_receipts!({ n: 2 });
    // Explicit expected positions pin filtering BEFORE truncation, for both callers.
    expect(outputText(output)).toBe(caller === agent ? [lines[2], lines[4]].join("\n") : [lines[3], lines[5]].join("\n"));
    expect(h.chain).toEqual([["get_receipts", { n: 2 }, "allow", "returned 2"]]);
    expect(h.calls).toEqual([]);
  });
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
  failJournal("attempt_envelope");
  const output = await h.handlers.get_snapshot!({ camera: "cam" });
  expect(h.calls).toEqual(["metadata"]);
  expect(bundle(output).find(r => r.kind === "action_attempt").body).toMatchObject({ disposition: "not_dispatched", refusal_reason: "journal/unavailable" });
});

test("actual preset handler on journal failure never recalls or records transport error", async () => {
  const h = harness("ok");
  failJournal("attempt_envelope");
  const output = await h.handlers.ptz_preset!({ camera: "cam", preset: "Home" });
  expect(h.calls).toEqual(["metadata"]);
  expect(JSON.stringify(h.chain)).not.toContain("transport error");
  expect(JSON.stringify(output)).toContain("preset not dispatched");
  expect(bundle(output).find(r => r.kind === "action_attempt").body).toMatchObject({ disposition: "not_dispatched", refusal_reason: "journal/unavailable" });
});

test("actual preset handler late journal refusal fails loudly with JSONL aar_emit and no send", async () => {
  const h = harness("ok");
  failJournal("attempt_envelope", true);
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

function failJournal(event: string, late = false) {
  const append = fs.appendFileSync;
  spies.push(spyOn(fs, "appendFileSync").mockImplementation((...args: Parameters<typeof append>) => {
    if (String(args[1]).includes(`"event":"${event}"`)) {
      if (late) now += 1000;
      throw Error("journal unavailable");
    }
    return append(...args);
  }));
}

function producerTree(path = join(root, "receipts", "aar")): unknown {
  if (!fs.statSync(path).isDirectory()) return fs.readFileSync(path).toString("hex");
  return Object.fromEntries(fs.readdirSync(path).sort().map(name => [name, producerTree(join(path, name))]));
}
function journalRecords(): any[] {
  const path = join(root, "receipts", "aar", "journal.jsonl");
  return fs.existsSync(path) ? fs.readFileSync(path, "utf8").trim().split("\n").filter(Boolean).map(line => JSON.parse(line)) : [];
}
function assertSigned(h: ReturnType<typeof harness>, id: string | null) {
  expect(h.lines().length).toBeGreaterThan(0);
  expect(verifyChain(h.lines(), h.publicKey)).toEqual({ count: h.lines().length, bad: [] });
  for (const r of h.signedReceipts()) expect(r.invocation_id).toBe(id);
}

for (const tool of ["get_snapshot", "ptz_preset"]) {
  for (const mode of ["ok", "deny", "journal-unavailable"]) {
    test(`W2b invocation binding: ${tool} ${mode} binds signed chain, bundle and journal`, async () => {
      const h = harness(mode);
      // Fail the marker after the envelope was written, so the refusal path
      // exercises both a written attempt and refusal_persisted with this ID.
      if (mode === "journal-unavailable") failJournal("attempt_committed");
      await runWithInvocation(async () => {
        const id = currentInvocationId()!;
        const output = await h.rawHandlers[tool]!({ camera: "cam", preset: "Home" });
        const rs = bundle(output); // Decodes bundle.cbor and verifies with pyref.
        expect(outputText(output).match(/aar-bundle: (.+)/)![1]!.endsWith(id.slice(0, 8))).toBe(true);
        for (const r of rs) expect(toHex(r.freshness.invocation_id)).toBe(id);
        const attempt = rs.find(r => r.kind === "action_attempt");
        expect(toHex(attempt.body.command.idempotency_key)).toBe(id);
        const dispatch = rs.find(r => r.kind === "dispatch");
        if (mode === "ok") {
          expect(toHex(dispatch.body.adapter_invocation_id)).toBe(id);
          expect(journalRecords().map(r => r.event)).toEqual(["attempt_envelope", "attempt_committed", "dispatch_completed"]);
        } else {
          expect(dispatch).toBeUndefined();
          expect(attempt.body.disposition).toBe("not_dispatched");
          expect(h.calls).toEqual(mode === "deny" ? [] : ["metadata"]);
          if (mode === "deny") expect(fs.existsSync(join(root, "receipts", "aar", "journal.jsonl"))).toBe(false);
          else expect(journalRecords().map(r => r.event)).toEqual(["attempt_envelope", "refusal_persisted"]);
        }
        for (const record of journalRecords()) expect(record.invocation_id).toBe(id);
        assertSigned(h, id);
      });
    });
  }
}

for (const mode of ["ok", "throws", "throws-pending", "completion-failure"]) {
  test(`W2b invocation binding: actual emitAar rejects a second claim after ${mode} without producer changes`, async () => {
    const h = harness("ok");
    if (mode === "completion-failure") failJournal("dispatch_completed");
    // If the ambiguous marker itself cannot be written, recovery must retain
    // the original pending attempt; a successful ambiguity marker closes it.
    if (mode === "throws-pending") failJournal("dispatch_ambiguous");
    await runWithInvocation(async () => {
      const id = currentInvocationId()!;
      let sends = 0;
      const send = async () => {
        h.assertCommitted();
        sends++;
        expect(journalRecords().at(-1)).toMatchObject({ event: "attempt_committed", invocation_id: id });
        if (mode.startsWith("throws")) throw Error("transport failed");
        return { dispatch: { status: 200, responseBody: Buffer.from("ok"), observation: Buffer.from("position"),
          outcomeLevel: "device_acknowledged", outcomeState: "unknown" }, dispatchedAt: now / 1000, outcomeObservedAt: now / 1000 };
      };
      const emit = () => h.emitAar("ptz_preset", "cam", "camera.ptz.preset", { preset: "Home" }, now / 1000, { send });
      const first = await emit();
      expect(first).toContain(mode === "ok" ? "aar-bundle:" : "aar-emit FAILED:");
      if (mode === "ok") bundle({ content: [{ type: "text", text: first }] });
      const before = producerTree();
      const receiptCount = h.signedReceipts().length;
      const second = await emit();
      expect(second).toBe("\naar-emit FAILED: invocation already claimed for AAR emission");
      expect(h.calls).toEqual(["metadata"]);
      expect(sends).toBe(1);
      expect(producerTree()).toEqual(before);
      expect(h.signedReceipts()).toHaveLength(receiptCount + 1);
      expect(h.signedReceipts().at(-1)).toMatchObject({ action: { tool: "aar_emit" }, decision: "allow",
        detail: "wire emission FAILED: invocation already claimed for AAR emission" });
      assertSigned(h, id);
      for (const record of journalRecords()) expect(record.invocation_id).toBe(id);
      const warning = spyOn(console, "error").mockImplementation(() => {});
      spies.push(warning);
      checkAarJournal(join(root, "receipts", "aar", "journal.jsonl"));
      if (mode === "throws-pending" || mode === "completion-failure") {
        expect(warning.mock.calls.flat().join(" ")).toContain(`invocation ${id} has no completion`);
      } else expect(warning).not.toHaveBeenCalled();
    });
  });
}

test("W2b invocation binding: actual emitAar outside a run signs a null-ID failure without metadata or producer changes", async () => {
  const h = harness("ok");
  const before = producerTree();
  expect(currentInvocationId()).toBeUndefined();
  const output = await h.emitAar("get_snapshot", "cam", "camera.stream.view", {}, now / 1000, {
    send: async () => { throw Error("unexpected send"); },
  });
  expect(output).toBe("\naar-emit FAILED: no invocation context");
  expect(h.calls).toEqual([]);
  expect(producerTree()).toEqual(before);
  expect(h.signedReceipts()).toHaveLength(1);
  expect(h.signedReceipts()[0]).toMatchObject({ action: { tool: "aar_emit" }, decision: "allow", detail: "wire emission FAILED: no invocation context" });
  assertSigned(h, null);
});
