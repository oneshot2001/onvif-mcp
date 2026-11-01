import { expect, spyOn, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { accountFor } from "./account-for";
import { curlRequest } from "./curl-args";
import { parseSnapshotUri, snapshotPath } from "./device-info";
import { parseParams } from "./vapix-params";
import { currentCommandDigest, currentInvocationId, runAsDispatch, runWithInvocation } from "./invocation";
import { AppendOnlyWitnessLog } from "aar-kat-harness/demo/witness/log";

// Execute the actual helpers without importing index.ts (startup accesses credentials/keys).
const source = readFileSync(resolve(import.meta.dir, "index.ts"), "utf8");
const helpers = source.slice(source.indexOf("async function vapix("), source.indexOf("async function observeEvents("))
  + source.slice(source.indexOf("async function configParams("), source.indexOf("// Transport dispatch:"));
const code = new Bun.Transpiler({ loader: "ts" }).transformSync(helpers);

const snapshotCode = new Bun.Transpiler({ loader: "ts" }).transformSync(
  helpers + source.slice(source.indexOf("async function snapshot("), source.indexOf("async function ptzMove(")),
);

const eventStart = source.indexOf("async function observeEvents(");
const eventEnd = source.indexOf("type Baseline =", eventStart);
if (eventStart < 0 || eventEnd <= eventStart) throw new Error("observeEvents slice boundaries missing");
const eventSource = source.slice(eventStart, eventEnd);
if (!eventSource.startsWith("async function observeEvents(")
  || !eventSource.trimEnd().endsWith("}")
  || !source.slice(eventEnd).startsWith("type Baseline =")) throw new Error("observeEvents slice boundaries invalid");
const eventCode = new Bun.Transpiler({ loader: "ts" }).transformSync(eventSource);

const accountCamera = {
  base: "https://camera.invalid", protocol: "onvif", user: "root-user", credKey: "kr",
  accounts: {
    viewer: { user: "viewer-user", credKey: "kv" },
    operator: { user: "operator-user", credKey: "ko" },
  },
};
const accountPasswords = { kr: "stand-in-root-password", kv: "stand-in-viewer-password", ko: "stand-in-operator-password" };
const accountCases = [
  ["get_snapshot", "viewer-user", "kv"],
  ["commission_verify", "viewer-user", "kv"],
  ["ptz_preset", "operator-user", "ko"],
  ["ptz_move", "operator-user", "ko"],
  ["config_remediate", "root-user", "kr"],
  ["commission_apply", "root-user", "kr"],
] as const;
type CurlCall = { args: string[]; stdin: string };

function accountTransports(body = "<Response/>", camera = accountCamera) {
  const calls: CurlCall[] = [];
  const dependencies = {
    curlRequest, currentInvocationId, currentCommandDigest, accountFor, parseParams, parseSnapshotUri, snapshotPath,
    camOf: () => camera, passwords: accountPasswords,
    process: { env: {} },
    Bun: { spawnSync(args: string[], opts: { stdin: Buffer }) {
      calls.push({ args: [...args], stdin: opts.stdin.toString() });
      return { exitCode: 0, stdout: Buffer.from(body), stderr: Buffer.alloc(0) };
    } },
  };
  const transports = new Function(
    ...Object.keys(dependencies), snapshotCode + "\nreturn { vapix, vapixPost, soap, snapshot };",
  )(...Object.values(dependencies));
  return { calls, ...transports };
}

function expectAccountCall(call: CurlCall, user: string, key: keyof typeof accountPasswords, result: unknown) {
  expect(call.stdin).toBe(`user = "${user}:${accountPasswords[key]}"\n`);
  expect(call.args.slice(call.args.indexOf("--config"), call.args.indexOf("--config") + 2)).toEqual(["--config", "-"]);
  const urls = call.args.filter(arg => /^https?:\/\//.test(arg));
  expect(urls).toHaveLength(1);
  expect(new URL(urls[0]!).username).toBe("");
  expect(new URL(urls[0]!).password).toBe("");
  for (const [otherKey, password] of Object.entries(accountPasswords)) {
    expect(JSON.stringify(call.args)).not.toContain(password);
    expect(JSON.stringify(result)).not.toContain(password);
    if (otherKey !== key) expect(call.stdin).not.toContain(password);
  }
}

for (const transport of ["vapix", "vapixPost", "soap"] as const) {
  for (const [tool, user, key] of accountCases) {
    test(`transport account wiring: ${transport} ${tool} selects ${user}`, async () => {
      const h = accountTransports();
      const result = await (transport === "soap"
        ? h.soap(tool, "cam", "<GetDeviceInformation/>")
        : transport === "vapixPost"
          ? h.vapixPost(tool, "cam", "/json", { method: "read" })
          : h.vapix(tool, "cam", "/get"));
      expect(result).toEqual({ ok: true, body: "<Response/>" });
      expect(h.calls).toHaveLength(1);
      expectAccountCall(h.calls[0]!, user, key, result);
    });
  }
}

for (const [tool, user, key] of accountCases.slice(0, 2)) {
  test(`transport account wiring: VAPIX snapshot ${tool} selects viewer`, async () => {
    const root = mkdtempSync(join(tmpdir(), "transport-account-"));
    try {
      const camera = { ...accountCamera, protocol: "vapix" };
      const h = accountTransports("", camera);
      const outFile = join(root, "snapshot.jpg");
      const result = await h.snapshot(tool, "cam", outFile);
      expect(result).toBe(true);
      expect(h.calls).toHaveLength(1);
      expect(h.calls[0]!.args[0]).toBe("curl");
      expect(h.calls[0]!.args.slice(-3)).toEqual([`${camera.base}/axis-cgi/jpg/image.cgi`, "-o", outFile]);
      expectAccountCall(h.calls[0]!, user, key, result);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test(`transport account wiring: ONVIF snapshot ${tool} selects viewer at both stages`, async () => {
    const root = mkdtempSync(join(tmpdir(), "transport-account-"));
    try {
      const h = accountTransports("<tt:Uri>https://camera.invalid/snapshot.jpg</tt:Uri>");
      const outFile = join(root, "snapshot.jpg");
      const result = await h.snapshot(tool, "cam", outFile);
      expect(result).toBe(true);
      expect(h.calls).toHaveLength(2);
      expect(h.calls[0]!.args.at(-1)).toBe(`${accountCamera.base}/onvif/services`);
      expect(h.calls[0]!.args.join(" ")).toContain("GetSnapshotUri");
      expect(h.calls[0]!.args).not.toContain("-o");
      expect(h.calls[1]!.args.slice(-3)).toEqual([`${accountCamera.base}/snapshot.jpg`, "-o", outFile]);
      for (const call of h.calls) expectAccountCall(call, user, key, result);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
}

for (const [label, body, ok] of [
  ["s:Fault", "<s:Envelope><s:Body><s:Fault>failed</s:Fault></s:Body></s:Envelope>", false],
  ["SOAP-ENV:Fault", "<SOAP-ENV:Envelope><SOAP-ENV:Body><SOAP-ENV:Fault>failed</SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>", false],
  ["normal body", "<s:Envelope><s:Body><Response/></s:Body></s:Envelope>", true],
] as const) {
  test(`transport account wiring: soap exit 0 with ${label} has ok ${ok}`, async () => {
    const h = accountTransports(body);
    const result = await h.soap("commission_verify", "cam", "<GetDeviceInformation/>");
    expect(result.ok).toBe(ok);
    expect(result.body).toBe(body);
    expect(h.calls).toHaveLength(1);
    expectAccountCall(h.calls[0]!, "viewer-user", "kv", result);
  });
}

for (const [tool, user, key] of [accountCases[1], accountCases[5]]) {
  test(`transport account wiring: observeEvents ${tool} selects ${user} in credential thunk`, async () => {
    const credentials: Array<{ user: string; password: string }> = [];
    const timers = new Set<ReturnType<typeof setTimeout>>();
    const listeners: string[] = [];
    let closes = 0;
    const socket = new EventTarget();
    const ws = {
      readyState: WebSocket.CONNECTING,
      close() { closes++; },
      addEventListener(type: string, listener: EventListener) {
        listeners.push(type);
        socket.addEventListener(type, listener);
      },
    };
    const dependencies = {
      accountFor, camOf: () => accountCamera, passwords: accountPasswords,
      process: { env: {} }, WebSocket,
      openEventWebSocket(cam: typeof accountCamera, credential: () => { user: string; password: string }) {
        expect(cam).toBe(accountCamera);
        credentials.push(credential());
        queueMicrotask(() => socket.dispatchEvent(new Event("error")));
        return ws;
      },
      setTimeout(callback: () => void, ms: number) {
        const timer = setTimeout(callback, ms);
        timers.add(timer);
        return timer;
      },
      clearTimeout(timer: ReturnType<typeof setTimeout>) {
        timers.delete(timer);
        clearTimeout(timer);
      },
    };
    const observeEvents = new Function(...Object.keys(dependencies), eventCode + "\nreturn observeEvents;")(...Object.values(dependencies));
    try {
      const result = await observeEvents(tool, "cam", ["test/topic"], 1);
      expect(credentials).toEqual([{ user, password: accountPasswords[key] }]);
      expect(listeners).toEqual(["open", "message", "error", "close"]);
      expect(result).toEqual({ events: [], warnings: ["event WebSocket failed"] });
      expect(closes).toBe(1);
      expect(timers.size).toBe(0);
      for (const [otherKey, password] of Object.entries(accountPasswords)) {
        expect(JSON.stringify(result)).not.toContain(password);
        expect(JSON.stringify(accountCamera)).not.toContain(password);
        if (otherKey !== key) expect(JSON.stringify(credentials)).not.toContain(password);
      }
    } finally {
      for (const timer of timers) clearTimeout(timer);
    }
  });
}

async function captureSnapshot(uri: string, base: string, protocol = "onvif", commandDigest?: string) {
  const calls: Array<{ args: string[]; stdin: string }> = [];
  const password = "stand-in-snapshot-password";
  const outFile = join(tmpdir(), "snapshot-origin.jpg");
  const dependencies = {
    curlRequest, currentInvocationId, currentCommandDigest, accountFor, parseParams, parseSnapshotUri, snapshotPath,
    camOf: () => ({ base, protocol, user: "snapshot-user", credKey: "test" }),
    passwords: { test: password },
  };
  const snapshot = new Function(
    ...Object.keys(dependencies), snapshotCode + "\nreturn snapshot;",
  )(...Object.values(dependencies));
  const spawn = spyOn(Bun, "spawnSync").mockImplementation(((args: string[], opts: { stdin: Buffer }) => {
    calls.push({ args: [...args], stdin: opts.stdin.toString() });
    const body = args.includes(`${base}/onvif/services`)
      ? `<tt:Uri>${uri.replace(/&/g, "&amp;")}</tt:Uri>` : "";
    return { exitCode: 0, stdout: Buffer.from(body), stderr: Buffer.alloc(0) };
  }) as typeof Bun.spawnSync);
  try {
    const capture = () => snapshot("get_snapshot", "cam", outFile);
    const result = await (commandDigest === undefined ? capture() : runAsDispatch(commandDigest, capture));
    for (const { args, stdin } of calls) {
      expect(stdin).toBe(`user = "snapshot-user:${password}"\n`);
      expect(JSON.stringify(args)).not.toContain(password);
      expect(args.slice(args.indexOf("--config"), args.indexOf("--config") + 2)).toEqual(["--config", "-"]);
    }
    expect(JSON.stringify(result)).not.toContain(password);
    return { result, calls, outFile };
  } finally {
    spawn.mockRestore();
  }
}

for (const base of ["http://192.168.1.32", "https://camera.invalid:9443"]) {
  test.each([
    ["@attacker.example/x.jpg", null],
    [".attacker.example/x.jpg", null],
    [":8443/x.jpg", null],
    ["x.jpg", null],
    ["//attacker.example/x.jpg", null],
    ["ftp://attacker.example/x.jpg", null],
    ["http://[invalid/x.jpg", null],
    ["HTTP://attacker.example/x.jpg", "/x.jpg"],
    ["hTtPs://attacker.example:8443/x.jpg", "/x.jpg"],
    ["https://user:uri-password@attacker.example/x.jpg", "/x.jpg"],
    ["/axis-cgi/jpg/image.cgi", "/axis-cgi/jpg/image.cgi"],
    ["/x.jpg?a=1&b=2#fragment", "/x.jpg?a=1&b=2"],
    ["http://attacker.example/x.jpg?a=1&b=2#fragment", "/x.jpg?a=1&b=2"],
    ["http://attacker.example//other.example/x.jpg", "//other.example/x.jpg"],
  ])(`snapshot origin: ${base} fetch for %s`, async (uri, path) => {
    const { result, calls, outFile } = await captureSnapshot(uri!, base);
    expect(calls[0]!.args.at(-1)).toBe(`${base}/onvif/services`);
    expect(calls[0]!.args).not.toContain("-o");
    expect(result).toBe(path !== null);
    expect(calls).toHaveLength(path === null ? 1 : 2);
    if (path !== null) {
      const args = calls[1]!.args;
      expect(args.slice(-3)).toEqual([base + path, "-o", outFile]);
      const url = new URL(args.at(-3)!);
      expect(url.origin).toBe(base);
      expect(url.pathname + url.search).toBe(path);
      expect(url.username).toBe("");
      expect(url.password).toBe("");
      expect(url.hash).toBe("");
    }
  });
}

test("snapshot origin: VAPIX keeps its direct image fetch", async () => {
  const base = "https://camera.invalid:9443";
  const { result, calls, outFile } = await captureSnapshot("", base, "vapix");
  expect(result).toBe(true);
  expect(calls).toHaveLength(1);
  expect(calls[0]!.args.slice(-3)).toEqual([`${base}/axis-cgi/jpg/image.cgi`, "-o", outFile]);
});

test("invocations are installed immediately after server creation, before commission registration", () => {
  expect(source).toMatch(/const server = new McpServer\([^\n]+\);\nwithInvocations\(server\);\nregisterCommission\(server,/);
});

test("actual transport helpers pass the active invocation ID into every curl argv", async () => {
  const calls: string[][] = [];
  const spawn = spyOn(Bun, "spawnSync").mockImplementation(((args: string[]) => {
    calls.push([...args]);
    return { exitCode: 0, stdout: Buffer.from("root.Brand.Name=Test\n"), stderr: Buffer.alloc(0) };
  }) as typeof Bun.spawnSync);
  const dependencies = {
    curlRequest, currentInvocationId, currentCommandDigest, accountFor, parseParams,
    camOf: () => ({ base: "https://camera.invalid", user: "test", credKey: "test" }),
    passwords: { test: "fake-password" },
  };
  const { vapix, vapixPost, soap, configParams } = new Function(
    ...Object.keys(dependencies), code + "\nreturn { vapix, vapixPost, soap, configParams };",
  )(...Object.values(dependencies));
  try {
    await runWithInvocation(async () => {
      const id = currentInvocationId();
      expect(id).toMatch(/^[0-9a-f]{32}$/);
      const requests = [
        () => vapix("list_cameras", "cam", "/get"),
        () => vapix("get_snapshot", "cam", "/snapshot", join(tmpdir(), "invocation-snapshot.jpg")),
        () => vapixPost("clock_check", "cam", "/json", { method: "read" }),
        () => soap("list_cameras", "cam", "<GetDeviceInformation/>"),
        () => configParams("config_baseline", "cam", ["Brand"]),
      ];
      for (const request of requests) {
        const count = calls.length;
        expect((await request()).ok).toBe(true);
        expect(calls).toHaveLength(count + 1);
        const args = calls[count]!;
        const header = `X-AAR-Invocation-ID: ${id}`;
        expect(args.filter(arg => arg.startsWith("X-AAR-Invocation-ID:"))).toEqual([header]);
        expect(args[args.indexOf(header) - 1]).toBe("-H");
        expect(currentInvocationId()).toBe(id);
      }
    });
    expect(currentInvocationId()).toBeUndefined();
  } finally {
    spawn.mockRestore();
  }
});

function expectMarks(args: string[], digest?: string) {
  const marks = args.filter(arg => /^X-AAR-(Action-Bearing|Command-Digest):/.test(arg));
  expect(marks).toEqual(digest === undefined ? [] : ["X-AAR-Action-Bearing: 1", `X-AAR-Command-Digest: ${digest}`]);
  for (const mark of marks) expect(args[args.indexOf(mark) - 1]).toBe("-H");
}

for (const protocol of ["onvif", "vapix"]) {
  test(`W2a dispatch wiring: actual ${protocol} snapshot marks only the image fetch`, async () => {
    const digest = "a1".repeat(32);
    const base = "https://camera.invalid:9443";
    const { result, calls, outFile } = await captureSnapshot("/onvif-snapshot.jpg", base, protocol, digest);
    expect(result).toBe(true);
    expect(calls).toHaveLength(protocol === "onvif" ? 2 : 1);
    if (protocol === "onvif") {
      expect(calls[0]!.args.join(" ")).toContain("GetSnapshotUri");
      expect(calls[0]!.args.at(-1)).toBe(`${base}/onvif/services`);
      expectMarks(calls[0]!.args);
    }
    const image = calls.at(-1)!.args;
    expect(image.slice(-3)).toEqual([base + (protocol === "onvif" ? "/onvif-snapshot.jpg" : "/axis-cgi/jpg/image.cgi"), "-o", outFile]);
    expectMarks(image, digest);
    expect(currentCommandDigest()).toBeUndefined();
  });
}

test("W2a dispatch wiring: actual transports mark only VAPIX in dispatch scope", async () => {
  const digest = "b2".repeat(32);
  const password = "stand-in-dispatch-password";
  const calls: Array<{ args: string[]; stdin: string }> = [];
  const dependencies = {
    curlRequest, currentInvocationId, currentCommandDigest, accountFor, parseParams,
    camOf: () => ({ base: "https://camera.invalid", user: "test", credKey: "test" }),
    passwords: { test: password },
  };
  const { vapix, vapixPost, soap, configParams } = new Function(
    ...Object.keys(dependencies), code + "\nreturn { vapix, vapixPost, soap, configParams };",
  )(...Object.values(dependencies));
  const spawn = spyOn(Bun, "spawnSync").mockImplementation(((args: string[], opts: { stdin: Buffer }) => {
    calls.push({ args: [...args], stdin: opts.stdin.toString() });
    return { exitCode: 0, stdout: Buffer.from("root.Brand.Name=Test\n"), stderr: Buffer.alloc(0) };
  }) as typeof Bun.spawnSync);
  try {
    await runWithInvocation(async () => {
      const id = currentInvocationId();
      for (const scoped of [false, true, false]) {
        const requests = async () => {
          for (const [request, marked] of [
            [() => vapix("ptz_preset", "cam", "/recall"), scoped],
            [() => soap("get_snapshot", "cam", "<GetSnapshotUri/>"), false],
            [() => vapixPost("clock_check", "cam", "/json", { method: "read" }), false],
            // configParams inherits scope through vapix; it has no suppression rule.
            [() => configParams("config_baseline", "cam", ["Brand"]), scoped],
          ] as const) {
            expect((await request()).ok).toBe(true);
            const { args, stdin } = calls.at(-1)!;
            expectMarks(args, marked ? digest : undefined);
            expect(args).toContain(`X-AAR-Invocation-ID: ${id}`);
            expect(args).toContain("--digest");
            expect(args.slice(args.indexOf("--config"), args.indexOf("--config") + 2)).toEqual(["--config", "-"]);
            expect(JSON.stringify(args)).not.toContain(password);
            expect(stdin).toBe(`user = "test:${password}"\n`);
          }
        };
        await (scoped ? runAsDispatch(digest, requests) : requests());
        expect(currentCommandDigest()).toBeUndefined();
      }
    });
    expect(calls).toHaveLength(12);
  } finally {
    spawn.mockRestore();
  }
});

test("W2a dispatch wiring: witness counts both marked Digest 401 and 200 exchanges", async () => {
  const root = mkdtempSync(join(tmpdir(), "w2a-witness-"));
  try {
    // Execute the pinned AAR witness filter, without starting its proxy/listener.
    const log = new AppendOnlyWitnessLog(join(root, "witness.jsonl"));
    const invocationId = "c3".repeat(16);
    const exchange = {
      timestamp: "2026-10-27T00:00:00.000Z", invocation_id: invocationId,
      command_digest: "d4".repeat(32), action_bearing: true,
      request_line: "GET http://camera.invalid/axis-cgi/jpg/image.cgi HTTP/1.1",
      request_body_sha256: "e5".repeat(32), response_body_sha256: "f6".repeat(32),
    };
    const pair = ["HTTP/1.1 401 Unauthorized", "HTTP/1.1 200 OK"].map(response_line => ({ ...exchange, response_line }));
    for (const entry of pair) await log.append(entry);
    await log.append({ ...pair[1]!, action_bearing: false });
    await log.append({ ...pair[1]!, invocation_id: "00".repeat(16) });
    const attributable = await log.attributableDispatches(invocationId);
    expect(attributable).toHaveLength(2);
    expect(attributable).toEqual(pair);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
