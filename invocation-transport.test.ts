import { expect, spyOn, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { accountFor } from "./account-for";
import { curlRequest } from "./curl-args";
import { parseSnapshotUri, snapshotPath } from "./device-info";
import { parseParams } from "./vapix-params";
import { currentInvocationId, runWithInvocation } from "./invocation";

// Execute the actual helpers without importing index.ts (startup accesses credentials/keys).
const source = readFileSync(resolve(import.meta.dir, "index.ts"), "utf8");
const helpers = source.slice(source.indexOf("async function vapix("), source.indexOf("async function observeEvents("))
  + source.slice(source.indexOf("async function configParams("), source.indexOf("// Transport dispatch:"));
const code = new Bun.Transpiler({ loader: "ts" }).transformSync(helpers);

const snapshotCode = new Bun.Transpiler({ loader: "ts" }).transformSync(
  helpers + source.slice(source.indexOf("async function snapshot("), source.indexOf("async function ptzMove(")),
);

async function captureSnapshot(uri: string, base: string, protocol = "onvif") {
  const calls: Array<{ args: string[]; stdin: string }> = [];
  const password = "stand-in-snapshot-password";
  const outFile = join(tmpdir(), "snapshot-origin.jpg");
  const dependencies = {
    curlRequest, currentInvocationId, accountFor, parseParams, parseSnapshotUri, snapshotPath,
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
    const result = await snapshot("get_snapshot", "cam", outFile);
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
    curlRequest, currentInvocationId, accountFor, parseParams,
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
