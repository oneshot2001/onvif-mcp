import { expect, spyOn, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { accountFor } from "./account-for";
import { curlRequest } from "./curl-args";
import { parseParams } from "./vapix-params";
import { currentInvocationId, runWithInvocation } from "./invocation";

// Execute the actual helpers without importing index.ts (startup accesses credentials/keys).
const source = readFileSync(resolve(import.meta.dir, "index.ts"), "utf8");
const helpers = source.slice(source.indexOf("async function vapix("), source.indexOf("async function observeEvents("))
  + source.slice(source.indexOf("async function configParams("), source.indexOf("// Transport dispatch:"));
const code = new Bun.Transpiler({ loader: "ts" }).transformSync(helpers);

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
