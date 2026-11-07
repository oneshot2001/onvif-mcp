import { afterEach, beforeEach, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Read source only: importing index.ts would fetch credentials and start MCP.
const source = readFileSync(join(import.meta.dir, "index.ts"), "utf8");
function slice(startMarker: string, endMarker: string): string {
  const start = source.indexOf(startMarker), end = source.indexOf(endMarker);
  if (start < 0 || end <= start
    || source.lastIndexOf(startMarker) !== start || source.lastIndexOf(endMarker) !== end) {
    throw new Error(`gateway startup slice boundaries must be unique and ordered: ${startMarker}`);
  }
  return source.slice(start, end);
}
const routing = slice("const gateway = gatewayConfigFromEnv(process.env);", "const vault = VAULT === undefined");
// The slice includes the vault branch's closing brace. Supply its opening brace
// and the local signer declaration, which lives outside the requested slice.
const signing = `let signer;\n{\n${slice("  signer = vault.signer();", "const PUB = signer.publicKeyPem;")}\nreturn signer;`;
const vaultPem = "-----BEGIN PUBLIC KEY-----\nstand-in-vault-key\n-----END PUBLIC KEY-----\n";
let root: string;
beforeEach(() => { root = mkdtempSync(join(tmpdir(), "onvif-gateway-startup-")); });
afterEach(() => rmSync(root, { recursive: true, force: true }));

function harness(gateway: boolean, env: Record<string, string | undefined>) {
  const cameras = {
    first: { base: "https://first.example", pin: "stand-in-first-pin", ptz: true },
    second: { base: "https://second.example", pin: "stand-in-second-pin", ptz: false },
    unpinned: { base: "http://third.example", ptz: false },
  };
  const originalCameras = structuredClone(cameras);
  const errors: string[] = [], exits: number[] = [];
  const configEnvs: unknown[] = [];
  const exited = {};
  const fakeSigner = { publicKeyPem: vaultPem };
  let signerCalls = 0;
  const deps = {
    gatewayConfigFromEnv: (input: unknown) => {
      configEnvs.push(input);
      return gateway ? { port: 8080 } : null;
    },
    cameras,
    process: { env, exit: (status: number) => { exits.push(status); throw exited; } },
    console: { error: (message: string) => errors.push(message) },
    vault: { signer: () => { signerCalls++; return fakeSigner; } },
    KEYDIR: root, join, existsSync, readFileSync, writeFileSync,
  };
  function run(code: string) {
    try {
      const signer = new Function(...Object.keys(deps), code)(...Object.values(deps));
      return { continued: true, signer };
    } catch (error) {
      if (error !== exited) throw error;
      return { continued: false, signer: undefined };
    }
  }
  return {
    env, cameras, originalCameras, errors, exits, configEnvs, fakeSigner,
    signerCalls: () => signerCalls,
    route: () => run(routing), sign: () => run(signing),
  };
}

test("gateway startup wiring: stdio deletes a stray witness socket and preserves cameras", () => {
  const h = harness(false, { GATEWAY_WITNESS_SOCKET: "/unused/witness.sock", GATEWAY_VAULT_SOCKET: "/unused/vault.sock" });
  expect(h.route().continued).toBe(true);
  expect(Object.hasOwn(h.env, "GATEWAY_WITNESS_SOCKET"), "stdio removes the stray witness socket").toBe(false);
  expect(h.env.GATEWAY_VAULT_SOCKET).toBe("/unused/vault.sock");
  expect(h.cameras).toEqual(h.originalCameras);
  expect(h.configEnvs).toHaveLength(1);
  expect(h.configEnvs[0]).toBe(h.env);
  expect(h.exits).toEqual([]);
  expect(h.errors).toEqual([]);
});

test("gateway startup wiring: both sockets are kept and every camera is rewritten without a pin", () => {
  const h = harness(true, { GATEWAY_WITNESS_SOCKET: "/unused/witness.sock", GATEWAY_VAULT_SOCKET: "/unused/vault.sock" });
  const originalEnv = { ...h.env };
  expect(h.route().continued).toBe(true);
  expect(h.env).toEqual(originalEnv);
  expect(h.configEnvs).toHaveLength(1);
  expect(h.configEnvs[0]).toBe(h.env);
  for (const [id, camera] of Object.entries(h.cameras)) {
    expect(camera.base, `gateway rewrites ${id} base to its camera id`).toBe(`http://${id}`);
    expect(Object.hasOwn(camera, "pin"), `gateway removes ${id} pin`).toBe(false);
  }
  expect(h.exits).toEqual([]);
  expect(h.errors).toEqual([]);
});

for (const socket of ["GATEWAY_WITNESS_SOCKET", "GATEWAY_VAULT_SOCKET"]) {
  for (const value of [undefined, ""]) {
    test(`gateway startup wiring: ${socket} ${value === undefined ? "missing" : "empty"} exits before camera rewrites`, () => {
      const env: Record<string, string | undefined> = {
        GATEWAY_WITNESS_SOCKET: "/unused/witness.sock", GATEWAY_VAULT_SOCKET: "/unused/vault.sock",
      };
      if (value === undefined) delete env[socket];
      else env[socket] = value;
      const h = harness(true, env);
      const result = h.route();
      expect(h.exits, "gateway requires both sockets before continuing").toEqual([1]);
      expect(result.continued).toBe(false);
      expect(h.errors).toEqual(["gateway mode needs GATEWAY_WITNESS_SOCKET and GATEWAY_VAULT_SOCKET"]);
      expect(h.cameras, "socket rejection precedes every camera rewrite").toEqual(h.originalCameras);
    });
  }
}

test("gateway startup wiring: conflicting receipt.pub exits and preserves file bytes", () => {
  const h = harness(true, {});
  const pubFile = join(root, "receipt.pub");
  const original = Buffer.from("another public key\r\n\0");
  writeFileSync(pubFile, original);
  const result = h.sign();
  expect(h.exits, "conflicting receipt key fails closed").toEqual([1]);
  expect(result.continued).toBe(false);
  expect(h.errors).toHaveLength(1);
  expect(h.errors[0]).toContain("differs from the vault's public key");
  expect(readFileSync(pubFile), "conflicting receipt key bytes are unchanged").toEqual(original);
  expect(h.signerCalls()).toBe(1);
});

test.each(["absent", "equal"])("gateway startup wiring: %s receipt.pub continues with the vault PEM", (kind) => {
  const h = harness(true, {});
  const pubFile = join(root, "receipt.pub");
  if (kind === "equal") writeFileSync(pubFile, vaultPem);
  else expect(existsSync(pubFile)).toBe(false);
  const result = h.sign();
  expect(result.continued).toBe(true);
  expect(result.signer).toBe(h.fakeSigner);
  expect(h.signerCalls()).toBe(1);
  expect(h.exits).toEqual([]);
  expect(h.errors).toEqual([]);
  expect(readFileSync(pubFile)).toEqual(Buffer.from(vaultPem));
});
