import { describe, expect, spyOn, test } from "bun:test";
import { createVaultClient, curlVaultCall, VaultWithheld, type VaultCall } from "./vault-client";

function fakeVault(routes: Record<string, (body: unknown) => { status: number; body: unknown }>): { call: VaultCall; seen: Array<[string, string, unknown]> } {
  const seen: Array<[string, string, unknown]> = [];
  const call: VaultCall = (method, path, body) => {
    seen.push([method, path, body]);
    const route = routes[`${method} ${path}`];
    if (route === undefined) return { status: 404, body: JSON.stringify({ reason: "no route" }) };
    const reply = route(body);
    return { status: reply.status, body: typeof reply.body === "string" ? reply.body : JSON.stringify(reply.body) };
  };
  return { call, seen };
}
const PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n";

for (const status of [500, 201]) {
  test(`vault status gate: credential HTTP ${status} rejects a password without leaking it`, () => {
    const password = "vault-status-credential-stand-in";
    const vault = fakeVault({ "POST /credential": () => ({ status, body: { password } }) });
    let error: unknown;
    try { createVaultClient(vault.call).credential("camera", "viewer"); } catch (caught) { error = caught; }
    expect(error instanceof Error, "non-200 credential fails closed").toBe(true);
    const message = (error as Error).message;
    expect(message).toBe(`vault credential: HTTP ${status}`);
    expect(message.includes(password), "credential stays out of diagnostics").toBe(false);
  });
}

test("vault status gate: sign HTTP 409 rejects a signature and reports the refusal reason", () => {
  const vault = fakeVault({
    "GET /public-key": () => ({ status: 200, body: { pem: PEM } }),
    "POST /sign": () => ({ status: 409, body: { sig: "c2ln", reason: "no witnessed traffic" } }),
  });
  const signer = createVaultClient(vault.call).signer();
  expect(() => signer.sign("receipt", {}), "non-200 signature fails closed").toThrow("vault refused to sign the receipt: no witnessed traffic");
});

test("vault status gate: public-key HTTP 503 rejects an otherwise accepted PEM", () => {
  const vault = fakeVault({ "GET /public-key": () => ({ status: 503, body: { pem: PEM } }) });
  expect(() => createVaultClient(vault.call).signer(), "non-200 public key fails closed").toThrow("vault public-key: HTTP 503");
});

test("vault status gate: sign HTTP 200 rejects an empty signature", () => {
  const vault = fakeVault({
    "GET /public-key": () => ({ status: 200, body: { pem: PEM } }),
    "POST /sign": () => ({ status: 200, body: { sig: "" } }),
  });
  const signer = createVaultClient(vault.call).signer();
  expect(() => signer.sign("receipt", {}), "empty signature fails closed").toThrow("vault refused to sign the receipt: HTTP 200");
});

test("vault status gate: HTTP 200 preserves credentials, public keys and both signature kinds", () => {
  const password = "vault-status-success-stand-in";
  const vault = fakeVault({
    "POST /credential": () => ({ status: 200, body: { password } }),
    "GET /public-key": () => ({ status: 200, body: { pem: PEM } }),
    "POST /sign": () => ({ status: 200, body: { sig: "c2ln" } }),
  });
  const client = createVaultClient(vault.call);
  expect(client.credential("camera", "viewer") === password).toBe(true);
  const signer = client.signer();
  expect(signer.publicKeyPem).toBe(PEM);
  expect(signer.sign("receipt", { seq: 1 })).toBe("c2ln");
  expect(signer.sign("handoff", { camera: "camera" })).toBe("c2ln");
  expect(vault.seen).toEqual([
    ["POST", "/credential", { camera: "camera", tier: "viewer" }],
    ["GET", "/public-key", undefined],
    ["POST", "/sign", { kind: "receipt", body: { seq: 1 } }],
    ["POST", "/sign", { kind: "handoff", body: { camera: "camera" } }],
  ]);
});

for (const exitCode of [18, 0]) {
  test(`vault status gate: curl exit ${exitCode} ${exitCode ? "overrides valid JSON and HTTP 200" : "preserves valid JSON and HTTP 200"}`, () => {
    const password = "vault-status-transport-stand-in";
    const body = JSON.stringify({ password });
    const spawn = spyOn(Bun, "spawnSync").mockImplementation(((_args: string[]) => ({
      exitCode, stdout: Buffer.from(`${body}\n200`), stderr: Buffer.alloc(0),
    })) as typeof Bun.spawnSync);
    try {
      const call = curlVaultCall("/fake-vault.sock");
      if (exitCode !== 0) {
        let error: unknown;
        try { call("POST", "/credential", { camera: "camera", tier: "viewer" }); } catch (caught) { error = caught; }
        expect(error instanceof Error, "transport failure wins over HTTP 200").toBe(true);
        const message = (error as Error).message;
        expect(message).toBe("vault unreachable at /fake-vault.sock (curl exit 18)");
        expect(message.includes(password), "transport diagnostics exclude credentials").toBe(false);
      } else {
        const response = call("POST", "/credential", { camera: "camera", tier: "viewer" });
        expect(response.status).toBe(200);
        expect(response.body === body).toBe(true);
      }
      expect(spawn).toHaveBeenCalledTimes(1);
    } finally {
      spawn.mockRestore();
    }
  });
}

describe("vault client", () => {
  test("returns a released credential and names the tier it asked for", () => {
    const vault = fakeVault({ "POST /credential": (body) => ({ status: 200, body: { password: `pw-${(body as any).tier}` } }) });
    const client = createVaultClient(vault.call);
    expect(client.credential("q6358", "viewer")).toBe("pw-viewer");
    expect(vault.seen).toEqual([["POST", "/credential", { camera: "q6358", tier: "viewer" }]]);
  });

  test("a withheld tier is a VaultWithheld error carrying the vault's reason", () => {
    const vault = fakeVault({ "POST /credential": () => ({ status: 403, body: { reason: "admin tier withheld until the approval service (P4)" } }) });
    const client = createVaultClient(vault.call);
    expect(() => client.credential("q6358", "admin")).toThrow(VaultWithheld);
    expect(() => client.credential("q6358", "admin")).toThrow("withheld until the approval service");
  });

  test("an empty password, an unknown camera or a non-JSON body is an error, never a credential", () => {
    expect(() => createVaultClient(fakeVault({ "POST /credential": () => ({ status: 200, body: { password: "" } }) }).call).credential("q6358", "viewer")).toThrow("HTTP 200");
    expect(() => createVaultClient(fakeVault({ "POST /credential": () => ({ status: 404, body: { reason: "unknown camera" } }) }).call).credential("nope", "viewer")).toThrow("unknown camera");
    expect(() => createVaultClient(fakeVault({ "POST /credential": () => ({ status: 200, body: "<html>" }) }).call).credential("q6358", "viewer")).toThrow("non-JSON");
  });

  test("the signer sends kind and body and returns the vault's signature", () => {
    const vault = fakeVault({
      "GET /public-key": () => ({ status: 200, body: { pem: PEM } }),
      "POST /sign": (body) => ({ status: 200, body: { sig: `sig-of-${(body as any).kind}` } }),
    });
    const signer = createVaultClient(vault.call).signer();
    expect(signer.publicKeyPem).toBe(PEM);
    expect(signer.sign("receipt", { seq: 1 })).toBe("sig-of-receipt");
    expect(signer.sign("handoff", { camera: "q6358" })).toBe("sig-of-handoff");
    expect(vault.seen.slice(1)).toEqual([["POST", "/sign", { kind: "receipt", body: { seq: 1 } }], ["POST", "/sign", { kind: "handoff", body: { camera: "q6358" } }]]);
  });

  test("a refused signature is an error with the vault's reason; a missing public key fails at signer creation", () => {
    const refused = fakeVault({
      "GET /public-key": () => ({ status: 200, body: { pem: PEM } }),
      "POST /sign": () => ({ status: 403, body: { reason: "no witnessed traffic for invocation 0f..." } }),
    });
    expect(() => createVaultClient(refused.call).signer().sign("receipt", {})).toThrow("vault refused to sign the receipt: no witnessed traffic");
    expect(() => createVaultClient(fakeVault({ "GET /public-key": () => ({ status: 200, body: { pem: "nope" } }) }).call).signer()).toThrow("no PEM");
  });
});
