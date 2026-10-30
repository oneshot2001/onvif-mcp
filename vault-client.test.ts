import { describe, expect, test } from "bun:test";
import { createVaultClient, VaultWithheld, type VaultCall } from "./vault-client";

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
