import { afterEach, expect, test } from "bun:test";
import { createHash, generateKeyPairSync, sign as edSign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { createSessionRouter, type TokenRecord } from "./gateway-listen";
import { currentClientCall, currentInvocationId, runWithInvocation, setInvocationRecorder, withInvocations, type InvocationRecord } from "./invocation";
import { cameraEntrySha256, appendLocked, outcomeEvidence, verifyChain } from "./receipt-chain";

// Execute the real writer without index.ts startup, credentials, keys or MCP.
const source = readFileSync(join(import.meta.dir, "index.ts"), "utf8");
const writer = source.slice(source.indexOf("const NODE_KIND:"), source.indexOf("function allowed("));
const code = new Bun.Transpiler({ loader: "ts" }).transformSync(writer);
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function harness() {
  const root = mkdtempSync(join(tmpdir(), "invocation-receipt-"));
  roots.push(root);
  const log = join(root, "chain.jsonl");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const dependencies = {
    POLICY_SHA256: "stand-in-policy-sha256", cameraEntrySha256,
    appendLocked, currentClientCall, currentInvocationId, outcomeEvidence, createHash, edSign,
    cameras: {}, policy: {},
    LOG: log, PRIV: privateKey, AGENT: "test-agent",
    signer: { sign: (_kind: string, body: unknown) => edSign(null, Buffer.from(createHash("sha256").update(JSON.stringify(body)).digest("hex")), privateKey).toString("base64") },
  };
  const receipt = new Function(...Object.keys(dependencies), code + "\nreturn receipt;")(...Object.values(dependencies));
  const lines = () => readFileSync(log, "utf8").trim().split("\n");
  return { receipt, lines, log, privateKey, publicKey: publicKey.export({ type: "spki", format: "pem" }).toString() };
}

test("actual receipt writer signs null outside a run and the shared ID within each run", async () => {
  const h = harness();
  expect(currentInvocationId()).toBeUndefined();
  h.receipt("list_cameras", {}, "allow", "outside before");
  const ids: string[] = [];
  for (let run = 0; run < 2; run++) {
    await runWithInvocation(async () => {
      const id = currentInvocationId()!;
      expect(id).toMatch(/^[0-9a-f]{32}$/);
      ids.push(id);
      for (const [tool, decision] of [["commission_apply", "allow"], ["get_snapshot", "deny"], ["aar_emit", "allow"]]) {
        await Promise.resolve();
        h.receipt(tool, {}, decision, "test receipt");
        expect(JSON.parse(h.lines().at(-1)!).invocation_id).toBe(currentInvocationId());
        expect(currentInvocationId()).toBe(id);
      }
    });
  }
  expect(currentInvocationId()).toBeUndefined();
  h.receipt("list_cameras", {}, "allow", "outside after");
  expect(ids[0]).not.toBe(ids[1]);
  expect(h.lines().map(line => JSON.parse(line).invocation_id)).toEqual([
    null, ids[0], ids[0], ids[0], ids[1], ids[1], ids[1], null,
  ]);
  expect(verifyChain(h.lines(), h.publicKey)).toEqual({ count: 8, bad: [] });
});

test("new receipts append to a valid legacy chain without rewriting its bytes", () => {
  const h = harness();
  const body = { seq: 1, ts: "2026-10-20T00:00:00.000Z", action: { tool: "list_cameras", params: {} }, decision: "allow", prev: "genesis" };
  const hash = createHash("sha256").update(JSON.stringify(body)).digest("hex");
  const sig = edSign(null, Buffer.from(hash), h.privateKey).toString("base64");
  const legacy = JSON.stringify({ ...body, hash, sig }) + "\n";
  writeFileSync(h.log, legacy);
  runWithInvocation(() => h.receipt("commission_apply", {}, "allow", "new receipt"));
  h.receipt("list_cameras", {}, "allow", "outside");
  expect(readFileSync(h.log, "utf8").startsWith(legacy)).toBe(true);
  expect(JSON.parse(h.lines()[0]!)).not.toHaveProperty("invocation_id");
  expect(JSON.parse(h.lines()[1]!).invocation_id).toMatch(/^[0-9a-f]{32}$/);
  expect(JSON.parse(h.lines()[2]!).invocation_id).toBeNull();
  expect(verifyChain(h.lines(), h.publicKey)).toEqual({ count: 3, bad: [] });
});

test.each(["edit", "remove"])("%s invocation_id breaks the body hash and cannot be repaired without signing", change => {
  const h = harness();
  runWithInvocation(() => h.receipt("commission_apply", {}, "allow", "new receipt"));
  expect(verifyChain(h.lines(), h.publicKey).bad).toEqual([]);
  const receipt = JSON.parse(h.lines()[0]!);
  if (change === "remove") delete receipt.invocation_id;
  else receipt.invocation_id = receipt.invocation_id === "0".repeat(32) ? "1".repeat(32) : "0".repeat(32);
  expect(verifyChain([JSON.stringify(receipt)], h.publicKey).bad).toEqual([{ seq: 1, reason: "hash mismatch" }]);
  const { hash, sig, ...body } = receipt;
  receipt.hash = createHash("sha256").update(JSON.stringify(body)).digest("hex");
  expect(verifyChain([JSON.stringify(receipt)], h.publicKey).bad).toEqual([{ seq: 1, reason: "invalid signature" }]);
});

const SOURCE = "claudecode/toolUseId, client-supplied, not verified";

test("createSessionRouter hands the client's call id to the receipt writer; absent or malformed ids sign null", async () => {
  const h = harness();
  const server = new McpServer({ name: "t", version: "0" });
  withInvocations(server);
  server.tool("echo", "echo", { text: z.string() }, async ({ text }) => {
    h.receipt("echo", { text }, "allow", "test receipt");
    return { content: [{ type: "text", text }] };
  });
  const token: TokenRecord = { agent: "claude-main", sha256: createHash("sha256").update("s").digest("hex"), expires: "2099-01-01T00:00:00Z" };
  const handle = createSessionRouter(server, { token, now: () => 0, log: () => {}, schedule: () => {} });
  const headers = { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: "Bearer s" };
  const init = await handle(new Request("http://g/mcp", { method: "POST", headers, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } } }) }));
  const sid = init.headers.get("mcp-session-id")!;
  await init.text();
  const metas = [{ "claudecode/toolUseId": "toolu_test_1" }, undefined, { "claudecode/toolUseId": { id: "toolu_test_3" } }, { "claudecode/toolUseId": "a".repeat(200) }];
  for (const [index, _meta] of metas.entries()) {
    const call = await handle(new Request("http://g/mcp", { method: "POST", headers: { ...headers, "mcp-session-id": sid }, body: JSON.stringify({ jsonrpc: "2.0", id: index + 2, method: "tools/call", params: { name: "echo", arguments: { text: `served ${index}` }, _meta } }) }));
    expect(await call.text()).toContain(`"text":"served ${index}"`);
  }
  expect(h.lines().map(line => JSON.parse(line).client_call)).toEqual([{ id: "toolu_test_1", source: SOURCE }, null, null, null]);
  expect(verifyChain(h.lines(), h.publicKey)).toEqual({ count: 4, bad: [] });
});

test("receipts with client_call append to a chain whose first lines lack it without rewriting their bytes", () => {
  const h = harness();
  let legacy = "", prev = "genesis";
  for (const extra of [{}, { invocation_id: "0".repeat(32) }]) {
    const body = { seq: prev === "genesis" ? 1 : 2, ts: "2026-10-20T00:00:00.000Z", ...extra, action: { tool: "list_cameras", params: {} }, decision: "allow", prev };
    prev = createHash("sha256").update(JSON.stringify(body)).digest("hex");
    legacy += JSON.stringify({ ...body, hash: prev, sig: edSign(null, Buffer.from(prev), h.privateKey).toString("base64") }) + "\n";
  }
  writeFileSync(h.log, legacy);
  runWithInvocation(() => h.receipt("commission_apply", {}, "allow", "new receipt"), "toolu_test_1");
  runWithInvocation(() => h.receipt("list_cameras", {}, "allow", "no client id"));
  expect(readFileSync(h.log, "utf8").startsWith(legacy)).toBe(true);
  const receipts = h.lines().map(line => JSON.parse(line));
  expect(receipts[0]).not.toHaveProperty("client_call");
  expect(receipts[1]).not.toHaveProperty("client_call");
  expect(receipts[2].client_call).toEqual({ id: "toolu_test_1", source: SOURCE });
  expect(receipts[3].client_call).toBeNull();
  expect(verifyChain(h.lines(), h.publicKey)).toEqual({ count: 4, bad: [] });
});

test.each(["edit", "remove"])("%s client_call breaks the body hash and cannot be repaired without signing", change => {
  const h = harness();
  runWithInvocation(() => h.receipt("commission_apply", {}, "allow", "new receipt"), "toolu_test_1");
  expect(verifyChain(h.lines(), h.publicKey).bad).toEqual([]);
  const receipt = JSON.parse(h.lines()[0]!);
  if (change === "remove") delete receipt.client_call;
  else receipt.client_call.id = "toolu_test_2";
  expect(verifyChain([JSON.stringify(receipt)], h.publicKey).bad).toEqual([{ seq: 1, reason: "hash mismatch" }]);
  const { hash, sig, ...body } = receipt;
  receipt.hash = createHash("sha256").update(JSON.stringify(body)).digest("hex");
  expect(verifyChain([JSON.stringify(receipt)], h.publicKey).bad).toEqual([{ seq: 1, reason: "invalid signature" }]);
});

// A real McpServer behind withInvocations, called by a real SDK client in memory.
const sessions: Array<() => Promise<void>> = [];
afterEach(async () => {
  setInvocationRecorder(undefined);
  for (const close of sessions.splice(0)) await close();
});
async function connect(register: (server: McpServer) => void) {
  const server = new McpServer({ name: "t", version: "0" });
  withInvocations(server);
  register(server);
  const client = new Client({ name: "t", version: "0" });
  sessions.push(async () => { await client.close(); await server.close(); });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return (name: string, toolUseId: string, args?: Record<string, unknown>) =>
    client.callTool({ name, arguments: args, _meta: { "claudecode/toolUseId": toolUseId } });
}

test("a tool registered without an input schema still sees the client's call id", async () => {
  let seen: unknown, argCount = 0;
  const call = await connect(server => server.tool("bare", async (...args: unknown[]) => {
    argCount = args.length;
    seen = currentClientCall();
    return { content: [] };
  }));
  expect((await call("bare", "toolu_schemaless_1")).isError).not.toBe(true);
  expect(argCount).toBe(1); // the SDK passed only its request extra
  expect(seen).toEqual({ id: "toolu_schemaless_1", source: SOURCE });
});

test("overlapping invocations each sign their own client call id", async () => {
  const h = harness();
  let started = 0, release!: () => void;
  const bothStarted = new Promise<void>(resolve => { release = resolve; });
  const call = await connect(server => server.tool("echo", "echo", { label: z.string() }, async ({ label }) => {
    if (++started === 2) release();
    await bothStarted;
    h.receipt("echo", { label }, "allow", "test receipt");
    return { content: [{ type: "text", text: label }] };
  }));
  await Promise.all(["one", "two"].map(label => call("echo", `toolu_${label}`, { label })));
  const receipts = h.lines().map(line => JSON.parse(line));
  expect(receipts.map(r => [r.action.params.label, r.client_call]).sort()).toEqual([
    ["one", { id: "toolu_one", source: SOURCE }], ["two", { id: "toolu_two", source: SOURCE }],
  ]);
  expect(receipts[0].invocation_id).not.toBe(receipts[1].invocation_id);
  expect(verifyChain(h.lines(), h.publicKey)).toEqual({ count: 2, bad: [] });
});

test("a client call id shaped like the server's invocation id never replaces it", async () => {
  const h = harness();
  const clientId = "0123456789abcdef0123456789abcdef";
  const records: InvocationRecord[] = [];
  setInvocationRecorder(entry => { records.push(entry); });
  const call = await connect(server => server.tool("echo", "echo", { label: z.string() }, async ({ label }) => {
    h.receipt("echo", { label }, "allow", "test receipt");
    return { content: [{ type: "text", text: label }] };
  }));
  expect((await call("echo", clientId, { label: "x" })).isError).not.toBe(true);
  const receipt = JSON.parse(h.lines()[0]!);
  expect(receipt.client_call).toEqual({ id: clientId, source: SOURCE });
  expect(receipt.invocation_id).toMatch(/^[0-9a-f]{32}$/);
  expect(receipt.invocation_id).not.toBe(clientId);
  expect(records.map(entry => entry.invocation_id)).toEqual([receipt.invocation_id]);
});
