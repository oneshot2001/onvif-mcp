import { afterEach, expect, test } from "bun:test";
import { createHash, generateKeyPairSync, sign as edSign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { currentInvocationId, runWithInvocation } from "./invocation";
import { appendLocked, outcomeEvidence, verifyChain } from "./receipt-chain";

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
    appendLocked, currentInvocationId, outcomeEvidence, createHash, edSign,
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
