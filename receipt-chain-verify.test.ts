import { describe, expect, test } from "bun:test";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { missingHandoffHeads, verifyChain } from "./receipt-chain";

function chain(seqs: readonly number[] = [1, 2, 3]) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  let prev = "genesis";
  const lines = seqs.map((seq) => {
    const body = { seq, detail: "allowed", action: { tool: "get_snapshot", params: { camera: "test" } }, prev };
    const hash = createHash("sha256").update(JSON.stringify(body)).digest("hex");
    const sig = sign(null, Buffer.from(hash), privateKey).toString("base64");
    prev = hash;
    return JSON.stringify({ ...body, hash, sig });
  });
  return { lines, publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
}

describe("receipt chain verification", () => {
  test("accepts an intact three-receipt chain in parsed key order", () => {
    const { lines, publicKeyPem } = chain();
    expect(verifyChain(lines, publicKeyPem)).toEqual({ count: 3, bad: [] });
    expect(verifyChain([], publicKeyPem)).toEqual({ count: 0, bad: [] });
  });

  test("accepts handoff heads in an intact chain and reports a dropped tail", () => {
    const { lines, publicKeyPem } = chain();
    const hashes = lines.map((line) => JSON.parse(line).hash as string);
    const handoffs = [
      { file: "earlier.json", chain_head_hash: hashes[1]! },
      { file: "latest.json", chain_head_hash: hashes[2]! },
    ];
    expect(verifyChain(lines, publicKeyPem).bad).toEqual([]);
    expect(missingHandoffHeads(new Set(hashes), handoffs)).toEqual([]);
    expect(verifyChain(lines.slice(0, -1), publicKeyPem).bad).toEqual([]);
    expect(missingHandoffHeads(new Set(hashes.slice(0, -1)), handoffs)).toEqual(["latest.json"]);
    expect(missingHandoffHeads(new Set(), handoffs)).toEqual(["earlier.json", "latest.json"]);
    expect(missingHandoffHeads(new Set(hashes), [])).toEqual([]);
  });

  test.each([
    { seqs: [1, 4, 5], badSeq: 4 },
    { seqs: [2, 3, 4], badSeq: 2 },
    { seqs: [1, 1, 2], badSeq: 1 },
  ])("reports a seq gap in a correctly signed chain $seqs", ({ seqs, badSeq }) => {
    const { lines, publicKeyPem } = chain(seqs);
    expect(verifyChain(lines, publicKeyPem)).toEqual({ count: 3, bad: [{ seq: badSeq, reason: "seq gap" }] });
  });

  test("reports a flipped body byte", () => {
    const { lines, publicKeyPem } = chain();
    lines[1] = lines[1]!.replace("allowed", "`llowed"); // 'a' XOR 1
    expect(verifyChain(lines, publicKeyPem)).toEqual({ count: 3, bad: [{ seq: 2, reason: "hash mismatch" }] });
  });

  test("reports a deleted middle line", () => {
    const { lines, publicKeyPem } = chain();
    lines.splice(1, 1);
    expect(verifyChain(lines, publicKeyPem)).toEqual({ count: 2, bad: [{ seq: 3, reason: "prev mismatch, seq gap" }] });
  });

  test("reports two swapped lines and checks the genesis link", () => {
    const { lines, publicKeyPem } = chain();
    expect(verifyChain([lines[1]!, lines[0]!, lines[2]!], publicKeyPem)).toEqual({
      count: 3,
      bad: [2, 1, 3].map((seq) => ({ seq, reason: "prev mismatch, seq gap" })),
    });
  });

  test("reports a flipped signature byte even when the body hash matches", () => {
    const { lines, publicKeyPem } = chain();
    const receipt = JSON.parse(lines[1]!);
    const sig = Buffer.from(receipt.sig, "base64");
    sig[0] = sig[0]! ^ 1;
    lines[1] = JSON.stringify({ ...receipt, sig: sig.toString("base64") });
    expect(verifyChain(lines, publicKeyPem)).toEqual({ count: 3, bad: [{ seq: 2, reason: "invalid signature" }] });
  });

  test("rejects signatures made by another key", () => {
    const { lines } = chain();
    const { publicKeyPem } = chain();
    expect(verifyChain(lines, publicKeyPem)).toEqual({
      count: 3,
      bad: [1, 2, 3].map((seq) => ({ seq, reason: "invalid signature" })),
    });
  });

  test.each([['{"seq":2,', "invalid JSON"], ["null", "invalid receipt"]])("reports malformed line %s and continues", (line, reason) => {
    const { lines, publicKeyPem } = chain();
    lines[1] = line;
    expect(verifyChain(lines, publicKeyPem)).toEqual({
      count: 3,
      bad: [{ seq: 2, reason }, { seq: 3, reason: "prev mismatch, seq gap" }],
    });
  });
});
