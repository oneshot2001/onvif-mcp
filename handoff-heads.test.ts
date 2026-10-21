import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { handoffHeads, verifyHandoffs } from "./commission";

describe("startup handoff heads", () => {
  let root: string;
  let dir: string;
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "onvif-handoff-heads-"));
    dir = join(root, "handoff");
    mkdirSync(dir);
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  test.each(["fifo", "directory", "symlink"])("rejects a %s JSON candidate promptly and names it", (kind) => {
    const file = `${kind}.json`;
    const path = join(dir, file);
    if (kind === "fifo") expect(Bun.spawnSync(["mkfifo", path]).exitCode).toBe(0);
    if (kind === "directory") mkdirSync(path);
    if (kind === "symlink") {
      const target = join(root, "target");
      writeFileSync(target, JSON.stringify({ receipts: { chain_head_hash: "linked-head" } }));
      symlinkSync(target, path);
    }
    const started = performance.now();
    expect(() => handoffHeads(dir)).toThrow(`handoff '${file}' is not a regular file`);
    expect(performance.now() - started).toBeLessThan(1000);
  });

  test("returns the chain heads of regular signed handoffs", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const heads = ["head-1", "head-2"];
    for (const [i, head] of heads.entries()) {
      const body = {
        artifact: "camspec-handoff/0.1",
        receipts: { first_seq: i + 1, last_seq: i + 1, chain_head_hash: head },
      };
      const hash = createHash("sha256").update(JSON.stringify(body)).digest("hex");
      const sig = sign(null, Buffer.from(hash), privateKey).toString("base64");
      writeFileSync(join(dir, `${i}.json`), JSON.stringify({ ...body, sig }));
    }
    expect(verifyHandoffs(root, publicKey.export({ type: "spki", format: "pem" }).toString()))
      .toEqual({ count: 2, bad: [], heads: heads.map((chain_head_hash, i) => ({ file: `${i}.json`, chain_head_hash })) });
    expect(handoffHeads(dir).sort()).toEqual(heads);
  });

  test("fails closed on malformed JSON", () => {
    writeFileSync(join(dir, "broken.json"), "{broken");
    expect(() => handoffHeads(dir)).toThrow(SyntaxError);
  });

  test("returns no heads for absent or empty directories and ignores non-JSON entries", () => {
    expect(handoffHeads(join(root, "missing"))).toEqual([]);
    expect(handoffHeads(dir)).toEqual([]);
    mkdirSync(join(dir, "ignored"));
    writeFileSync(join(dir, "notes.txt"), "not JSON");
    expect(handoffHeads(dir)).toEqual([]);
  });
});
