import { afterEach, beforeEach, expect, test } from "bun:test";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verifyHandoffs } from "./commission";
import { missingHandoffHeads, verifyChain } from "./receipt-chain";

// Execute only the real --verify branch with an in-memory public key, never startup.
const source = readFileSync(join(import.meta.dir, "index.ts"), "utf8");
const branch = source.slice(source.indexOf('if (process.argv.includes("--verify"))'), source.indexOf("// --verify-aar"));
const code = new Bun.Transpiler({ loader: "ts" }).transformSync(branch);
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
const receipt = { seq: 1, prev: "genesis", detail: "offline fixture" };
const head = createHash("sha256").update(JSON.stringify(receipt)).digest("hex");
const signature = (hash: string) => sign(null, Buffer.from(hash), privateKey).toString("base64");
let root: string, dir: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "onvif-verify-handoffs-"));
  dir = join(root, "handoff");
  mkdirSync(dir);
  writeFileSync(join(root, "chain.jsonl"), JSON.stringify({ ...receipt, hash: head, sig: signature(head) }));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

function signedHandoff(file: string, chainHead = head) {
  const body = { receipts: { chain_head_hash: chainHead } };
  const hash = createHash("sha256").update(JSON.stringify(body)).digest("hex");
  writeFileSync(join(dir, file), JSON.stringify({ ...body, sig: signature(hash) }));
}

function runVerify(afterVerify?: () => void) {
  const output: string[] = [];
  const exited = {};
  let exitCode: number | undefined;
  const keydir = join(root, "in-memory-public-key");
  const deps = {
    ROOT: root, KEYDIR: keydir, LOG: join(root, "chain.jsonl"), join, existsSync, readdirSync,
    readFileSync: (path: string, encoding: "utf8") => {
      if (path === join(keydir, "receipt.pub")) return pem;
      if (afterVerify && path.startsWith(dir + "/")) throw new Error("verifier reopened a handoff");
      return readFileSync(path, encoding);
    },
    verifyChain, missingHandoffHeads,
    verifyHandoffs: (path: string, key: string) => {
      const result = verifyHandoffs(path, key);
      afterVerify?.();
      return result;
    },
    console: { log: (text: string) => output.push(text) },
    process: { argv: ["bun", "index.ts", "--verify"], exit: (status: number) => { exitCode = status; throw exited; } },
  };
  try { new Function(...Object.keys(deps), code)(...Object.values(deps)); }
  catch (error) { if (error !== exited) throw error; }
  expect(exitCode).toBeDefined();
  return { output, exitCode };
}

const validOutput = "chain OK — 1 receipts, every hash linked + signature valid; 1 handoff signatures valid, heads present";
test.each(["fifo", "directory", "symlink", "malformed", "valid"])("--verify preserves output and exit code for %s", (kind) => {
  signedHandoff("valid.json");
  const candidate = join(dir, `${kind}.json`);
  if (kind === "fifo") expect(Bun.spawnSync(["mkfifo", candidate]).exitCode).toBe(0);
  if (kind === "directory") mkdirSync(candidate);
  if (kind === "symlink") symlinkSync(join(dir, "valid.json"), candidate);
  if (kind === "malformed") writeFileSync(candidate, "{broken");
  const started = performance.now();
  expect(runVerify()).toEqual(kind === "valid"
    ? { output: [validOutput], exitCode: 0 }
    : { output: [`1 broken receipts or handoffs (${kind}.json)`], exitCode: 1 });
  expect(performance.now() - started).toBeLessThan(1000);
});

test("--verify preserves missing-head reporting", () => {
  signedHandoff("missing.json", "missing-head");
  expect(runVerify()).toEqual({ output: [
    "handoff head missing — chain truncated? missing.json", "1 broken receipts or handoffs",
  ], exitCode: 1 });
});

test("returns heads only from valid signatures and handles absent handoffs", () => {
  expect(verifyHandoffs(root, pem)).toEqual({ count: 0, bad: [], heads: [] });
  signedHandoff("valid.json");
  signedHandoff("tampered.json");
  const path = join(dir, "tampered.json");
  writeFileSync(path, readFileSync(path, "utf8").replace(head, "tampered-head"));
  expect(verifyHandoffs(root, pem)).toEqual({
    count: 2, bad: ["tampered.json"], heads: [{ file: "valid.json", chain_head_hash: head }],
  });
  expect(runVerify()).toEqual({ output: ["1 broken receipts or handoffs (tampered.json)"], exitCode: 1 });
  rmSync(dir, { recursive: true });
  expect(verifyHandoffs(root, pem)).toEqual({ count: 0, bad: [], heads: [] });
});

test("--verify uses the parsed head even if the file becomes a FIFO", () => {
  signedHandoff("valid.json");
  expect(runVerify(() => {
    rmSync(join(dir, "valid.json"));
    expect(Bun.spawnSync(["mkfifo", join(dir, "valid.json")]).exitCode).toBe(0);
  })).toEqual({ output: [validOutput], exitCode: 0 });
});
