import { afterEach, beforeEach, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";

// Execute only the real offline branch, retaining its builtin dynamic imports.
const source = readFileSync(join(import.meta.dir, "index.ts"), "utf8");
const startMarker = 'if (process.argv.includes("--verify-aar"))';
const endMarker = "// Recovery is read-only";
const start = source.indexOf(startMarker), end = source.indexOf(endMarker);
if (start < 0 || end <= start
  || source.lastIndexOf(startMarker) !== start || source.lastIndexOf(endMarker) !== end) {
  throw new Error("verify-aar slice boundaries must be unique and ordered");
}
const code = new Bun.Transpiler({ loader: "ts" }).transformSync(source.slice(start, end));
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
let root: string;
beforeEach(() => { root = mkdtempSync(join(tmpdir(), "onvif-verify-aar-")); });
afterEach(() => rmSync(root, { recursive: true, force: true }));

function bundle(name: string) {
  const dir = join(root, "receipts", "aar", name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "bundle.cbor"), "offline fixture; verifier is stubbed");
  return dir;
}

async function runVerify(
  verify: (dir: string) => { conformant: boolean; output: string } = () => ({ conformant: true, output: "" }),
  args: string[] = [],
) {
  const output: string[] = [];
  const calls: { root: string; dir: string }[] = [];
  const exited = {};
  let exitCode: number | undefined;
  const deps = {
    ROOT: root, join, existsSync,
    verifyBundleDir: (root: string, dir: string) => {
      calls.push({ root, dir });
      return verify(dir);
    },
    process: {
      argv: ["bun", "index.ts", "--verify-aar", ...args],
      exit: (status: number) => { exitCode = status; throw exited; },
    },
    console: { log: (text: string) => output.push(text) },
  };
  try { await new AsyncFunction(...Object.keys(deps), code)(...Object.values(deps)); }
  catch (error) { if (error !== exited) throw error; }
  expect(exitCode).toBeDefined();
  return { output, calls, exitCode };
}

test("verify-aar wiring: all conformant bundles exit successfully", async () => {
  const dirs = [bundle("first"), bundle("second")];
  mkdirSync(join(root, "receipts", "aar", "incomplete"));
  writeFileSync(join(root, "receipts", "aar", "journal.jsonl"), "");
  const result = await runVerify();
  expect(result.exitCode).toBe(0);
  expect(result.calls).toHaveLength(2);
  for (const dir of dirs) {
    expect(result.calls).toContainEqual({ root, dir });
    expect(result.output).toContain(`CONFORMANT  ${dir}`);
  }
  expect(result.output.at(-1)).toBe("2 bundle(s) conformant (pyref offline verify)");
});

test("verify-aar wiring: one nonconformant bundle fails the batch", async () => {
  const good = bundle("good"), bad = bundle("bad");
  const result = await runVerify((dir) => ({ conformant: dir === good, output: "invalid bundle evidence" }));
  expect(result.exitCode).toBe(1);
  expect(result.calls).toHaveLength(2);
  expect(result.calls).toContainEqual({ root, dir: good });
  expect(result.calls).toContainEqual({ root, dir: bad });
  expect(result.output).toContain(`CONFORMANT  ${good}`);
  expect(result.output).toContain(`NONCONFORMANT  ${bad}`);
  expect(result.output).toContain("invalid bundle evidence");
  expect(result.output.at(-1)).toBe("1/2 bundles FAILED");
});

test("verify-aar wiring: a throwing verifier fails the batch", async () => {
  const dir = bundle("throws");
  const result = await runVerify(() => { throw new Error("offline verifier failed"); });
  expect(result.exitCode).toBe(1);
  expect(result.calls).toEqual([{ root, dir }]);
  expect(result.output).toEqual([
    `NONCONFORMANT  ${dir}\nverification error: Error: offline verifier failed`,
    "1/1 bundles FAILED",
  ]);
});

test.each(["no bundle root", "no bundles", "only directories without bundle.cbor"])(
  "verify-aar wiring: %s fails closed", async (kind) => {
    const base = join(root, "receipts", "aar");
    if (kind !== "no bundle root") mkdirSync(base, { recursive: true });
    if (kind === "only directories without bundle.cbor") {
      mkdirSync(join(base, "incomplete"));
      mkdirSync(join(base, "also-incomplete"));
    }
    const result = await runVerify();
    expect(result.exitCode).toBe(1);
    expect(result.output).toEqual(["no AAR bundles found"]);
    expect(result.calls).toEqual([]);
  },
);

test("verify-aar wiring: an explicit directory verifies only that directory", async () => {
  bundle("unselected");
  const selected = join(root, "explicit");
  mkdirSync(selected);
  writeFileSync(join(selected, "bundle.cbor"), "offline fixture; verifier is stubbed");
  const result = await runVerify(undefined, [relative(process.cwd(), selected)]);
  expect(result.exitCode).toBe(0);
  expect(result.calls).toEqual([{ root, dir: selected }]);
  expect(result.output).toEqual([
    `CONFORMANT  ${selected}`, "1 bundle(s) conformant (pyref offline verify)",
  ]);
});
