import { afterEach, beforeEach, expect, spyOn, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { toHex } from "aar-kat-harness/harness/cbor";
import { hash } from "aar-kat-harness/harness/crypto";
import { appendJournal, checkAarJournal } from "./journal";

let root: string, path: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "onvif-journal-test-"));
  path = join(root, "receipts", "aar", "journal.jsonl");
  mkdirSync(join(root, "receipts", "aar"), { recursive: true });
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

function runChild(source: string) {
  const proc = Bun.spawnSync([process.execPath, "-e", `
    import { checkAarJournal } from ${JSON.stringify(join(import.meta.dir, "journal.ts"))};
    import { join } from "node:path";
    import assert from "node:assert/strict";
    const ROOT = process.argv[1];
    const path = join(ROOT, "receipts", "aar", "journal.jsonl");
    ${source}
  `, root], { cwd: root, timeout: 2000, killSignal: "SIGKILL" });
  expect(proc.signalCode).toBeUndefined();
  return proc;
}

function specialJournal(kind: "FIFO" | "symlink to FIFO" | "directory") {
  if (kind === "directory") {
    mkdirSync(path);
  } else {
    const fifo = kind === "FIFO" ? path : join(root, "fifo");
    const proc = Bun.spawnSync(["mkfifo", fifo], { timeout: 2000, killSignal: "SIGKILL" });
    expect(proc.signalCode).toBeUndefined();
    expect(proc.exitCode).toBe(0);
    if (kind === "symlink to FIFO") symlinkSync(fifo, path);
  }
}

for (const kind of ["FIFO", "symlink to FIFO", "directory"] as const) {
  test(`journal regular file: ${kind} throws the corruption diagnostic`, () => {
    specialJournal(kind);
    const proc = runChild(`
      assert.throws(() => checkAarJournal(path), {
        message: "aar journal corrupt: not a regular file (" + path + ")"
      });
      console.log("check completed");
    `);
    expect(proc.exitCode).toBe(0);
    expect(proc.stdout.toString()).toBe("check completed\n");
    expect(proc.stderr.toString()).toBe("");
  });

  test(`journal regular file: startup exits 1 for ${kind} without continuing`, () => {
    specialJournal(kind);
    const source = readFileSync(join(import.meta.dir, "..", "index.ts"), "utf8");
    const start = source.indexOf("// Recovery is read-only");
    const end = source.indexOf("const AGENT =", start);
    expect(start).toBeGreaterThanOrEqual(0);
    expect(end).toBeGreaterThan(start);
    const proc = runChild(`${source.slice(start, end)} console.log("startup continued");`);
    expect(proc.exitCode).toBe(1);
    expect(proc.stderr.toString()).toBe(`aar journal corrupt: not a regular file (${path})\n`);
    expect(proc.stdout.toString()).toBe("");
  });
}

for (const kind of ["regular journal", "symlink to regular journal"]) {
  test(`journal regular file: ${kind} preserves recovery and validation`, () => {
    const target = kind === "regular journal" ? path : join(root, "regular.jsonl");
    const invocation = "01".repeat(16);
    const pending = JSON.stringify({ event: "attempt_envelope", invocation_id: invocation,
      receipt_id: "02".repeat(32), envelope_cbor: "00", envelope_digest: toHex(hash(new Uint8Array([0]))) }) + "\n";
    writeFileSync(target, pending);
    if (target !== path) symlinkSync(target, path);
    const warning = spyOn(console, "error").mockImplementation(() => {});
    try {
      checkAarJournal(path);
      expect(warning.mock.calls).toEqual([[`aar journal warning: invocation ${invocation} has no completion; never redispatch (${path})`]]);
      expect(readFileSync(target, "utf8")).toBe(pending);
      appendJournal(path, { event: "dispatch_completed", invocation_id: invocation, observed_at: 1 });
      warning.mockClear();
      checkAarJournal(path);
      expect(warning).not.toHaveBeenCalled();
      writeFileSync(target, '{"event":');
      expect(() => checkAarJournal(path)).toThrow(`aar journal corrupt: torn last line (${path})`);
      expect(readFileSync(target, "utf8")).toBe('{"event":');
    } finally { warning.mockRestore(); }
  });
}

test("journal regular file: absent journal stays absent without warnings", () => {
  const warning = spyOn(console, "error").mockImplementation(() => {});
  try {
    checkAarJournal(path);
    expect(warning).not.toHaveBeenCalled();
    expect(existsSync(path)).toBe(false);
  } finally { warning.mockRestore(); }
});
