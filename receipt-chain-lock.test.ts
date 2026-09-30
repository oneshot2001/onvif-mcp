import { describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { appendLocked, STALE_LOCK_MS, verifyChain } from "./receipt-chain";

describe("receipt chain locking", () => {
  test("reclaims a 61-second-old lock naming this test's live PID and appends", async () => {
    const root = mkdtempSync(join(tmpdir(), "receipt-chain-stale-lock-"));
    const log = join(root, "chain.jsonl");
    let child: Bun.Subprocess<"ignore", "pipe", "pipe"> | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      expect(STALE_LOCK_MS).toBe(60_000);
      writeFileSync(log + ".lock", String(process.pid));
      const staleTime = new Date(Date.now() - 61_000);
      utimesSync(log + ".lock", staleTime, staleTime);
      const worker = join(root, "writer.ts");
      writeFileSync(worker, `
        import { appendLocked } from ${JSON.stringify(join(import.meta.dir, "receipt-chain.ts"))};
        appendLocked(process.argv[2], (prev) => JSON.stringify({ seq: prev.seq + 1, prev: prev.hash, hash: "test-hash" }));
      `);
      child = Bun.spawn([process.execPath, worker, log], {
        cwd: root, stdin: "ignore", stdout: "pipe", stderr: "pipe",
      });
      timer = setTimeout(() => child!.kill(), 3000);
      expect(await child.exited).toBe(0);
      const stderr = await new Response(child.stderr).text();
      expect(stderr).toMatch(/^receipt lock reclaimed \(stale \d+s\)\n$/);
      expect(Number(stderr.match(/stale (\d+)s/)![1])).toBeGreaterThanOrEqual(61);
      expect(readFileSync(log, "utf8")).toBe('{"seq":1,"prev":"genesis","hash":"test-hash"}\n');
      expect(existsSync(log + ".lock")).toBe(false);
      expect(readdirSync(root).filter((name) => name.endsWith(".tmp"))).toEqual([]);
    } finally {
      clearTimeout(timer);
      if (child?.exitCode === null) child.kill();
      if (child) await child.exited;
      rmSync(root, { recursive: true, force: true });
    }
  });

  for (const [contents, reason] of [["", "empty"], ["garbage", "invalid pid"]]) {
    test(`reclaims a lock with ${reason} contents and appends`, async () => {
      const root = mkdtempSync(join(tmpdir(), "receipt-chain-invalid-lock-"));
      const log = join(root, "chain.jsonl");
      let child: Bun.Subprocess<"ignore", "pipe", "pipe"> | undefined;
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        writeFileSync(log + ".lock", contents!);
        const worker = join(root, "writer.ts");
        writeFileSync(worker, `
          import { appendLocked } from ${JSON.stringify(join(import.meta.dir, "receipt-chain.ts"))};
          appendLocked(process.argv[2], (prev) => JSON.stringify({ seq: prev.seq + 1, prev: prev.hash, hash: "test-hash" }));
        `);
        child = Bun.spawn([process.execPath, worker, log], {
          cwd: root, stdin: "ignore", stdout: "pipe", stderr: "pipe",
        });
        timer = setTimeout(() => child!.kill(), 3000);
        expect(await child.exited).toBe(0);
        expect(await new Response(child.stderr).text()).toBe(`receipt lock reclaimed (${reason})\n`);
        expect(readFileSync(log, "utf8")).toBe('{"seq":1,"prev":"genesis","hash":"test-hash"}\n');
        expect(existsSync(log + ".lock")).toBe(false);
        expect(readdirSync(root).filter((name) => name.endsWith(".tmp"))).toEqual([]);
      } finally {
        clearTimeout(timer);
        if (child?.exitCode === null) child.kill();
        if (child) await child.exited;
        rmSync(root, { recursive: true, force: true });
      }
    });
  }

  test("publishes a PID-filled lock and leaves no temporary file after an append", () => {
    const root = mkdtempSync(join(tmpdir(), "receipt-chain-tmp-lock-"));
    const log = join(root, "chain.jsonl");
    try {
      appendLocked(log, () => {
        expect(readFileSync(log + ".lock", "utf8")).toBe(String(process.pid));
        expect(readdirSync(root)).toEqual(["chain.jsonl.lock"]);
        return JSON.stringify({ seq: 1, hash: "test-hash" });
      });
      expect(readdirSync(root)).toEqual(["chain.jsonl"]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("four processes append 100 signed receipts without forks or seq gaps", async () => {
    const root = mkdtempSync(join(tmpdir(), "receipt-chain-lock-"));
    const log = join(root, "chain.jsonl");
    const children: Bun.Subprocess<"ignore", "pipe", "pipe">[] = [];
    try {
      const { privateKey, publicKey } = generateKeyPairSync("ed25519");
      writeFileSync(join(root, "test-key.pem"), privateKey.export({ type: "pkcs8", format: "pem" }));
      const worker = join(root, "writer.ts");
      writeFileSync(worker, `
        import { appendLocked } from ${JSON.stringify(join(import.meta.dir, "receipt-chain.ts"))};
        import { createHash, sign } from "node:crypto";
        import { existsSync, readFileSync, writeFileSync } from "node:fs";
        const [log, keyPath, ready, start] = process.argv.slice(2);
        const key = readFileSync(keyPath, "utf8");
        writeFileSync(ready, "ready");
        while (!existsSync(start)) Bun.sleepSync(5);
        for (let i = 0; i < 25; i++) {
          appendLocked(log, (prev) => {
            Bun.sleepSync(2); // Widen the read/append window to exercise contention.
            const body = { seq: prev.seq + 1, prev: prev.hash, writer: process.pid, i };
            const hash = createHash("sha256").update(JSON.stringify(body)).digest("hex");
            const sig = sign(null, Buffer.from(hash), key).toString("base64");
            return JSON.stringify({ ...body, hash, sig });
          });
        }
      `);
      // Hold a live owner's lock until all children have attempted an append.
      writeFileSync(log + ".lock", String(process.pid));
      for (let i = 0; i < 4; i++) {
        children.push(Bun.spawn([process.execPath, worker, log, join(root, "test-key.pem"), join(root, `ready-${i}`), join(root, "start")], {
          cwd: root, stdin: "ignore", stdout: "pipe", stderr: "pipe",
        }));
      }
      const deadline = Date.now() + 5000;
      while (![0, 1, 2, 3].every((i) => existsSync(join(root, `ready-${i}`)))) {
        if (Date.now() > deadline) throw new Error("writers did not become ready");
        await Bun.sleep(10);
      }
      writeFileSync(join(root, "start"), "start");
      await Bun.sleep(100);
      expect(existsSync(log)).toBe(false);
      expect(readFileSync(log + ".lock", "utf8")).toBe(String(process.pid));
      rmSync(log + ".lock");
      const results = await Promise.all(children.map(async (child) => ({
        code: await child.exited,
        stderr: await new Response(child.stderr).text(),
      })));
      expect(results).toEqual(Array.from({ length: 4 }, () => ({ code: 0, stderr: "" })));
      const lines = readFileSync(log, "utf8").trim().split("\n");
      const result = verifyChain(lines, publicKey.export({ type: "spki", format: "pem" }).toString());
      expect(lines).toHaveLength(100);
      expect(result).toEqual({ count: 100, bad: [] });
      expect(result.bad.some(({ reason }) => reason.includes("seq gap"))).toBe(false);
      expect(new Set(lines.map((line) => JSON.parse(line).writer)).size).toBe(4);
      expect(existsSync(log + ".lock")).toBe(false);
      expect(readdirSync(root).filter((name) => name.endsWith(".tmp"))).toEqual([]);
    } finally {
      for (const child of children) if (child.exitCode === null) child.kill();
      await Promise.all(children.map((child) => child.exited));
      rmSync(root, { recursive: true, force: true });
    }
  }, 15000);

  test("reclaims a dead owner's lock", async () => {
    const root = mkdtempSync(join(tmpdir(), "receipt-chain-dead-lock-"));
    const log = join(root, "chain.jsonl");
    try {
      const child = Bun.spawn([process.execPath, "-e", ""], { cwd: root });
      expect(await child.exited).toBe(0);
      writeFileSync(log + ".lock", String(child.pid));
      appendLocked(log, (prev) => {
        expect(prev).toEqual({ seq: 0, hash: "genesis" });
        return JSON.stringify({ seq: 1, hash: "test-hash" });
      });
      expect(readFileSync(log, "utf8")).toBe('{"seq":1,"hash":"test-hash"}\n');
      expect(existsSync(log + ".lock")).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("releases the lock after callback and corrupt-tail errors without changing the chain", () => {
    const root = mkdtempSync(join(tmpdir(), "receipt-chain-error-lock-"));
    const log = join(root, "chain.jsonl");
    try {
      expect(() => appendLocked(log, () => { throw new Error("build failed"); })).toThrow("build failed");
      expect(existsSync(log + ".lock")).toBe(false);
      expect(existsSync(log)).toBe(false);
      writeFileSync(log, '{"seq":');
      expect(() => appendLocked(log, () => { throw new Error("must not build"); })).toThrow("receipt chain corrupt:");
      expect(readFileSync(log, "utf8")).toBe('{"seq":');
      expect(existsSync(log + ".lock")).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
