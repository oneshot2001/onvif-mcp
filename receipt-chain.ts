import { createHash, verify as edVerify } from "node:crypto";
import { appendFileSync, closeSync, existsSync, fstatSync, linkSync, openSync, readFileSync, statSync, unlinkSync, writeFileSync } from "node:fs";

export const STALE_LOCK_MS = 60_000;

export function formatReceiptsText(lines: string[]): string {
  // Escape display text only; stored receipt bytes remain unchanged.
  return lines.join("\n").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029") || "(empty chain)";
}

export function selectReceipts(lines: string[], agent: string, n: number): string[] {
  if (n <= 0) return [];
  return lines.filter((line) => {
    try {
      return JSON.parse(line)?.principal?.id === agent;
    } catch {
      return false;
    }
  }).slice(-n);
}

export function appendLocked(logPath: string, build: (prev: { seq: number; hash: string }) => string): void {
  const lockPath = logPath + ".lock";
  const tmpPath = `${lockPath}.${process.pid}.tmp`;
  while (true) {
    writeFileSync(tmpPath, String(process.pid));
    try {
      try {
        // Publish the lock only after its PID has been written.
        linkSync(tmpPath, lockPath);
      } finally {
        unlinkSync(tmpPath);
      }
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    try {
      const fd = openSync(lockPath, "r");
      try {
        const owner = fstatSync(fd);
        const contents = readFileSync(fd, "utf8").trim();
        const pid = Number(contents);
        const ageMs = Date.now() - owner.mtimeMs;
        let reason: string | undefined;
        if (ageMs > STALE_LOCK_MS) {
          reason = `stale ${Math.floor(ageMs / 1000)}s`;
        } else if (Number.isSafeInteger(pid) && pid > 0) {
          try {
            process.kill(pid, 0);
          } catch (error) {
            // EPERM does not mean the owner is dead.
            if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
            reason = `dead owner ${pid}`;
          }
        } else {
          reason = contents ? "invalid pid" : "empty";
        }
        if (reason) {
          const current = statSync(lockPath);
          if (current.dev === owner.dev && current.ino === owner.ino) {
            unlinkSync(lockPath);
            console.error(`receipt lock reclaimed (${reason})`);
          }
        }
      } finally {
        closeSync(fd);
      }
    } catch (error) {
      if (!["ENOENT", "EPERM"].includes((error as NodeJS.ErrnoException).code ?? "")) throw error;
    }
    Bun.sleepSync(10);
  }
  try {
    const prev = lastReceiptFrom(existsSync(logPath) ? readFileSync(logPath, "utf8") : "");
    appendFileSync(logPath, build(prev) + "\n");
  } finally {
    unlinkSync(lockPath);
  }
}

export function verifyChain(lines: string[], publicKeyPem: string): { count: number; bad: Array<{ seq: number; reason: string }> } {
  const bad: Array<{ seq: number; reason: string }> = [];
  let prev: string | undefined = "genesis";
  let prevSeq: number | undefined = 0;
  for (const [index, line] of lines.entries()) {
    let r;
    try {
      r = JSON.parse(line);
    } catch {
      bad.push({ seq: index + 1, reason: "invalid JSON" });
      prev = undefined;
      prevSeq = undefined;
      continue;
    }
    if (!r || typeof r !== "object" || Array.isArray(r)) {
      bad.push({ seq: index + 1, reason: "invalid receipt" });
      prev = undefined;
      prevSeq = undefined;
      continue;
    }
    const { hash, sig, ...body } = r;
    const expected = createHash("sha256").update(JSON.stringify(body)).digest("hex");
    const reasons: string[] = [];
    if (expected !== hash) reasons.push("hash mismatch");
    let okSig = false;
    if (typeof hash === "string" && typeof sig === "string") {
      try {
        okSig = edVerify(null, Buffer.from(hash), publicKeyPem, Buffer.from(sig, "base64"));
      } catch {
        // Malformed signatures must be reported as verification failures.
      }
    }
    if (!okSig) reasons.push("invalid signature");
    if (prev === undefined || body.prev !== prev) reasons.push("prev mismatch");
    if (!Number.isInteger(r.seq) || prevSeq === undefined || r.seq !== prevSeq + 1) reasons.push("seq gap");
    if (reasons.length) bad.push({ seq: Number.isInteger(r.seq) ? r.seq : index + 1, reason: reasons.join(", ") });
    prev = typeof hash === "string" ? hash : undefined;
    prevSeq = Number.isInteger(r.seq) ? r.seq : undefined;
  }
  return { count: lines.length, bad };
}

export function missingHandoffHeads(chainHashes: Set<string>, handoffs: Array<{ file: string; chain_head_hash: string }>): string[] {
  return handoffs.filter(({ chain_head_hash }) => !chainHashes.has(chain_head_hash)).map(({ file }) => file);
}

export function emptyChainConflict(head: { seq: number; hash: string }, handoffHeads: string[]): string | null {
  return head.seq === 0 && handoffHeads.length > 0
    ? `receipt chain is empty but ${handoffHeads.length} handoff(s) reference earlier receipts — chain truncated?`
    : null;
}

export function lastReceiptFrom(text: string): { seq: number; hash: string } {
  const trimmed = text.trim();
  if (!trimmed) return { seq: 0, hash: "genesis" };
  const lines = trimmed.split("\n");
  let last;
  try {
    last = JSON.parse(lines[lines.length - 1]!);
  } catch {
    throw new Error("receipt chain corrupt: last line is not valid JSON");
  }
  if (!Number.isInteger(last?.seq) || last.seq <= 0) {
    throw new Error("receipt chain corrupt: last seq must be a positive integer");
  }
  if (typeof last.hash !== "string" || last.hash.length === 0) {
    throw new Error("receipt chain corrupt: last hash must be a non-empty string");
  }
  return { seq: last.seq, hash: last.hash };
}
