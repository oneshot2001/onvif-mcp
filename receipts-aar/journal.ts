import { appendFileSync, closeSync, existsSync, fstatSync, fsyncSync, openSync, readFileSync, readSync, statSync } from "node:fs";
import { dirname } from "node:path";
import { fromHex, toHex } from "aar-kat-harness/harness/cbor";
import { hash } from "aar-kat-harness/harness/crypto";

type Attempt = {
  invocation_id: string;
  receipt_id: string;
  envelope_digest: string;
  envelope_cbor: string;
};
export type JournalRecord =
  | (Attempt & { event: "attempt_envelope" })
  // This reading follows the envelope record's fsync, not this marker's fsync.
  | (Attempt & { event: "attempt_committed"; envelope_synced_at: number })
  | { event: "dispatch_completed" | "dispatch_ambiguous" | "refusal_persisted"; invocation_id: string; observed_at: number };

function pendingAttempts(path: string): Set<string> {
  const pending = new Set<string>();
  if (!existsSync(path)) return pending;
  if (!statSync(path).isFile()) throw Error(`aar journal corrupt: not a regular file (${path})`);
  const text = readFileSync(path, "utf8");
  try {
    if (text && !text.endsWith("\n")) throw Error("torn last line");
    for (const line of text ? text.slice(0, -1).split("\n") : []) {
      const r = JSON.parse(line);
      if (!r || !/^[0-9a-f]{32}$/.test(r.invocation_id)) throw Error("invalid invocation_id");
      switch (r.event) {
        case "attempt_envelope":
        case "attempt_committed":
          if (!/^[0-9a-f]{64}$/.test(r.receipt_id) || !/^[0-9a-f]{64}$/.test(r.envelope_digest)
            || typeof r.envelope_cbor !== "string" || !/^(?:[0-9a-f]{2})+$/.test(r.envelope_cbor)
            || toHex(hash(fromHex(r.envelope_cbor))) !== r.envelope_digest) throw Error("invalid attempt envelope");
          if (r.event === "attempt_committed" && !Number.isSafeInteger(r.envelope_synced_at)) throw Error("invalid sync time");
          pending.add(r.invocation_id);
          break;
        case "dispatch_completed":
        case "dispatch_ambiguous":
          if (!Number.isSafeInteger(r.observed_at) || !pending.delete(r.invocation_id)) throw Error("completion without attempt");
          break;
        case "refusal_persisted":
          if (!Number.isSafeInteger(r.observed_at)) throw Error("invalid refusal time");
          // The initial envelope append itself may have failed before writing.
          pending.delete(r.invocation_id);
          break;
        default: throw Error("unknown journal event");
      }
    }
  } catch (error) {
    throw Error(`aar journal corrupt: ${error instanceof Error ? error.message : String(error)} (${path})`);
  }
  return pending;
}

export function checkAarJournal(path: string): void {
  for (const invocation of pendingAttempts(path)) {
    console.error(`aar journal warning: invocation ${invocation} has no completion; never redispatch (${path})`);
  }
}

export function appendJournal(path: string, record: JournalRecord): void {
  // A failed partial append must also stop subsequent calls in this process.
  // Full validation belongs to startup; append cost is independent of history.
  const fd = openSync(path, "a+", 0o600);
  try {
    const size = fstatSync(fd).size;
    if (size > 0) {
      const tail = Buffer.alloc(1);
      if (readSync(fd, tail, 0, 1, size - 1) !== 1 || tail[0] !== 0x0a) {
        throw Error(`aar journal corrupt: torn last line (${path})`);
      }
    }
    appendFileSync(fd, `${JSON.stringify(record)}\n`);
    fsyncSync(fd);
  } finally { closeSync(fd); }
  // Persist a newly created journal directory entry as well as its contents.
  const directory = openSync(dirname(path), "r");
  try { fsyncSync(directory); } finally { closeSync(directory); }
}
