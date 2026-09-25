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
