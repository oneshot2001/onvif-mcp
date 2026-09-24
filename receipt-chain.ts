export function lastReceiptFrom(text: string): { seq: number; hash: string } {
  const trimmed = text.trim();
  if (!trimmed) return { seq: 0, hash: "genesis" };
  const lines = trimmed.split("\n");
  const last = JSON.parse(lines[lines.length - 1]!);
  return { seq: last.seq, hash: last.hash };
}
