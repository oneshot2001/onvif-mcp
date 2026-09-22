export function keyModeProblem(mode: number): string | null {
  return (mode & 0o077) !== 0
    ? "receipt.key has group/other permissions; run chmod 600 .keys/receipt.key"
    : null;
}
