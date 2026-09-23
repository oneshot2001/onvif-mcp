export function parseParams(body: string): Record<string, string> {
  const params: Record<string, string> = {};
  for (const line of body.split(/\r?\n/)) {
    // Firmware quirk (AXIS OS 12.x): group listings prefix lines with "root.",
    // exact-param queries don't. Accept both.
    const key = line.startsWith("root.") ? line.slice(5) : line;
    const i = key.indexOf("=");
    if (i > 0 && /^[A-Za-z]/.test(key)) params[key.slice(0, i)] = key.slice(i + 1);
  }
  return Object.fromEntries(Object.entries(params).sort(([a], [b]) => a.localeCompare(b)));
}
