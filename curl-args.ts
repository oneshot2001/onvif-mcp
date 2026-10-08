export function validatePin(pin: unknown): void {
  if (pin === undefined) return;
  if (typeof pin !== "string" || !pin.startsWith("sha256//")) throw new Error("camera pin must start with sha256//");
  if (pin.length === "sha256//".length) throw new Error("camera pin must include a hash after sha256//");
}

export function curlRequest(
  cam: { base: string; user: string; pin?: string },
  password: string,
  path: string,
  opts: { outFile?: string; jsonBody?: unknown; soapBody?: string; maxTime?: number } = {},
): { args: string[]; stdin: string } {
  const url = `${cam.base}${path}`;
  const credentials = `${cam.user}:${password}`.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  const args = ["curl", "-sk", "--digest", "--fail", "--config", "-", "--max-time", String(opts.maxTime ?? 10)];
  if (cam.pin !== undefined) {
    validatePin(cam.pin);
    if (!url.startsWith("https://")) throw new Error("camera pin requires an https:// URL");
    args.push("--pinnedpubkey", cam.pin);
  }
  if (opts.jsonBody !== undefined) args.push("-H", "content-type: application/json", "--data-raw", JSON.stringify(opts.jsonBody));
  if (opts.soapBody !== undefined) args.push("-H", "Content-Type: application/soap+xml", "--data-raw", opts.soapBody);
  args.push(url);
  if (opts.outFile) args.push("-o", opts.outFile);
  return { args, stdin: `user = "${credentials}"\n` };
}
