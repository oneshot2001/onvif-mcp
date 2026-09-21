export function curlRequest(
  cam: { base: string; user: string },
  password: string,
  path: string,
  opts: { outFile?: string; jsonBody?: unknown; soapBody?: string; maxTime?: number } = {},
): { args: string[]; stdin: string } {
  const credentials = `${cam.user}:${password}`.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  const args = ["curl", "-sk", "--digest", "--config", "-", "--max-time", String(opts.maxTime ?? 10)];
  if (opts.jsonBody !== undefined) args.push("-H", "content-type: application/json", "--data-raw", JSON.stringify(opts.jsonBody));
  if (opts.soapBody !== undefined) args.push("-H", "Content-Type: application/soap+xml", "--data-raw", opts.soapBody);
  args.push(`${cam.base}${path}`);
  if (opts.outFile) args.push("-o", opts.outFile);
  return { args, stdin: `user = "${credentials}"\n` };
}
