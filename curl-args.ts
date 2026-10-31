export const CURL_TIMEOUT_SECONDS = 10;

export function validatePin(pin: unknown): void {
  if (pin === undefined) return;
  if (typeof pin !== "string" || !pin.startsWith("sha256//")) throw new Error("camera pin must start with sha256//");
  if (pin.length === "sha256//".length) throw new Error("camera pin must include a hash after sha256//");
}

export function curlRequest(
  cam: { base: string; user: string; pin?: string },
  password: string,
  path: string,
  opts: { outFile?: string; jsonBody?: unknown; soapBody?: string; maxTime?: number; invocationId?: string; commandDigest?: string; unixSocket?: string } = {},
): { args: string[]; stdin: string } {
  const url = `${cam.base}${path}`;
  const credentials = `${cam.user}:${password}`.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  // Direct: Digest only (plain HTTP must never carry Basic). Through the witness: the
  // camera leg is pinned HTTPS and Axis offers only Basic over HTTPS on 12.9 firmware
  // (Digest over HTTPS on the P3285), so curl negotiates whichever the camera offers.
  const auth = opts.unixSocket !== undefined ? "--anyauth" : "--digest";
  const args = ["curl", "-sk", "--globoff", auth, "--fail", "--config", "-", "--max-time", String(opts.maxTime ?? CURL_TIMEOUT_SECONDS)];
  if (opts.unixSocket !== undefined) {
    // Gateway mode: the witness is the only path. It owns TLS and the pin; the
    // URL names the camera by id and the request-target is passed unchanged.
    if (cam.pin !== undefined) throw new Error("camera pin belongs to the witness in gateway mode");
    if (!url.startsWith("http://")) throw new Error("gateway mode requires an http://<camera-id> base");
    args.push("--unix-socket", opts.unixSocket);
  }
  if (cam.pin !== undefined) {
    validatePin(cam.pin);
    if (!url.startsWith("https://")) throw new Error("camera pin requires an https:// URL");
    args.push("--pinnedpubkey", cam.pin);
  }
  if (opts.jsonBody !== undefined) args.push("-H", "content-type: application/json", "--data-raw", JSON.stringify(opts.jsonBody));
  if (opts.soapBody !== undefined) args.push("-H", "Content-Type: application/soap+xml", "--data-raw", opts.soapBody);
  if (opts.invocationId !== undefined) {
    if (typeof opts.invocationId !== "string" || !/^[0-9a-f]{32}$/.test(opts.invocationId)) throw new Error("invalid invocation ID");
    args.push("-H", `X-AAR-Invocation-ID: ${opts.invocationId}`);
  }
  if (opts.commandDigest !== undefined) {
    if (typeof opts.commandDigest !== "string" || !/^[0-9a-f]{64}$/.test(opts.commandDigest)) throw new Error("invalid command digest");
    args.push("-H", "X-AAR-Action-Bearing: 1", "-H", `X-AAR-Command-Digest: ${opts.commandDigest}`);
  }
  args.push(url);
  if (opts.outFile) args.push("-o", opts.outFile);
  return { args, stdin: `user = "${credentials}"\n` };
}
