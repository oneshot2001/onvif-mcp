// Bun's WebSocket TLS options do not expose a peer-certificate check before
// the authenticated upgrade. Refuse pins rather than probe a separate socket:
// a separate connection would not authenticate the peer receiving credentials.
function refuseUnverifiablePin(): boolean {
  throw new Error("event observation refused: Bun WebSocket cannot verify the peer SPKI pin before sending Authorization");
}

export function openEventWebSocket(
  cam: { base: string; pin?: string },
  credentials: () => { user: string; password: string },
  checkPin: (url: string, pin: string) => boolean = refuseUnverifiablePin,
  connect: (url: string, options: Bun.WebSocketOptions) => WebSocket = (url, options) => new WebSocket(url, options),
): WebSocket {
  const url = `wss://${new URL(cam.base).host}/vapix/ws-data-stream?sources=events`;
  if (cam.pin !== undefined && checkPin(url, cam.pin) !== true) {
    throw new Error("event WebSocket SPKI pin mismatch");
  }
  const { user, password } = credentials();
  return connect(url, {
    headers: { Authorization: `Basic ${Buffer.from(`${user}:${password}`).toString("base64")}` },
    tls: { rejectUnauthorized: false },
  });
}
