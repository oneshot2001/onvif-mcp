// Gateway mode (P1): the `vault` uid holds the camera credentials and the
// receipt signing key. The actor asks over a per-agent unix socket; calls are
// synchronous (curl, like the camera path) so `receipt()` can stay inside the
// chain lock. The vault refuses tiers it withholds (admin until P4).
//
// Signing contract (the vault enforces it; this client only relays):
// - `deny` receipts, `list_cameras`/`get_receipts` receipts and `aar_emit`
//   notes are signed as claims: they assert no camera traffic.
// - an `allow` receipt for a camera tool is signed only if the witness log
//   holds traffic for its invocation_id from this agent; for get_snapshot the
//   receipt's result_sha256 must equal a witnessed response body hash.
// - `principal.id` must equal the agent of the socket.
// A refusal here throws inside the chain lock: the tool returns an error and
// no receipt line is written, while the action may already have run; the
// vault records the refusal on its side.
export type VaultResponse = { status: number; body: string };
export type VaultCall = (method: "GET" | "POST", path: string, body?: unknown) => VaultResponse;

export interface Signer {
  sign(kind: "receipt" | "handoff", body: unknown): string;
  publicKeyPem: string;
}

export function curlVaultCall(socket: string): VaultCall {
  return (method, path, body) => {
    const args = ["curl", "-s", "--unix-socket", socket, "--max-time", "5", "-X", method, "-o", "-", "-w", "\n%{http_code}"];
    if (body !== undefined) args.push("-H", "content-type: application/json", "--data-binary", "@-");
    args.push(`http://vault${path}`);
    const p = Bun.spawnSync(args, { stdin: body === undefined ? undefined : Buffer.from(JSON.stringify(body)) });
    if (p.exitCode !== 0) throw new Error(`vault unreachable at ${socket} (curl exit ${p.exitCode})`);
    const out = p.stdout.toString();
    const cut = out.lastIndexOf("\n");
    return { status: Number(out.slice(cut + 1)), body: out.slice(0, cut) };
  };
}

function parse(response: VaultResponse, what: string): Record<string, unknown> {
  let parsed: unknown;
  try { parsed = JSON.parse(response.body); } catch { throw new Error(`vault ${what}: HTTP ${response.status} with a non-JSON body`); }
  if (parsed === null || typeof parsed !== "object") throw new Error(`vault ${what}: HTTP ${response.status} with a non-object body`);
  return parsed as Record<string, unknown>;
}

export class VaultWithheld extends Error {}

export function createVaultClient(call: VaultCall) {
  return {
    /** The credential for a camera tier, or a VaultWithheld error naming the vault's reason. */
    credential(camera: string, tier: "viewer" | "operator" | "admin"): string {
      const response = call("POST", "/credential", { camera, tier });
      const body = parse(response, "credential");
      if (response.status === 403) throw new VaultWithheld(typeof body.reason === "string" ? body.reason : `tier ${tier} withheld`);
      if (response.status !== 200 || typeof body.password !== "string" || body.password === "") throw new Error(`vault credential: HTTP ${response.status} ${typeof body.reason === "string" ? body.reason : ""}`.trim());
      return body.password;
    },
    signer(): Signer {
      const key = parse(call("GET", "/public-key"), "public-key");
      if (typeof key.pem !== "string" || !key.pem.includes("PUBLIC KEY")) throw new Error("vault public-key: no PEM in the reply");
      return {
        publicKeyPem: key.pem,
        sign(kind, body) {
          const response = call("POST", "/sign", { kind, body });
          const reply = parse(response, "sign");
          if (response.status !== 200 || typeof reply.sig !== "string") throw new Error(`vault refused to sign the ${kind}: ${typeof reply.reason === "string" ? reply.reason : `HTTP ${response.status}`} (the action may have executed; no signed ${kind} was written)`);
          return reply.sig;
        },
      };
    },
  };
}
