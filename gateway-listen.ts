// Gateway mode (physec network plan P1): the same tool surface served over
// Streamable HTTP behind a bearer token, one agent identity per process.
// The unit that starts the process sets AGENT_ID; the token file binds the
// caller to that identity. Stdio mode is untouched.
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";

export interface TokenRecord { agent: string; sha256: string; expires: string }
export interface GatewayConfig { port: number; hostname: string; token: TokenRecord; tls?: { cert: string; key: string } }

export function parseTokenRecord(text: string): TokenRecord {
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { throw new Error("token file is not JSON"); }
  const record = parsed as Partial<TokenRecord> | null;
  if (typeof record?.agent !== "string" || record.agent === "") throw new Error("token file: agent must be a non-empty string");
  if (typeof record.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(record.sha256)) throw new Error("token file: sha256 must be 64 lowercase hex characters");
  if (typeof record.expires !== "string" || Number.isNaN(Date.parse(record.expires))) throw new Error("token file: expires must be an ISO timestamp");
  return { agent: record.agent, sha256: record.sha256, expires: record.expires };
}

export function gatewayConfigFromEnv(
  env: Record<string, string | undefined>,
  read: (path: string) => string = (path) => readFileSync(path, "utf8"),
  now?: () => number,
): GatewayConfig | null {
  const listen = env.GATEWAY_LISTEN;
  if (listen === undefined || listen === "") return null;
  const port = Number(listen);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("GATEWAY_LISTEN must be a TCP port number");
  if (!env.GATEWAY_TOKEN_FILE) throw new Error("GATEWAY_TOKEN_FILE is required in gateway mode");
  const token = parseTokenRecord(read(env.GATEWAY_TOKEN_FILE));
  if (Date.parse(token.expires) <= (now ?? Date.now)()) throw new Error(`token for agent '${token.agent}' expired at ${token.expires}; issue a new one`);
  if (token.agent !== env.AGENT_ID) throw new Error(`token file is for agent '${token.agent}' but AGENT_ID is '${env.AGENT_ID ?? ""}'`);
  const certPath = env.GATEWAY_TLS_CERT;
  const keyPath = env.GATEWAY_TLS_KEY;
  if ((certPath === undefined) !== (keyPath === undefined)) throw new Error("GATEWAY_TLS_CERT and GATEWAY_TLS_KEY must be set together");
  const tls = certPath !== undefined && keyPath !== undefined ? { cert: read(certPath), key: read(keyPath) } : undefined;
  const hostname = env.GATEWAY_BIND ?? "127.0.0.1";
  // A bearer token in cleartext on the LAN is a stolen token. TLS is the
  // contract (plan C2); loopback is the only exception, for local tests.
  if (tls === undefined && hostname !== "127.0.0.1" && hostname !== "::1" && hostname !== "localhost") throw new Error(`GATEWAY_BIND=${hostname} needs GATEWAY_TLS_CERT and GATEWAY_TLS_KEY; plaintext is allowed on loopback only`);
  return { port, hostname, token, tls };
}

export function bearerProblem(authorization: string | null, token: TokenRecord, now: number): string | null {
  if (authorization === null || authorization === "") return "missing bearer token";
  const match = /^Bearer\s+(\S+)$/i.exec(authorization);
  if (match === null) return "malformed Authorization header";
  const presented = Buffer.from(createHash("sha256").update(match[1]!).digest("hex"), "hex");
  const expected = Buffer.from(token.sha256, "hex");
  if (presented.length !== expected.length || !timingSafeEqual(presented, expected)) return "invalid token";
  if (Date.parse(token.expires) <= now) return "token expired";
  return null;
}

function unauthorized(problem: string): Response {
  return new Response(problem, { status: 401, headers: { "www-authenticate": 'Bearer realm="onvif-mcp"' } });
}

/**
 * One live MCP session per process. A fresh initialize replaces the previous
 * session (a client that restarted must not be locked out by its own ghost);
 * requests for a replaced session get the transport's 404.
 */
export function createSessionRouter(
  server: McpServer,
  opts: { token: TokenRecord; now?: () => number; log?: (line: string) => void; schedule?: (fn: () => void, ms: number) => void; onExpired?: () => void },
): (request: Request) => Promise<Response> {
  const now = opts.now ?? Date.now;
  const log = opts.log ?? ((line) => console.error(line));
  const schedule = opts.schedule ?? ((fn, ms) => { setTimeout(fn, ms).unref?.(); });
  // After the expiry close the process exits so the unit's restart re-reads the
  // token file; a revoked or expired file then refuses startup.
  const onExpired = opts.onExpired ?? (() => process.exit(0));
  const MAX_DELAY = 2 ** 31 - 1; // setTimeout clamps anything longer to 1 ms
  const armExpiry = (transport: WebStandardStreamableHTTPServerTransport) => {
    const remaining = Date.parse(opts.token.expires) - now();
    schedule(async () => {
      if (current !== transport) return;
      if (Date.parse(opts.token.expires) - now() > 0) { armExpiry(transport); return; }
      log(`gateway: token for agent ${opts.token.agent} expired; closing session ${transport.sessionId ?? "?"}`);
      current = undefined;
      await server.close();
      onExpired();
    }, Math.min(Math.max(0, remaining), MAX_DELAY));
  };
  let current: WebStandardStreamableHTTPServerTransport | undefined;
  // Initializes are serialized: two at once must not both connect a transport.
  let pending: Promise<unknown> = Promise.resolve();
  return async (request) => {
    const problem = bearerProblem(request.headers.get("authorization"), opts.token, now());
    if (problem !== null) return unauthorized(problem);
    if (request.headers.get("mcp-session-id") === null && request.method === "POST") {
      let body: unknown;
      try { body = await request.clone().json(); } catch { body = undefined; }
      if (isInitializeRequest(body)) {
        const opened = pending.then(async () => {
          const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: randomUUID });
          if (current !== undefined) {
            log(`gateway: new initialize for agent ${opts.token.agent} replaces session ${current.sessionId ?? "?"}`);
            await server.close();
          }
          await server.connect(transport);
          current = transport;
          // Token expiry ends the session and its streams, not only new requests.
          armExpiry(transport);
          return transport;
        });
        pending = opened.catch(() => undefined);
        return (await opened).handleRequest(request);
      }
    }
    if (current === undefined) return new Response("no MCP session: send an initialize request first", { status: 400 });
    return current.handleRequest(request);
  };
}

export function serveGateway(server: McpServer, cfg: GatewayConfig, log: (line: string) => void = (line) => console.error(line)) {
  const handle = createSessionRouter(server, { token: cfg.token, log });
  const listener = Bun.serve({
    hostname: cfg.hostname,
    port: cfg.port,
    tls: cfg.tls,
    // Bun's maximum. The notification SSE stream idles between calls; a
    // client whose stream is closed at the limit reopens it.
    idleTimeout: 255,
    fetch: handle,
  });
  log(`onvif-mcp gateway: ${cfg.tls ? "https" : "http"}://${cfg.hostname}:${cfg.port} for agent ${cfg.token.agent}, token expires ${cfg.token.expires}`);
  return listener;
}
