import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { bearerProblem, createSessionRouter, gatewayConfigFromEnv, parseTokenRecord, type TokenRecord } from "./gateway-listen";

const SECRET = "test-token-0123456789abcdef";
const TOKEN: TokenRecord = { agent: "claude-main", sha256: createHash("sha256").update(SECRET).digest("hex"), expires: "2099-01-01T00:00:00Z" };
const NOW = Date.parse("2026-10-30T12:00:00Z");

function mcpRequest(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request("http://gateway.test/mcp", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${SECRET}`, ...headers },
    body: JSON.stringify(body),
  });
}
const initialize = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } } };

async function firstSseMessage(response: Response): Promise<any> {
  const text = await response.text();
  const data = text.split("\n").find((line) => line.startsWith("data: "));
  if (data === undefined) throw new Error(`no SSE data in: ${text.slice(0, 200)}`);
  return JSON.parse(data.slice("data: ".length));
}

function serverWithEcho(): { server: McpServer; calls: string[] } {
  const calls: string[] = [];
  const server = new McpServer({ name: "t", version: "0" });
  server.tool("echo", "echo", { text: z.string() }, async ({ text }) => { calls.push(text); return { content: [{ type: "text", text }] }; });
  return { server, calls };
}

describe("bearer tokens", () => {
  test("missing, malformed, wrong and expired tokens are refused with distinct reasons", () => {
    expect(bearerProblem(null, TOKEN, NOW)).toBe("missing bearer token");
    expect(bearerProblem("Basic abc", TOKEN, NOW)).toBe("malformed Authorization header");
    expect(bearerProblem("Bearer nope", TOKEN, NOW)).toBe("invalid token");
    expect(bearerProblem(`Bearer ${SECRET}`, { ...TOKEN, expires: "2026-10-30T11:59:59Z" }, NOW)).toBe("token expired");
    expect(bearerProblem(`Bearer ${SECRET}`, TOKEN, NOW)).toBeNull();
    expect(bearerProblem(`bearer ${SECRET}`, TOKEN, NOW)).toBeNull();
  });

  test("a wrong token is reported as invalid even when the record is expired", () => {
    expect(bearerProblem("Bearer nope", { ...TOKEN, expires: "2000-01-01T00:00:00Z" }, NOW)).toBe("invalid token");
  });
});

describe("token file", () => {
  test("rejects non-JSON, bad hash, bad expiry and empty agent", () => {
    expect(() => parseTokenRecord("{")).toThrow("not JSON");
    expect(() => parseTokenRecord(JSON.stringify({ ...TOKEN, sha256: "abc" }))).toThrow("sha256");
    expect(() => parseTokenRecord(JSON.stringify({ ...TOKEN, sha256: TOKEN.sha256.toUpperCase() }))).toThrow("sha256");
    expect(() => parseTokenRecord(JSON.stringify({ ...TOKEN, expires: "soon" }))).toThrow("expires");
    expect(() => parseTokenRecord(JSON.stringify({ ...TOKEN, agent: "" }))).toThrow("agent");
    expect(parseTokenRecord(JSON.stringify({ ...TOKEN, extra: 1 }))).toEqual(TOKEN);
  });
});

describe("gateway config from the environment", () => {
  const files: Record<string, string> = { "/t/token.json": JSON.stringify(TOKEN), "/t/cert.pem": "CERT", "/t/key.pem": "KEY" };
  const read = (path: string) => { const text = files[path]; if (text === undefined) throw new Error(`ENOENT ${path}`); return text; };

  test("absent GATEWAY_LISTEN means stdio mode", () => {
    expect(gatewayConfigFromEnv({ AGENT_ID: "claude-main" }, read)).toBeNull();
    expect(gatewayConfigFromEnv({ GATEWAY_LISTEN: "" }, read)).toBeNull();
  });

  test("port, token file and agent binding are validated", () => {
    expect(() => gatewayConfigFromEnv({ GATEWAY_LISTEN: "unix:/x" }, read)).toThrow("TCP port");
    expect(() => gatewayConfigFromEnv({ GATEWAY_LISTEN: "70000" }, read)).toThrow("TCP port");
    expect(() => gatewayConfigFromEnv({ GATEWAY_LISTEN: "8443" }, read)).toThrow("GATEWAY_TOKEN_FILE");
    expect(() => gatewayConfigFromEnv({ GATEWAY_LISTEN: "8443", GATEWAY_TOKEN_FILE: "/t/token.json", AGENT_ID: "codex-main" }, read)).toThrow("AGENT_ID is 'codex-main'");
    expect(() => gatewayConfigFromEnv({ GATEWAY_LISTEN: "8443", GATEWAY_TOKEN_FILE: "/t/token.json" }, read)).toThrow("AGENT_ID is ''");
    expect(gatewayConfigFromEnv({ GATEWAY_LISTEN: "8443", GATEWAY_TOKEN_FILE: "/t/token.json", AGENT_ID: "claude-main" }, read))
      .toEqual({ port: 8443, hostname: "127.0.0.1", token: TOKEN, tls: undefined });
  });

  test("an expired token refuses startup, so a restarted unit cannot serve a dead token", () => {
    const expired: Record<string, string> = { ...files, "/t/old.json": JSON.stringify({ ...TOKEN, expires: "2026-10-30T11:00:00Z" }) };
    expect(() => gatewayConfigFromEnv({ GATEWAY_LISTEN: "8443", GATEWAY_TOKEN_FILE: "/t/old.json", AGENT_ID: "claude-main" }, (p) => expired[p]!, () => NOW)).toThrow("expired at 2026-10-30T11:00:00Z");
  });

  test("a non-loopback bind without TLS is refused: bearer tokens never travel in cleartext on the LAN", () => {
    const base = { GATEWAY_LISTEN: "8443", GATEWAY_TOKEN_FILE: "/t/token.json", AGENT_ID: "claude-main" };
    expect(() => gatewayConfigFromEnv({ ...base, GATEWAY_BIND: "0.0.0.0" }, read)).toThrow("plaintext is allowed on loopback only");
    expect(() => gatewayConfigFromEnv({ ...base, GATEWAY_BIND: "192.168.1.250" }, read)).toThrow("needs GATEWAY_TLS_CERT");
    expect(gatewayConfigFromEnv({ ...base, GATEWAY_BIND: "::1" }, read)!.hostname).toBe("::1");
  });

  test("TLS needs both files and reads them", () => {
    const base = { GATEWAY_LISTEN: "8443", GATEWAY_TOKEN_FILE: "/t/token.json", AGENT_ID: "claude-main", GATEWAY_BIND: "192.168.1.250" };
    expect(() => gatewayConfigFromEnv({ ...base, GATEWAY_TLS_CERT: "/t/cert.pem" }, read)).toThrow("set together");
    expect(gatewayConfigFromEnv({ ...base, GATEWAY_TLS_CERT: "/t/cert.pem", GATEWAY_TLS_KEY: "/t/key.pem" }, read))
      .toEqual({ port: 8443, hostname: "192.168.1.250", token: TOKEN, tls: { cert: "CERT", key: "KEY" } });
  });
});

describe("session router", () => {
  test("refuses every request without a valid bearer before the MCP layer sees it", async () => {
    const { server, calls } = serverWithEcho();
    const handle = createSessionRouter(server, { token: TOKEN, now: () => NOW, log: () => {} });
    const denied = await handle(mcpRequest(initialize, { authorization: "Bearer wrong" }));
    expect(denied.status).toBe(401);
    expect(denied.headers.get("www-authenticate")).toBe('Bearer realm="onvif-mcp"');
    expect(await denied.text()).toBe("invalid token");
    expect(calls).toEqual([]);
  });

  test("initialize opens a session; tool calls run under its session id", async () => {
    const { server, calls } = serverWithEcho();
    const handle = createSessionRouter(server, { token: TOKEN, now: () => NOW, log: () => {} });
    const opened = await handle(mcpRequest(initialize));
    expect(opened.status).toBe(200);
    const sessionId = opened.headers.get("mcp-session-id");
    expect(sessionId).toMatch(/^[0-9a-f-]{36}$/);
    expect((await firstSseMessage(opened)).result.serverInfo.name).toBe("t");
    const call = { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo", arguments: { text: "hello" } } };
    const answered = await handle(mcpRequest(call, { "mcp-session-id": sessionId! }));
    expect(answered.status).toBe(200);
    expect((await firstSseMessage(answered)).result.content[0].text).toBe("hello");
    expect(calls).toEqual(["hello"]);
  });

  test("a non-initialize request before any session is a 400, not a crash", async () => {
    const { server } = serverWithEcho();
    const handle = createSessionRouter(server, { token: TOKEN, now: () => NOW, log: () => {} });
    const call = { jsonrpc: "2.0", id: 2, method: "tools/list" };
    const response = await handle(mcpRequest(call));
    expect(response.status).toBe(400);
  });

  test("a second initialize replaces the session and the old session id stops working", async () => {
    const { server, calls } = serverWithEcho();
    const lines: string[] = [];
    const handle = createSessionRouter(server, { token: TOKEN, now: () => NOW, log: (line) => lines.push(line) });
    const first = await handle(mcpRequest(initialize));
    const firstId = first.headers.get("mcp-session-id")!;
    await first.text();
    const second = await handle(mcpRequest(initialize));
    const secondId = second.headers.get("mcp-session-id")!;
    await second.text();
    expect(secondId).not.toBe(firstId);
    expect(lines).toEqual([`gateway: new initialize for agent claude-main replaces session ${firstId}`]);
    const call = { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "echo", arguments: { text: "late" } } };
    const stale = await handle(mcpRequest(call, { "mcp-session-id": firstId }));
    expect(stale.status).toBe(404);
    const live = await handle(mcpRequest(call, { "mcp-session-id": secondId }));
    expect(live.status).toBe(200);
    await live.text();
    expect(calls).toEqual(["late"]);
  });
});
