import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { curlRequest } from "./curl-args";
import { setInvocationRecorder, withInvocations, type InvocationRecord } from "./invocation";
import { createSessionRouter, type TokenRecord } from "./gateway-listen";

describe("curl in gateway mode", () => {
  test("routes through the witness socket with the camera id as host and the request-target unchanged", () => {
    const { args, stdin } = curlRequest({ base: "http://q6358", user: "gateway-view", auth: "any" }, "pw", "/axis-cgi/param.cgi?action=list&group=Brand", { unixSocket: "/run/gateway/witness/claude-main.sock" });
    expect(args.slice(args.indexOf("--unix-socket"), args.indexOf("--unix-socket") + 2)).toEqual(["--unix-socket", "/run/gateway/witness/claude-main.sock"]);
    expect(args.at(-1)).toBe("http://q6358/axis-cgi/param.cgi?action=list&group=Brand");
    expect(args).not.toContain("--pinnedpubkey");
    expect(args).toContain("--anyauth");
    expect(args).not.toContain("--digest");
    expect(stdin).toBe('user = "gateway-view:pw"\n');
    // a camera that offers Digest keeps Digest even through the witness: no downgrade to Basic
    const digest = curlRequest({ base: "http://p3285", user: "gateway-view" }, "pw", "/x", { unixSocket: "/s" }).args;
    expect(digest).toContain("--digest");
    expect(digest).not.toContain("--anyauth");
    // and "any" never applies to a direct (non-witness) call
    expect(curlRequest({ base: "http://192.168.1.33", user: "u", auth: "any" }, "pw", "/x").args).toContain("--digest");
  });

  test("refuses a pin or an https base: TLS belongs to the witness", () => {
    expect(() => curlRequest({ base: "http://p3285", user: "u", pin: "sha256//AAAA" }, "pw", "/x", { unixSocket: "/s" })).toThrow("belongs to the witness");
    expect(() => curlRequest({ base: "https://192.168.1.19", user: "u" }, "pw", "/x", { unixSocket: "/s" })).toThrow("http://<camera-id>");
  });

  test("without a socket nothing changes", () => {
    const { args } = curlRequest({ base: "https://192.168.1.19", user: "u", pin: "sha256//AAAA" }, "pw", "/x");
    expect(args).toContain("--pinnedpubkey");
    expect(args).toContain("--digest");
    expect(args).not.toContain("--anyauth");
    expect(args).not.toContain("--unix-socket");
  });
});

describe("invocation ownership record", () => {
  afterEach(() => setInvocationRecorder(undefined));

  test("is written before the tool body runs and carries the tool name and the invocation id", async () => {
    const order: string[] = [];
    const records: InvocationRecord[] = [];
    setInvocationRecorder((entry) => { order.push("record"); records.push(entry); });
    const server = new McpServer({ name: "t", version: "0" });
    withInvocations(server);
    let seenId: string | undefined;
    server.tool("echo", "echo", { text: z.string() }, async ({ text }) => {
      order.push("body");
      const { currentInvocationId } = await import("./invocation");
      seenId = currentInvocationId();
      return { content: [{ type: "text", text }] };
    });
    const token: TokenRecord = { agent: "claude-main", sha256: createHash("sha256").update("s").digest("hex"), expires: "2099-01-01T00:00:00Z" };
    const handle = createSessionRouter(server, { token, now: () => 0, log: () => {}, schedule: () => {} });
    const headers = { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: "Bearer s" };
    const init = await handle(new Request("http://g/mcp", { method: "POST", headers, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } } }) }));
    const sid = init.headers.get("mcp-session-id")!;
    await init.text();
    const call = await handle(new Request("http://g/mcp", { method: "POST", headers: { ...headers, "mcp-session-id": sid }, body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo", arguments: { text: "x" } } }) }));
    await call.text();
    expect(order).toEqual(["record", "body"]);
    expect(records).toHaveLength(1);
    expect(records[0]!.tool).toBe("echo");
    expect(records[0]!.invocation_id).toMatch(/^[0-9a-f]{32}$/);
    expect(records[0]!.invocation_id).toBe(seenId!);
    expect(Date.parse(records[0]!.ts)).not.toBeNaN();
  });

  test("a recorder that throws stops the tool body (ownership is durable or nothing runs)", async () => {
    setInvocationRecorder(() => { throw new Error("disk full"); });
    const server = new McpServer({ name: "t", version: "0" });
    withInvocations(server);
    let ran = false;
    server.tool("echo", "echo", { text: z.string() }, async ({ text }) => { ran = true; return { content: [{ type: "text", text }] }; });
    const token: TokenRecord = { agent: "claude-main", sha256: createHash("sha256").update("s").digest("hex"), expires: "2099-01-01T00:00:00Z" };
    const handle = createSessionRouter(server, { token, now: () => 0, log: () => {}, schedule: () => {} });
    const headers = { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: "Bearer s" };
    const init = await handle(new Request("http://g/mcp", { method: "POST", headers, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } } }) }));
    const sid = init.headers.get("mcp-session-id")!;
    await init.text();
    const call = await handle(new Request("http://g/mcp", { method: "POST", headers: { ...headers, "mcp-session-id": sid }, body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo", arguments: { text: "x" } } }) }));
    const text = await call.text();
    expect(ran).toBe(false);
    expect(text).toContain("disk full");
  });
});

describe("token expiry closes the live session", () => {
  test("the scheduled close fires at the expiry and the old session id is gone", async () => {
    const scheduled: Array<{ fn: () => void; ms: number }> = [];
    const server = new McpServer({ name: "t", version: "0" });
    server.tool("echo", "echo", { text: z.string() }, async ({ text }) => ({ content: [{ type: "text", text }] }));
    let now = Date.parse("2026-10-30T12:00:00Z");
    const token: TokenRecord = { agent: "claude-main", sha256: createHash("sha256").update("s").digest("hex"), expires: "2026-10-30T12:10:00Z" };
    const lines: string[] = [];
    let exited = 0;
    const handle = createSessionRouter(server, { token, now: () => now, log: (line) => lines.push(line), schedule: (fn, ms) => scheduled.push({ fn, ms }), onExpired: () => { exited++; } });
    const headers = { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: "Bearer s" };
    const init = await handle(new Request("http://g/mcp", { method: "POST", headers, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } } }) }));
    const sid = init.headers.get("mcp-session-id")!;
    await init.text();
    expect(scheduled).toHaveLength(1);
    expect(scheduled[0]!.ms).toBe(10 * 60 * 1000);
    await scheduled[0]!.fn();
    expect(lines).toEqual([]);
    expect(scheduled).toHaveLength(2);
    now = Date.parse("2026-10-30T12:10:00Z");
    await scheduled[1]!.fn();
    expect(lines).toEqual([`gateway: token for agent claude-main expired; closing session ${sid}`]);
    expect(exited).toBe(1);
    const late = await handle(new Request("http://g/mcp", { method: "POST", headers: { ...headers, "mcp-session-id": sid }, body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }) }));
    expect(late.status).toBe(401);
    expect(await late.text()).toBe("token expired");
  });

  test("a far-future expiry is re-armed in chunks, never clamped to 1 ms (real timers)", async () => {
    const server = new McpServer({ name: "t", version: "0" });
    server.tool("echo", "echo", { text: z.string() }, async ({ text }) => ({ content: [{ type: "text", text }] }));
    const token: TokenRecord = { agent: "claude-main", sha256: createHash("sha256").update("s").digest("hex"), expires: "2099-01-01T00:00:00Z" };
    const arms: number[] = [];
    const handle = createSessionRouter(server, { token, log: () => {}, onExpired: () => { throw new Error("must not expire"); }, schedule: (fn, ms) => { arms.push(ms); setTimeout(fn, ms).unref(); } });
    const headers = { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: "Bearer s" };
    const init = await handle(new Request("http://g/mcp", { method: "POST", headers, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } } }) }));
    const sid = init.headers.get("mcp-session-id")!;
    await init.text();
    expect(arms).toEqual([2 ** 31 - 1]);
    await new Promise((resolve) => setTimeout(resolve, 30));
    const call = await handle(new Request("http://g/mcp", { method: "POST", headers: { ...headers, "mcp-session-id": sid }, body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo", arguments: { text: "alive" } } }) }));
    expect(call.status).toBe(200);
    await call.text();
  });
});

describe("tier denial", () => {
  test("a tool whose credential tier the vault withholds is a receipted deny, not a curl with an undefined password", async () => {
    const { configHarness } = await import("./config-tools-harness");
    const { mkdtempSync, writeFileSync, mkdirSync } = await import("node:fs");
    const root = mkdtempSync(join(tmpdir(), "tier-"));
    try {
      mkdirSync(join(root, "baselines"), { recursive: true });
      writeFileSync(join(root, "baselines", "cam.json"), JSON.stringify({ camera: "cam", captured: "x", groups: ["Image"], params: { "Image.X": "saved" }, sha256: "x" }));
      const policy = { test: { tools: ["config_remediate"], cameras: ["cam"], config: { groups: ["Image"], remediate: true } } };
      const h = configHarness(root, { policy, tierDenied: (tool, camera) => `credential tier for '${tool}' withheld by the vault: admin until P4 (${camera})` });
      const input = { camera: "cam", param: "Image.X", approve: true };
      expect(await h.handlers.config_remediate!(input)).toEqual({ content: [{ type: "text", text: "DENIED: credential tier for 'config_remediate' withheld by the vault: admin until P4 (cam)" }] });
      expect(h.chain).toEqual([["config_remediate", input, "deny", "credential tier for 'config_remediate' withheld by the vault: admin until P4 (cam)"]]);
      expect(h.calls).toEqual([]);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});
