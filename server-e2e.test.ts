import { afterEach, expect, test } from "bun:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { copyFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SERVER_INSTRUCTIONS } from "./server-instructions";

const servers: Array<{ dir: string; client: Client }> = [];

afterEach(async () => {
  for (const { dir, client } of servers.splice(0)) {
    try { await client.close(); }
    finally { rmSync(dir, { recursive: true, force: true }); }
  }
});

async function startServer(agent: string | undefined) {
  const dir = mkdtempSync(join(tmpdir(), "onvif-server-e2e-"));
  const client = new Client({ name: "server-e2e", version: "1.0.0" });
  servers.push({ dir, client });
  const root = join(dir, "root");
  const home = join(dir, "home");
  const bin = join(dir, "bin");
  mkdirSync(root);
  mkdirSync(join(home, ".claude", "bin"), { recursive: true });
  mkdirSync(bin);
  for (const file of readdirSync(import.meta.dir)) {
    if (file.endsWith(".ts") && !file.endsWith(".test.ts")) {
      copyFileSync(join(import.meta.dir, file), join(root, file));
    }
  }
  cpSync(join(import.meta.dir, "receipts-aar"), join(root, "receipts-aar"), {
    recursive: true, filter: (file) => !file.endsWith(".test.ts"),
  });
  symlinkSync(join(import.meta.dir, "node_modules"), join(root, "node_modules"), "dir");
  writeFileSync(join(root, "cameras.json"), JSON.stringify(Object.fromEntries(
    ["lobby", "gate", "dome"].map((id) => [id, {
      base: `http://${id}.invalid`, user: "standin", credKey: "standin-camera",
      protocol: "vapix", ptz: id === "dome",
    }]),
  )));
  writeFileSync(join(root, "policy.json"), JSON.stringify({ agents: {
    "claude-main": { tools: ["get_receipts"], cameras: ["lobby"] },
    viewer: { tools: ["get_receipts", "ptz_move"], cameras: ["lobby", "dome"], ptz: { maxStep: 30, maxZoomStep: 5 } },
  } }));
  writeFileSync(join(home, ".claude", "bin", "cred"), "#!/bin/sh\nprintf '%s\\n' 'standin-password'\n", { mode: 0o755 });
  const hits = join(dir, "hits");
  writeFileSync(hits, "");
  writeFileSync(join(bin, "curl"), `#!/bin/sh
for arg do
  case "$arg" in http*) printf '%s\\n' "$arg" >> "$(dirname "$0")/../hits" ;; esac
done
cat > /dev/null
exit 7
`, { mode: 0o755 });
  const env: Record<string, string> = { PATH: `${bin}:${process.env.PATH ?? ""}`, HOME: home };
  if (agent !== undefined) env.AGENT_ID = agent;
  await client.connect(new StdioClientTransport({ command: process.execPath, args: ["index.ts"], cwd: root, env }));
  return {
    root, env,
    instructions: () => client.getInstructions(),
    callRaw: (name: string, args: Record<string, unknown>) => client.callTool({ name, arguments: args }),
    hits: () => readFileSync(hits, "utf8"),
    chain: () => readFileSync(join(root, "receipts", "chain.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line)),
    async call(name: string, args: Record<string, unknown> = {}) {
      const result = await client.callTool({ name, arguments: args });
      expect(result.isError).not.toBe(true);
      return (result.content as Array<{ type: string; text?: string }>).filter((part) => part.type === "text").map((part) => part.text).join("\n");
    },
  };
}

test("server e2e: the policy gate refuses an ungranted tool, an unlisted camera, an over-bound zoom and a missing identity before any camera request", async () => {
  const server = await startServer("viewer");
  const toolReason = "tool 'get_snapshot' not allowlisted for agent 'viewer'";
  const cameraReason = "camera 'gate' not allowlisted for agent 'viewer'";
  const zoomReason = "zoom step exceeds policy maxZoomStep 5";
  expect((await server.call("get_snapshot", { camera: "lobby" })).startsWith(`DENIED: ${toolReason}\naar-bundle: `)).toBe(true);
  expect(await server.call("ptz_move", { camera: "gate", pan: 1 })).toBe(`DENIED: ${cameraReason}`);
  expect(await server.call("ptz_move", { camera: "dome", zoom: 10 })).toBe(`DENIED: ${zoomReason}`);
  await server.call("get_receipts", { n: 10 });
  expect(server.hits()).toBe("");
  expect(server.chain().map((r) => [r.principal.id, r.action.tool, r.decision, r.node_kind, r.detail])).toEqual([
    ["viewer", "get_snapshot", "deny", "authorization", toolReason],
    ["viewer", "ptz_move", "deny", "authorization", cameraReason],
    ["viewer", "ptz_move", "deny", "authorization", zoomReason],
    ["viewer", "get_receipts", "allow", "observation", "returned 3"],
  ]);

  const anonymous = await startServer(undefined);
  expect(await anonymous.call("get_receipts")).toBe("DENIED: agent 'unknown' not in policy (fail closed)");
  expect(anonymous.hits()).toBe("");
  expect(anonymous.chain().map((r) => [r.principal.id, r.action.tool, r.decision, r.node_kind])).toEqual([
    ["unknown", "get_receipts", "deny", "authorization"],
  ]);
}, 60_000);

test("server e2e: --verify passes the chain the server wrote and fails naming an edited receipt", async () => {
  const server = await startServer("viewer");
  await server.call("ptz_move", { camera: "gate", pan: 1 });
  await server.call("get_receipts");
  await server.call("ptz_move", { camera: "dome", zoom: 10 });
  const verified = Bun.spawnSync([process.execPath, "index.ts", "--verify"], { cwd: server.root, env: server.env });
  expect(verified.exitCode).toBe(0);
  expect(verified.stdout.toString()).toBe("chain OK — 3 receipts, every hash linked + signature valid; 0 handoff signatures valid, heads present\n");

  const log = join(server.root, "receipts", "chain.jsonl");
  const lines = readFileSync(log, "utf8").split("\n");
  expect(JSON.parse(lines[1]!).decision).toBe("allow");
  lines[1] = lines[1]!.replace('"decision":"allow"', '"decision":"deny"');
  writeFileSync(log, lines.join("\n"));
  const broken = Bun.spawnSync([process.execPath, "index.ts", "--verify"], { cwd: server.root, env: server.env });
  expect(broken.exitCode).toBe(1);
  expect(broken.stdout.toString().startsWith("BROKEN at seq 2: ")).toBe(true);
  expect(broken.stdout.toString().endsWith("\n1 broken receipts or handoffs\n")).toBe(true);
  expect(server.hits()).toBe("");
}, 60_000);

test("server e2e: initialize carries the server instructions and a case-only camera miss names the granted id before any camera request", async () => {
  const server = await startServer("viewer");
  expect(server.instructions()).toBe(SERVER_INSTRUCTIONS);
  expect(SERVER_INSTRUCTIONS.length).toBeLessThanOrEqual(2048); // older Claude Code cut server instructions at 2,048 characters (4,096 now)
  expect(await server.call("ptz_move", { camera: "DOME", pan: 1 }))
    .toBe("DENIED: camera 'DOME' not allowlisted for agent 'viewer' (camera ids are case-sensitive; did you mean 'dome'?)");
  expect(await server.call("ptz_move", { camera: "GATE", pan: 1 })).toBe("DENIED: camera 'GATE' not allowlisted for agent 'viewer'");
  expect(server.hits()).toBe("");
  expect(server.chain().map((r) => [r.principal.id, r.action.tool, r.decision, r.node_kind]))
    .toEqual([["viewer", "ptz_move", "deny", "authorization"], ["viewer", "ptz_move", "deny", "authorization"]]);
}, 60_000);

test("server e2e: ptz_preset without a preset name is rejected before any policy decision, receipt or camera request", async () => {
  const server = await startServer("viewer");
  const result = await server.callRaw("ptz_preset", { camera: "dome" });
  expect(result.isError).toBe(true);
  expect(server.hits()).toBe("");
  expect(existsSync(join(server.root, "receipts", "chain.jsonl")) ? server.chain() : []).toEqual([]);
}, 60_000);
