import { afterEach, describe, expect, test } from "bun:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { copyFileSync, cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { clientCallId } from "./invocation";
import { verifyChain } from "./receipt-chain";

const SOURCE = "claudecode/toolUseId, client-supplied, not verified";

describe("clientCallId", () => {
  test.each([
    "toolu_01TzHJ22FCfCW2LGybXUimxs",
    "repl_5feb511b-6110-43cf-9e63-bb7fe70f8232",
    "a",
    "a".repeat(128),
  ])("accepts %p", (value) => {
    expect(clientCallId(value)).toBe(value);
  });

  test.each([
    ["129 characters", "a".repeat(129)],
    ["an empty string", ""],
    ["a space", "toolu a"],
    ["a CR", "toolu\r"],
    ["an LF", "toolu\n"],
    ["a NUL", "toolu\0"],
    ["a default-ignorable character", "toolu​"],
    ["a number", 7],
    ["an object", { id: "toolu_1" }],
    ["an array", ["toolu_1"]],
    ["null", null],
    ["undefined", undefined],
  ])("returns null for %s", (_name, value) => {
    expect(clientCallId(value)).toBeNull();
  });
});

// Harness copied from server-e2e.test.ts: the real server over stdio in a temp
// root, with a stand-in credential helper and a stand-in curl that never dials.
const servers: Array<{ dir: string; client: Client }> = [];

afterEach(async () => {
  for (const { dir, client } of servers.splice(0)) {
    try { await client.close(); }
    finally { rmSync(dir, { recursive: true, force: true }); }
  }
});

async function startServer() {
  const dir = mkdtempSync(join(tmpdir(), "onvif-client-call-"));
  const client = new Client({ name: "client-call", version: "1.0.0" });
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
    viewer: { tools: ["get_receipts", "list_cameras", "ptz_move"], cameras: ["lobby", "dome"], ptz: { maxStep: 30, maxZoomStep: 5 } },
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
  const env: Record<string, string> = { PATH: `${bin}:${process.env.PATH ?? ""}`, HOME: home, AGENT_ID: "viewer" };
  await client.connect(new StdioClientTransport({ command: process.execPath, args: ["index.ts"], cwd: root, env }));
  const log = join(root, "receipts", "chain.jsonl");
  return {
    hits: () => readFileSync(hits, "utf8"),
    chainText: () => readFileSync(log, "utf8"),
    publicKey: () => readFileSync(join(root, ".keys", "receipt.pub"), "utf8"),
    async call(name: string, args: Record<string, unknown>, toolUseId?: unknown) {
      const result = await client.callTool({
        name, arguments: args,
        ...(toolUseId === undefined ? {} : { _meta: { "claudecode/toolUseId": toolUseId } }),
      });
      expect(result.isError).not.toBe(true);
      return (result.content as Array<{ type: string; text?: string }>).filter((part) => part.type === "text").map((part) => part.text).join("\n");
    },
  };
}

test("client call e2e: stdio receipts carry the client's call id on allow, deny and failure, null when absent or malformed, and the chain verifies", async () => {
  const server = await startServer();
  const texts = [
    await server.call("get_receipts", { n: 1 }, "toolu_test_1"),
    await server.call("ptz_move", { camera: "gate", pan: 1 }, "toolu_test_2"),
    await server.call("ptz_move", { camera: "dome", pan: 1 }, "repl_5feb511b-6110-43cf-9e63-bb7fe70f8232"),
    await server.call("list_cameras", {}, "toolu_test_4"),
    await server.call("get_receipts", { n: 1 }),
    await server.call("get_receipts", { n: 1 }, { id: "toolu_test_6" }),
    await server.call("get_receipts", { n: 1 }, "a".repeat(200)),
  ];
  expect(texts[1]).toBe("DENIED: camera 'gate' not allowlisted for agent 'viewer'");
  expect(texts[2]).toBe("move failed");
  // A malformed id changes nothing but the field: get_receipts still returns the previous receipt.
  expect(texts.slice(4).map((out) => JSON.parse(out!).seq)).toEqual([4, 5, 6]);
  const text = server.chainText();
  const lines = text.trim().split("\n");
  const chain = lines.map((line) => JSON.parse(line));
  expect(chain.map((r) => [r.action.tool, r.decision, r.client_call])).toEqual([
    ["get_receipts", "allow", { id: "toolu_test_1", source: SOURCE }],
    ["ptz_move", "deny", { id: "toolu_test_2", source: SOURCE }],
    ["ptz_move", "allow", { id: "repl_5feb511b-6110-43cf-9e63-bb7fe70f8232", source: SOURCE }],
    ["list_cameras", "allow", { id: "toolu_test_4", source: SOURCE }],
    ["get_receipts", "allow", null],
    ["get_receipts", "allow", null],
    ["get_receipts", "allow", null],
  ]);
  for (const r of chain) expect(Object.keys(r).slice(2, 4)).toEqual(["invocation_id", "client_call"]);
  expect(verifyChain(lines, server.publicKey())).toEqual({ count: 7, bad: [] });
  expect(server.hits()).toContain("http://dome.invalid/axis-cgi/com/ptz.cgi"); // the password was in play: one call reached the stand-in curl
  for (const out of [text, ...texts]) expect(out).not.toContain("standin-password");
}, 60_000);
