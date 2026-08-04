// Exercises onvif-mcp through the real MCP protocol (stdio transport), as an agent would.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const agent = process.argv[2] ?? "claude-main";
const calls: Array<[string, Record<string, unknown>]> = JSON.parse(process.argv[3] ?? "[]");

const client = new Client({ name: "test-client", version: "0.0.1" });
await client.connect(new StdioClientTransport({
  command: "bun", args: [`${import.meta.dir}/index.ts`],
  env: { ...process.env as Record<string, string>, AGENT_ID: agent },
}));

for (const [tool, args] of calls) {
  const r = await client.callTool({ name: tool, arguments: args });
  const text = (r.content as Array<{ type: string; text?: string }>).map((c) => c.text).join("");
  console.log(`[${agent}] ${tool}(${JSON.stringify(args)}) →\n${text}\n`);
}
await client.close();
