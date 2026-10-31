// gate-probe: deterministic Streamable HTTP client for the gateway (physec network plan P1 gate).
// Usage: GW_TOKEN=... bun gate-probe.ts https://<gateway>:<port>/mcp <agent> '[["list_cameras",{}]]'  (CA via NODE_EXTRA_CA_CERTS). The token is read from the environment and never printed.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
const [url, agent] = [process.argv[2]!, process.argv[3]!];
const token = process.env.GW_TOKEN!;
const calls: Array<[string, Record<string, unknown>]> = JSON.parse(process.argv[4] ?? "[]");
const transport = new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers: { authorization: `Bearer ${token}` } } });
const client = new Client({ name: `gate-probe-${agent}`, version: "0" });
await client.connect(transport);
const tools = (await client.listTools()).tools.map((t) => t.name);
console.log(`${agent}: connected, ${tools.length} tools: ${tools.join(",")}`);
for (const [name, args] of calls) {
  const t0 = Date.now();
  try {
    const r = await client.callTool({ name, arguments: args }, undefined, { timeout: 120_000 });
    const text = (r.content as any[]).filter((c) => c.type === "text").map((c) => c.text).join(" ").replace(/\s+/g, " ");
    const image = (r.content as any[]).find((c) => c.type === "image");
    console.log(`${agent}: ${name}(${JSON.stringify(args)}) ${Date.now() - t0}ms -> ${text.slice(0, 160)}${image ? ` [image ${image.data.length} b64 chars]` : ""}`);
  } catch (e) { console.log(`${agent}: ${name}(${JSON.stringify(args)}) ERROR ${String(e).slice(0, 200)}`); }
}
await client.close();
