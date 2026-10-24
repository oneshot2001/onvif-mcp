import * as fs from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { z } from "zod";
import { cameraId, paramName } from "./schemas";
import { baselineDenied, configDenied as policyConfigDenied, type Policy } from "./policy-check";
import { hardDenied } from "./commission";
import { formatDriftLines } from "./config-drift";
import { deviceText } from "./device-text";

// Run the actual helpers and registrations without importing index.ts (startup
// would fetch credentials, touch .keys and connect MCP).
const source = fs.readFileSync(join(import.meta.dir, "index.ts"), "utf8");
const helpers = source.slice(source.indexOf("type Baseline ="), source.indexOf("async function configParams("));
const registrations = source.slice(source.indexOf('server.tool("config_baseline"'), source.indexOf('server.tool("get_receipts"'));
const code = new Bun.Transpiler({ loader: "ts" }).transformSync(helpers + registrations);

export function configHarness(root: string, options: {
  statSync?: typeof fs.statSync;
  readFileSync?: typeof fs.readFileSync;
} = {}) {
  const chain: any[][] = [], calls: any[][] = [];
  const handlers: Record<string, (input: any) => Promise<any>> = {};
  const policy: Policy = { test: {
    tools: ["config_baseline", "config_drift", "config_remediate"], cameras: ["cam"],
    config: { groups: ["Image"], remediate: true },
  } };
  let value = "live";
  const dependencies = {
    ROOT: root, AGENT: "test", policy, join, createHash, z, cameraId, paramName,
    baselineDenied, policyConfigDenied, hardDenied, formatDriftLines, deviceText,
    existsSync: fs.existsSync, statSync: options.statSync ?? fs.statSync,
    readFileSync: options.readFileSync ?? fs.readFileSync,
    mkdirSync: fs.mkdirSync, writeFileSync: fs.writeFileSync,
    rateDenied: () => null,
    receipt: (...args: any[]) => chain.push(args),
    server: { tool: (name: string, _description: string, _schema: unknown, handler: any) => { handlers[name] = handler; } },
    configParams: async (...args: any[]) => {
      calls.push(["configParams", ...args]);
      return { ok: true, params: { "Image.X": value } };
    },
    vapix: async (...args: any[]) => {
      calls.push(["vapix", ...args]);
      value = "saved";
      return { ok: true, body: "OK" };
    },
  };
  new Function(...Object.keys(dependencies), code)(...Object.values(dependencies));
  return { handlers, chain, calls };
}
