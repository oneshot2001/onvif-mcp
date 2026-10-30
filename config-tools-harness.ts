import * as fs from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { z } from "zod";
import { cameraId, paramName } from "./schemas";
import { baselineDenied, configDenied as policyConfigDenied, type Policy } from "./policy-check";
import { hardDenied } from "./commission";
import { formatDriftLines } from "./config-drift";
import { deviceText } from "./device-text";
import { parseParams } from "./vapix-params";

// Run the actual helpers and registrations without importing index.ts (startup
// would fetch credentials, touch .keys and connect MCP).
const source = fs.readFileSync(join(import.meta.dir, "index.ts"), "utf8");
const helpers = source.slice(source.indexOf("type Baseline ="), source.indexOf("async function configParams("));
const registrations = source.slice(source.indexOf('server.tool("config_baseline"'), source.indexOf('server.tool("get_receipts"'));
const code = new Bun.Transpiler({ loader: "ts" }).transformSync(helpers + registrations);
const configParamsStart = source.indexOf("async function configParams(");
const configParamsEnd = source.indexOf("// ONVIF SOAP call.", configParamsStart);
if (configParamsStart < 0 || configParamsEnd <= configParamsStart) throw new Error("configParams slice boundaries missing");
const readCode = new Bun.Transpiler({ loader: "ts" }).transformSync(source.slice(configParamsStart, configParamsEnd));

export function configHarness(root: string, options: {
  statSync?: typeof fs.statSync;
  readFileSync?: typeof fs.readFileSync;
  policy?: Policy;
  rateDenied?: (kind: string) => string | null;
  liveParams?: Record<string, string>;
  readReply?: { ok: boolean; body: string };
  writeReply?: { ok: boolean; body: string };
  writeSticks?: boolean;
} = {}) {
  const chain: any[][] = [], calls: any[][] = [];
  const handlers: Record<string, (input: any) => Promise<any>> = {};
  const policy: Policy = structuredClone(options.policy ?? { test: {
    tools: ["config_baseline", "config_drift", "config_remediate"], cameras: ["cam"],
    config: { groups: ["Image"], remediate: true },
  } });
  const liveParams = { ...(options.liveParams ?? { "Image.X": "live" }) };
  const dependencies = {
    ROOT: root, AGENT: "test", policy, join, createHash, z, cameraId, paramName,
    baselineDenied, policyConfigDenied, hardDenied, formatDriftLines, deviceText,
    existsSync: fs.existsSync, statSync: options.statSync ?? fs.statSync,
    readFileSync: options.readFileSync ?? fs.readFileSync,
    mkdirSync: fs.mkdirSync, writeFileSync: fs.writeFileSync,
    rateDenied: options.rateDenied ?? (() => null),
    receipt: (...args: any[]) => chain.push(args),
    server: { tool: (name: string, _description: string, _schema: unknown, handler: any) => { handlers[name] = handler; } },
    configParams: async (tool: string, camera: string, groups: string[]) => {
      calls.push(["configParams", tool, camera, [...groups]]);
      return { ok: true, params: Object.fromEntries(Object.entries(liveParams)
        .filter(([param]) => groups.some(g => param === g || param.startsWith(`${g}.`)))) };
    },
    vapix: async (tool: string, camera: string, path: string) => {
      calls.push(["vapix", tool, camera, path]);
      for (const [param, value] of new URL(path, "https://camera.invalid").searchParams) {
        if (param !== "action" && (options.writeSticks ?? true)) liveParams[param] = value;
      }
      return options.writeReply ?? { ok: true, body: "OK" };
    },
  };
  if (options.readReply) {
    const readParams = new Function("vapix", "parseParams", `${readCode}\nreturn configParams;`)(
      async (tool: string, camera: string, path: string) => {
        calls.push(["vapix", tool, camera, path]);
        return options.readReply;
      }, parseParams,
    );
    dependencies.configParams = readParams;
  }
  new Function(...Object.keys(dependencies), code)(...Object.values(dependencies));
  return { handlers, chain, calls, configParams: dependencies.configParams };
}
