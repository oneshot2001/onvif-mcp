import { expect, test } from "bun:test";
import { createHash, generateKeyPairSync, sign as edSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { cameraId } from "./schemas";
import { allowed as policyAllowed, ptzBound } from "./policy-check";
import { outcomeEvidence, verifyChain } from "./receipt-chain";

// Execute the actual helper, registration and receipt builder without importing
// index.ts: no startup, credentials, repository keys, listener or camera access.
const source = readFileSync(join(import.meta.dir, "index.ts"), "utf8");
function slice(start: string, end: string) {
  const from = source.indexOf(start), to = source.indexOf(end);
  expect(from).toBeGreaterThanOrEqual(0);
  expect(to).toBeGreaterThan(from);
  return source.slice(from, to);
}
const code = new Bun.Transpiler({ loader: "ts" }).transformSync(
  slice("const NODE_KIND:", "function allowed(")
  + slice("async function ptzMove(", "// AXIS firmware version")
  + slice('server.tool("ptz_move"', 'server.tool("config_baseline"'),
);

type Input = { camera: string; pan: number; tilt: number; zoom: number };
type Reply = { ok: boolean; body: string };
function harness(protocol: "vapix" | "onvif", reply: Reply) {
  const calls: unknown[][] = [], lines: string[] = [];
  const handlers: Record<string, (input: Input) => Promise<unknown>> = {};
  const cameras = { cam: { ptz: true, protocol, profile: "test-profile" } };
  const policy = { test: { tools: ["ptz_move"], cameras: ["cam"], ptz: { maxStep: 30, maxZoomStep: 2 } } };
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const dependencies = {
    z, cameraId, ptzBound, policy, cameras, AGENT: "test",
    createHash, edSign, PRIV: privateKey, outcomeEvidence, LOG: "in-memory",
    currentInvocationId: () => undefined,
    appendLocked: (_log: string, build: (prev: { seq: number; hash: string }) => string) => {
      const prev = lines.length ? JSON.parse(lines.at(-1)!) : { seq: 0, hash: "genesis" };
      lines.push(build(prev));
    },
    allowed: (tool: string, camera?: string) => policyAllowed(policy, "test", tool, camera),
    rateDenied: () => null,
    camOf: (camera: keyof typeof cameras) => cameras[camera],
    vapix: async (...args: unknown[]) => { calls.push(["vapix", ...args]); return reply; },
    soap: async (...args: unknown[]) => { calls.push(["soap", ...args]); return reply; },
    server: { tool: (name: string, _description: string, _schema: unknown, handler: typeof handlers[string]) => { handlers[name] = handler; } },
  };
  const ptzMove = new Function(...Object.keys(dependencies), code + "\nreturn ptzMove;")(...Object.values(dependencies)) as
    (tool: string, camera: string, pan: number, tilt: number, zoom: number) => Promise<boolean>;
  return { ptzMove, handlers, calls, lines, publicKey: publicKey.export({ type: "spki", format: "pem" }).toString() };
}

const cases = [
  ["documented multiline rejection", "vapix", { ok: true, body: "Error:\nPTZ unavailable" }, false],
  ["rejection on a later line", "vapix", { ok: true, body: "response\r\nError: PTZ unavailable" }, false],
  ["plain Error prefix", "vapix", { ok: true, body: "Error PTZ unavailable" }, false],
  ["empty success", "vapix", { ok: true, body: "" }, true],
  ["Error away from line start", "vapix", { ok: true, body: "No Error: reported" }, true],
  ["transport failure", "vapix", { ok: false, body: "" }, false],
  ["ONVIF success", "onvif", { ok: true, body: "<tptz:RelativeMoveResponse/>" }, true],
  ["ONVIF transport failure", "onvif", { ok: false, body: "<tptz:RelativeMoveResponse/>" }, false],
  ["ONVIF missing acknowledgement", "onvif", { ok: true, body: "" }, false],
  ["ONVIF body check unchanged", "onvif", { ok: true, body: "Error:\n<tptz:RelativeMoveResponse/>" }, true],
] as const;

for (const [name, protocol, reply, ok] of cases) {
  for (const target of ["helper", "registration"] as const) {
    test(`PTZ move error body: ${target} ${name}`, async () => {
      const h = harness(protocol, reply);
      const input = { camera: "cam", pan: 18, tilt: -9, zoom: 2 };
      if (target === "helper") {
        expect(await h.ptzMove("ptz_move", "cam", input.pan, input.tilt, input.zoom)).toBe(ok);
        expect(h.lines).toEqual([]);
      } else {
        expect(await h.handlers.ptz_move!(input)).toEqual({ content: [{ type: "text", text: ok
          ? `moved cam pan=18° tilt=-9° zoom=2 (${protocol})` : "move failed" }] });
        expect(h.lines).toHaveLength(1);
        expect(JSON.parse(h.lines[0]!)).toMatchObject({
          action: { tool: "ptz_move", params: input }, decision: "allow",
          detail: ok ? `moved via ${protocol}` : "transport error",
          outcome_evidence: ok ? "device_acknowledged" : "unknown",
        });
        expect(verifyChain(h.lines, h.publicKey)).toEqual({ count: 1, bad: [] });
      }
      expect(h.calls).toEqual([[protocol === "vapix" ? "vapix" : "soap", "ptz_move", "cam",
        protocol === "vapix" ? "/axis-cgi/com/ptz.cgi?rpan=18&rtilt=-9&rzoom=200"
          : '<tptz:RelativeMove xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema"><tptz:ProfileToken>test-profile</tptz:ProfileToken><tptz:Translation><tt:PanTilt x="0.05" y="-0.025"/><tt:Zoom x="0.02"/></tptz:Translation></tptz:RelativeMove>',
      ]]);
    });
  }
}
