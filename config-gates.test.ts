import { afterEach, beforeEach, expect, test } from "bun:test";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { configHarness } from "./config-tools-harness";
import type { Policy } from "./policy-check";

let root: string, file: string, policy: Policy;
const tools = ["config_baseline", "config_drift", "config_remediate"] as const;
beforeEach(() => {
  root = fs.mkdtempSync(join(tmpdir(), "config-gate-wiring-"));
  fs.mkdirSync(join(root, "baselines"));
  file = join(root, "baselines", "cam.json");
  policy = { test: { tools: [...tools], cameras: ["cam"],
    config: { groups: ["Image", "Time"], remediate: true } } };
});
afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

function baseline(params = { "Image.X": "saved" } as Record<string, string>, groups = ["Image"]) {
  fs.writeFileSync(file, JSON.stringify({ groups, params }, null, 2) + "\n");
}
const hash = (value: unknown) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
function denied(h: ReturnType<typeof configHarness>, tool: string, input: unknown, output: unknown, reason: string) {
  expect(output).toEqual({ content: [{ type: "text", text: `DENIED: ${reason}` }] });
  expect(h.chain).toEqual([[tool, input, "deny", reason]]);
  expect(h.calls).toEqual([]);
}

for (const [param, reason] of [
  ["Time.NTP.Server", "hard-denied"],
  ["Image.I0.Text.UserString", "hard-denied"],
  ["Storage.Foo", "outside allowed config groups"],
] as const) {
  test(`config gate wiring: config_remediate denies ${param} as ${reason}`, async () => {
    // Every candidate exists and differs from live, so a missing gate reaches a write.
    baseline({ [param]: "saved" }, ["Image", "Time", "Storage"]);
    const h = configHarness(root, { policy, liveParams: { [param]: "live" } });
    const input = { camera: "cam", param, approve: true };
    denied(h, "config_remediate", input, await h.handlers.config_remediate!(input),
      `param '${param}' is ${reason}`);
  });
}

test("config gate wiring: approved remediation requires the remediation grant", async () => {
  delete policy.test!.config!.remediate;
  baseline();
  const h = configHarness(root, { policy });
  const input = { camera: "cam", param: "Image.X", approve: true };
  denied(h, "config_remediate", input, await h.handlers.config_remediate!(input),
    "agent 'test' has no config remediation grant");
});

test("config gate wiring: dry-run needs no remediation grant or actuation rate allowance", async () => {
  delete policy.test!.config!.remediate;
  baseline();
  const rateCalls: string[] = [];
  const h = configHarness(root, { policy, rateDenied: kind => { rateCalls.push(kind); return "actuation limit"; } });
  const input = { camera: "cam", param: "Image.X", approve: false };
  expect(await h.handlers.config_remediate!(input)).toEqual({ content: [
    { type: "text", text: 'would set Image.X: "live" → "saved"' },
  ] });
  expect(h.chain).toEqual([["config_remediate", input, "allow", "dry-run: would set Image.X: live → saved"]]);
  expect(h.calls).toEqual([["configParams", "config_remediate", "cam", ["Image.X"]]]);
  expect(rateCalls).toEqual([]);
});

test("config gate wiring: approved remediation enforces the actuation rate limit", async () => {
  baseline();
  const rateCalls: string[] = [];
  const h = configHarness(root, { policy, rateDenied: kind => { rateCalls.push(kind); return "actuation limit"; } });
  const input = { camera: "cam", param: "Image.X", approve: true };
  denied(h, "config_remediate", input, await h.handlers.config_remediate!(input), "actuation limit");
  expect(rateCalls).toEqual(["actuation"]);
});

test("config gate wiring: existing baseline requires rebaseline before any camera call", async () => {
  baseline();
  const before = fs.readFileSync(file);
  const h = configHarness(root, { policy });
  const input = { camera: "cam" };
  const output = await h.handlers.config_baseline!(input);
  expect(fs.readFileSync(file)).toEqual(before);
  denied(h, "config_baseline", input, output, "baseline exists; agent 'test' has no rebaseline grant");
});

test("config gate wiring: drift neither requests nor reports revoked baseline groups", async () => {
  baseline({ "Image.X": "saved", "Time.NTP.Server": "old-server" }, ["Image", "Time"]);
  policy.test!.config!.groups = ["Image"];
  const h = configHarness(root, { policy, liveParams: { "Image.X": "live", "Time.NTP.Server": "new-server" } });
  const input = { camera: "cam" };
  const output = await h.handlers.config_drift!(input);
  expect(h.calls).toEqual([["configParams", "config_drift", "cam", ["Image"]]]);
  const summary = "drift: 1 changed, 0 added, 0 removed";
  expect(output).toEqual({ content: [{ type: "text", text: `changed Image.X: "saved" → "live"\n${summary}` }] });
  expect(JSON.stringify(output)).not.toContain("Time");
  expect(h.chain).toEqual([["config_drift", input, "allow", summary,
    hash({ changed: [{ param: "Image.X", baseline: "saved", live: "live" }], added: [], removed: [] }), "device_acknowledged"]]);
});

for (const existing of [false, true]) {
  test(`config gate wiring: baseline ${existing ? "replacement with rebaseline grant" : "creation"} succeeds`, async () => {
    if (existing) {
      baseline();
      policy.test!.config!.rebaseline = true;
    }
    const liveParams = { "Image.X": "live", "Time.NTP.Server": "server" };
    const h = configHarness(root, { policy, liveParams });
    const input = { camera: "cam" };
    expect(await h.handlers.config_baseline!(input)).toEqual({ content: [
      { type: "text", text: `baselined cam: 2 params sha256:${hash(liveParams)}` },
    ] });
    expect(JSON.parse(fs.readFileSync(file, "utf8"))).toEqual({ camera: "cam", captured: expect.any(String),
      groups: ["Image", "Time"], params: liveParams, sha256: hash(liveParams) });
    expect(h.calls).toEqual([["configParams", "config_baseline", "cam", ["Image", "Time"]]]);
    expect(h.chain).toEqual([["config_baseline", input, "allow", "baselined 2 params", hash(liveParams), "device_acknowledged"]]);
  });
}

test("config gate wiring: granted remediation writes and verifies the baseline value", async () => {
  baseline();
  const rateCalls: string[] = [];
  const h = configHarness(root, { policy, rateDenied: kind => { rateCalls.push(kind); return null; } });
  const input = { camera: "cam", param: "Image.X", approve: true };
  expect(await h.handlers.config_remediate!(input)).toEqual({ content: [
    { type: "text", text: 'remediated Image.X: "live" → "saved"' },
  ] });
  expect(h.calls).toEqual([
    ["configParams", "config_remediate", "cam", ["Image.X"]],
    ["vapix", "config_remediate", "cam", "/axis-cgi/param.cgi?action=update&Image.X=saved"],
    ["configParams", "config_remediate", "cam", ["Image.X"]],
  ]);
  expect(h.chain).toEqual([["config_remediate", input, "allow", "remediated",
    createHash("sha256").update("saved").digest("hex"), "device_acknowledged"]]);
  expect(rateCalls).toEqual(["actuation"]);
});

for (const tool of tools) {
  for (const missing of ["tool", "camera", "config"] as const) {
    test(`config gate wiring: ${tool} requires its ${missing} grant`, async () => {
      baseline();
      if (missing === "tool") policy.test!.tools = [];
      if (missing === "camera") policy.test!.cameras = [];
      if (missing === "config") delete policy.test!.config;
      const h = configHarness(root, { policy });
      const input = tool === "config_remediate"
        ? { camera: "cam", param: "Image.X", approve: true } : { camera: "cam" };
      const reason = missing === "tool" ? `tool '${tool}' not allowlisted for agent 'test'`
        : missing === "camera" ? "camera 'cam' not allowlisted for agent 'test'" : "agent 'test' has no config grant";
      denied(h, tool, input, await h.handlers[tool]!(input), reason);
    });
  }
}
