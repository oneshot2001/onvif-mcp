import { afterEach, beforeEach, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { configHarness } from "./config-tools-harness";
import type { Policy } from "./policy-check";

let root: string;
const saved = JSON.stringify({ groups: ["Image"], params: { "Image.X": "saved" } });
const policy: Policy = { test: {
  tools: ["config_baseline", "config_drift", "config_remediate"], cameras: ["cam"],
  config: { groups: ["Image"], remediate: true, rebaseline: true },
} };
function saveBaseline() {
  mkdirSync(join(root, "baselines"));
  writeFileSync(join(root, "baselines", "cam.json"), saved);
}
function textResult(text: string) { return { content: [{ type: "text", text }] }; }
function listCall(tool: string, group = "Image") {
  return ["vapix", tool, "cam", `/axis-cgi/param.cgi?action=list&group=${group}`];
}
beforeEach(() => { root = mkdtempSync(join(tmpdir(), "config-read-error-")); });
afterEach(() => rmSync(root, { recursive: true, force: true }));

for (const [name, body] of [
  ["documented error-only", "# Error: Error -1 getting param"],
  ["plain error-only", "Error: Error -1 getting param"],
  ["documented mixed", "root.Image.X=live\r\n# Error: Error -1 getting param\r\nroot.Image.Y=2"],
  ["plain mixed", "root.Image.X=live\nError: Error -1 getting param"],
] as const) {
  for (const existing of [false, true]) {
    test(`param.cgi read error: ${name} baseline ${existing ? "preserves existing bytes" : "creates no baseline"}`, async () => {
      if (existing) saveBaseline();
      const h = configHarness(root, { policy, readReply: { ok: true, body } });
      expect(await h.handlers.config_baseline!({ camera: "cam" })).toEqual(textResult("baseline fetch failed"));
      expect(h.chain).toEqual([["config_baseline", { camera: "cam" }, "allow", "fetch FAILED"]]);
      expect(h.calls).toEqual([listCall("config_baseline")]);
      const file = join(root, "baselines", "cam.json");
      if (existing) expect(readFileSync(file, "utf8")).toBe(saved);
      else expect(existsSync(file)).toBe(false);
    });
  }
  test(`param.cgi read error: ${name} drift reports fetch failure`, async () => {
    saveBaseline();
    const h = configHarness(root, { readReply: { ok: true, body } });
    expect(await h.handlers.config_drift!({ camera: "cam" })).toEqual(textResult("drift fetch failed"));
    expect(h.chain).toEqual([["config_drift", { camera: "cam" }, "allow", "fetch FAILED"]]);
    expect(h.calls).toEqual([listCall("config_drift")]);
    expect(readFileSync(join(root, "baselines", "cam.json"), "utf8")).toBe(saved);
  });
  for (const approve of [false, true]) {
    test(`param.cgi read error: ${name} remediation approve=${approve} fails before update`, async () => {
      saveBaseline();
      const h = configHarness(root, { readReply: { ok: true, body } });
      const input = { camera: "cam", param: "Image.X", approve };
      expect(await h.handlers.config_remediate!(input)).toEqual(textResult("live config read failed"));
      expect(h.chain).toEqual([["config_remediate", input, "allow", "read FAILED"]]);
      expect(h.calls).toEqual([listCall("config_remediate", "Image.X")]);
      expect(readFileSync(join(root, "baselines", "cam.json"), "utf8")).toBe(saved);
    });
  }
}

test("param.cgi read error: actual helper preserves parsing and transport failure", async () => {
  const body = "root.Image.X=value=with=equals\r\nroot.Image.Y=Error in a value\r\nignored";
  for (const ok of [true, false]) {
    const h = configHarness(root, { readReply: { ok, body } });
    expect(await h.configParams("config_drift", "cam", ["Image.X", "Image Y"])).toEqual({
      ok, params: { "Image.X": "value=with=equals", "Image.Y": "Error in a value" },
    });
    expect(h.calls).toEqual([listCall("config_drift", "Image.X,Image%20Y")]);
  }
});

test("param.cgi read error: empty groups still succeed without transport", async () => {
  const h = configHarness(root, { readReply: { ok: false, body: "# Error: failure" } });
  expect(await h.configParams("config_drift", "cam", [])).toEqual({ ok: true, params: {} });
  expect(h.calls).toEqual([]);
});

for (const existing of [false, true]) {
  test(`param.cgi read error: successful listing ${existing ? "replaces" : "creates"} baseline`, async () => {
    if (existing) saveBaseline();
    const h = configHarness(root, { policy, readReply: { ok: true, body: "root.Image.X=live" } });
    const output = await h.handlers.config_baseline!({ camera: "cam" });
    expect(output.content[0].text).toStartWith("baselined cam: 1 params sha256:");
    expect(JSON.parse(readFileSync(join(root, "baselines", "cam.json"), "utf8")).params).toEqual({ "Image.X": "live" });
    expect(h.chain[0]![3]).toBe("baselined 1 params");
    expect(h.chain[0]![5]).toBe("device_acknowledged");
    expect(h.calls).toEqual([listCall("config_baseline")]);
  });
}

test("param.cgi read error: successful listing still reports drift and remediation dry-run", async () => {
  saveBaseline();
  const h = configHarness(root, { readReply: { ok: true, body: "root.Image.X=live" } });
  const drift = await h.handlers.config_drift!({ camera: "cam" });
  expect(drift.content[0].text).toContain("drift: 1 changed, 0 added, 0 removed");
  expect(h.chain[0]![5]).toBe("device_acknowledged");
  expect(await h.handlers.config_remediate!({ camera: "cam", param: "Image.X", approve: false }))
    .toEqual(textResult('would set Image.X: "live" → "saved"'));
  expect(h.calls).toEqual([listCall("config_drift"), listCall("config_remediate", "Image.X")]);
});
