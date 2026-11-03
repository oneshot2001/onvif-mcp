import { afterEach, beforeEach, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { configHarness } from "./config-tools-harness";
import type { Policy } from "./policy-check";

let root: string, file: string;
beforeEach(() => {
  root = fs.mkdtempSync(join(tmpdir(), "config-outcome-wiring-"));
  fs.mkdirSync(join(root, "baselines"));
  file = join(root, "baselines", "cam.json");
});
afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

function baseline(params: Record<string, string>) {
  fs.writeFileSync(file, JSON.stringify({ groups: ["Image"], params }));
}
const hash = (value: string) => createHash("sha256").update(value).digest("hex");

for (const writeSticks of [false, true]) {
  test(`config outcome wiring: acknowledged remediation ${writeSticks ? "with target readback succeeds" : "without target readback fails"}`, async () => {
    baseline({ "Image.X": "saved" });
    const h = configHarness(root, { writeReply: { ok: true, body: "OK" }, writeSticks });
    const input = { camera: "cam", param: "Image.X", approve: true };
    const output = await h.handlers.config_remediate!(input);
    if (writeSticks) {
      expect(output).toEqual({ content: [{ type: "text", text: 'remediated Image.X: "live" → "saved"' }] });
      expect(h.chain).toEqual([["config_remediate", input, "allow", "remediated", hash("saved"), "device_acknowledged"]]);
    } else {
      expect(output).toEqual({ content: [{ type: "text", text: 'write acked but postcondition FAILED (live="live")' }] });
      expect(h.chain).toEqual([["config_remediate", input, "allow", "write acked but postcondition FAILED (live=live)",
        undefined, "device_acknowledged"]]);
      expect(JSON.stringify({ output, chain: h.chain })).not.toContain("remediated");
    }
    expect(h.calls).toEqual([
      ["configParams", "config_remediate", "cam", ["Image.X"]],
      ["vapix", "config_remediate", "cam", "/axis-cgi/param.cgi?action=update&Image.X=saved"],
      ["configParams", "config_remediate", "cam", ["Image.X"]],
    ]);
  });
}

for (const approve of [false, true]) {
  test(`config outcome wiring: missing baseline param is denied with approve=${approve}`, async () => {
    baseline({ "Image.X": "saved" });
    const h = configHarness(root, { liveParams: { "Image.Y": "1" } });
    const input = { camera: "cam", param: "Image.Y", approve };
    expect(await h.handlers.config_remediate!(input)).toEqual({ content: [
      { type: "text", text: "DENIED: param 'Image.Y' not in baseline" },
    ] });
    expect(h.chain).toEqual([["config_remediate", input, "deny", "param 'Image.Y' not in baseline"]]);
    expect(h.calls).toEqual([]);
  });

  test(`config outcome wiring: present baseline param succeeds with approve=${approve}`, async () => {
    baseline({ "Image.Y": "saved" });
    const h = configHarness(root, { liveParams: { "Image.Y": "1" } });
    const input = { camera: "cam", param: "Image.Y", approve };
    expect(await h.handlers.config_remediate!(input)).toEqual({ content: [
      { type: "text", text: `${approve ? "remediated" : "would set"} Image.Y: "1" → "saved"` },
    ] });
    expect(h.chain).toEqual([approve
      ? ["config_remediate", input, "allow", "remediated", hash("saved"), "device_acknowledged"]
      : ["config_remediate", input, "allow", "dry-run: would set Image.Y: 1 → saved"]]);
    expect(h.calls).toEqual([
      ["configParams", "config_remediate", "cam", ["Image.Y"]],
      ...(approve ? [
        ["vapix", "config_remediate", "cam", "/axis-cgi/param.cgi?action=update&Image.Y=saved"],
        ["configParams", "config_remediate", "cam", ["Image.Y"]],
      ] : []),
    ]);
  });
}

for (const scenario of ["appears without grant", "appears with grant", "fresh creation"] as const) {
  test(`config outcome wiring: baseline ${scenario}`, async () => {
    const policy: Policy = { test: {
      tools: ["config_baseline"], cameras: ["cam"], config: { groups: ["Image"] },
    } };
    if (scenario === "appears with grant") policy.test!.config!.rebaseline = true;
    const competingBytes = Buffer.from('{ "groups": ["Image"], "params": { "Image.X": "other" } }\n');
    let fetches = 0;
    const h = configHarness(root, {
      policy, liveParams: { "Image.X": "live", "Time.NTP.Server": "excluded" },
      onFetch: () => {
        fetches++;
        expect(fs.existsSync(file)).toBe(false);
        expect(h.calls).toEqual([["configParams", "config_baseline", "cam", ["Image"]]]);
        if (scenario !== "fresh creation") fs.writeFileSync(file, competingBytes);
      },
    });
    const input = { camera: "cam" };
    expect(fs.existsSync(file)).toBe(false);
    const output = await h.handlers.config_baseline!(input);
    expect(fetches).toBe(1);
    expect(h.calls).toEqual([["configParams", "config_baseline", "cam", ["Image"]]]);
    if (scenario === "appears without grant") {
      expect(output).toEqual({ content: [
        { type: "text", text: "DENIED: baseline exists; agent 'test' has no rebaseline grant" },
      ] });
      expect(h.chain).toEqual([["config_baseline", input, "deny", "baseline exists; agent 'test' has no rebaseline grant"]]);
      expect(fs.readFileSync(file)).toEqual(competingBytes);
    } else {
      const params = { "Image.X": "live" }, sha256 = hash(JSON.stringify(params));
      expect(output).toEqual({ content: [{ type: "text", text: `baselined cam: 1 params sha256:${sha256}` }] });
      expect(h.chain).toEqual([["config_baseline", input, "allow", "baselined 1 params", sha256, "device_acknowledged"]]);
      expect(JSON.parse(fs.readFileSync(file, "utf8"))).toEqual({
        camera: "cam", captured: expect.any(String), groups: ["Image"], params, sha256,
      });
    }
  });
}
