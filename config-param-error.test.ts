import { afterEach, beforeEach, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { configHarness } from "./config-tools-harness";

let root: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "config-param-error-"));
  mkdirSync(join(root, "baselines"));
  writeFileSync(join(root, "baselines", "cam.json"), JSON.stringify({ groups: ["Image"], params: { "Image.X": "saved" } }));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

for (const [name, writeReply, acknowledged] of [
  ["documented rejection", { ok: true, body: "# Error: Error setting 'Image.X' to 'saved'!" }, false],
  ["plain rejection", { ok: true, body: "Error: x" }, false],
  ["documented rejection on a later line", { ok: true, body: "response\n# Error: Error setting 'Image.X' to 'saved'!" }, false],
  ["transport failure", { ok: false, body: "OK" }, false],
  ["OK without sticking", { ok: true, body: "OK" }, true],
] as const) {
  test(`param.cgi error body: config_remediate ${name} labels receipt detail, evidence and tool text`, async () => {
    const h = configHarness(root, { writeReply, writeSticks: false });
    const input = { camera: "cam", param: "Image.X", approve: true };
    const output = await h.handlers.config_remediate!(input);
    const label = acknowledged ? "write acked but postcondition FAILED" : "write FAILED";
    expect(h.chain).toEqual([["config_remediate", input, "allow", `${label} (live=live)`, undefined,
      acknowledged ? "device_acknowledged" : "unknown"]]);
    expect(output).toEqual({ content: [{ type: "text", text: `${label} (live="live")` }] });
    expect(h.calls).toEqual([
      ["configParams", "config_remediate", "cam", ["Image.X"]],
      ["vapix", "config_remediate", "cam", "/axis-cgi/param.cgi?action=update&Image.X=saved"],
      ["configParams", "config_remediate", "cam", ["Image.X"]],
    ]);
  });
}

for (const [name, writeReply] of [
  ["default OK", undefined],
  ["rejected write", { ok: true, body: "# Error: Error setting 'Image.X' to 'saved'!" }],
] as const) {
  test(`param.cgi error body: config_remediate ${name} with target readback still reports remediated`, async () => {
    const h = configHarness(root, { writeReply });
    const input = { camera: "cam", param: "Image.X", approve: true };
    expect(await h.handlers.config_remediate!(input)).toEqual({ content: [
      { type: "text", text: 'remediated Image.X: "live" → "saved"' },
    ] });
    expect(h.chain).toEqual([["config_remediate", input, "allow", "remediated",
      createHash("sha256").update("saved").digest("hex"), "device_acknowledged"]]);
  });
}
