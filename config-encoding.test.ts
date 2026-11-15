import { afterEach, beforeEach, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { configHarness } from "./config-tools-harness";

let root: string;
beforeEach(() => { root = mkdtempSync(join(tmpdir(), "config-encoding-")); });
afterEach(() => rmSync(root, { recursive: true, force: true }));

test("camera request encoding: config_remediate percent-encodes the parameter name and the baseline value in the update request", async () => {
  const name = "Image.I0.Text.String&a=b #%+é?/x";
  const value = "a&b=c d#e%f+g?é/h";
  mkdirSync(join(root, "baselines"));
  writeFileSync(join(root, "baselines/cam.json"), JSON.stringify({ groups: ["Image"], params: { [name]: value } }));
  const h = configHarness(root, { liveParams: { [name]: "live" } });
  const input = { camera: "cam", param: name, approve: true };
  const result = await h.handlers.config_remediate!(input);
  expect(h.calls).toEqual([
    ["configParams", "config_remediate", "cam", [name]],
    ["vapix", "config_remediate", "cam", "/axis-cgi/param.cgi?action=update&Image.I0.Text.String%26a%3Db%20%23%25%2B%C3%A9%3F%2Fx=a%26b%3Dc%20d%23e%25f%2Bg%3F%C3%A9%2Fh"],
    ["configParams", "config_remediate", "cam", [name]],
  ]);
  expect(h.chain).toEqual([["config_remediate", input, "allow", "remediated", expect.any(String), "device_acknowledged"]]);
  expect(result.content[0].text).toStartWith("remediated ");
});

test("camera request encoding: configParams percent-encodes each group and joins them with a literal comma", async () => {
  const name = "Image.I0.Text.String&a=b #%+é?/x";
  const h = configHarness(root, { readReply: { ok: true, body: "" } });
  await h.configParams("config_remediate", "cam", [name, "Time"]);
  expect(h.calls).toEqual([
    ["vapix", "config_remediate", "cam", "/axis-cgi/param.cgi?action=list&group=Image.I0.Text.String%26a%3Db%20%23%25%2B%C3%A9%3F%2Fx,Time"],
  ]);
});
