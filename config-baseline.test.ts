import { afterEach, beforeEach, expect, test } from "bun:test";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { configHarness } from "./config-tools-harness";

let root: string, file: string;
beforeEach(() => {
  root = fs.mkdtempSync(join(tmpdir(), "baseline-guarded-read-"));
  fs.mkdirSync(join(root, "baselines"));
  file = join(root, "baselines", "cam.json");
});
afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

const valid = JSON.stringify({ groups: ["Image"], params: { "Image.X": "saved" } });
const input = { camera: "cam", param: "Image.X", approve: true };
const tools = ["config_drift", "config_remediate"] as const;
function unreadable(tool: typeof tools[number], output: any, chain: any[][], calls: any[][]) {
  expect(output).toEqual({ content: [{ type: "text", text: "baseline unreadable" }] });
  expect(chain).toEqual([[tool, tool === "config_drift" ? { camera: "cam" } : input,
    tool === "config_drift" ? "allow" : "deny", "baseline unreadable"]]);
  expect(calls).toEqual([]);
}

for (const tool of tools) {
  for (const body of [
    "{", "null", "{}", '{"groups":"Image"}',
    '{"groups":["Image"],"params":{"Image.X":null}}',
    '{"groups":["Image"],"params":[]}',
    '[]', '"baseline"', '{"groups":[1],"params":{}}',
    '{"groups":["Image"],"params":null}',
    '{"groups":["Image"],"params":{"Image.X":1}}',
  ]) {
    test(`baseline guarded read: ${tool} rejects ${body}`, async () => {
      fs.writeFileSync(file, body);
      const h = configHarness(root);
      unreadable(tool, await h.handlers[tool]!(input), h.chain, h.calls);
    });
  }

  for (const operation of ["statSync", "readFileSync"] as const) {
    test(`baseline guarded read: ${tool} receipts an injected ${operation} error`, async () => {
      fs.writeFileSync(file, valid);
      let attempts = 0;
      const h = configHarness(root, { [operation]: () => { attempts++; throw Error("injected failure"); } });
      unreadable(tool, await h.handlers[tool]!(input), h.chain, h.calls);
      expect(attempts).toBe(1);
    });
  }

  test(`baseline guarded read: ${tool} rejects a directory`, async () => {
    fs.mkdirSync(file);
    const h = configHarness(root);
    unreadable(tool, await h.handlers[tool]!(input), h.chain, h.calls);
  });

  for (const symlink of [false, true]) {
    test(`baseline guarded read: ${tool} rejects ${symlink ? "a symlink to a FIFO" : "a FIFO"} before the deadline`, async () => {
      const fifo = symlink ? join(root, "fifo") : file;
      expect(Bun.spawnSync(["mkfifo", fifo]).exitCode).toBe(0);
      if (symlink) fs.symlinkSync(fifo, file);
      const script = `
        import { configHarness } from ${JSON.stringify(join(import.meta.dir, "config-tools-harness.ts"))};
        const h = configHarness(${JSON.stringify(root)});
        const output = await h.handlers[${JSON.stringify(tool)}](${JSON.stringify(input)});
        console.log(JSON.stringify({ output, chain: h.chain, calls: h.calls }));
      `;
      const child = Bun.spawn([process.execPath, "-e", script], { cwd: root, stdout: "pipe", stderr: "pipe" });
      let timedOut = false;
      const timer = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, 2000);
      try {
        const [exit, stdout, stderr] = await Promise.all([
          child.exited, new Response(child.stdout).text(), new Response(child.stderr).text(),
        ]);
        expect(timedOut).toBe(false);
        expect(stderr).toBe("");
        expect(exit).toBe(0);
        const result = JSON.parse(stdout);
        unreadable(tool, result.output, result.chain, result.calls);
      } finally {
        clearTimeout(timer);
        child.kill("SIGKILL");
      }
    });
  }

  test(`baseline guarded read: ${tool} preserves missing baseline behavior`, async () => {
    const h = configHarness(root);
    const output = await h.handlers[tool]!(input);
    expect(output).toEqual({ content: [{ type: "text", text: tool === "config_drift"
      ? "no baseline — run config_baseline" : "DENIED: no baseline" }] });
    expect(h.chain).toEqual([[tool, tool === "config_drift" ? { camera: "cam" } : input,
      tool === "config_drift" ? "allow" : "deny", "no baseline"]]);
    expect(h.calls).toEqual([]);
  });
}

const hash = (value: unknown) => createHash("sha256").update(typeof value === "string" ? value : JSON.stringify(value)).digest("hex");
for (const symlink of [false, true]) {
  for (const mode of ["drift", "remediate", "dry-run"]) {
    test(`baseline guarded read: ${symlink ? "valid symlink" : "valid file"} preserves ${mode} output and receipt`, async () => {
      if (symlink) {
        const target = join(root, "valid.json");
        fs.writeFileSync(target, valid);
        fs.symlinkSync(target, file);
      } else fs.writeFileSync(file, valid);
      const h = configHarness(root);
      const tool = mode === "drift" ? "config_drift" : "config_remediate";
      const args = mode === "drift" ? { camera: "cam" } : { ...input, approve: mode === "remediate" };
      const output = await h.handlers[tool]!(args);
      if (mode === "drift") {
        const summary = "drift: 1 changed, 0 added, 0 removed";
        expect(output).toEqual({ content: [{ type: "text", text: `changed Image.X: "saved" → "live"\n${summary}` }] });
        expect(h.chain).toEqual([[tool, args, "allow", summary,
          hash({ changed: [{ param: "Image.X", baseline: "saved", live: "live" }], added: [], removed: [] }), "device_acknowledged"]]);
        expect(h.calls).toEqual([["configParams", tool, "cam", ["Image"]]]);
      } else if (mode === "remediate") {
        expect(output).toEqual({ content: [{ type: "text", text: 'remediated Image.X: "live" → "saved"' }] });
        expect(h.chain).toEqual([[tool, args, "allow", "remediated", hash("saved"), "device_acknowledged"]]);
        expect(h.calls).toEqual([
          ["configParams", tool, "cam", ["Image.X"]],
          ["vapix", tool, "cam", "/axis-cgi/param.cgi?action=update&Image.X=saved"],
          ["configParams", tool, "cam", ["Image.X"]],
        ]);
      } else {
        expect(output).toEqual({ content: [{ type: "text", text: 'would set Image.X: "live" → "saved"' }] });
        expect(h.chain).toEqual([[tool, args, "allow", "dry-run: would set Image.X: live → saved"]]);
        expect(h.calls).toEqual([["configParams", tool, "cam", ["Image.X"]]]);
      }
    });
  }
}
