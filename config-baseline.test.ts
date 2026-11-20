import { afterEach, beforeEach, expect, spyOn, test } from "bun:test";
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

const publishSteps = [
  "mkdirSync", "openSync", "writeFileSync", "fsyncSync", "closeSync", "linkSync", "renameSync", "rmSync",
] as const;
type PublishStep = typeof publishSteps[number];
function recordingFs(failures: Partial<Record<PublishStep, string>> = {}) {
  const steps: PublishStep[] = [];
  const io = Object.fromEntries(publishSteps.map(name => [name, (...args: any[]) => {
    steps.push(name);
    if (failures[name]) {
      if (name === "writeFileSync") fs.writeFileSync(args[0], "{");
      throw Object.assign(new Error(`injected ${name} failure`), { code: failures[name] });
    }
    return (fs[name] as (...args: any[]) => unknown)(...args);
  }])) as Partial<typeof fs>;
  return { io, steps };
}

const baselineArgs = { camera: "cam" };
const writeFailure = { content: [{ type: "text", text: "baseline write failed" }] };
const writeFailureChain = [["config_baseline", baselineArgs, "allow", "write FAILED"]];
const liveParams = { "Image.X": "live" };
const baselineSuccess = { content: [{ type: "text", text: `baselined cam: 1 params sha256:${hash(liveParams)}` }] };
const rebaselinePolicy = { test: {
  tools: ["config_baseline", "config_drift", "config_remediate"], cameras: ["cam"],
  config: { groups: ["Image"], rebaseline: true },
} };

test("baseline atomic write: a write that fails part way leaves no baseline file and is receipted", async () => {
  const failed = recordingFs({ writeFileSync: "ENOSPC" });
  const h = configHarness(root, { fs: failed.io });
  expect(await h.handlers.config_baseline!(baselineArgs)).toEqual(writeFailure);
  expect(h.chain).toEqual(writeFailureChain);
  expect(h.calls).toEqual([["configParams", "config_baseline", "cam", ["Image"]]]);
  expect(fs.readdirSync(join(root, "baselines"))).toEqual([]);

  const retry = recordingFs();
  const fresh = configHarness(root, { fs: retry.io });
  expect(await fresh.handlers.config_baseline!(baselineArgs)).toEqual(baselineSuccess);
  expect(retry.steps).toEqual(["mkdirSync", "openSync", "writeFileSync", "fsyncSync", "closeSync", "linkSync", "rmSync"]);
  expect(await fresh.handlers.config_drift!(baselineArgs)).toEqual({
    content: [{ type: "text", text: "drift: 0 changed, 0 added, 0 removed" }],
  });
  expect(fs.readdirSync(join(root, "baselines"))).toEqual(["cam.json"]);
});

test("baseline atomic write: a rebaseline that fails part way keeps the previous baseline byte for byte", async () => {
  fs.writeFileSync(file, valid);
  const previous = fs.readFileSync(file);
  const failed = recordingFs({ writeFileSync: "ENOSPC" });
  const h = configHarness(root, { fs: failed.io, policy: rebaselinePolicy });
  expect(await h.handlers.config_baseline!(baselineArgs)).toEqual(writeFailure);
  expect(h.chain).toEqual(writeFailureChain);
  expect(fs.readFileSync(file)).toEqual(previous);
  expect(fs.readdirSync(join(root, "baselines"))).toEqual(["cam.json"]);

  const retry = recordingFs();
  const fresh = configHarness(root, { fs: retry.io, policy: rebaselinePolicy });
  expect(await fresh.handlers.config_baseline!(baselineArgs)).toEqual(baselineSuccess);
  expect(retry.steps).toEqual(["mkdirSync", "openSync", "writeFileSync", "fsyncSync", "closeSync", "renameSync", "rmSync"]);
  expect(JSON.parse(fs.readFileSync(file, "utf8")).params).toEqual(liveParams);
  expect(fs.readdirSync(join(root, "baselines"))).toEqual(["cam.json"]);
});

test("baseline atomic write: directory, publish and cleanup errors keep a receipted outcome", async () => {
  const stderr = spyOn(console, "error").mockImplementation(() => {});
  const baselines = join(root, "baselines");
  try {
    for (const [step, code] of [
      ["mkdirSync", "EACCES"], ["fsyncSync", "EIO"], ["linkSync", "EPERM"], ["renameSync", "EXDEV"],
    ] as const) {
      fs.rmSync(baselines, { recursive: true, force: true });
      const failed = recordingFs({ [step]: code });
      const h = configHarness(root, {
        fs: failed.io, ...(step === "renameSync" ? { policy: rebaselinePolicy } : {}),
      });
      expect(await h.handlers.config_baseline!(baselineArgs)).toEqual(writeFailure);
      expect(h.chain).toEqual(writeFailureChain);
      expect(fs.existsSync(file)).toBe(false);
      expect(fs.existsSync(baselines) ? fs.readdirSync(baselines) : []).toEqual([]);
      expect(stderr.mock.calls).toEqual([]);
    }

    fs.rmSync(baselines, { recursive: true, force: true });
    const cleanup = recordingFs({ rmSync: "EPERM" });
    const h = configHarness(root, { fs: cleanup.io, randomUUID: () => "stand-in" });
    expect(await h.handlers.config_baseline!(baselineArgs)).toEqual(baselineSuccess);
    expect(h.chain).toEqual([["config_baseline", baselineArgs, "allow", "baselined 1 params", hash(liveParams), "device_acknowledged"]]);
    expect(JSON.parse(fs.readFileSync(file, "utf8")).params).toEqual(liveParams);
    expect(fs.readdirSync(baselines).sort()).toEqual(["cam.json", "cam.json.stand-in.tmp"]);
    expect(stderr.mock.calls).toEqual([["baseline temp cleanup failed"]]);

    fs.rmSync(baselines, { recursive: true, force: true });
    const both = recordingFs({ writeFileSync: "ENOSPC", rmSync: "EPERM" });
    const failed = configHarness(root, { fs: both.io, randomUUID: () => "stand-in" });
    expect(await failed.handlers.config_baseline!(baselineArgs)).toEqual(writeFailure);
    expect(failed.chain).toEqual(writeFailureChain);
    expect(fs.existsSync(file)).toBe(false);
    expect(fs.readdirSync(baselines)).toEqual(["cam.json.stand-in.tmp"]);
    expect(stderr.mock.calls).toEqual([["baseline temp cleanup failed"], ["baseline temp cleanup failed"]]);
  } finally {
    stderr.mockRestore();
  }
});

test("baseline atomic write: a rebaseline keeps an owner-only baseline owner-only and an existing temporary path is never opened", async () => {
  fs.writeFileSync(file, valid, { mode: 0o600 });
  const recording = recordingFs();
  const h = configHarness(root, { fs: recording.io, policy: rebaselinePolicy });
  expect(await h.handlers.config_baseline!(baselineArgs)).toEqual(baselineSuccess);
  expect(fs.statSync(file).mode & 0o777).toBe(0o600);
  expect(JSON.parse(fs.readFileSync(file, "utf8")).params).toEqual(liveParams);

  const victim = join(root, "victim.txt");
  fs.writeFileSync(victim, "victim");
  for (const rebaseline of [false, true]) {
    fs.rmSync(file, { force: true });
    if (rebaseline) fs.writeFileSync(file, valid);
    const previous = rebaseline ? fs.readFileSync(file) : null;
    fs.symlinkSync(victim, file + ".stand-in.tmp");
    const collision = recordingFs();
    const attempt = configHarness(root, {
      fs: collision.io, randomUUID: () => "stand-in", ...(rebaseline ? { policy: rebaselinePolicy } : {}),
    });
    expect(await attempt.handlers.config_baseline!(baselineArgs)).toEqual(writeFailure);
    expect(attempt.chain).toEqual(writeFailureChain);
    expect(fs.readFileSync(victim, "utf8")).toBe("victim");
    if (rebaseline) expect(fs.readFileSync(file)).toEqual(previous!);
    else expect(fs.existsSync(file)).toBe(false);
    expect(fs.readdirSync(join(root, "baselines"))).toEqual(rebaseline ? ["cam.json"] : []);
  }
});

test("baseline atomic write: a rebaseline replaces a symlinked baseline and leaves its target unchanged", async () => {
  fs.mkdirSync(join(root, "outside"));
  const target = join(root, "outside", "target.json");
  fs.writeFileSync(target, "OUTSIDE");
  fs.symlinkSync("../outside/target.json", file);
  const recording = recordingFs();
  const h = configHarness(root, { fs: recording.io, policy: rebaselinePolicy });
  expect(await h.handlers.config_baseline!(baselineArgs)).toEqual(baselineSuccess);
  expect(fs.lstatSync(file).isSymbolicLink()).toBe(false);
  expect(JSON.parse(fs.readFileSync(file, "utf8")).params).toEqual(liveParams);
  expect(fs.readFileSync(target, "utf8")).toBe("OUTSIDE");
  expect(fs.readdirSync(join(root, "baselines"))).toEqual(["cam.json"]);
});
