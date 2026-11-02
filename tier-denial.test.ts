import { afterEach, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { accountFor, type CameraAccounts } from "./account-for";
import { configHarness } from "./config-tools-harness";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
const tools = ["config_baseline", "config_drift"] as const;
const params = { "Image.X": "live" };
const baselineBytes = JSON.stringify({ groups: ["Image"], params }, null, 2) + "\n";
function setup(seeded = false) {
  const root = mkdtempSync(join(tmpdir(), "tier-denial-"));
  roots.push(root);
  const file = join(root, "baselines", "cam.json");
  if (seeded) { mkdirSync(join(root, "baselines")); writeFileSync(file, baselineBytes); }
  return { root, file };
}

for (const tool of tools) {
  for (const seeded of [false, true]) {
    test(`tier denial wiring: ${tool} denies before transport with ${seeded ? "seeded" : "absent"} baseline`, async () => {
      const { root, file } = setup(seeded);
      const tierCalls: string[][] = [];
      const reason = `credential tier for '${tool}' withheld by the vault: admin until P4 (cam)`;
      const h = configHarness(root, { tierDenied: (...args) => { tierCalls.push(args); return reason; } });
      const input = { camera: "cam" };
      expect(await h.handlers[tool]!(input)).toEqual({ content: [{ type: "text", text: `DENIED: ${reason}` }] });
      expect(h.chain).toEqual([[tool, input, "deny", reason]]);
      expect(h.calls).toEqual([]);
      expect(tierCalls).toEqual([[tool, "cam"]]);
      if (seeded) expect(readFileSync(file)).toEqual(Buffer.from(baselineBytes));
      else expect(existsSync(file)).toBeFalse();
    });
  }

  test(`tier denial wiring: ${tool} preserves output when tier is available`, async () => {
    const { root, file } = setup(tool === "config_drift");
    const tierCalls: string[][] = [];
    const h = configHarness(root, { tierDenied: (...args) => { tierCalls.push(args); return null; } });
    const hash = createHash("sha256").update(JSON.stringify(params)).digest("hex");
    const expected = tool === "config_baseline" ? `baselined cam: 1 params sha256:${hash}` : "drift: 0 changed, 0 added, 0 removed";
    expect(await h.handlers[tool]!({ camera: "cam" })).toEqual({ content: [{ type: "text", text: expected }] });
    expect(h.chain).toHaveLength(1);
    expect(h.chain[0]![2]).toBe("allow");
    expect(h.calls).toEqual([["configParams", tool, "cam", ["Image"]]]);
    expect(tierCalls).toEqual([[tool, "cam"]]);
    expect(JSON.parse(readFileSync(file, "utf8")).params).toEqual(params);
  });

  test(`tier denial wiring: ${tool} policy denial precedes tier denial`, async () => {
    const { root, file } = setup();
    const tierCalls: string[][] = [];
    const h = configHarness(root, {
      policy: { test: { tools: [], cameras: ["cam"], config: { groups: ["Image"] } } },
      tierDenied: (...args) => { tierCalls.push(args); return "withheld tier"; },
    });
    const input = { camera: "cam" };
    const reason = `tool '${tool}' not allowlisted for agent 'test'`;
    expect(await h.handlers[tool]!(input)).toEqual({ content: [{ type: "text", text: `DENIED: ${reason}` }] });
    expect(h.chain).toEqual([[tool, input, "deny", reason]]);
    expect(h.calls).toEqual([]);
    expect(tierCalls).toEqual([]);
    expect(existsSync(file)).toBeFalse();
  });
}

// Execute the production helper with real accountFor, excluding all startup code.
const source = readFileSync(join(import.meta.dir, "index.ts"), "utf8");
const start = source.indexOf("function tierDenied(");
const end = source.indexOf("const missing = missingPasswords(passwords);", start);
if (start < 0 || end <= start) throw new Error("tierDenied slice boundaries missing");
const slice = source.slice(start, end);
if (!slice.trimEnd().endsWith("}")) throw new Error("tierDenied slice end changed");
const code = new Bun.Transpiler({ loader: "ts" }).transformSync(slice);
for (const tool of [...tools, "commission_plan", "commission_verify"]) {
  for (const scenario of ["admin fallback withheld", "separate viewer available", "viewer withheld", "empty withheld map"] as const) {
    test(`tier denial wiring: actual tierDenied ${tool} ${scenario}`, () => {
      const cam: CameraAccounts = { user: "admin", credKey: "admin-key" };
      if (scenario === "separate viewer available" || scenario === "viewer withheld") {
        cam.accounts = { viewer: { user: "viewer", credKey: "viewer-key" } };
      }
      const withheld: Record<string, string> = scenario === "empty withheld map" ? {}
        : scenario === "viewer withheld" ? { "viewer-key": "viewer unavailable (cam)" }
        : { "admin-key": "admin until P4 (cam)" };
      const tierDenied = new Function("cameras", "withheld", "accountFor", `${code}\nreturn tierDenied;`)(
        { cam }, withheld, accountFor,
      );
      const reason = scenario === "admin fallback withheld" ? "admin until P4 (cam)"
        : scenario === "viewer withheld" ? "viewer unavailable (cam)" : null;
      expect(tierDenied(tool, "cam")).toBe(reason === null ? null : `credential tier for '${tool}' withheld by the vault: ${reason}`);
    });
  }
}
