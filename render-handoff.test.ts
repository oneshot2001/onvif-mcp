import { expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import fixture from "./handoff/p3285-2026-09-18T21:45:04.914Z.json";

const scope = "PASS/FAIL covers camspec conformance only. Clock and scene observations are not part of it and do not establish time accuracy or physical location.";

test("renders scenario rows and the receipt hash from an offline handoff without PDF", () => {
  const root = mkdtempSync(join(tmpdir(), "onvif-render-handoff-"));
  try {
    const file = join(root, "handoff.json");
    copyFileSync(join(import.meta.dir, "handoff/p3285-2026-09-18T21:45:04.914Z.json"), file);
    const result = Bun.spawnSync([process.execPath, join(import.meta.dir, "render-handoff.ts"), file], {
      cwd: root,
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(result.exitCode).toBe(0);
    expect(result.stderr.toString()).toBe("");

    const html = readFileSync(join(root, "handoff.html"), "utf8");
    expect(html).toContain("<h2>Analytics scenarios</h2>");
    expect(fixture.scenarios.length).toBeGreaterThan(0);
    for (const scenario of fixture.scenarios) {
      expect(html).toContain(`<tr><td>${scenario.name}</td><td>${scenario.id}</td><td>${scenario.type}</td><td>${scenario.deployed}</td><td>${scenario.readback_diff.length}</td></tr>`);
    }
    expect(html).toContain(`chain head ${fixture.receipts.chain_head_hash}<br>`);
    expect(html).not.toContain("Camera clock (observed at handoff time)");
    expect(html).toContain(scope);
    expect(existsSync(join(root, "handoff.pdf"))).toBeFalse();
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

function renderClock(clock: unknown, passed = true): string {
  const root = mkdtempSync(join(tmpdir(), "onvif-render-clock-"));
  try {
    const file = join(root, "handoff.json");
    writeFileSync(file, JSON.stringify({ ...fixture, clock, verify: { passed, failed: [] } }));
    const result = Bun.spawnSync([process.execPath, join(import.meta.dir, "render-handoff.ts"), file], {
      cwd: root, stdout: "pipe", stderr: "pipe",
    });
    expect(result.exitCode).toBe(0);
    expect(result.stderr.toString()).toBe("");
    expect(existsSync(join(root, "handoff.pdf"))).toBeFalse();
    return readFileSync(join(root, "handoff.html"), "utf8");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test.each([
  [580.512, 1.181, "9 min 40.5 s fast (±1.2 s)"],
  [-33.6, 1.201, "33.6 s slow (±1.3 s)"],
  [59.96, 1.2, "1 min 0.0 s fast (±1.2 s)"],
] as const)("renders clock offset %s with uncertainty rounded up", (offset_s, uncertainty_s, expected) => {
  const html = renderClock({ state: "ok", offset_s, uncertainty_s, ntp: null });
  const heading = "<h2>Camera clock (observed at handoff time)</h2>";
  expect(html).toContain(heading);
  expect(html.indexOf(heading)).toBeGreaterThan(html.indexOf("<h2>Device</h2>"));
  expect(html.indexOf(heading)).toBeLessThan(html.indexOf("<h2>Plan (live → desired)</h2>"));
  expect(html).toContain(expected);
  expect(html).toContain("Measured against the commissioning host's system clock; the host's own sync was not checked.");
  expect(html).toContain("NTP: unavailable");
  expect(html).toContain(scope);
});

test("renders escaped device-reported NTP fields", () => {
  const html = renderClock({ state: "ok", offset_s: 0, uncertainty_s: 1, ntp: {
    enabled: true, synced_since_restart: false, nts_enabled: false,
    servers_source: "<script>source</script>&", static_servers: ["<static>&", "two"], advertised_servers: ["<advertised>&"],
  } });
  expect(html).toContain("NTP (device-reported): enabled true, synced since restart false, NTS false, source &lt;script&gt;source&lt;/script&gt;&amp;, static &lt;static&gt;&amp;, two, advertised &lt;advertised&gt;&amp;");
  expect(html).not.toContain("<script>");
});

test.each(["clock check threw", "time read failed", "<script>&"])("renders escaped clock failure %s without changing FAIL", (reason) => {
  const html = renderClock({ state: "failed", reason }, false);
  expect(html).toContain('<span class="badge">FAIL</span>');
  expect(html).toContain(scope);
  expect(html).toContain(`Clock read failed: ${reason === "<script>&" ? "&lt;script&gt;&amp;" : reason}`);
  expect(html).not.toContain("<script>");
  expect(html).not.toContain("NTP:");
});

test("escapes the spec name and plan desired value in HTML without PDF", () => {
  const root = mkdtempSync(join(tmpdir(), "onvif-render-handoff-"));
  try {
    const file = join(root, "handoff.json");
    copyFileSync(join(import.meta.dir, "handoff/p3285-2026-09-18T21:46:19.264Z.json"), file);
    const handoff = JSON.parse(readFileSync(file, "utf8"));
    handoff.spec.name = "spec <script>alert(1)</script> & name";
    handoff.plan[0].desired = "desired <script>alert(2)</script> & value";
    writeFileSync(file, JSON.stringify(handoff));

    const result = Bun.spawnSync([process.execPath, join(import.meta.dir, "render-handoff.ts"), file], {
      cwd: root,
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(result.exitCode).toBe(0);
    expect(result.stderr.toString()).toBe("");

    const html = readFileSync(join(root, "handoff.html"), "utf8");
    expect(html).toContain("<b>spec &lt;script&gt;alert(1)&lt;/script&gt; &amp; name</b>");
    expect(html).toContain("<td>desired &lt;script&gt;alert(2)&lt;/script&gt; &amp; value</td>");
    expect(html).not.toContain("<script>");
    expect(existsSync(join(root, "handoff.pdf"))).toBeFalse();
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
