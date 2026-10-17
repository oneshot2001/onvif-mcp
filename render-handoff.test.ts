import { createHash } from "node:crypto";
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
    expect(html).not.toContain("Scene reference");
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


function renderScene(scene: unknown, sidecar?: Buffer) {
  const root = mkdtempSync(join(tmpdir(), "onvif-render-scene-"));
  try {
    const file = join(root, "handoff.json");
    writeFileSync(file, JSON.stringify({ ...fixture, scene }));
    if (sidecar) writeFileSync(join(root, "handoff.jpg"), sidecar);
    const result = Bun.spawnSync([process.execPath, join(import.meta.dir, "render-handoff.ts"), file], { cwd: root, stdout: "pipe", stderr: "pipe" });
    expect(result.exitCode).toBe(0);
    expect(result.stderr.toString()).toBe("");
    return readFileSync(join(root, "handoff.html"), "utf8");
  } finally { rmSync(root, { recursive: true, force: true }); }
}

test.each(["match", "missing", "changed"])("renders scene sidecar %s against the signed hash", (mode) => {
  const bytes = readFileSync(join(import.meta.dir, "fixtures/scene/synthetic-8x8.jpg"));
  const hash = createHash("sha256").update(bytes).digest("hex");
  const sidecar = Buffer.from(bytes);
  if (mode === "changed") sidecar[10] = sidecar[10]! ^ 1;
  const html = renderScene({
    reference_frame: { file: "handoff.jpg", sha256: hash },
    ptz_position: { pan: 143.25, tilt: -31.81, zoom: 100 },
    location: { text: "<gate>&", source: "installer-entered, not verified" },
  }, mode === "missing" ? undefined : sidecar);
  expect(html).toContain("<h2>Scene reference (observed at handoff time; not proof of location)</h2>");
  expect(html).toContain("handoff.jpg");
  expect(html).toContain(hash);
  expect(html).toContain(mode === "match" ? "frame file matches the signed hash" : mode === "missing" ? "frame file missing" : "frame file does not match the signed hash");
  expect(html).toContain("PTZ position read after the frame (device-reported): pan 143.25° tilt -31.81° zoom 100 (VAPIX zoom units)");
  expect(html).toContain("Location (entered by the installer, not verified): &lt;gate&gt;&amp;");
  expect(html).not.toContain("<gate>");
});

test.each(["snapshot rate limited", "snapshot failed", "not a complete JPEG"])("renders frame failure %s and absent location", (reason) => {
  const html = renderScene({ reference_frame: { state: "failed", reason }, ptz_position: null, location: null });
  expect(html).toContain(reason);
  expect(html).toContain("Location: not entered");
  expect(html).not.toContain("PTZ position read after the frame");
});
test.each(["position read failed", "position reply malformed"])("renders PTZ failure %s", (reason) => {
  expect(renderScene({ reference_frame: { state: "failed", reason: "snapshot failed" }, ptz_position: { state: "failed", reason }, location: null })).toContain(reason);
});

function renderChanges(scene_changes: unknown) {
  const root = mkdtempSync(join(tmpdir(), "onvif-render-changes-"));
  try {
    const file = join(root, "handoff.json");
    writeFileSync(file, JSON.stringify({ ...fixture, scene_changes }));
    // The renderer must use the signed fields even if the prior JSON is invalid.
    writeFileSync(join(root, "previous<&>.json"), "{invalid JSON");
    const result = Bun.spawnSync([process.execPath, join(import.meta.dir, "render-handoff.ts"), file], { cwd: root, stdout: "pipe", stderr: "pipe" });
    expect(result.exitCode).toBe(0);
    expect(result.stderr.toString()).toBe("");
    return readFileSync(join(root, "handoff.html"), "utf8");
  } finally { rmSync(root, { recursive: true, force: true }); }
}

const changes = {
  previous_handoff: { file: "previous<&>.json", sha256: "abc123" },
  previous_reference_frame: { file: "previous<&>.jpg", sha256: "def456" },
  ptz_coordinate_difference: { pan: 6.75, tilt: -1.25, zoom: 0 },
  entered_location_text_changed: true,
  observed_offset_difference_s: 0.5,
  observed_offset_difference_allowance_s: 2.381,
};

test("renders signed differences and previous frame for human comparison without reopening previous JSON", () => {
  const html = renderChanges(changes);
  expect(html).toContain("<h2>Changes since previous handoff previous&lt;&amp;&gt;.json</h2>");
  expect(html).toContain("PTZ coordinate difference (not distance moved): pan +6.75° tilt -1.25° zoom +0 (VAPIX zoom units)");
  expect(html).toContain("Entered location text changed: yes");
  expect(html).toContain("Observed camera-minus-host offset difference: +0.5 s (±2.381 s; host reference changes can contribute; not a measure of camera clock drift)");
  expect(html).toContain("Previous reference frame: previous&lt;&amp;&gt;.jpg def456");
  expect(html.replace("not distance moved", "")).not.toMatch(/\b(moved|unchanged|drifted)\b/);
});

test("renders all null differences as unavailable, with no numerical zero or verdict", () => {
  const html = renderChanges({ ...changes, previous_reference_frame: null, ptz_coordinate_difference: null,
    entered_location_text_changed: null, observed_offset_difference_s: null, observed_offset_difference_allowance_s: null });
  expect(html).toContain("PTZ coordinate difference (not distance moved): unavailable");
  expect(html).toContain("Entered location text changed: unavailable (not comparable)");
  expect(html).toContain("Observed camera-minus-host offset difference: unavailable (±unavailable;");
  expect(html).toContain("Previous reference frame: unavailable");
  const section = html.split("<h2>Changes since previous handoff")[1]!.split("<h2>")[0]!;
  expect(section).not.toMatch(/[+-]?0(?:[. ]|°)/);
  expect(section.replace("not distance moved", "")).not.toMatch(/\b(moved|unchanged|drifted)\b/);
});

test.each([null, undefined])("omits changes section when scene_changes is %s", (value) => {
  expect(renderChanges(value)).not.toContain("Changes since previous handoff");
});

test("renders false as no and a negative offset with its sign", () => {
  const html = renderChanges({ ...changes, entered_location_text_changed: false, observed_offset_difference_s: -0.5 });
  expect(html).toContain("Entered location text changed: no");
  expect(html).toContain("offset difference: -0.5 s (±2.381 s;");
});
