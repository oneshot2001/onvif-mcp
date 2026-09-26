import { expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import fixture from "./handoff/p3285-2026-09-18T21:45:04.914Z.json";

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
    expect(existsSync(join(root, "handoff.pdf"))).toBeFalse();
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
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
