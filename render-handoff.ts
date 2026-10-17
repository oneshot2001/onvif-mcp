// Render a signed camspec handoff (handoff/*.json) to HTML + PDF. JSON stays the source of truth.
// usage: bun render-handoff.ts handoff/<file>.json [--pdf]
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { basename, dirname, join } from "node:path";
import { execSync } from "node:child_process";

const file = process.argv[2]!;
const h = JSON.parse(readFileSync(file, "utf8"));
const esc = (v: unknown) => String(v ?? "—").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]!);
const rows = (items: any[], cols: string[]) => items.length
  ? `<table><tr>${cols.map((c) => `<th>${c}</th>`).join("")}</tr>${items.map((r) => `<tr>${cols.map((c) => `<td>${esc(r[c])}</td>`).join("")}</tr>`).join("")}</table>`
  : `<p class="muted">none</p>`;
const status = h.verify.passed ? "PASS" : "FAIL";
const fired = h.observation ? Object.entries(h.observation.fired ?? {}).map(([name, v]: any) => ({ name, ...v })) : [];
const clockSection = () => {
  const clock = h.clock;
  if (!clock) return "";
  const heading = "<h2>Camera clock (observed at handoff time)</h2>";
  if (clock.state === "failed") return `${heading}<p>Clock read failed: ${esc(clock.reason)}</p>`;
  const tenths = Math.round(Math.abs(clock.offset_s) * 10);
  const minutes = Math.floor(tenths / 600);
  const offset = `${minutes ? `${minutes} min ` : ""}${((tenths % 600) / 10).toFixed(1)} s ${clock.offset_s < 0 ? "slow" : "fast"} (±${(Math.ceil(clock.uncertainty_s * 10) / 10).toFixed(1)} s)`;
  const ntp = clock.ntp;
  const ntpText = ntp
    ? `NTP (device-reported): enabled ${ntp.enabled}, synced since restart ${ntp.synced_since_restart}, NTS ${ntp.nts_enabled}, source ${ntp.servers_source}, static ${ntp.static_servers.join(", ") || "none"}, advertised ${ntp.advertised_servers.join(", ") || "none"}`
    : "NTP: unavailable";
  return `${heading}<p>${esc(offset)}</p><p>Measured against the commissioning host's system clock; the host's own sync was not checked.</p><p>${esc(ntpText)}</p>`;
};

const sceneSection = () => {
  const scene = h.scene;
  if (!scene) return "";
  const frame = scene.reference_frame;
  let frameText: string;
  if (frame.state === "failed") frameText = esc(frame.reason);
  else {
    const sidecar = join(dirname(file), basename(frame.file));
    let state = "frame file missing";
    if (existsSync(sidecar)) {
      const hash = createHash("sha256").update(readFileSync(sidecar)).digest("hex");
      state = hash === frame.sha256 ? "frame file matches the signed hash" : "frame file does not match the signed hash";
    }
    frameText = `Frame: ${esc(frame.file)}<br>sha256 ${esc(frame.sha256)}<br>${state}`;
  }
  const ptz = scene.ptz_position;
  const ptzText = !ptz ? "" : ptz.state === "failed" ? `<p>${esc(ptz.reason)}</p>`
    : `<p>PTZ position read after the frame (device-reported): pan ${esc(ptz.pan)}° tilt ${esc(ptz.tilt)}° zoom ${esc(ptz.zoom)} (VAPIX zoom units)</p>`;
  const location = scene.location ? `Location (entered by the installer, not verified): ${esc(scene.location.text)}` : "Location: not entered";
  return `<h2>Scene reference (observed at handoff time; not proof of location)</h2><p>${frameText}</p>${ptzText}<p>${location}</p>`;
};

const changesSection = () => {
  const changes = h.scene_changes;
  if (!changes) return "";
  const signed = (value: number) => `${value >= 0 ? "+" : ""}${value}`;
  const ptz = changes.ptz_coordinate_difference;
  const coordinates = ptz ? `pan ${esc(signed(ptz.pan))}° tilt ${esc(signed(ptz.tilt))}° zoom ${esc(signed(ptz.zoom))} (VAPIX zoom units)` : "unavailable";
  const location = changes.entered_location_text_changed == null ? "unavailable (not comparable)" : changes.entered_location_text_changed ? "yes" : "no";
  const offset = changes.observed_offset_difference_s == null ? "unavailable" : `${esc(signed(changes.observed_offset_difference_s))} s`;
  const allowance = changes.observed_offset_difference_allowance_s == null ? "unavailable" : `${esc(changes.observed_offset_difference_allowance_s)} s`;
  const frame = changes.previous_reference_frame;
  return `<h2>Changes since previous handoff ${esc(changes.previous_handoff.file)}</h2>
<p>PTZ coordinate difference (not distance moved): ${coordinates}</p>
<p>Entered location text changed: ${location}</p>
<p>Observed camera-minus-host offset difference: ${offset} (±${allowance}; host reference changes can contribute; not a measure of camera clock drift)</p>
<p>Previous reference frame: ${frame ? `${esc(frame.file)} ${esc(frame.sha256)}` : "unavailable"}</p>`;
};

const html = `<!doctype html><meta charset="utf-8"><title>Handoff ${esc(h.camera.id)}</title>
<style>
body{font:11pt/1.45 -apple-system,Inter,system-ui,sans-serif;color:#111;margin:0;padding:32px 40px}
h1{font-size:20pt;margin:0 0 2px}h2{font-size:11pt;margin:22px 0 6px;text-transform:uppercase;letter-spacing:.06em;color:#555}
.badge{display:inline-block;padding:4px 12px;border-radius:4px;font-weight:700;color:#fff;background:${h.verify.passed ? "#1a7f37" : "#b42318"}}
table{border-collapse:collapse;width:100%;font-size:9.5pt}th,td{border-bottom:1px solid #ddd;padding:5px 8px;text-align:left;vertical-align:top}th{background:#f4f4f4;font-weight:600}
code,.mono{font-family:"JetBrains Mono",Menlo,monospace;font-size:8.5pt;word-break:break-all}.muted{color:#777}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:4px 24px}.sig{margin-top:40px;display:grid;grid-template-columns:1fr 1fr;gap:40px}.sig div{border-top:1px solid #111;padding-top:6px;font-size:9pt}
</style>
<h1>Camera commissioning handoff <span class="badge">${status}</span></h1>
<p class="muted">PASS/FAIL covers camspec conformance only. Clock and scene observations are not part of it and do not establish time accuracy or physical location.</p>
<div class="muted">${esc(h.artifact)} · spec <b>${esc(h.spec.name)}</b> · run ${esc(h.run.started)} → ${esc(h.run.finished)}</div>
<h2>Device</h2><div class="grid"><div>Camera: <b>${esc(h.camera.id)}</b> — ${esc(h.camera.model)}</div><div>Firmware: ${esc(h.camera.firmware)}</div><div>Serial: ${esc(h.camera.serial)}</div><div>Agent: ${esc(h.agent)}</div></div>
${clockSection()}
${sceneSection()}
${changesSection()}
<h2>Plan (live → desired)</h2>${rows(h.plan, ["param", "current", "desired"])}
<h2>Applied</h2>${rows(h.applied.map((a: any) => a.param ? a : a.preset ? { param: `preset:${a.preset}`, previous: "", desired: `pan ${a.pan} tilt ${a.tilt} zoom ${a.zoom}` } : { param: `scenario:${a.scenario}`, previous: "", desired: `${a.type} (id ${a.id})` }), ["param", "previous", "desired"])}
<h2>Verification — ${status}</h2>${rows(h.verify.failed, ["param", "desired", "observed"])}
${h.rollback ? `<p>Rollback performed: <b>${h.rollback.performed}</b> · rollback verified: <b>${h.rollback.verified}</b></p>` : ""}
${h.scenarios ? `<h2>Analytics scenarios</h2>${rows(h.scenarios.map((s: any) => ({ ...s, readback_diff: (s.readback_diff ?? []).length })), ["name", "id", "type", "deployed", "readback_diff"])}` : ""}
${h.observation ? `<h2>Observation window (${esc(h.observation.window_seconds)}s)</h2>${rows(fired, ["name", "count", "first", "last"])}${(h.observation.warnings ?? []).map((w: string) => `<p class="muted">⚠ ${esc(w)}</p>`).join("")}` : ""}
<h2>Provenance</h2>
<div class="mono">spec sha256 ${esc(h.spec.sha256)}<br>policy sha256 ${esc(h.policy_sha256)}<br>receipts seq ${esc(h.receipts.first_seq)}–${esc(h.receipts.last_seq)} · chain head ${esc(h.receipts.chain_head_hash)}<br>handoff signature (ed25519) ${esc(h.sig)}</div>
<p class="muted">Verify: <code>bun index.ts --verify</code> in the onvif-mcp checkout that produced this artifact.</p>
<div class="sig"><div>Installer signature / date</div><div>Customer acceptance / date</div></div>`;

const out = file.replace(/\.json$/, "");
writeFileSync(`${out}.html`, html);
console.log(`${out}.html`);
if (process.argv.includes("--pdf")) {
  const bin = execSync(`ls -d "$HOME"/Library/Caches/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-mac-arm64/chrome-headless-shell | tail -1`).toString().trim();
  if (!existsSync(bin)) throw new Error("chrome-headless-shell not found (bunx playwright install chromium)");
  const tmp = execSync("mktemp -d").toString().trim();
  execSync(`"${bin}" --no-pdf-header-footer --user-data-dir="${tmp}" --virtual-time-budget=3000 --print-to-pdf="${out}.pdf" "file://${process.cwd()}/${out}.html"`, { stdio: "ignore" });
  execSync(`rm -rf "${tmp}"`);
  console.log(`${out}.pdf`);
}
