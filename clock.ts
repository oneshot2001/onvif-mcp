import { createHash } from "node:crypto";
import { deviceText } from "./device-text";

export type NtpInfo = {
  enabled: boolean;
  synced_since_restart: boolean;
  nts_enabled: boolean;
  servers_source: string;
  static_servers: string[];
  advertised_servers: string[];
};

export type ClockResult = {
  state: "ok";
  camera_time: string;
  host_before: string;
  host_after: string;
  offset_s: number;
  uncertainty_s: number;
  reference: "host system clock, sync not checked";
  ntp: NtpInfo | null;
} | {
  state: "failed";
  reason: "time read failed" | "time reply malformed" | "host clock stepped backwards";
};

export type ClockDeps = {
  now: () => number;
  vapixPost: (tool: string, camera: string, path: string, body: unknown) => Promise<{ ok: boolean; body: string }>;
};

export async function clockCheck(tool: string, camera: string, deps: ClockDeps): Promise<ClockResult> {
  const before = deps.now();
  let time: { ok: boolean; body: string };
  try {
    time = await deps.vapixPost(tool, camera, "/axis-cgi/time.cgi", { apiVersion: "1.0", method: "getDateTimeInfo" });
  } catch {
    return { state: "failed", reason: "time read failed" };
  }
  const after = deps.now();
  if (!time.ok) return { state: "failed", reason: "time read failed" };
  const cameraMs = parseDateTimeInfo(time.body);
  if (cameraMs === null) return { state: "failed", reason: "time reply malformed" };
  const offset = clockOffset(cameraMs, before, after);
  if (offset === null) return { state: "failed", reason: "host clock stepped backwards" };
  let ntp: NtpInfo | null = null;
  try {
    const r = await deps.vapixPost(tool, camera, "/axis-cgi/ntp.cgi", { apiVersion: "1.0", method: "getNTPInfo" });
    if (r.ok) ntp = parseNtpInfo(r.body);
  } catch { /* NTP availability does not change the observed offset. */ }
  return {
    state: "ok", camera_time: new Date(cameraMs).toISOString(),
    host_before: new Date(before).toISOString(), host_after: new Date(after).toISOString(),
    ...offset, reference: "host system clock, sync not checked", ntp,
  };
}

export function clockReceipt(camera: string, result: ClockResult) {
  return {
    detail: formatClock(camera, result).split("\n")[0]!,
    resultHash: createHash("sha256").update(JSON.stringify(result)).digest("hex"),
    evidence: result.state === "ok" ? "device_acknowledged" : "unknown",
  };
}

export function formatClock(camera: string, r: ClockResult): string {
  if (r.state === "failed") return `${camera} clock read FAILED: ${r.reason}`;
  const sign = r.offset_s >= 0 ? "+" : "";
  const observation = `${camera} clock: observed ${sign}${r.offset_s} s (±${r.uncertainty_s} s) against this host's system clock (host sync not checked; ± covers the request round trip and whole-second camera time only)`;
  const list = (servers: string[]) => servers.length ? servers.map(s => deviceText(s)).join(",") : "none";
  const ntp = r.ntp;
  return observation + "\n" + (ntp
    ? `NTP (device-reported): enabled=${ntp.enabled}, synced since restart=${ntp.synced_since_restart}, NTS=${ntp.nts_enabled}, source=${deviceText(ntp.servers_source)}, static=${list(ntp.static_servers)}, advertised=${list(ntp.advertised_servers)}`
    : "NTP: unavailable");
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function responseData(body: string, method: string): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(body);
    if (!isObject(value) || value.method !== method || "error" in value
      || typeof value.apiVersion !== "string"
      || value.apiVersion.match(/^1\.\d+$/)?.[0] !== value.apiVersion
      || !isObject(value.data)) return null;
    return value.data;
  } catch {
    return null;
  }
}

export function parseDateTimeInfo(body: string): number | null {
  const dateTime = responseData(body, "getDateTimeInfo")?.dateTime;
  if (typeof dateTime !== "string"
    || dateTime.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/)?.[0] !== dateTime) return null;
  const ms = Date.parse(dateTime);
  if (!Number.isFinite(ms) || new Date(ms).toISOString().slice(0, 19) !== dateTime.slice(0, 19)) return null;
  return ms;
}

export function parseNtpInfo(body: string): NtpInfo | null {
  const client = responseData(body, "getNTPInfo")?.client;
  if (!isObject(client)
    || typeof client.enabled !== "boolean" || typeof client.synced !== "boolean"
    || typeof client.NTSEnabled !== "boolean" || typeof client.serversSource !== "string"
    || !Array.isArray(client.staticServers) || !client.staticServers.every(s => typeof s === "string")
    || !Array.isArray(client.advertisedServers) || !client.advertisedServers.every(s => typeof s === "string")) return null;
  return {
    enabled: client.enabled,
    synced_since_restart: client.synced,
    nts_enabled: client.NTSEnabled,
    servers_source: client.serversSource,
    static_servers: client.staticServers,
    advertised_servers: client.advertisedServers,
  };
}

// Positive offsets mean the camera is ahead. Uncertainty excludes host clock error.
export function clockOffset(cameraMs: number, hostBeforeMs: number, hostAfterMs: number): { offset_s: number; uncertainty_s: number } | null {
  if (!Number.isFinite(cameraMs) || !Number.isFinite(hostBeforeMs) || !Number.isFinite(hostAfterMs)
    || hostAfterMs < hostBeforeMs) return null;
  const rawOffset = (cameraMs - (hostBeforeMs + hostAfterMs) / 2) / 1000;
  const offset_s = Math.round(rawOffset * 1000) / 1000;
  // Half the request round trip, 1 s for unknown camera rounding, and offset rounding loss.
  const uncertainty_s = Math.ceil(((hostAfterMs - hostBeforeMs) / 2000 + 1 + Math.abs(offset_s - rawOffset)) * 1000 - 1e-9) / 1000;
  return { offset_s, uncertainty_s };
}
