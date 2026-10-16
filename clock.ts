export type NtpInfo = {
  enabled: boolean;
  synced_since_restart: boolean;
  nts_enabled: boolean;
  servers_source: string;
  static_servers: string[];
  advertised_servers: string[];
};

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
