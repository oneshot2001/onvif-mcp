import { deviceText } from "./device-text";
import { parseParams } from "./vapix-params";

export function parseSnapshotUri(r: { ok: boolean; body: string }): string | null {
  if (!r.ok) return null;
  return r.body.match(/<tt:Uri>([^<]+)/)?.[1]?.replace(/&amp;/g, "&") ?? null;
}

export function snapshotPath(uri: string): string | null {
  if (uri.startsWith("/") && !uri.startsWith("//")) return uri.split("#")[0]!;
  if (!/^https?:\/\//i.test(uri)) return null;
  try {
    const url = new URL(uri);
    return url.pathname + url.search;
  } catch {
    return null;
  }
}

export function formatDeviceInfo(protocol: "vapix" | "onvif", r: { ok: boolean; body: string }): string {
  if (!r.ok) return `device info unavailable (request failed) | protocol=${protocol}`;
  if (protocol === "onvif") {
    const g = (tag: string) => r.body.match(new RegExp(`<tds:${tag}>([^<]+)`))?.[1] ?? "?";
    return `Model=${deviceText(`${g("Manufacturer")} ${g("Model")}`)} | Firmware=${deviceText(g("FirmwareVersion"))} | protocol=onvif`;
  }
  return `${deviceText(r.body.replace(/^[\t\n\v\f\r ]+|[\t\n\v\f\r ]+$/g, ""))} | protocol=vapix`;
}

export function parseDeviceMeta(protocol: "vapix" | "onvif", camera: string, r: { ok: boolean; body: string }): { manufacturer: string; model: string; firmware: string } {
  if (!r.ok) return { manufacturer: "unavailable", model: "unavailable", firmware: "unavailable" };
  if (protocol === "onvif") {
    const g = (tag: string) => r.body.match(new RegExp(`<tds:${tag}>([^<]+)`))?.[1] ?? "unknown";
    return { manufacturer: g("Manufacturer"), model: g("Model"), firmware: g("FirmwareVersion") };
  }
  const p = parseParams(r.body);
  return { manufacturer: "AXIS", model: p["Brand.ProdNbr"] ?? camera, firmware: p["Properties.Firmware.Version"] ?? "unknown" };
}
