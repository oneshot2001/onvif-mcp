import { deviceText, escapeInvisible } from "./device-text";

export type ConfigDiff = {
  changed: Array<{ param: string; baseline: string; live: string }>;
  added: Array<{ param: string; live: string }>;
  removed: Array<{ param: string; baseline: string }>;
};

// Escape controls, line separators and invisible code points in names as \uXXXX, so two keys that differ only by
// hidden characters display differently; evidence retains the raw keys.
function displayParamName(param: string): string {
  return escapeInvisible(param.replace(/\\/g, "\\\\")
    .replace(/[\u0000-\u001f]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")));
}

export function formatDriftLines(diff: ConfigDiff): string[] {
  return [
    ...diff.changed.map((d) => `changed ${displayParamName(d.param)}: ${deviceText(d.baseline)} → ${deviceText(d.live)}`),
    ...diff.added.map((d) => `added ${displayParamName(d.param)}: ${deviceText(d.live)}`),
    ...diff.removed.map((d) => `removed ${displayParamName(d.param)}: ${deviceText(d.baseline)}`),
  ];
}
