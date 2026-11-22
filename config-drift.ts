import { deviceText, escapeInvisible } from "./device-text";

export type ConfigDiff = {
  changed: Array<{ param: string; baseline: string; live: string }>;
  added: Array<{ param: string; live: string }>;
  removed: Array<{ param: string; baseline: string }>;
};

// Escape controls, line separators and invisible code points in names as \uXXXX, so two keys that differ only by
// hidden characters display differently; evidence retains the raw keys. Only raw names of 1–56 ASCII
// letters, digits, dots and underscores stay bare; all others display as JSON strings of the escaped form.
// The 56-character cap is the longest of the 271 distinct names in the three committed baselines.
function displayParamName(param: string): string {
  const escaped = escapeInvisible(param.replace(/\\/g, "\\\\")
    .replace(/[\u0000-\u001f]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")));
  return /^[A-Za-z0-9._]{1,56}$/.test(param) ? escaped : JSON.stringify(escaped);
}

export function formatDriftLines(diff: ConfigDiff): string[] {
  return [
    ...diff.changed.map((d) => `changed ${displayParamName(d.param)}: ${deviceText(d.baseline)} → ${deviceText(d.live)}`),
    ...diff.added.map((d) => `added ${displayParamName(d.param)}: ${deviceText(d.live)}`),
    ...diff.removed.map((d) => `removed ${displayParamName(d.param)}: ${deviceText(d.baseline)}`),
  ];
}
