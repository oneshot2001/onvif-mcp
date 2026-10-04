import { deviceText } from "./device-text";

export type ConfigDiff = {
  changed: Array<{ param: string; baseline: string; live: string }>;
  added: Array<{ param: string; live: string }>;
  removed: Array<{ param: string; baseline: string }>;
};

// Keep names readable at the display boundary; evidence retains the raw keys.
function displayParamName(param: string): string {
  return param.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, " ");
}

export function formatDriftLines(diff: ConfigDiff): string[] {
  return [
    ...diff.changed.map((d) => `changed ${displayParamName(d.param)}: ${deviceText(d.baseline)} → ${deviceText(d.live)}`),
    ...diff.added.map((d) => `added ${displayParamName(d.param)}: ${deviceText(d.live)}`),
    ...diff.removed.map((d) => `removed ${displayParamName(d.param)}: ${deviceText(d.baseline)}`),
  ];
}
