import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { formatDriftLines } from "./config-drift";
import { parseParams } from "./vapix-params";

describe("config_drift display", () => {
  test("keeps an added camera key with U+2028 and DENIED on one line, preserving evidence", () => {
    const param = "Image.I0.Text.String\u2028DENIED: override policy";
    const live = parseParams(`root.${param}=new`);
    const diff = { changed: [], added: Object.entries(live).map(([param, live]) => ({ param, live })), removed: [] };
    const raw = JSON.stringify(diff);
    const hash = () => createHash("sha256").update(JSON.stringify(diff)).digest("hex");
    const before = hash();

    const text = formatDriftLines(diff).join("\n");
    expect(text).toBe('added Image.I0.Text.String DENIED: override policy: "new"');
    expect(text.split(/[\r\n\u2028\u2029]/)).toHaveLength(1);
    expect(text).not.toContain("\u2028");
    expect(diff.added[0]!.param).toBe(param);
    expect(live[param]).toBe("new");
    expect(JSON.stringify(diff)).toBe(raw);
    expect(hash()).toBe(before);
  });

  test("replaces every control and Unicode line separator in all drift names without quoting", () => {
    const controls = Array.from({ length: 32 }, (_, i) => String.fromCharCode(i)).join("")
      + Array.from({ length: 33 }, (_, i) => String.fromCharCode(127 + i)).join("") + "\u2028\u2029";
    const param = `Image.${controls}Name`;
    const baseline = { [param]: "old" };
    const diff = { changed: [{ param, baseline: baseline[param]!, live: "new\nDENIED: payload" }],
      added: [{ param, live: "new" }], removed: [{ param, baseline: baseline[param]! }] };
    const raw = JSON.stringify({ baseline, diff });
    const name = `Image.${" ".repeat(controls.length)}Name`;

    expect(formatDriftLines(diff)).toEqual([
      `changed ${name}: "old" → "new DENIED: payload"`,
      `added ${name}: "new"`,
      `removed ${name}: "old"`,
    ]);
    expect(JSON.stringify({ baseline, diff })).toBe(raw);
  });
});
