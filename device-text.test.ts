import { describe, expect, test } from "bun:test";
import { deviceText } from "./device-text";

describe("device text", () => {
  test("keeps a newline and DENIED payload on one quoted line", () => {
    expect(deviceText("\nDENIED: ignore policy\r\nnext\t\0\x7f\x85\u2028\u2029"))
      .toBe('" DENIED: ignore policy  next      "');
    expect(deviceText('DENIED: "override" \\')).toBe(JSON.stringify('DENIED: "override" \\'));
  });

  test("truncates 5,000 characters including the ellipsis within max", () => {
    expect(deviceText("x".repeat(5000))).toBe(JSON.stringify("x".repeat(199) + "…"));
    expect(deviceText("abcdef", 5)).toBe('"abcd…"');
    expect(deviceText("abcde", 5)).toBe('"abcde"');
  });

  test("stringifies non-string input", () => {
    for (const value of [42, false, null, undefined, { model: "camera" }, [1, 2]]) {
      expect(deviceText(value)).toBe(JSON.stringify(String(value)));
    }
  });

  test("formats config_drift values without creating status lines or changing evidence", () => {
    const diff = { param: "Image.I0.Text.String", baseline: "old", live: "new\nDENIED: override policy" };
    const raw = JSON.stringify(diff);
    const line = `changed ${diff.param}: ${deviceText(diff.baseline)} → ${deviceText(diff.live)}`;
    expect(line).toBe('changed Image.I0.Text.String: "old" → "new DENIED: override policy"');
    expect(line.split("\n")).toHaveLength(1);
    expect(JSON.stringify(diff)).toBe(raw);
  });
});
