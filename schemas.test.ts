import { describe, expect, test } from "bun:test";
import { cameraId, presetName, paramName, specRef } from "./schemas";

for (const [name, schema, max] of [
  ["cameraId", cameraId, 64],
  ["presetName", presetName, 128],
  ["paramName", paramName, 128],
  ["specRef", specRef, 128],
] as const) {
  describe(name, () => {
    test("accepts minimum and maximum lengths", () => {
      for (const length of [1, max]) {
        const value = "a".repeat(length);
        expect(schema.parse(value)).toBe(value);
      }
    });

    test("rejects one character over the maximum", () => {
      expect(schema.safeParse("a".repeat(max + 1)).success).toBeFalse();
    });

    test("rejects empty strings", () => {
      expect(schema.safeParse("").success).toBeFalse();
    });
  });
}
