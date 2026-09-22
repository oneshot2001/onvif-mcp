import { describe, expect, test } from "bun:test";
import { keyModeProblem } from "./key-perms";

describe("receipt key permissions", () => {
  test("accepts owner-only access with regular-file type bits", () => {
    expect(keyModeProblem(0o100600)).toBeNull();
  });

  for (const mode of [0o100644, 0o100640, 0o100604]) {
    test(`rejects mode ${mode.toString(8)} with a problem message`, () => {
      expect(keyModeProblem(mode)).toBe("receipt.key has group/other permissions; run chmod 600 .keys/receipt.key");
    });
  }

  test("rejects every group/other permission bit", () => {
    for (const bit of [0o040, 0o020, 0o010, 0o004, 0o002, 0o001]) {
      expect(keyModeProblem(0o100600 | bit)).not.toBeNull();
    }
  });
});
