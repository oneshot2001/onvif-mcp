import { describe, expect, test } from "bun:test";
import { missingPasswords } from "./creds-check";

describe("missing camera passwords", () => {
  test("returns no ids when all passwords are present", () => {
    expect(missingPasswords({ first: "secret", second: " padded secret " })).toEqual([]);
  });

  test("returns ids with empty or whitespace-only passwords", () => {
    expect(missingPasswords({ present: "secret", empty: "", whitespace: " \t\r\n " })).toEqual(["empty", "whitespace"]);
  });
});
