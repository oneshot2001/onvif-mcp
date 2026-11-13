import { describe, expect, test } from "bun:test";
import { missingPasswords, unsafeCredentials } from "./creds-check";

describe("missing camera passwords", () => {
  test("returns no ids when all passwords are present", () => {
    expect(missingPasswords({ first: "secret", second: " padded secret " })).toEqual([]);
  });

  test("returns ids with empty or whitespace-only passwords", () => {
    expect(missingPasswords({ present: "secret", empty: "", whitespace: " \t\r\n " })).toEqual(["empty", "whitespace"]);
  });
});


for (const [name, bytes] of [["LF", "\n"], ["CR", "\r"], ["CRLF", "\r\n"], ["NUL", "\0"]] as const) {
  for (const field of ["username", "password"] as const) {
    test(`credential control characters: helper rejects ${name} in ${field} without secrets`, () => {
      const user = field === "username" ? `stand-in-user${bytes}suffix` : "stand-in-user";
      const password = field === "password" ? `stand-in-password${bytes}suffix` : "stand-in-password";
      const labels = unsafeCredentials({ cam: { user, credKey: "key" } }, { key: password });
      expect(labels).toEqual([`cam ${field} (credKey: key)`]);
      expect(labels.join(", ")).not.toContain("stand-in");
      expect(labels.join(", ")).not.toContain("suffix");
    });
  }
}

test("credential control characters: helper preserves camera and admin viewer operator order", () => {
  const account = (credKey: string) => ({ user: "stand-in-user\n", credKey });
  const cameras = {
    second: { ...account("a"), accounts: { operator: account("o"), viewer: account("v") } },
    first: { ...account("b"), accounts: { viewer: account("w"), operator: account("p") } },
  };
  const labels = unsafeCredentials(cameras, Object.fromEntries(["a", "v", "o", "b", "w", "p"].map(key => [key, "stand-in-password\0"])));
  expect(labels).toEqual([
    "second username (credKey: a)", "second password (credKey: a)",
    "second username (credKey: v)", "second password (credKey: v)",
    "second username (credKey: o)", "second password (credKey: o)",
    "first username (credKey: b)", "first password (credKey: b)",
    "first username (credKey: w)", "first password (credKey: w)",
    "first username (credKey: p)", "first password (credKey: p)",
  ]);
  expect(labels.join(", ")).not.toContain("stand-in");
});

test("credential control characters: helper checks withheld username but not missing password", () => {
  expect(unsafeCredentials({ cam: {
    user: "stand-in-admin\r", credKey: "admin",
    accounts: { viewer: { user: "stand-in-viewer", credKey: "viewer" } },
  } }, { viewer: "stand-in-password" })).toEqual(["cam username (credKey: admin)"]);
  expect(unsafeCredentials({ cam: { user: "stand-in-admin", credKey: "admin" } }, {})).toEqual([]);
});

test("credential control characters: helper accepts ordinary quote backslash tab and literal backslash-n", () => {
  for (const value of ["stand-in-ordinary", 'stand-in-quote"', "stand-in-backslash\\", "stand-in-tab\t", "stand-in-literal\\n"]) {
    expect(unsafeCredentials({ cam: { user: value, credKey: "key" } }, { key: value })).toEqual([]);
  }
});
