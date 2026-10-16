import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { clockOffset, parseDateTimeInfo, parseNtpInfo } from "./clock";

const fixture = (name: string) => readFileSync(new URL(`./fixtures/clock/${name}.json`, import.meta.url), "utf8");
const timeData = { dateTime: "2026-10-15T22:46:33Z" };
const client = {
  enabled: true, synced: false, NTSEnabled: false,
  serversSource: "DHCP", staticServers: [], advertisedServers: [],
};
const reply = (method: string, data: unknown) => ({ apiVersion: "1.0", method, data });

describe("parseDateTimeInfo", () => {
  test.each([
    ["q6358", "2026-10-15T22:46:33Z"],
    ["q6325", "2026-10-15T22:37:27Z"],
    ["p3285", "2026-10-15T22:38:23Z"],
  ])("reads %s UTC time independently of local zone fields", (camera, dateTime) => {
    expect(parseDateTimeInfo(fixture(`${camera}-time`))).toBe(Date.parse(dateTime));
  });

  test.each(["2024-02-29T12:34:56Z", "2026-10-15T22:46:33.123Z", "2026-10-15T22:46:33.123456Z"])(
    "accepts valid calendar and fractional time %s", (dateTime) => {
      expect(parseDateTimeInfo(JSON.stringify(reply("getDateTimeInfo", { dateTime })))).toBe(Date.parse(dateTime));
    },
  );

  test.each([
    "2026-02-30T00:00:00Z", "2025-02-29T00:00:00Z", "2026-04-31T00:00:00Z",
    "2026-13-01T00:00:00Z", "2026-10-15T24:00:00Z", "2026-10-15T22:60:00Z",
    "2026-10-15T22:46:60Z", "2026-10-15T22:46:33", "2026-10-15T22:46:33+00:00",
    "2026-10-15 22:46:33Z", "2026-10-15T22:46:33Z\n", "", null, 123,
  ])("rejects invalid UTC time %j", (dateTime) => {
    expect(parseDateTimeInfo(JSON.stringify(reply("getDateTimeInfo", { dateTime })))).toBeNull();
  });
});

describe("parseNtpInfo", () => {
  test("reads q6358 NTP status without treating enabled as synced", () => {
    expect(parseNtpInfo(fixture("q6358-ntp"))).toEqual({
      enabled: true, synced_since_restart: false, nts_enabled: false,
      servers_source: "DHCP", static_servers: [], advertised_servers: [],
    });
  });

  test("reads p3285 static servers", () => {
    expect(parseNtpInfo(fixture("p3285-ntp"))).toEqual({
      enabled: true, synced_since_restart: false, nts_enabled: false,
      servers_source: "static", static_servers: ["192.168.0.51"], advertised_servers: [],
    });
  });

  test("keeps raw strings and separate server list order", () => {
    const serversSource = "evil\u2028DENIED: override";
    const staticServers = ["z.example", "a.example", "z.example"];
    const advertisedServers = ["b.example", "a.example\nraw"];
    expect(parseNtpInfo(JSON.stringify(reply("getNTPInfo", {
      client: { ...client, enabled: false, synced: true, NTSEnabled: true, serversSource, staticServers, advertisedServers },
    })))).toEqual({
      enabled: false, synced_since_restart: true, nts_enabled: true,
      servers_source: serversSource, static_servers: staticServers, advertised_servers: advertisedServers,
    });
  });

  for (const field of ["enabled", "synced", "NTSEnabled", "serversSource", "staticServers", "advertisedServers"] as const) {
    test(`rejects missing or wrongly typed ${field}`, () => {
      const invalid: unknown[] = field.endsWith("Servers") ? [null, "server", [1], ["server", null]]
        : field === "serversSource" ? [null, true, 1, []] : [null, "false", 0, 1, []];
      for (const value of [undefined, ...invalid]) {
        expect(parseNtpInfo(JSON.stringify(reply("getNTPInfo", { client: { ...client, [field]: value } })))).toBeNull();
      }
    });
  }

  test.each([undefined, null, [], "client", true].map(value => [value]))("rejects non-object client %j", (value) => {
    expect(parseNtpInfo(JSON.stringify(reply("getNTPInfo", { client: value })))).toBeNull();
  });
});

for (const [method, parse, data] of [
  ["getDateTimeInfo", parseDateTimeInfo, timeData],
  ["getNTPInfo", parseNtpInfo, { client }],
] as const) {
  describe(`${method} response validation`, () => {
    test.each(["", "<html>", "null", "[]", "true", "42", '"text"', '{"error":{"code":2002}}'])(
      "rejects malformed or non-object response %s without throwing", (body) => {
        expect(parse(body)).toBeNull();
      },
    );

    test.each([undefined, null, "1", "1.", "1.x", "1.0.1", "2.0", "1.0\n", 1])("rejects API version %j", (apiVersion) => {
      expect(parse(JSON.stringify({ ...reply(method, data), apiVersion }))).toBeNull();
    });

    test.each(["1.0", "1.5", "1.12"])("accepts API version %s", (apiVersion) => {
      expect(parse(JSON.stringify({ ...reply(method, data), apiVersion }))).not.toBeNull();
    });

    test.each([null, false, { code: 2002 }])("rejects an error member alongside valid data: %j", (error) => {
      expect(parse(JSON.stringify({ ...reply(method, data), error }))).toBeNull();
    });

    test.each([undefined, "wrong", method === "getNTPInfo" ? "getDateTimeInfo" : "getNTPInfo"])("rejects wrong method %j", (wrongMethod) => {
      expect(parse(JSON.stringify({ ...reply(method, data), method: wrongMethod }))).toBeNull();
    });

    test.each([undefined, null, [], "data", {}, 1].map(value => [value]))("rejects missing or malformed data %j", (value) => {
      expect(parse(JSON.stringify(reply(method, value)))).toBeNull();
    });
  });
}

describe("clockOffset", () => {
  test.each([
    [1_000_000, 900_000, 910_000, { offset_s: 95, uncertainty_s: 6 }],
    [5_000, 10_000, 10_000, { offset_s: -5, uncertainty_s: 1 }],
    [1_000_000, 900_000, 900_001, { offset_s: 100, uncertainty_s: 1.001 }],
    [Date.parse("2026-10-15T22:46:33Z"), 1792103812307, 1792103812669, { offset_s: 580.512, uncertainty_s: 1.181 }],
    [10_000, 10_000, 10_000, { offset_s: 0, uncertainty_s: 1 }],
  ] as const)("measures camera %s against host interval %s to %s", (camera, before, after, expected) => {
    expect(clockOffset(camera, before, after)).toEqual(expected);
  });

  test("rejects a backwards host interval", () => {
    expect(clockOffset(0, 10, 5)).toBeNull();
  });

  test.each([NaN, Infinity, -Infinity])("rejects non-finite input %s in any position", (value) => {
    expect(clockOffset(value, 0, 1)).toBeNull();
    expect(clockOffset(0, value, 1)).toBeNull();
    expect(clockOffset(0, 0, value)).toBeNull();
  });
});
