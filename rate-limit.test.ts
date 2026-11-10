import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { makeLimiter } from "./rate-limit";

const malformedBudgets: [string, unknown][] = [
  ["unit string", "30deg"], ["numeric string", "30"], ["boolean", true],
  ["array", [30]], ["null", null], ["NaN", NaN], ["Infinity", Infinity],
  ["JSON overflow", JSON.parse("1e400")], ["Infinity string", "Infinity"],
  ["negative Infinity", -Infinity], ["missing", undefined],
];

for (const [label, value] of malformedBudgets) {
  test(`policy limit fail-closed: limiter ${label} denies first call without consuming budget`, () => {
    const limiter = makeLimiter(() => 0);
    expect(limiter.check("actuation", value as number)).toStartWith("rate limit:");
    expect(limiter.check("actuation", 1)).toBeNull();
    expect(limiter.check("actuation", 1)).toBe("rate limit: 1/min for actuation");
  });
}

test("policy limit fail-closed: finite budget 2 allows twice then denies", () => {
  const limiter = makeLimiter(() => 0);
  expect(limiter.check("actuation", 2)).toBeNull();
  expect(limiter.check("actuation", 2)).toBeNull();
  expect(limiter.check("actuation", 2)).toBe("rate limit: 2/min for actuation");
});

// Execute only the actual rate gate, without importing server startup or credentials.
function rateGate(rate?: unknown) {
  return agentRateGate(rate === undefined ? {} : { rate });
}

function agentRateGate(agent: Record<string, unknown>) {
  const source = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
  const startMarker = "function rateDenied(";
  const endMarker = "// --- credentials:";
  const start = source.indexOf(startMarker), end = source.indexOf(endMarker);
  if (start < 0 || end <= start || source.lastIndexOf(startMarker) !== start
    || source.lastIndexOf(endMarker) !== end) {
    throw new Error("rateDenied slice boundaries must be unique and ordered");
  }
  const code = new Bun.Transpiler({ loader: "ts" }).transformSync(source.slice(start, end));
  return new Function("policy", "AGENT", "limiter", code + "\nreturn rateDenied;")(
    { tester: agent }, "tester", makeLimiter(() => 0),
  ) as (key: "actuation" | "snapshot") => string | null;
}

for (const name of ["Rate", "rates", "RATES"]) {
  for (const key of ["actuation", "snapshot"] as const) {
    test(`policy rate container typo: ${name} denies first ${key} call`, () => {
      expect(agentRateGate({ [name]: { actuationPerMin: 2 } })(key)).toStartWith("rate limit:");
    });
  }
}

test("policy rate container typo: typo beside exact rate denies both budgets", () => {
  const rateDenied = agentRateGate({ rate: { actuationPerMin: 2, snapshotPerMin: 2 }, Rate: {} });
  expect(rateDenied("actuation")).toStartWith("rate limit:");
  expect(rateDenied("snapshot")).toStartWith("rate limit:");
});

test("policy rate container typo: omitted rate allows five calls per budget", () => {
  const rateDenied = agentRateGate({ tools: ["get_snapshot"], cameras: ["stand-in"] });
  for (const key of ["actuation", "snapshot"] as const) {
    for (let i = 0; i < 5; i++) expect(rateDenied(key)).toBeNull();
  }
});

test("policy rate container typo: exact rate allows twice then denies each budget", () => {
  const rateDenied = agentRateGate({ rate: { actuationPerMin: 2, snapshotPerMin: 2 } });
  for (const key of ["actuation", "snapshot"] as const) {
    expect(rateDenied(key)).toBeNull();
    expect(rateDenied(key)).toBeNull();
    expect(rateDenied(key)).toBe(`rate limit: 2/min for ${key}`);
  }
});

test("policy limit fail-closed: actual rateDenied allows five calls with omitted budget", () => {
  const rateDenied = rateGate({});
  for (let i = 0; i < 5; i++) expect(rateDenied("actuation")).toBeNull();
});

test("policy limit fail-closed: actual rateDenied denies first call with budget two string", () => {
  expect(rateGate({ actuationPerMin: "two" })("actuation")).toBe("rate limit: two/min for actuation");
});

for (const [label, value] of [
  ["number", 6], ["string", "six"], ["array", [6]], ["null", null],
  ["boolean", true], ["non-plain object", new Date(0)],
] as [string, unknown][]) {
  test(`policy rate container: ${label} denies first call`, () => {
    const rateDenied = rateGate(value);
    expect(rateDenied("actuation")).toStartWith("rate limit:");
    expect(rateDenied("snapshot")).toStartWith("rate limit:");
  });
}

test("policy rate container: empty object allows five calls", () => {
  const rateDenied = rateGate({});
  for (let i = 0; i < 5; i++) expect(rateDenied("actuation")).toBeNull();
});

test("policy rate container: omitted rate allows five calls", () => {
  const rateDenied = rateGate();
  for (let i = 0; i < 5; i++) expect(rateDenied("actuation")).toBeNull();
});

test("policy rate container: omitted budget allows five calls", () => {
  const rateDenied = rateGate({ snapshotPerMin: 30 });
  for (let i = 0; i < 5; i++) expect(rateDenied("actuation")).toBeNull();
});

test("policy rate container: budget 2 allows twice then denies", () => {
  const rateDenied = rateGate({ actuationPerMin: 2 });
  expect(rateDenied("actuation")).toBeNull();
  expect(rateDenied("actuation")).toBeNull();
  expect(rateDenied("actuation")).toBe("rate limit: 2/min for actuation");
});

for (const [label, rate] of [
  ["actuationPerMinute", { actuationPerMinute: 2 }],
  ["ActuationPerMin", { ActuationPerMin: 2 }],
  ["extra beside known budget", { actuationPerMin: 2, extra: 1 }],
] as const) {
  for (const key of ["actuation", "snapshot"] as const) {
    test(`policy rate unknown key: ${label} denies first ${key} call`, () => {
      expect(rateGate(rate)(key)).toStartWith("rate limit:");
    });
  }
}

for (const [label, rate] of [
  ["omitted actuation budget", { snapshotPerMin: 30 }],
  ["empty object", {}],
  ["omitted rate", undefined],
] as const) {
  test(`policy rate unknown key: ${label} allows five actuation calls`, () => {
    const rateDenied = rateGate(rate);
    for (let i = 0; i < 5; i++) expect(rateDenied("actuation")).toBeNull();
  });
}

test("policy rate unknown key: known budgets allow twice then deny actuation", () => {
  const rateDenied = rateGate({ actuationPerMin: 2, snapshotPerMin: 30 });
  expect(rateDenied("actuation")).toBeNull();
  expect(rateDenied("actuation")).toBeNull();
  expect(rateDenied("actuation")).toBe("rate limit: 2/min for actuation");
});

for (const [key, rate] of [
  ["actuation", { actuationPerMin: "two" }],
  ["snapshot", { snapshotPerMin: "two" }],
] as const) {
  test(`policy rate unknown key: known ${key} value still reaches limiter`, () => {
    expect(rateGate(rate)(key)).toBe(`rate limit: two/min for ${key}`);
  });
}

describe("sliding rate limits", () => {
  test("allows six calls, denies the seventh, and allows again at 60 seconds", () => {
    let time = 0;
    const limiter = makeLimiter(() => time);
    for (let i = 0; i < 6; i++) expect(limiter.check("actuation", 6)).toBeNull();
    expect(limiter.check("actuation", 6)).toBe("rate limit: 6/min for actuation");
    time = 59_999;
    expect(limiter.check("actuation", 6)).toBe("rate limit: 6/min for actuation");
    time = 60_000;
    for (let i = 0; i < 6; i++) expect(limiter.check("actuation", 6)).toBeNull();
    expect(limiter.check("actuation", 6)).toBe("rate limit: 6/min for actuation");
  });

  test("expires each call individually in a sliding window", () => {
    let time = 0;
    const limiter = makeLimiter(() => time);
    expect(limiter.check("actuation", 2)).toBeNull();
    time = 30_000;
    expect(limiter.check("actuation", 2)).toBeNull();
    time = 60_000;
    expect(limiter.check("actuation", 2)).toBeNull();
    expect(limiter.check("actuation", 2)).toBe("rate limit: 2/min for actuation");
    time = 90_000;
    expect(limiter.check("actuation", 2)).toBeNull();
  });

  test("keys have independent budgets", () => {
    const limiter = makeLimiter(() => 0);
    for (let i = 0; i < 6; i++) expect(limiter.check("actuation", 6)).toBeNull();
    expect(limiter.check("actuation", 6)).toBe("rate limit: 6/min for actuation");
    for (let i = 0; i < 30; i++) expect(limiter.check("snapshot", 30)).toBeNull();
    expect(limiter.check("snapshot", 30)).toBe("rate limit: 30/min for snapshot");
  });

  test("a zero budget denies every call", () => {
    const limiter = makeLimiter(() => 0);
    expect(limiter.check("actuation", 0)).toBe("rate limit: 0/min for actuation");
  });
});
