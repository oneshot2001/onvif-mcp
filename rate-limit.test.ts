import { describe, expect, test } from "bun:test";
import { makeLimiter } from "./rate-limit";

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
