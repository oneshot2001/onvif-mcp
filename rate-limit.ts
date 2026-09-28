// The injected clock returns milliseconds, like Date.now.
export function makeLimiter(now: () => number) {
  const calls = new Map<string, number[]>();
  return {
    check(key: string, perMinute: number): string | null {
      const time = now();
      const recent = (calls.get(key) ?? []).filter((at) => at > time - 60_000);
      calls.set(key, recent);
      if (recent.length >= perMinute) return `rate limit: ${perMinute}/min for ${key}`;
      recent.push(time);
      return null;
    },
  };
}
