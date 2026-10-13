import { afterEach, expect, spyOn, test } from "bun:test";
import { sendPreset, sendSnapshot } from "./actions";
import { REAL_CLOCK_BOUND_SECONDS } from "aar-kat-harness/demo/ep/wire-builder";

let now = 1_800_000_000_000;
const clock = spyOn(Date, "now").mockImplementation(() => now);
afterEach(() => { now = 1_800_000_000_000; });
// Restore once this file's tests have finished (other files also fake clocks).
import { afterAll } from "bun:test";
afterAll(() => clock.mockRestore());
const sleep = async (ms: number) => { now += ms; };

test("recall success with failed readback preserves dispatch and unknown outcome", async () => {
  const result = await sendPreset(now / 1000, async () => ({ ok: true, body: "OK" }), async () => ({ ok: false, body: "" }), sleep);
  expect(result.dispatch).toMatchObject({ status: 200, outcomeLevel: "unknown", outcomeState: "unknown" });
});
test("recall transport failure becomes status zero and unknown with no readback", async () => {
  let reads = 0;
  const result = await sendPreset(now / 1000, async () => ({ ok: false, body: "" }), async () => { reads++; return { ok: true, body: "position" }; }, sleep);
  expect(result.dispatch).toMatchObject({ status: 0, outcomeLevel: "unknown", outcomeState: "unknown" });
  expect(reads).toBe(0);
});
test("snapshot transport failure becomes status zero and unknown", async () => {
  const result = await sendSnapshot(async () => undefined);
  expect(result.dispatch).toMatchObject({ status: 0, outcomeLevel: "unknown", outcomeState: "unknown" });
});
test("snapshot checks the actual captured bytes", async () => {
  const jpeg = Buffer.from([255, 216, 255, 217]);
  const result = await sendSnapshot(async () => jpeg);
  expect(result.dispatch).toMatchObject({ status: 200, outcomeLevel: "device_acknowledged", outcomeState: "consistent", observation: jpeg, responseBody: jpeg });
});
test("slow settle readbacks stop before another timeout plus sleep exceeds bound", async () => {
  const startedAt = now / 1000;
  let reads = 0;
  const result = await sendPreset(startedAt, async () => { now += 10_000; return { ok: true, body: "OK" }; }, async () => {
    reads++; now += 10_000; return { ok: true, body: `pan=${reads}` };
  }, sleep);
  expect(reads).toBe(4);
  expect(now / 1000 - startedAt).toBeLessThan(REAL_CLOCK_BOUND_SECONDS);
  expect(now / 1000 - startedAt + 11).toBeGreaterThanOrEqual(REAL_CLOCK_BOUND_SECONDS);
  expect(result.dispatch.outcomeLevel).toBe("device_acknowledged");
});
test("settled position requires consecutive successful equal reads", async () => {
  let reads = 0;
  const result = await sendPreset(now / 1000, async () => ({ ok: true, body: "OK" }), async () => { reads++; return { ok: true, body: "pan=1\n" }; }, sleep);
  expect(reads).toBe(2);
  expect(result.dispatch.outcomeLevel).toBe("device_acknowledged");
  expect(result.dispatch.outcomeState).toBe("unknown");
});
test("unexpected send exception is not converted to a false refusal", async () => {
  await expect(sendSnapshot(async () => { throw Error("ambiguous"); })).rejects.toThrow("ambiguous");
});
