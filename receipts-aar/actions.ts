import { REAL_CLOCK_BOUND_SECONDS } from "aar-kat-harness/demo/ep/wire-builder";
import { CURL_TIMEOUT_SECONDS } from "../curl-args";
import { jsonBytes, type WireSendResult } from "./producer";

type Response = { ok: boolean; body: string };
const seconds = () => Math.floor(Date.now() / 1000);

export async function sendSnapshot(capture: () => Promise<Uint8Array | undefined>): Promise<WireSendResult & { jpeg?: Uint8Array }> {
  const dispatchedAt = seconds();
  const jpeg = await capture();
  const outcomeObservedAt = seconds();
  const valid = jpeg !== undefined && jpeg.length > 2 && jpeg[0] === 0xff && jpeg[1] === 0xd8;
  return { jpeg, dispatchedAt, outcomeObservedAt, dispatch: {
    status: jpeg === undefined ? 0 : 200, responseBody: jpeg ?? new Uint8Array(),
    outcomeLevel: valid ? "device_acknowledged" : "unknown", outcomeState: valid ? "consistent" : "unknown",
    observation: jpeg ?? new Uint8Array(),
  } };
}

export async function sendPreset(t0: number, recall: () => Promise<Response>, readback: () => Promise<Response>,
  sleep: (ms: number) => Promise<unknown> = Bun.sleep): Promise<WireSendResult & { ok: boolean; pos: Response }> {
  const dispatchedAt = seconds();
  const r = await recall();
  let outcomeObservedAt = seconds();
  const ok = r.ok && !/^Error/m.test(r.body);
  let pos: Response = { ok: false, body: "" };
  if (ok) {
    let prev = "";
    for (let i = 0; i < 8; i++) {
      // Strict inequality leaves time for completion journaling and T1; the
      // builder still rejects overruns (scheduler/fsync delays are unbounded).
      if (Date.now() / 1000 + CURL_TIMEOUT_SECONDS + 1 >= t0 + REAL_CLOCK_BOUND_SECONDS) break;
      pos = await readback();
      outcomeObservedAt = seconds();
      if (pos.ok && prev && pos.body.trim() === prev) break;
      prev = pos.ok ? pos.body.trim() : "";
      await sleep(1000);
    }
  }
  return { ok, pos, dispatchedAt, outcomeObservedAt, dispatch: {
    status: ok ? 200 : 0, responseBody: jsonBytes({ body: r.body }),
    // Position is not an independently known preset target: state stays unknown.
    outcomeLevel: ok && pos.ok ? "device_acknowledged" : "unknown", outcomeState: "unknown",
    observation: jsonBytes({ settled_position: pos.body.trim() }),
  } };
}
