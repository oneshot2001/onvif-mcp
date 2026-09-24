import { describe, expect, test } from "bun:test";
import { parseEventMessage } from "./event-parse";

describe("event message parsing", () => {
  const notification = { topic: "CameraApplicationPlatform/ObjectAnalytics/Device1Scenario1", timestamp: 1_700_000_000_000, message: { data: { active: "1" } } };

  test("returns an events:notify notification with a string topic", () => {
    expect(parseEventMessage(JSON.stringify({ method: "events:notify", params: { notification } }))).toEqual({ event: notification });
  });

  test("decodes binary messages", () => {
    const data = new TextEncoder().encode(JSON.stringify({ method: "events:notify", params: { notification } }));
    expect(parseEventMessage(data.buffer)).toEqual({ event: notification });
  });

  test("returns the event stream error warning", () => {
    expect(parseEventMessage(JSON.stringify({ error: { message: "subscription rejected" } }))).toEqual({ warning: "event stream error: subscription rejected" });
    expect(parseEventMessage(JSON.stringify({ error: {} }))).toEqual({ warning: "event stream error: unknown" });
  });

  test("returns both an event and a warning when both are present", () => {
    expect(parseEventMessage(JSON.stringify({ method: "events:notify", params: { notification }, error: { message: "partial failure" } }))).toEqual({ event: notification, warning: "event stream error: partial failure" });
  });

  test("returns the invalid-JSON warning", () => {
    expect(parseEventMessage("{invalid")).toEqual({ warning: "event stream returned invalid JSON" });
  });

  test("ignores non-notify messages", () => {
    expect(parseEventMessage(JSON.stringify({ method: "events:configure", params: { notification } }))).toEqual({});
  });

  test("ignores notifications without a string topic", () => {
    for (const notification of [null, {}, { topic: 42 }, "topic"]) {
      expect(parseEventMessage(JSON.stringify({ method: "events:notify", params: { notification } }))).toEqual({});
    }
  });
});
