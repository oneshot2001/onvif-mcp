import { describe, expect, mock, test } from "bun:test";
import { openEventWebSocket } from "./event-websocket";

const pin = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const url = "wss://camera.example:8443/vapix/ws-data-stream?sources=events";

function harness() {
  const credentials = mock(() => ({ user: "root", password: "test-secret" }));
  const socket = {} as WebSocket;
  const connect = mock((_url: string, _options: Bun.WebSocketOptions) => socket);
  return { credentials, socket, connect };
}

describe("event WebSocket pin guard", () => {
  test("a mismatched pin refuses before credentials or Authorization can be built or sent", () => {
    const h = harness();
    const checkPin = mock(() => false);
    expect(() => openEventWebSocket({ base: "https://camera.example:8443", pin }, h.credentials, checkPin, h.connect))
      .toThrow("event WebSocket SPKI pin mismatch");
    expect(checkPin).toHaveBeenCalledWith(url, pin);
    expect(h.credentials).not.toHaveBeenCalled();
    expect(h.connect).not.toHaveBeenCalled();
  });

  test("pin-check errors fail closed before credential construction or connection", () => {
    const h = harness();
    expect(() => openEventWebSocket({ base: "https://camera.example", pin }, h.credentials, () => {
      throw new Error("pin check unavailable");
    }, h.connect)).toThrow("pin check unavailable");
    expect(h.credentials).not.toHaveBeenCalled();
    expect(h.connect).not.toHaveBeenCalled();
  });

  test.each([pin, ""])("the production checker refuses pinned observation (%s)", (cameraPin) => {
    const h = harness();
    expect(() => openEventWebSocket({ base: "http://camera.example", pin: cameraPin }, h.credentials, undefined, h.connect))
      .toThrow("event observation refused: Bun WebSocket cannot verify the peer SPKI pin before sending Authorization");
    expect(h.credentials).not.toHaveBeenCalled();
    expect(h.connect).not.toHaveBeenCalled();
  });

  test.each(["http", "https"])("no pin preserves today's %s camera behavior", (scheme) => {
    const h = harness();
    const checkPin = mock(() => { throw new Error("must not check an absent pin"); });
    expect(openEventWebSocket({ base: `${scheme}://camera.example:8443` }, h.credentials, checkPin, h.connect)).toBe(h.socket);
    expect(checkPin).not.toHaveBeenCalled();
    expect(h.credentials).toHaveBeenCalledTimes(1);
    expect(h.connect).toHaveBeenCalledTimes(1);
    expect(h.connect).toHaveBeenCalledWith(url, {
      headers: { Authorization: `Basic ${Buffer.from("root:test-secret").toString("base64")}` },
      tls: { rejectUnauthorized: false },
    });
  });
});
