import { describe, expect, test } from "bun:test";
import { ReadBuffer, serializeMessage } from "@modelcontextprotocol/sdk/shared/stdio.js";
import { CAMERA_REPLY_MAX_BYTES } from "./curl-args";
import { snapshotContent } from "./snapshot-content";

const file = "/receipts/snap-camera.jpg";
const hash = "0123456789abcdef".repeat(4);
const aar = "\naar-bundle: /receipts/aar-bundle";

describe("snapshot content", () => {
  test("returns a JPEG image followed by the saved path, hash prefix, and AAR", () => {
    const jpeg = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0xff, 0xd9]);
    expect(snapshotContent(jpeg, file, hash, aar)).toEqual([
      { type: "image", data: jpeg.toString("base64"), mimeType: "image/jpeg" },
      { type: "text", text: `${file} sha256:0123456789abcdef…${aar}` },
    ]);
  });

  test("returns only text for non-JPEG or truncated bytes", () => {
    for (const bytes of [Buffer.from("not a JPEG"), Buffer.alloc(0), Buffer.from([0xff, 0xd8]), Buffer.from([0xff, 0x00, 0xff])]) {
      expect(snapshotContent(bytes, file, hash, aar)).toEqual([
        { type: "text", text: `${file} sha256:0123456789abcdef… invalid JPEG${aar}` },
      ]);
    }
  });
});

test("snapshot reply size: a frame of CAMERA_REPLY_MAX_BYTES fits one MCP stdio message and a frame 1 MiB larger does not", () => {
  for (const size of [CAMERA_REPLY_MAX_BYTES, CAMERA_REPLY_MAX_BYTES + 1024 * 1024]) {
    const jpeg = Buffer.alloc(size);
    jpeg[0] = 0xff;
    jpeg[1] = 0xd8;
    const content = snapshotContent(jpeg, "/" + "p".repeat(1023), hash, "\n" + "a".repeat(1023));
    expect(content[0]!.type).toBe("image");
    const message = { jsonrpc: "2.0" as const, id: Number.MAX_SAFE_INTEGER, result: { content } };
    const serialized = Buffer.from(serializeMessage(message));
    const reader = new ReadBuffer();
    if (size === CAMERA_REPLY_MAX_BYTES) {
      reader.append(serialized);
      expect(reader.readMessage()).toEqual(message);
    } else {
      expect(() => reader.append(serialized)).toThrow("ReadBuffer exceeded maximum size");
    }
  }
});
