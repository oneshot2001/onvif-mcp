import { describe, expect, test } from "bun:test";
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
