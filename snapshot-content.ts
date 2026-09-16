import type { ImageContent, TextContent } from "@modelcontextprotocol/sdk/types.js";

export function snapshotContent(jpeg: Buffer, file: string, hash: string, aar: string): (ImageContent | TextContent)[] {
  const jpegValid = jpeg.length > 2 && jpeg[0] === 0xff && jpeg[1] === 0xd8;
  const text: TextContent = { type: "text", text: `${file} sha256:${hash.slice(0, 16)}…${jpegValid ? "" : " invalid JPEG"}${aar}` };
  return jpegValid
    ? [{ type: "image", data: jpeg.toString("base64"), mimeType: "image/jpeg" }, text]
    : [text];
}
