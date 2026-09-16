# Packet: get_snapshot returns MCP image content (2026-09-15)

## Why
`get_snapshot` returns only a file path + hash as text. The calling model never sees the frame.
Return the JPEG as an MCP `image` content block so Claude Code / Codex / ChatGPT can look at it.

## Change (index.ts only, plus a new offline test file)
1. In the `get_snapshot` tool handler, on success return:
   ```ts
   content: [
     { type: "image", data: jpeg.toString("base64"), mimeType: "image/jpeg" },
     { type: "text", text: `${file} sha256:${h.slice(0, 16)}…${aar}` },
   ]
   ```
   Keep the receipt, the on-disk file, the hash, and the AAR emission exactly as they are.
   If `jpegValid` is false, do NOT emit the image block — text only, same as today (say "invalid JPEG" in the text).
2. Update the tool description to "Capture a JPEG snapshot from a camera; returns the image plus saved file path and sha256".
3. Add `snapshot-content.test.ts` (offline, no network, Bun test): extract the content-shaping into a small pure function `snapshotContent(jpeg: Buffer, file: string, hash: string, aar: string)` exported from index.ts (or a new `snapshot-content.ts` that index.ts imports — prefer the separate file so the test does not start the MCP server). Tests: (a) valid JPEG bytes (`ff d8 ff e0 ...`) → first block is image with correct base64 + mimeType, second is text with hash prefix; (b) non-JPEG bytes → single text block, no image.
4. README: one line under Features noting snapshots return inline image content.

## Constraints
- Minimum code. No new dependencies. No changes to policy, receipts, PTZ, commission, or the pre-existing failing `commission.test.ts` (that is a separate BACKLOG item — leave it).
- No live camera calls in tests.
- Accept: `bun test snapshot-content.test.ts` exits 0; `bun run --bun tsc --noEmit` (or `bunx tsc --noEmit`) has no new errors in changed files.
- Commit on this branch with message `get_snapshot: return MCP image content block alongside path+hash`.
