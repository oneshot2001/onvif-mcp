import { describe, expect, test } from "bun:test";
import { lastReceiptFrom } from "./receipt-chain";

describe("last receipt parsing", () => {
  test("returns genesis for empty text", () => {
    expect(lastReceiptFrom("")).toEqual({ seq: 0, hash: "genesis" });
  });

  test("returns genesis for whitespace-only text", () => {
    expect(lastReceiptFrom(" \t\r\n\n ")).toEqual({ seq: 0, hash: "genesis" });
  });

  test("returns the sequence and hash from one line", () => {
    const line = JSON.stringify({ seq: 1, hash: "hash-1", prev: "genesis", sig: "signature" });
    expect(lastReceiptFrom(line)).toEqual({ seq: 1, hash: "hash-1" });
    expect(lastReceiptFrom(line + "\n")).toEqual({ seq: 1, hash: "hash-1" });
  });

  test("returns the last receipt from many lines", () => {
    const lines = [1, 2, 3].map((seq) => JSON.stringify({ seq, hash: `hash-${seq}` }));
    expect(lastReceiptFrom(lines.join("\n"))).toEqual({ seq: 3, hash: "hash-3" });
    expect(lastReceiptFrom(lines.join("\r\n") + "\r\n \t")).toEqual({ seq: 3, hash: "hash-3" });
  });
});
