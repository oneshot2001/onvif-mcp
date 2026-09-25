import { describe, expect, test } from "bun:test";
import { emptyChainConflict, lastReceiptFrom } from "./receipt-chain";

describe("empty receipt chain conflict", () => {
  test("allows a fresh install with no handoffs", () => {
    expect(emptyChainConflict({ seq: 0, hash: "genesis" }, [])).toBeNull();
  });

  test("reports two handoffs referencing an empty chain", () => {
    expect(emptyChainConflict({ seq: 0, hash: "genesis" }, ["hash-1", "hash-2"]))
      .toBe("receipt chain is empty but 2 handoff(s) reference earlier receipts — chain truncated?");
  });

  test("allows a non-empty chain with handoffs", () => {
    expect(emptyChainConflict({ seq: 2, hash: "hash-2" }, ["hash-1", "hash-2"])).toBeNull();
  });
});

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

  test.each([
    ['{"seq":2,"hash":', "truncated JSON"],
    ["{}", "missing sequence and hash"],
    ['{"seq":0,"hash":"x"}', "zero sequence"],
    ['{"seq":2,"hash":""}', "empty hash"],
  ])("rejects corrupt last line %s (%s)", (line) => {
    expect(() => lastReceiptFrom('{"seq":1,"hash":"hash-1"}\n' + line + "\n \t\n"))
      .toThrow(/^receipt chain corrupt:/);
  });
});
