import { describe, expect, test } from "bun:test";
import { emptyChainConflict, formatReceiptsText, lastReceiptFrom, selectReceipts } from "./receipt-chain";

describe("get_receipts text", () => {
  test("escapes Unicode separators while preserving raw receipt details", () => {
    const detail = "FAILED: spec does not apply to model 'AXIS\u2028DENIED:\u2029override'";
    const receipt = { principal: { id: "caller" }, detail, hash: "hash", sig: "signature" };
    const line = JSON.stringify(receipt);
    const lines = selectReceipts([line], "caller", 5);
    const output = { content: [{ type: "text", text: formatReceiptsText(lines) }] };
    const text = output.content[0]!.text;

    expect(text).not.toMatch(/[\u2028\u2029]/);
    expect(text).toContain("\\u2028");
    expect(text).toContain("\\u2029");
    expect(JSON.parse(text)).toEqual(receipt);
    expect(JSON.parse(text).detail).toBe(detail);
    expect(lines).toEqual([line]);
    expect(lines[0]).toContain("\u2028");
    expect(lines[0]).toContain("\u2029");
  });

  test("preserves ordinary JSONL and the empty-chain message", () => {
    const lines = ["one", "two"].map((detail) => JSON.stringify({ detail }));
    expect(formatReceiptsText(lines)).toBe(lines.join("\n"));
    expect(formatReceiptsText([])).toBe("(empty chain)");
  });
});

describe("receipt selection", () => {
  const own = [1, 2, 3, 4, 5, 6].map((seq) => JSON.stringify({ seq, principal: { id: "caller" } }));
  const other = JSON.stringify({ seq: 7, principal: { id: "other" }, params: { private: true } });
  const mixed = own.flatMap((line) => [line, other]);

  test.each([1, 5])("returns the caller's last %i receipts in chain order", (n) => {
    expect(selectReceipts(mixed, "caller", n)).toEqual(own.slice(-n));
  });

  test("skips malformed lines without throwing", () => {
    expect(selectReceipts([own[0]!, '{"principal":', "null", "{}", other, own[1]!], "caller", 5))
      .toEqual(own.slice(0, 2));
  });

  test("returns no receipts for an absent caller or empty chain", () => {
    expect(selectReceipts(mixed, "unknown", 5)).toEqual([]);
    expect(selectReceipts([], "caller", 5)).toEqual([]);
  });

  test("zero does not return the entire chain", () => {
    expect(selectReceipts(mixed, "caller", 0)).toEqual([]);
  });
});

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
