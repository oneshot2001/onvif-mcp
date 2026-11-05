import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import ts from "typescript";
import { TOOL_HINTS } from "./tool-hints";

// Read source only: importing index.ts would start the server.
const sources = ["index.ts", "commission.ts"].map((file) => ({
  file,
  text: readFileSync(join(import.meta.dir, file), "utf8"),
}));
const policy = JSON.parse(readFileSync(join(import.meta.dir, "policy.json"), "utf8"));
const registrations = sources.map(({ file, text }) => ({
  file,
  names: [...text.matchAll(/\bserver\s*\.\s*tool\s*\(\s*["']([^"']+)["']/g)].map((match) => match[1]!),
}));

function toolCalls() {
  const calls: ts.CallExpression[] = [];
  for (const { file, text } of sources) {
    const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    const visit = (node: ts.Node) => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)
        && ts.isIdentifier(node.expression.expression) && node.expression.expression.text === "server"
        && node.expression.name.text === "tool") calls.push(node);
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  return calls;
}

test("tool annotations: exactly 12 unique registrations match the hint keys", () => {
  const calls = toolCalls();
  expect(calls).toHaveLength(12);
  const names = calls.map((call) => {
    const name = call.arguments[0]!;
    expect(ts.isStringLiteral(name)).toBe(true);
    return (name as ts.StringLiteral).text;
  });
  expect(new Set(names).size).toBe(12);
  expect(names.sort()).toEqual(Object.keys(TOOL_HINTS).sort());
});

test("tool annotations: every hint equals the explicit value table", () => {
  expect(TOOL_HINTS).toEqual({
    list_cameras: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    clock_check: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    get_snapshot: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    ptz_preset: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    ptz_move: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    config_baseline: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    config_drift: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    config_remediate: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    get_receipts: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    commission_plan: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    commission_apply: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    commission_verify: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  });
});

test("tool annotations: each registration passes its hint fourth and a function fifth", () => {
  const calls = toolCalls();
  expect(calls).toHaveLength(12);
  for (const call of calls) {
    expect(call.arguments.length).toBe(5);
    const [name, , , hint, callback] = call.arguments;
    expect(ts.isStringLiteral(name!)).toBe(true);
    expect(ts.isPropertyAccessExpression(hint!)).toBe(true);
    const access = hint as ts.PropertyAccessExpression;
    expect(ts.isIdentifier(access.expression)).toBe(true);
    expect((access.expression as ts.Identifier).text).toBe("TOOL_HINTS");
    expect(access.name.text).toBe((name as ts.StringLiteral).text);
    expect(ts.isArrowFunction(callback!) || ts.isFunctionExpression(callback!)).toBe(true);
  }
});

describe("tool registry drift", () => {
  test("clock_check is registered and granted only to claude-main", () => {
    expect(registrations[0]!.names).toContain("clock_check");
    expect(policy.agents["claude-main"].tools).toContain("clock_check");
    expect(policy.agents["untrusted-demo"].tools).not.toContain("clock_check");
  });

  test("finds tool registrations in both source files", () => {
    expect(registrations.filter(({ names }) => names.length === 0).map(({ file }) => file)).toEqual([]);
  });

  test("every registered tool has a NODE_KIND entry", () => {
    const nodeKind = sources[0]!.text.match(/\bconst\s+NODE_KIND\b[^=]*=\s*\{([\s\S]*?)\}\s*;/);
    expect(nodeKind).not.toBeNull();
    const names = new Set([...nodeKind![1]!.matchAll(/(?:^|,)\s*["']?([\w]+)["']?\s*:/g)].map((match) => match[1]!));
    const missing = registrations.flatMap(({ file, names: tools }) =>
      tools.filter((tool) => !names.has(tool)).map((tool) => `${file}: ${tool}`));
    expect(missing).toEqual([]);
  });

  test("every registered tool is allowed for claude-main", () => {
    const tools = policy.agents["claude-main"].tools;
    expect(Array.isArray(tools)).toBe(true);
    const missing = registrations.flatMap(({ file, names }) =>
      names.filter((tool) => !tools.includes(tool)).map((tool) => `${file}: ${tool}`));
    expect(missing).toEqual([]);
  });
});
