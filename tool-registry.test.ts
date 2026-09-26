import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

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

describe("tool registry drift", () => {
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
