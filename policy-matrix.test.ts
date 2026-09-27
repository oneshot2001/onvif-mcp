import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { allowed, type Policy } from "./policy-check";

const policy: Policy = JSON.parse(readFileSync(join(import.meta.dir, "policy.json"), "utf8")).agents;
const cameras = Object.keys(JSON.parse(readFileSync(join(import.meta.dir, "cameras.json"), "utf8")));
// Read source only: importing index.ts would start the server.
const registrations = ["index.ts", "commission.ts"].map((file) => ({
  file,
  names: [...readFileSync(join(import.meta.dir, file), "utf8")
    .matchAll(/\bserver\s*\.\s*tool\s*\(\s*["']([^"']+)["']/g)].map((match) => match[1]!),
}));
const tools = [...new Set(registrations.flatMap(({ names }) => names))];
const unknownAgent = "policy-matrix-unknown-agent";
const unknownCamera = "policy-matrix-unknown-camera";
const cameraIds = [...cameras, unknownCamera];

describe("real policy matrix", () => {
  test("matrix includes real registrations and cameras plus unknown identities", () => {
    expect(registrations.filter(({ names }) => names.length === 0).map(({ file }) => file)).toEqual([]);
    expect(Object.keys(policy).length).toBeGreaterThan(0);
    expect(cameras).toContain("p3285");
    expect(tools).toContain("get_snapshot");
    expect(Object.hasOwn(policy, "untrusted-demo")).toBe(true);
    expect(Object.hasOwn(policy, unknownAgent)).toBe(false);
    expect(cameras).not.toContain(unknownCamera);
    for (const grant of Object.values(policy)) expect(grant.cameras).not.toContain(unknownCamera);
  });

  for (const agent of [...Object.keys(policy), unknownAgent]) {
    for (const tool of tools) {
      for (const camera of cameraIds) {
        test(`${agent} × ${tool} × ${camera} matches the allowlists`, () => {
          const grant = policy[agent];
          const result = allowed(policy, agent, tool, camera);
          if (grant?.tools.includes(tool) && grant.cameras.includes(camera)) {
            expect(result).toBeNull();
          } else {
            expect(result).toBeString();
            expect(result).not.toBe("");
          }
        });
      }
    }
  }

  for (const tool of tools) {
    for (const camera of cameraIds) {
      test(`untrusted-demo permits only get_snapshot on p3285: ${tool} × ${camera}`, () => {
        const result = allowed(policy, "untrusted-demo", tool, camera);
        if (tool === "get_snapshot" && camera === "p3285") {
          expect(result).toBeNull();
        } else {
          expect(result).toBeString();
          expect(result).not.toBe("");
        }
      });
    }
  }
});
