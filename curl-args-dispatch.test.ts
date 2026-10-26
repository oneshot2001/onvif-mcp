import { expect, test } from "bun:test";
import { curlRequest } from "./curl-args";

const cam = { base: "https://camera.example", user: "viewer" };
const commandDigest = "0123456789abcdef".repeat(4);
const invocationId = "0123456789abcdef".repeat(2);

for (const [name, opts] of [
  ["GET", {}], ["JSON-body", { jsonBody: { method: "getConfiguration" } }],
  ["SOAP", { soapBody: "<Envelope/>" }], ["outFile", { outFile: "/tmp/snapshot.jpg" }],
] as const) {
  test(`W2a primitives: ${name} carries each dispatch header exactly once only when set`, () => {
    for (const id of [undefined, invocationId]) {
      const { args, stdin } = curlRequest(cam, "test-password", "/request", { ...opts, invocationId: id, commandDigest });
      for (const [name, value] of [["X-AAR-Action-Bearing", "1"], ["X-AAR-Command-Digest", commandDigest]]) {
        const header = `${name}: ${value}`;
        expect(args.filter(arg => arg.startsWith(`${name}:`))).toEqual([header]);
        expect(args[args.indexOf(header) - 1]).toBe("-H");
        expect(args.indexOf(header)).toBeLessThan(args.indexOf(`${cam.base}/request`));
        const unset = curlRequest(cam, "test-password", "/request", { ...opts, invocationId: id });
        expect(unset.args.some(arg => arg.startsWith(`${name}:`))).toBe(false);
      }
      expect(args.filter(arg => arg.startsWith("X-AAR-Invocation-ID:"))).toEqual(id ? [`X-AAR-Invocation-ID: ${id}`] : []);
      expect(args.join(" ")).not.toContain("test-password");
      expect(stdin).toBe('user = "viewer:test-password"\n');
    }
  });
}

test.each([
  commandDigest.toUpperCase(), commandDigest.slice(1), commandDigest + "0", "g".repeat(64), "",
  commandDigest + "\r", commandDigest + "\n", commandDigest + "\r\nX-Injected: yes",
  null, 123, false, {}, [commandDigest],
].map(commandDigest => ({ commandDigest })))("W2a primitives: rejects invalid command digest %j", ({ commandDigest }) => {
  expect(() => curlRequest(cam, "test-password", "/request", { commandDigest: commandDigest as string }))
    .toThrow("invalid command digest");
});
