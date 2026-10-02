import { describe, expect, test } from "bun:test";
import { curlRequest } from "./curl-args";

const cam = { base: "https://camera.example", user: "root" };
const password = "camera-secret-password";
const jsonBody = { method: "getConfiguration" };
const soapBody = '<?xml version="1.0"?><s:Envelope><s:Body/></s:Envelope>';

describe("curl request", () => {
  for (const [name, opts] of [
    ["GET", {}],
    ["JSON POST", { jsonBody, maxTime: 15 }],
    ["SOAP", { soapBody }],
  ] as const) {
    test(`${name} keeps credentials on stdin and requires digest authentication`, () => {
      const { args, stdin } = curlRequest(cam, password, "/request", opts);
      expect(args.join(" ")).not.toContain(password);
      expect(args).toContain("--digest");
      expect(args).not.toContain("--anyauth");
      expect(args).not.toContain("-u");
      expect(args.slice(args.indexOf("--config"), args.indexOf("--config") + 2)).toEqual(["--config", "-"]);
      expect(stdin).toBe(`user = "root:${password}"\n`);
      expect(args[0]).toBe("curl");
      expect(args).toContain("-sk");
      expect(args).toContain("https://camera.example/request");
      expect(args[args.indexOf("--max-time") + 1]).toBe(name === "JSON POST" ? "15" : "10");
    });
  }

  test("pins the public key while allowing self-signed certificates", () => {
    const pin = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    for (const opts of [{}, { jsonBody }, { soapBody }, { outFile: "/tmp/snapshot.jpg" }]) {
      const { args } = curlRequest({ ...cam, pin }, password, "/request", opts);
      expect(args.slice(args.indexOf("--pinnedpubkey"), args.indexOf("--pinnedpubkey") + 2)).toEqual(["--pinnedpubkey", pin]);
      expect(args).toContain("-sk");
    }
  });

  test("leaves requests without a pin unchanged", () => {
    const { args } = curlRequest(cam, password, "/request");
    expect(args).not.toContain("--pinnedpubkey");
    expect(args).toEqual(["curl", "-sk", "--digest", "--config", "-", "--max-time", "10", "https://camera.example/request"]);
  });

  test.each(["", "/tmp/key.pem", "sha512//AAAA", "SHA256//AAAA"])("rejects an invalid pin prefix: %s", (pin) => {
    expect(() => curlRequest({ ...cam, pin }, password, "/request")).toThrow("camera pin must start with sha256//");
  });

  test("escapes quotes and backslashes in config credentials", () => {
    const secret = 'pass"word\\end';
    const { args, stdin } = curlRequest({ ...cam, user: 'us"er\\name' }, secret, "/request");
    expect(stdin).toBe('user = "us\\"er\\\\name:pass\\"word\\\\end"\n');
    expect(args.join(" ")).not.toContain(secret);
  });

  test("keeps snapshot output files", () => {
    const { args } = curlRequest(cam, password, "/axis-cgi/jpg/image.cgi", { outFile: "/tmp/snapshot.jpg" });
    expect(args.slice(-2)).toEqual(["-o", "/tmp/snapshot.jpg"]);
    expect(args).not.toContain("--data-raw");
  });

  test("sends JSON on argv with its content type", () => {
    const { args } = curlRequest(cam, password, "/request", { jsonBody });
    expect(args.slice(args.indexOf("-H"), args.indexOf("-H") + 4)).toEqual([
      "-H", "content-type: application/json", "--data-raw", JSON.stringify(jsonBody),
    ]);
    expect(args).not.toContain("@-");
  });

  test("sends SOAP on argv with its content type", () => {
    const { args } = curlRequest(cam, password, "/onvif/services", { soapBody });
    expect(args.slice(args.indexOf("-H"), args.indexOf("-H") + 4)).toEqual([
      "-H", "Content-Type: application/soap+xml", "--data-raw", soapBody,
    ]);
    expect(args).not.toContain("@-");
  });
});
