import { describe, expect, test } from "bun:test";
import { curlRequest, validatePin } from "./curl-args";

const cam = { base: "https://camera.example", user: "root" };
const password = "camera-secret-password";
const jsonBody = { method: "getConfiguration" };
const soapBody = '<?xml version="1.0"?><s:Envelope><s:Body/></s:Envelope>';

describe("camera pin validation", () => {
  test("accepts a sha256 pin", () => {
    expect(() => validatePin("sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")).not.toThrow();
  });

  test("accepts an omitted pin", () => {
    expect(() => validatePin(undefined)).not.toThrow();
  });

  test.each(["", "/tmp/key.pem", "sha512//AAAA", "SHA256//AAAA", null, 123])("rejects an invalid pin: %s", (pin) => {
    expect(() => validatePin(pin)).toThrow("camera pin must start with sha256//");
  });

  test("rejects an empty hash after the prefix", () => {
    expect(() => validatePin("sha256//")).toThrow("camera pin must include a hash after sha256//");
  });
});

describe("curl request", () => {
  for (const [name, opts] of [
    ["GET", {}],
    ["JSON POST", { jsonBody, maxTime: 15 }],
    ["SOAP", { soapBody }],
  ] as const) {
    test(`${name} fails on HTTP errors`, () => {
      const { args } = curlRequest(cam, password, "/request", opts);
      expect(args).toContain("--fail");
    });

    for (const status of [401, 200]) {
      test(`${name} exits ${status === 200 ? "zero" : "non-zero"} for HTTP ${status}`, async () => {
        let requests = 0;
        const server = Bun.serve({
          hostname: "127.0.0.1",
          port: 0,
          fetch(request) {
            requests++;
            if (status === 200 && !request.headers.has("authorization")) {
              return new Response("Authenticate", {
                status: 401,
                headers: { "WWW-Authenticate": 'Digest realm="test", nonce="test-nonce", qop="auth"' },
              });
            }
            return new Response(status === 200 ? "OK" : "Unauthorized", {
              status,
              headers: status === 401 ? { "WWW-Authenticate": 'Basic realm="test"' } : {},
            });
          },
        });
        try {
          const { args, stdin } = curlRequest(
            { ...cam, base: `http://127.0.0.1:${server.port}` }, password, "/request", { ...opts, maxTime: 2 },
          );
          // Ignore user curl configuration and proxies so the request stays on loopback.
          const child = Bun.spawn([args[0]!, "-q", ...args.slice(1), "--noproxy", "*"], {
            stdin: Buffer.from(stdin), stdout: "ignore", stderr: "ignore",
          });
          const exitCode = await child.exited;
          expect(requests).toBeGreaterThan(0);
          if (status === 200) expect(exitCode).toBe(0);
          else expect(exitCode).not.toBe(0);
        } finally {
          await server.stop(true);
        }
      });
    }

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
    expect(args).toEqual(["curl", "-sk", "--digest", "--fail", "--config", "-", "--max-time", "10", "https://camera.example/request"]);
  });

  test("rejects a pin with an HTTP base", () => {
    const pin = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    expect(() => curlRequest({ ...cam, base: "http://camera.example", pin }, password, "/request"))
      .toThrow("camera pin requires an https:// URL");
  });

  test("keeps the pin with an HTTPS base", () => {
    const pin = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const { args } = curlRequest({ ...cam, pin }, password, "/request");
    expect(args.slice(-3)).toEqual(["--pinnedpubkey", pin, "https://camera.example/request"]);
  });

  test("leaves HTTP requests without a pin unchanged", () => {
    const { args, stdin } = curlRequest({ ...cam, base: "http://camera.example" }, password, "/request");
    expect(args).toEqual(["curl", "-sk", "--digest", "--fail", "--config", "-", "--max-time", "10", "http://camera.example/request"]);
    expect(stdin).toBe(`user = "root:${password}"\n`);
  });

  test.each(["", "/tmp/key.pem", "sha512//AAAA", "SHA256//AAAA"])("rejects an invalid pin prefix: %s", (pin) => {
    expect(() => curlRequest({ ...cam, pin }, password, "/request")).toThrow("camera pin must start with sha256//");
  });

  test("rejects an empty pin hash", () => {
    expect(() => curlRequest({ ...cam, pin: "sha256//" }, password, "/request"))
      .toThrow("camera pin must include a hash after sha256//");
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
