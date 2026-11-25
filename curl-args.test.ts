import { describe, expect, test } from "bun:test";
import { CAMERA_REPLY_MAX_BYTES, curlRequest, validatePin } from "./curl-args";

const cam = { base: "https://camera.example", user: "root" };
const password = "camera-secret-password";
const jsonBody = { method: "getConfiguration" };
const soapBody = '<?xml version="1.0"?><s:Envelope><s:Body/></s:Envelope>';

for (const [name, opts] of [
  ["GET", {}], ["JSON-body", { jsonBody }], ["SOAP", { soapBody }], ["outFile", { outFile: "/tmp/snapshot.jpg" }],
] as const) {
  test(`curl globoff: ${name} disables globbing before the literal URL`, () => {
    const path = "/snap[1-3].jpg";
    const { args } = curlRequest(cam, password, path, opts);
    expect(args).toContain("--globoff");
    expect(args).toContain(`${cam.base}${path}`);
    expect(args.indexOf("--globoff")).toBeLessThan(args.indexOf(`${cam.base}${path}`));
  });
}

describe("invocation header", () => {
  const invocationId = "0123456789abcdef0123456789abcdef";
  for (const [name, opts] of [
    ["GET", {}], ["JSON-body", { jsonBody }], ["SOAP", { soapBody }], ["outFile", { outFile: "/tmp/snapshot.jpg" }],
  ] as const) {
    test(`${name} carries exactly one invocation header before the URL, only when set`, () => {
      const { args } = curlRequest(cam, password, "/request", { ...opts, invocationId });
      const header = `X-AAR-Invocation-ID: ${invocationId}`;
      expect(args.filter(arg => arg.startsWith("X-AAR-Invocation-ID:"))).toEqual([header]);
      expect(args[args.indexOf(header) - 1]).toBe("-H");
      expect(args.indexOf(header)).toBeLessThan(args.indexOf(`${cam.base}/request`));
      const unset = curlRequest(cam, password, "/request", opts);
      expect(unset.args.some(arg => /x-aar-/i.test(arg))).toBe(false);
    });
  }
  test.each([
    invocationId.toUpperCase(), invocationId.slice(1), invocationId + "0",
    invocationId + "\r", invocationId + "\n", invocationId + "\r\nX-Injected: yes", "",
  ])("rejects malformed invocation ID %j", invocationId => {
    expect(() => curlRequest(cam, password, "/request", { invocationId })).toThrow("invalid invocation ID");
  });
});

let canListen = false;
try {
  const server = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => new Response() });
  server.stop(true);
  canListen = true;
} catch {
  canListen = false;
}

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
  test("ignores ~/.curlrc and proxy environment variables for every request shape", () => {
    for (const [camera, opts] of [
      [cam, {}],
      [cam, { jsonBody }],
      [cam, { soapBody }],
      [cam, { outFile: "/tmp/stand-in-snapshot.jpg" }],
      [{ ...cam, pin: "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }, {}],
      [{ ...cam, base: "http://camera.invalid" }, { unixSocket: "/tmp/stand-in-witness.sock" }],
    ] as const) {
      const { args } = curlRequest(camera, password, "/request", opts);
      expect(args.slice(0, 2)).toEqual(["curl", "-q"]);
      expect(args.filter(arg => arg === "-q")).toHaveLength(1);
      expect(args[args.indexOf("--noproxy") + 1]).toBe("*");
      expect(args.filter(arg => arg === "--noproxy")).toHaveLength(1);
    }
  });

  test("caps the reply size of every request shape at CAMERA_REPLY_MAX_BYTES", () => {
    expect(CAMERA_REPLY_MAX_BYTES).toBe(7 * 1024 * 1024);
    const invocationId = "0123456789abcdef0123456789abcdef";
    const assertCap = (args: string[]) => {
      expect(args.filter(arg => arg === "--max-filesize")).toHaveLength(1);
      expect(args[args.indexOf("--max-filesize") + 1]).toBe("7340032");
      expect(args.indexOf("--max-filesize")).toBeLessThan(args.findIndex(arg => arg.startsWith("http")));
    };
    for (const [camera, opts] of [
      [cam, {}],
      [cam, { jsonBody, maxTime: 15 }],
      [cam, { soapBody }],
      [cam, { outFile: "/tmp/stand-in-snapshot.jpg" }],
      [{ ...cam, pin: "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }, {}],
      [{ ...cam, base: "http://camera.invalid" }, { unixSocket: "/tmp/stand-in-witness.sock" }],
    ] as const) {
      assertCap(curlRequest(camera, password, "/request", opts).args);
      assertCap(curlRequest(camera, password, "/request", { ...opts, invocationId }).args);
    }
    assertCap(curlRequest(cam, password, "/request", {
      outFile: "/tmp/stand-in-snapshot.jpg", invocationId, commandDigest: "0123456789abcdef".repeat(4),
    }).args);
  });

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
      test.skipIf(!canListen)(`${name} exits ${status === 200 ? "zero" : "non-zero"} for HTTP ${status}`, async () => {
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
    expect(args).toEqual(["curl", "-q", "-sk", "--globoff", "--digest", "--fail", "--noproxy", "*", "--config", "-", "--max-time", "10", "--max-filesize", "7340032", "https://camera.example/request"]);
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
    expect(args).toEqual(["curl", "-q", "-sk", "--globoff", "--digest", "--fail", "--noproxy", "*", "--config", "-", "--max-time", "10", "--max-filesize", "7340032", "http://camera.example/request"]);
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


const credentialOptions = [
  ["GET", {}, []],
  ["JSON", { jsonBody }, ["-H", "content-type: application/json", "--data-raw", JSON.stringify(jsonBody)]],
  ["SOAP", { soapBody }, ["-H", "Content-Type: application/soap+xml", "--data-raw", soapBody]],
  ["outFile", { outFile: "/tmp/stand-in-snapshot.jpg" }, []],
  ["unix-socket", { unixSocket: "/tmp/stand-in-witness.sock" }, ["--unix-socket", "/tmp/stand-in-witness.sock"]],
] as const;

for (const [name, bytes] of [["LF", "\n"], ["CR", "\r"], ["CRLF", "\r\n"], ["NUL", "\0"]] as const) {
  for (const field of ["username", "password"] as const) {
    for (const [mode, opts] of credentialOptions) {
      test(`credential control characters: curl rejects ${name} in ${field} for ${mode}`, () => {
        const camera = { base: "http://camera.invalid", user: field === "username" ? `stand-in-user${bytes}suffix` : "stand-in-user" };
        const secret = field === "password" ? `stand-in-password${bytes}suffix` : "stand-in-password";
        let error: unknown;
        try { curlRequest(camera, secret, "/request", opts); } catch (caught) { error = caught; }
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe(`camera credential refused: ${field} contains CR, LF or NUL`);
        expect((error as Error).message).not.toContain("stand-in");
        expect((error as Error).message).not.toContain("suffix");
      });
    }
  }
}

test("credential control characters: curl checks username first even when both credentials are corrupt", () => {
  let error: unknown;
  try {
    curlRequest({ ...cam, user: "stand-in-user\n", pin: "invalid" }, "stand-in-password\0", "/request", { invocationId: "invalid" });
  } catch (caught) { error = caught; }
  expect(error).toBeInstanceOf(Error);
  expect((error as Error).message).toBe("camera credential refused: username contains CR, LF or NUL");
  expect((error as Error).message).not.toContain("stand-in");
});

for (const [label, user, secret, stdin] of [
  ["ordinary", "stand-in-user", "stand-in-password", 'user = "stand-in-user:stand-in-password"\n'],
  ["escaped", 'stand-in-user"\\\t\\n', 'stand-in-password"\\\t\\n', 'user = "stand-in-user\\"\\\\\t\\\\n:stand-in-password\\"\\\\\t\\\\n"\n'],
] as const) {
  for (const [mode, opts, extraArgs] of credentialOptions) {
    test(`credential control characters: curl preserves ${label} stdin and argv for ${mode}`, () => {
      const request = curlRequest({ base: "http://camera.invalid", user, auth: "any" }, secret, "/request", opts);
      expect(request).toEqual({
        args: ["curl", "-q", "-sk", "--globoff", mode === "unix-socket" ? "--anyauth" : "--digest", "--fail", "--noproxy", "*", "--config", "-", "--max-time", "10", "--max-filesize", "7340032",
          ...extraArgs, "http://camera.invalid/request", ...(mode === "outFile" ? ["-o", "/tmp/stand-in-snapshot.jpg"] : [])],
        stdin,
      });
    });
  }
}
