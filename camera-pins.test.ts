import { describe, expect, test } from "bun:test";
import { cameraPinProblem } from "./camera-pins";

const pin = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

describe("startup camera pin validation", () => {
  test("rejects a pinned HTTP camera naming only its id", () => {
    const cameras = {
      secure: { base: "https://camera.example", pin },
      insecure: { base: "http://user:secret@camera.example", pin },
    };
    expect(cameraPinProblem(cameras)).toBe("Invalid camera pin: insecure");
  });

  test("accepts a pinned HTTPS camera", () => {
    expect(cameraPinProblem({ secure: { base: "https://camera.example", pin } })).toBeNull();
  });

  test("accepts an HTTP camera without a pin", () => {
    expect(cameraPinProblem({ unpinned: { base: "http://camera.example" } })).toBeNull();
  });

  test.each(["", "ftp://camera.example", "HTTPS://camera.example"])("rejects a pinned non-https base: %s", (base) => {
    expect(cameraPinProblem({ invalid: { base, pin } })).toBe("Invalid camera pin: invalid");
  });

  test.each(["secret-invalid-pin", "sha256//", null, 123])("keeps rejecting malformed pins without disclosing them: %s", (invalidPin) => {
    expect(cameraPinProblem({ malformed: { base: "https://camera.example", pin: invalidPin } }))
      .toBe("Invalid camera pin: malformed");
  });
});
