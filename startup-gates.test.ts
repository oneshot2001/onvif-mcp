import { afterEach, beforeEach, expect, test } from "bun:test";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createPublicKey, generateKeyPairSync } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import ts from "typescript";

const source = readFileSync(join(import.meta.dir, "index.ts"), "utf8");
const parsed = ts.createSourceFile("index.ts", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
let root: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "onvif-startup-gates-"));
  mkdirSync(join(root, "keys"));
  mkdirSync(join(root, "handoff"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

// Check unique, ordered boundaries and top-level placement inside each test,
// before executing any slice. Parsing skips comments, strings (including nested
// templates) and regex literals, so their braces cannot hide an enclosing block.
// Credential fetching and listeners stay outside; keys are temporary fixtures.
function slice(startMarker: string, endMarker: string): string {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker);
  expect(start).toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(start);
  expect(source.lastIndexOf(startMarker)).toBe(start);
  expect(source.lastIndexOf(endMarker)).toBe(end);
  expect(parsed.statements.some((statement) => statement.getStart(parsed) === start),
    `startup slice must start at top-level nesting depth: ${startMarker}`).toBe(true);
  return source.slice(start, end);
}

function importHelper(names: string, file: string): string {
  return `import { ${names} } from ${JSON.stringify(join(import.meta.dir, file))};`;
}

function runGate(setup: string, gate: string) {
  const code = new Bun.Transpiler({ loader: "ts" }).transformSync(`
    import { existsSync, readFileSync, statSync } from "node:fs";
    import { join } from "node:path";
    const ROOT = process.argv[1];
    const KEYDIR = join(ROOT, "keys");
    const LOG = join(ROOT, "chain.jsonl");
    ${setup}
    ${gate}
    console.log("startup continued");
  `);
  const proc = Bun.spawnSync([process.execPath, "-e", code, root], {
    cwd: root, timeout: 2000, killSignal: "SIGKILL",
  });
  expect(proc.signalCode).toBeUndefined();
  return { exitCode: proc.exitCode, stdout: proc.stdout.toString(), stderr: proc.stderr.toString() };
}

function expectRejected(result: ReturnType<typeof runGate>, diagnostic: string) {
  expect(result.exitCode).toBe(1);
  expect(result.stderr).toBe(diagnostic + "\n");
  expect(result.stdout).toBe("");
}

function expectContinued(result: ReturnType<typeof runGate>) {
  expect(result.exitCode).toBe(0);
  expect(result.stderr).toBe("");
  expect(result.stdout).toBe("startup continued\n");
}

function runPolicyKeyGate(agents: unknown) {
  writeFileSync(join(root, "policy.json"), JSON.stringify({ agents }));
  return runGate(`
    ${importHelper("policyShapeProblem, unknownAgentKey", "policy-check.ts")}
    const AGENT = "viewer";
  `, slice('const policyBytes = readFileSync(join(ROOT, "policy.json"));', "const limiter = makeLimiter(Date.now);"));
}

test("policy key wiring: an unknown key in another agent exits 1 with the exact diagnostic", () => {
  expectRejected(runPolicyKeyGate({
    viewer: { tools: [], cameras: [] },
    operator: { tools: [], cameras: [], rateLimit: { actuationPerMin: 2 } },
  }), "policy agent 'operator' has unknown key 'rateLimit'");
});

test("policy key wiring: a clean policy continues with rate omitted", () => {
  expectContinued(runPolicyKeyGate({ viewer: { tools: [], cameras: [] } }));
});

function runPinGate(base: string) {
  const cameras = { pinned: { base, pin: "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" } };
  return runGate(`
    ${importHelper("cameraPinProblem", "camera-pins.ts")}
    const cameras = ${JSON.stringify(cameras)};
  `, slice("const pinProblem = cameraPinProblem(cameras);", "const gateway = gatewayConfigFromEnv(process.env);"));
}

test("startup gate wiring: pinned HTTP camera exits 1 without continuing", () => {
  expectRejected(runPinGate("http://camera.example"), "Invalid camera pin: pinned");
});

test("startup gate wiring: pinned HTTPS camera continues", () => {
  expectContinued(runPinGate("https://camera.example"));
});

const passwords = { empty: "", whitespace: " \t\n ", viewer: "stand-in-viewer-password", operator: "stand-in-operator-password" };
function runPasswordGate(values: Record<string, string>) {
  const credentials = Object.keys(values).map((credKey) => ({ id: `camera-${credKey}`, credKey }));
  const result = runGate(`
    ${importHelper("missingPasswords", "creds-check.ts")}
    const passwords = ${JSON.stringify(values)};
    const credentials = ${JSON.stringify(credentials)};
  `, slice("const missing = missingPasswords(passwords);", "// --- receipts: hash chain + ed25519 signature."));
  for (const password of Object.values(values).filter((value) => value.trim() !== "")) {
    expect(result.stdout).not.toContain(password);
    expect(result.stderr).not.toContain(password);
  }
  return result;
}

test("startup gate wiring: empty and whitespace passwords exit 1 naming ids and credKeys without secrets", () => {
  expectRejected(runPasswordGate(passwords), "Missing camera passwords: camera-empty (credKey: empty), camera-whitespace (credKey: whitespace)");
});

test("startup gate wiring: nonempty passwords continue without secrets", () => {
  expectContinued(runPasswordGate({ ...passwords, empty: "stand-in-admin-password", whitespace: "stand-in-second-admin-password" }));
});

function writeKeyPair(mode = 0o600) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const key = join(root, "keys", "receipt.key");
  writeFileSync(key, privateKey.export({ type: "pkcs8", format: "pem" }));
  writeFileSync(join(root, "keys", "receipt.pub"), publicKey.export({ type: "spki", format: "pem" }));
  chmodSync(key, mode);
}

function runStdioKeyGate() {
  return runGate(`
    ${importHelper("keyModeProblem", "key-perms.ts")}
    import { generateKeyPairSync, sign as edSign, createHash, createPublicKey } from "node:crypto";
    import { writeFileSync } from "node:fs";
    const vault = null;
    let PRIV = "";
    let signer;
  `, slice('if (vault === null) {\n  if (!existsSync(join(KEYDIR, "receipt.key"))) {', "const PUB = signer.publicKeyPem;"));
}

function runKeyGate(mode: number) {
  writeKeyPair(mode);
  return runStdioKeyGate();
}

test("startup gate wiring: mode 0644 receipt key exits 1 with chmod diagnostic", () => {
  expectRejected(runKeyGate(0o644), "receipt.key has group/other permissions; run chmod 600 .keys/receipt.key");
});

test("startup gate wiring: mode 0600 receipt key continues", () => {
  expectContinued(runKeyGate(0o600));
});

test("stdio key wiring: public key without private key rejects without re-keying", () => {
  writeKeyPair();
  const key = join(root, "keys", "receipt.key");
  const pub = join(root, "keys", "receipt.pub");
  const before = readFileSync(pub);
  rmSync(key);
  expectRejected(runStdioKeyGate(), "receipt.key is missing but receipt.pub exists; restore the key or use a fresh ROOT (a new key cannot verify the existing receipts)");
  expect(readFileSync(pub)).toEqual(before);
  expect(existsSync(key)).toBe(false);
});

test("stdio key wiring: private key without public rejects without re-keying", () => {
  writeKeyPair();
  const key = join(root, "keys", "receipt.key");
  const pub = join(root, "keys", "receipt.pub");
  const before = readFileSync(key);
  rmSync(pub);
  const result = runStdioKeyGate();
  expect(result.exitCode).toBe(1);
  expect(result.stderr, "missing public key reports exactly the restore-pair diagnostic")
    .toBe("receipt.pub is missing but receipt.key exists; restore the matching pair\n");
  expect(result.stdout).toBe("");
  expect(readFileSync(key)).toEqual(before);
  expect(existsSync(pub)).toBe(false);
});

test("stdio key wiring: private key without public reports chmod diagnostic first for mode 0644", () => {
  writeKeyPair(0o644);
  rmSync(join(root, "keys", "receipt.pub"));
  expectRejected(runStdioKeyGate(), "receipt.key has group/other permissions; run chmod 600 .keys/receipt.key");
});

test.each(["mismatched pair", "non-PEM public key"])("stdio key wiring: %s rejects without changing either file", (kind) => {
  writeKeyPair();
  const key = join(root, "keys", "receipt.key");
  const pub = join(root, "keys", "receipt.pub");
  writeFileSync(pub, kind === "mismatched pair"
    ? generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" })
    : "not a PEM public key\n");
  const keyBefore = readFileSync(key);
  const pubBefore = readFileSync(pub);
  expectRejected(runStdioKeyGate(), "receipt.pub does not match receipt.key; restore the matching pair");
  expect(readFileSync(key)).toEqual(keyBefore);
  expect(readFileSync(pub)).toEqual(pubBefore);
});

test.each(["original PEM", "CRLF PEM"])("stdio key wiring: matching pair continues with %s", (kind) => {
  writeKeyPair();
  const pub = join(root, "keys", "receipt.pub");
  if (kind === "CRLF PEM") writeFileSync(pub, readFileSync(pub, "utf8").replaceAll("\n", "\r\n"));
  expectContinued(runStdioKeyGate());
});

test("stdio key wiring: empty key directory creates matching pair with mode 0600", () => {
  expectContinued(runStdioKeyGate());
  const key = join(root, "keys", "receipt.key");
  const pub = join(root, "keys", "receipt.pub");
  expect(statSync(key).mode & 0o777).toBe(0o600);
  expect(createPublicKey(readFileSync(key)).export({ type: "spki", format: "der" }))
    .toEqual(createPublicKey(readFileSync(pub)).export({ type: "spki", format: "der" }));
});

test("stdio key wiring: mode 0644 reports chmod diagnostic before public key mismatch", () => {
  writeKeyPair(0o644);
  writeFileSync(join(root, "keys", "receipt.pub"), "not a PEM public key\n");
  expectRejected(runStdioKeyGate(), "receipt.key has group/other permissions; run chmod 600 .keys/receipt.key");
});

function runChainGate() {
  return runGate(`
    ${importHelper("emptyChainConflict, lastReceiptFrom", "receipt-chain.ts")}
    ${importHelper("handoffHeads", "commission.ts")}
    ${slice("function lastReceipt():", "// Receipt semantics follow AAR")}
  `, slice("try {\n  const head = lastReceipt();", "// Gateway mode (P1): GATEWAY_LISTEN=<port> serves Streamable HTTP behind a\n// bearer token bound to AGENT_ID; otherwise stdio as before."));
}

test("startup gate wiring: empty chain with handoff head exits 1 with truncation diagnostic and log path", () => {
  writeFileSync(join(root, "chain.jsonl"), "");
  writeFileSync(join(root, "handoff", "earlier.json"), JSON.stringify({ receipts: { chain_head_hash: "earlier-head" } }));
  expectRejected(runChainGate(), `receipt chain is empty but 1 handoff(s) reference earlier receipts — chain truncated? (${join(root, "chain.jsonl")})`);
});

test("startup gate wiring: empty chain without handoff heads continues", () => {
  writeFileSync(join(root, "chain.jsonl"), "");
  expectContinued(runChainGate());
});

function credentialGateResult(setup: string, start = "const unsafe = unsafeCredentials(cameras, passwords);", end = "function tierDenied(") {
  const result = runGate(`
    ${importHelper("unsafeCredentials, missingPasswords", "creds-check.ts")}
    ${importHelper("VaultWithheld", "vault-client.ts")}
    ${importHelper("accountFor", "account-for.ts")}
    ${setup}
  `, slice(start, end));
  expect(result.stdout).not.toContain("stand-in");
  expect(result.stderr).not.toContain("stand-in");
  expect(existsSync(join(root, "chain.jsonl"))).toBe(false);
  expect(existsSync(join(root, "receipts", "chain.jsonl"))).toBe(false);
  return result;
}

const credentialCamera = {
  user: "stand-in-admin", credKey: "admin",
  accounts: {
    viewer: { user: "stand-in-viewer", credKey: "viewer" },
    operator: { user: "stand-in-operator", credKey: "operator" },
  },
};

for (const [name, bytes] of [["LF", "\n"], ["CR", "\r"], ["CRLF", "\r\n"], ["NUL", "\0"]] as const) {
  for (const field of ["username", "password"] as const) {
    test(`credential gate wiring: ${name} in ${field} exits before startup continues`, () => {
      const user = field === "username" ? `stand-in-user${bytes}suffix` : "stand-in-user";
      const password = field === "password" ? `stand-in-password${bytes}suffix` : "stand-in-password";
      const result = credentialGateResult(`
        const cameras = { cam: { user: ${JSON.stringify(user)}, credKey: "key" } };
        const passwords = { key: ${JSON.stringify(password)} };
      `);
      expectRejected(result, `Camera credentials contain CR, LF or NUL: cam ${field} (credKey: key)`);
    });
  }
}

test("credential gate wiring: clean quote backslash and tab credentials continue", () => {
  const value = 'stand-in-quote"backslash\\tab\tliteral\\n';
  expectContinued(credentialGateResult(`
    const cameras = { cam: { user: ${JSON.stringify(value)}, credKey: "key" } };
    const passwords = { key: ${JSON.stringify(value)} };
  `));
});

function runCredentialLoad(mode: "stdio" | "gateway", password: string, options: {
  withheldAdmin?: boolean; corruptWithheldUsername?: boolean; bothGates?: boolean;
} = {}) {
  const cameras = {
    healthy: { user: "stand-in-healthy", credKey: "healthy" },
    cam: { ...credentialCamera, user: options.corruptWithheldUsername ? "stand-in-admin\n" : credentialCamera.user },
  };
  return credentialGateResult(`
    const cameras = ${JSON.stringify(cameras)};
    const reply = ${JSON.stringify(password)};
    const Bun = { spawnSync: () => ({ stdout: Buffer.from(reply) }) };
    const vault = ${mode === "stdio" ? "null" : `{
      credential(id, tier) {
        if (id === "healthy") return "stand-in-healthy-password";
        if (${Boolean(options.withheldAdmin)} && tier === "admin") throw new VaultWithheld("tier unavailable");
        return reply;
      }
    }`};
  `, "const credentials = Object.entries(cameras).flatMap(", options.bothGates
    ? "// --- receipts: hash chain + ed25519 signature." : "function tierDenied(");
}

for (const mode of ["stdio", "gateway"] as const) {
  test(`credential gate wiring: ${mode} warning line ahead of password is refused`, () => {
    const labels = [
      ...(mode === "stdio" ? ["healthy password (credKey: healthy)"] : []),
      "cam password (credKey: admin)", "cam password (credKey: viewer)", "cam password (credKey: operator)",
    ];
    expectRejected(runCredentialLoad(mode, "stand-in-warning\nstand-in-password"),
      `Camera credentials contain CR, LF or NUL: ${labels.join(", ")}`);
  });
}

test("credential gate wiring: stdio still trims a clean password trailing line break", () => {
  expectContinued(runCredentialLoad("stdio", "stand-in-password\n"));
});

test("credential gate wiring: gateway refuses a vault password trailing LF", () => {
  expectRejected(runCredentialLoad("gateway", "stand-in-password\n"),
    "Camera credentials contain CR, LF or NUL: cam password (credKey: admin), cam password (credKey: viewer), cam password (credKey: operator)");
});

test("credential gate wiring: clean vault replies with withheld admin continue", () => {
  expectContinued(runCredentialLoad("gateway", "stand-in-password", { withheldAdmin: true }));
});

test("credential gate wiring: withheld corrupt username stops even healthy cameras", () => {
  expectRejected(runCredentialLoad("gateway", "stand-in-password", { withheldAdmin: true, corruptWithheldUsername: true }),
    "Camera credentials contain CR, LF or NUL: cam username (credKey: admin)");
});

test("credential gate wiring: unsafe whitespace is refused before missing passwords", () => {
  expectRejected(runCredentialLoad("gateway", " \n", { bothGates: true }),
    "Camera credentials contain CR, LF or NUL: cam password (credKey: admin), cam password (credKey: viewer), cam password (credKey: operator)");
});

test("credential gate wiring: blank vault passwords retain the missing diagnostic", () => {
  expectRejected(runCredentialLoad("gateway", "  \t", { bothGates: true }),
    "Missing camera passwords: cam (credKey: admin), cam (credKey: viewer), cam (credKey: operator)");
});

test("credential gate wiring: clean vault passwords pass both gates", () => {
  expectContinued(runCredentialLoad("gateway", "stand-in-password", { bothGates: true }));
});

function runPolicyShapeGate(document: string) {
  writeFileSync(join(root, "policy.json"), document);
  return runGate(`
    ${importHelper("policyShapeProblem, unknownAgentKey", "policy-check.ts")}
    const AGENT = "viewer";
  `, slice('const policyBytes = readFileSync(join(ROOT, "policy.json"));', "const limiter = makeLimiter(Date.now);"));
}

test("policy shape wiring: a wrong-typed policy file exits 1 with the one-line diagnostic before startup continues", () => {
  const cases: [string, string][] = [
    ['{"agents":{"viewer":{"tools":[],"cameras":[]},"guard":{"tools":[],"cameras":"lobby2"}}}',
      "policy agent 'guard' field 'cameras' must be an array of strings"],
    ['{"agents":{"viewer":{"tools":[],"cameras":[]},"guard":{"tools":[],"cameras":[],"config":{"groups":[],"remediate":"false"}}}}',
      "policy agent 'guard' field 'config.remediate' must be a boolean"],
    ['{"agents":{"viewer":{"tools":[],"cameras":[]},"guard":{"tools":[],"cameras":[],"config":{"groups":[],"aoa":"no"}}}}',
      "policy agent 'guard' field 'config.aoa' must be a boolean"],
    ['{"agents":{"guard":"all"}}', "policy agent 'guard' must be an object"],
    ['{}', "policy 'agents' must be an object"],
    ['null', "policy 'agents' must be an object"],
    ['[]', "policy 'agents' must be an object"],
    ['7', "policy 'agents' must be an object"],
  ];
  for (const [document, message] of cases) expectRejected(runPolicyShapeGate(document), message);
});

test("policy shape wiring: the committed policy file and a full valid policy continue", () => {
  expectContinued(runPolicyShapeGate(readFileSync(join(import.meta.dir, "policy.json"), "utf8")));
  expectContinued(runPolicyShapeGate('{"agents":{"guard":{"tools":["ptz_move"],"cameras":["lobby"],"ptz":{"maxStep":30,"maxZoomStep":-1},"rate":{"actuationPerMin":6,"snapshotPerMin":30},"config":{"groups":["Image"],"remediate":true,"aoa":true,"rebaseline":true}}}}'));
});

const vaultFailureReason = "stand-in-secret-before-break\nstand-in-after-break\r";
const releasedVaultReply = { status: 200, body: JSON.stringify({ password: "stand-in-password" }) };

function runVaultFailureLoad(admin: { status: number; body: string }) {
  return runGate(`
    ${importHelper("createVaultClient, VaultWithheld", "vault-client.ts")}
    const cameras = {
      cam: { user: "stand-in-admin", credKey: "admin", accounts: {
        viewer: { user: "stand-in-viewer", credKey: "viewer" }
      } }
    };
    const replies = ${JSON.stringify({ admin, viewer: releasedVaultReply })};
    const vault = createVaultClient((_method, _path, body) => replies[body.tier]);
  `, slice("const credentials = Object.entries(cameras).flatMap(", "const unsafe = unsafeCredentials(cameras, passwords);")
    + '\nconsole.log(JSON.stringify({ released: Object.keys(passwords), withheld }));');
}

test("vault failure wiring: a credential reply with a reason prints only the status line", () => {
  for (const status of [500, 401, 404, 200]) {
    const result = runVaultFailureLoad({ status, body: JSON.stringify({ reason: vaultFailureReason, password: "" }) });
    expectRejected(result, status === 200
      ? "vault credential: HTTP 200 with no password in the reply"
      : `vault credential: HTTP ${status}`);
    expect(result.stdout).not.toContain("stand-in");
    expect(result.stderr).not.toContain("stand-in");
  }
});

test("vault failure wiring: a withheld tier keeps its reason and clean replies continue", () => {
  const reason = "admin tier withheld until approval";
  const cases = [
    { admin: { status: 403, body: JSON.stringify({ reason }) }, released: ["viewer"], withheld: { admin: reason } },
    { admin: { status: 403, body: "{}" }, released: ["viewer"], withheld: { admin: "tier admin withheld" } },
    { admin: releasedVaultReply, released: ["admin", "viewer"], withheld: {} },
  ];
  for (const { admin, released, withheld } of cases) {
    const result = runVaultFailureLoad(admin);
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toBe(JSON.stringify({ released, withheld }) + "\nstartup continued\n");
    expect(result.stdout).not.toContain("stand-in");
    expect(result.stdout).not.toContain("password");
  }
});

test("vault failure wiring: malformed replies print fixed text", () => {
  for (const status of [500, 403, 200]) {
    for (const [body, diagnostic] of [
      [vaultFailureReason, "non-JSON"],
      [JSON.stringify(vaultFailureReason), "non-object"],
    ] as const) {
      const result = runVaultFailureLoad({ status, body });
      expectRejected(result, `vault credential: HTTP ${status} with a ${diagnostic} body`);
      expect(result.stderr).not.toContain("stand-in");
    }
  }
});

function runPolicyCameraGate(policy: unknown, cameras: Record<string, unknown>) {
  return runGate(`
    ${importHelper("unknownPolicyCamera", "policy-check.ts")}
    const policy = ${JSON.stringify(policy)};
    const cameras = ${JSON.stringify(cameras)};
  `, slice("const policyCameraProblem = unknownPolicyCamera(policy, cameras);", "function rateDenied("));
}

test("policy camera wiring: a camera another agent names that cameras.json lacks exits 1 naming the agent and camera", () => {
  expectRejected(runPolicyCameraGate({
    viewer: { tools: [], cameras: ["lobby"] },
    operator: { tools: [], cameras: ["lobby", "retired"] },
  }, { lobby: {} }), "policy agent 'operator' names camera 'retired' that is not in cameras.json");
  expectRejected(runPolicyCameraGate({
    viewer: { tools: [], cameras: ["toString"] },
  }, {}), "policy agent 'viewer' names camera 'toString' that is not in cameras.json");
});

test("policy camera wiring: the committed policy and cameras files continue", () => {
  expectContinued(runPolicyCameraGate(
    JSON.parse(readFileSync(join(import.meta.dir, "policy.json"), "utf8")).agents,
    JSON.parse(readFileSync(join(import.meta.dir, "cameras.json"), "utf8")),
  ));
  expectContinued(runPolicyCameraGate({ viewer: { tools: [], cameras: [] } }, {}));
});
