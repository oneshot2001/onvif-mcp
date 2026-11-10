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
