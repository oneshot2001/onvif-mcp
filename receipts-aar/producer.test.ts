import { afterEach, beforeEach, expect, spyOn, test } from "bun:test";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { decodeCbor, encodeCbor, fromHex, toHex } from "aar-kat-harness/harness/cbor";
import { hash } from "aar-kat-harness/harness/crypto";
import { AarWireProducer, commandDigestHex, verifyBundleDir, type WireEmitInput } from "./producer";
import { appendJournal, checkAarJournal } from "./journal";

const repo = resolve(import.meta.dir, "..");
const originalHome = process.env.HOME;
let root: string, producer: AarWireProducer, now: number;
const spies: Array<{ mockRestore(): void }> = [];
beforeEach(() => {
  root = fs.mkdtempSync(join(tmpdir(), "onvif-aar-test-"));
  process.env.HOME = join(root, "home");
  now = 1_800_000_000_000;
  spies.push(spyOn(Date, "now").mockImplementation(() => now));
  spies.push(spyOn(Bun, "sleep").mockImplementation(async ms => { now += Number(ms); }));
  producer = new AarWireProducer(root, "test-agent", Buffer.from("policy"));
});
afterEach(() => {
  for (const spy of spies.splice(0).reverse()) spy.mockRestore();
  process.env.HOME = originalHome;
  fs.rmSync(root, { recursive: true, force: true });
});
const aar = () => join(root, "receipts", "aar");
const journal = () => join(aar(), "journal.jsonl");
const records = () => fs.readFileSync(journal(), "utf8").trim().split("\n").map(line => JSON.parse(line));
const dispatch = { status: 200, responseBody: Buffer.from("ok"), observation: Buffer.from("position"), outcomeLevel: "device_acknowledged", outcomeState: "unknown" } as const;
function input(send?: WireEmitInput["send"]): WireEmitInput {
  return { agentId: "test-agent", camera: "test-cam", cameraPtz: true, protocol: "vapix",
    deviceMetadata: { manufacturer: "AXIS", model: "test", firmware: "0" }, actionName: "camera.ptz.preset",
    parameters: { preset: "Home" }, startedAt: now / 1000, observedAt: now / 1000,
    send: send ?? (async () => ({ dispatch, dispatchedAt: now / 1000, outcomeObservedAt: now / 1000 })) };
}
function receipts(dir: string): any[] {
  const bundle = decodeCbor(fs.readFileSync(join(dir, "bundle.cbor"))) as any;
  return bundle.artifacts.receipts.map((envelope: any[]) => decodeCbor(envelope[0] as Uint8Array));
}
function verify(dir: string) {
  const result = verifyBundleDir(repo, dir);
  expect(result.output).toContain("Result: conformant");
  expect(result.output).toContain("evaluated_profile: AAR-3");
  expect(result.conformant).toBe(true);
  return result.output;
}
function key(e: any): Buffer {
  return Buffer.from(encodeCbor([fromHex(e.issuer_kid), e.issuer_seq, fromHex(e.epoch_owner_kid), e.epoch_id, e.epoch_seq, fromHex(e.receipt_id), fromHex(e.envelope_digest)]));
}
function sorted(es: any[]) {
  for (let i = 1; i < es.length; i++) expect(Buffer.compare(key(es[i - 1]), key(es[i]))).toBeLessThan(0);
}

for (const actionName of ["camera.ptz.preset", "camera.stream.view"] as const) {
  test(`W2a primitives: ${actionName} digest matches emitted commands across invocation IDs`, async () => {
    const logical = { ...input(), actionName,
      cameraPtz: actionName === "camera.ptz.preset", protocol: actionName === "camera.ptz.preset" ? "vapix" : "onvif",
      parameters: actionName === "camera.ptz.preset" ? { preset: "Home" } : { snapshot: "test.jpg" } } as WireEmitInput;
    const digest = commandDigestHex(logical);
    expect(digest).toMatch(/^[0-9a-f]{64}$/);
    const commands = [];
    for (const byte of [1, 2]) {
      const invocationId = new Uint8Array(16).fill(byte);
      const result = await producer.emit({ ...logical, invocationId });
      const command = receipts(result.dir).find(r => r.kind === "action_attempt").body.command;
      expect(toHex(command.command_digest)).toBe(digest);
      expect(toHex(command.idempotency_key)).toBe(toHex(invocationId));
      commands.push(command);
    }
    expect(toHex(commands[0].command_digest)).toBe(toHex(commands[1].command_digest));
    expect(toHex(commands[0].idempotency_key)).not.toBe(toHex(commands[1].idempotency_key));
    expect(toHex(commands[0].command_id)).not.toBe(toHex(commands[1].command_id));
    expect(commandDigestHex({ ...logical, camera: "other-cam" })).not.toBe(digest);
    expect(commandDigestHex({ ...logical, cameraPtz: !logical.cameraPtz })).not.toBe(digest);
    expect(commandDigestHex({ ...logical, parameters: { changed: true } })).not.toBe(digest);
  });
}

test("fast send is committed and durably reserved before dispatch, verifies with its own prior", async () => {
  const result = await producer.emit(input(async () => {
    expect(JSON.parse(fs.readFileSync(join(aar(), "producer-state.json"), "utf8")).next_epoch).toBe(2);
    expect(records().at(-1).event).toBe("attempt_committed");
    expect(records().at(-1).envelope_synced_at).toBe(now / 1000);
    return { dispatch, dispatchedAt: now / 1000, outcomeObservedAt: now / 1000 };
  }));
  verify(result.dir);
  const attempt = records().find(r => r.event === "attempt_committed");
  expect(attempt.envelope_digest).toBe(toHex(hash(fromHex(attempt.envelope_cbor))));
  const bundle = decodeCbor(fs.readFileSync(result.bundlePath)) as any;
  expect(bundle.artifacts.receipts.some((e: any) => toHex(hash(encodeCbor(e))) === attempt.envelope_digest)).toBe(true);
  expect(records().at(-1).event).toBe("dispatch_completed");
});

test("slow send crosses seconds with fresh post-send clocks and pyref AAR-3", async () => {
  const t0 = now / 1000 + 1;
  const result = await producer.emit(input(async () => {
    now += 1000;
    const dispatchedAt = now / 1000;
    now += 3000;
    return { dispatch, dispatchedAt, outcomeObservedAt: now / 1000 };
  }));
  expect(result.evaluatedAt).toBe(t0 + 4);
  const rs = receipts(result.dir);
  const attempt = rs.find(r => r.kind === "action_attempt");
  const outcome = rs.find(r => r.kind === "outcome_observation");
  expect(attempt.emission.committed_at).toBe(t0);
  expect(outcome.emission.committed_at).toBe(t0 + 4);
  expect(outcome.evidence.time.monotonic_ns).toBeGreaterThan(attempt.evidence.time.monotonic_ns);
  const output = verify(result.dir);
  console.log(`slow-send pyref:\n${output.split("\n").filter(line => !line.startsWith("  CBOR hex:")).join("\n")}`);
});

test("three subsequent snapshots preserve nonempty history in CBOR order", async () => {
  await producer.emit(input()); // First-ever bundle correctly has empty prior history.
  for (let i = 0; i < 3; i++) {
    const path = join(aar(), "prior-state.json");
    const prior = JSON.parse(fs.readFileSync(path, "utf8"));
    prior.prior_emissions.reverse(); // August history was append-ordered.
    fs.writeFileSync(path, JSON.stringify(prior));
    const result = await producer.emit(input());
    const snapshot = JSON.parse(fs.readFileSync(join(result.dir, "prior-state.json"), "utf8"));
    expect(snapshot.prior_emissions.length).toBe((i + 1) * 6);
    sorted(snapshot.prior_emissions);
    sorted(JSON.parse(fs.readFileSync(path, "utf8")).prior_emissions);
    verify(result.dir);
  }
});

test("duplicate prior emission fails before send and preserves history", async () => {
  await producer.emit(input());
  const path = join(aar(), "prior-state.json");
  const prior = JSON.parse(fs.readFileSync(path, "utf8"));
  prior.prior_emissions.push(prior.prior_emissions[0]);
  fs.writeFileSync(path, JSON.stringify(prior));
  let calls = 0;
  await expect(producer.emit(input(async () => { calls++; throw Error("unexpected"); }))).rejects.toThrow("duplicate prior emission");
  expect(calls).toBe(0);
  expect(JSON.parse(fs.readFileSync(path, "utf8"))).toEqual(prior);
});

for (const failure of ["append", "fsync"] as const) {
  test(`journal ${failure} failure refuses without dispatch and verifies`, async () => {
    let writingJournal = false, calls = 0;
    const append = fs.appendFileSync;
    const sync = fs.fsyncSync;
    spies.push(spyOn(fs, "appendFileSync").mockImplementation((...args: Parameters<typeof append>) => {
      writingJournal = true;
      if (failure === "append") throw Error("disk unavailable");
      return append(...args);
    }));
    spies.push(spyOn(fs, "fsyncSync").mockImplementation(fd => {
      if (writingJournal && failure === "fsync") { writingJournal = false; throw Error("fsync unavailable"); }
      return sync(fd);
    }));
    const result = await producer.emit(input(async () => { calls++; throw Error("must not send"); }));
    expect(calls).toBe(0);
    const attempt = receipts(result.dir).find(r => r.kind === "action_attempt");
    expect(attempt.body).toMatchObject({ disposition: "not_dispatched", refusal_reason: "journal/unavailable" });
    verify(result.dir);
  });
}

test("send throw leaves ambiguous attempt, no bundle, no retry; next epoch is not reused", async () => {
  let calls = 0;
  await expect(producer.emit(input(async () => { calls++; throw Error("secret-password"); }))).rejects.toThrow("dispatch outcome ambiguous");
  expect(calls).toBe(1);
  expect(records().at(-1).event).toBe("dispatch_ambiguous");
  expect(fs.readFileSync(journal(), "utf8")).not.toContain("secret-password");
  expect(fs.readdirSync(aar()).filter(f => fs.existsSync(join(aar(), f, "bundle.cbor")))).toEqual([]);
  const restarted = new AarWireProducer(root, "test-agent", Buffer.from("policy"));
  const result = await restarted.emit(input());
  expect(receipts(result.dir)[0].binding.epoch_id).toBe(2);
  verify(result.dir);
});

for (const delta of [61, -1]) {
  test(`reject clock delta ${delta} without a bundle`, async () => {
    await expect(producer.emit(input(async () => {
      const dispatchedAt = now / 1000;
      now += delta * 1000;
      return { dispatch, dispatchedAt, outcomeObservedAt: now / 1000 };
    }))).rejects.toThrow("real-clock");
    expect(fs.readdirSync(aar()).filter(f => fs.existsSync(join(aar(), f, "bundle.cbor")))).toEqual([]);
  });
}

test("overlapping calls across producer instances serialize and both verify", async () => {
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  let entered!: () => void;
  const begun = new Promise<void>(resolve => { entered = resolve; });
  const first = producer.emit(input(async () => {
    entered(); await gate;
    return { dispatch, dispatchedAt: now / 1000, outcomeObservedAt: now / 1000 };
  }));
  await begun;
  let secondSent = false;
  const other = new AarWireProducer(root, "test-agent", Buffer.from("policy"));
  const second = other.emit(input(async () => {
    secondSent = true;
    return { dispatch, dispatchedAt: now / 1000, outcomeObservedAt: now / 1000 };
  }));
  await Promise.resolve();
  expect(secondSent).toBe(false);
  release();
  const results = await Promise.all([first, second]);
  expect(results.map(r => receipts(r.dir)[0].binding.epoch_id)).toEqual([1, 2]);
  expect(JSON.parse(fs.readFileSync(join(aar(), "prior-state.json"), "utf8")).prior_emissions).toHaveLength(12);
  expect(JSON.parse(fs.readFileSync(join(results[1]!.dir, "prior-state.json"), "utf8")).prior_emissions).toHaveLength(6);
  results.forEach(r => verify(r.dir));
});

for (const event of ["attempt_envelope", "attempt_committed"]) {
  test(`late ${event} failure rejects refusal without dispatch or bundle`, async () => {
    const append = fs.appendFileSync;
    spies.push(spyOn(fs, "appendFileSync").mockImplementation((...args: Parameters<typeof append>) => {
      if (String(args[1]).includes(`"event":"${event}"`)) { now += 1000; throw Error("unavailable"); }
      return append(...args);
    }));
    let sends = 0;
    await expect(producer.emit(input(async () => { sends++; throw Error("unexpected"); }))).rejects.toThrow("journal refusal decided after T0");
    expect(sends).toBe(0);
    expect(fs.readdirSync(aar()).some(f => fs.existsSync(join(aar(), f, "bundle.cbor")))).toBe(false);
  });
}

test("epoch reservation completes before epoch-open time and wait", async () => {
  const sync = fs.fsyncSync;
  let reserved = false;
  spies.push(spyOn(fs, "fsyncSync").mockImplementation(fd => {
    sync(fd);
    if (!reserved) { now += 2000; reserved = true; }
  }));
  spies.push(spyOn(Bun, "sleep").mockImplementation(async ms => {
    expect(reserved).toBe(true);
    expect(JSON.parse(fs.readFileSync(join(aar(), "producer-state.json"), "utf8")).next_epoch).toBe(2);
    now += Number(ms);
  }));
  const result = await producer.emit(input());
  expect(result.evaluatedAt).toBe(1_800_000_003);
  verify(result.dir);
});

test("early timer wake sleeps again for the remaining epoch-open second", async () => {
  const sleeps: number[] = [];
  spies.push(spyOn(Bun, "sleep").mockImplementation(async ms => {
    sleeps.push(Number(ms));
    now += sleeps.length === 1 ? 400 : Number(ms);
  }));
  const result = await producer.emit(input());
  expect(sleeps).toEqual([1000, 600]);
  verify(result.dir);
});

test("persisted journal refusal completes an already-written envelope for recovery", async () => {
  const append = fs.appendFileSync;
  spies.push(spyOn(fs, "appendFileSync").mockImplementation((...args: Parameters<typeof append>) => {
    if (String(args[1]).includes('"event":"attempt_committed"')) throw Error("unavailable");
    return append(...args);
  }));
  const result = await producer.emit(input(async () => { throw Error("must not send"); }));
  expect(records().map(r => r.event)).toEqual(["attempt_envelope", "refusal_persisted"]);
  const warning = spyOn(console, "error").mockImplementation(() => {});
  spies.push(warning);
  checkAarJournal(journal());
  expect(warning).not.toHaveBeenCalled();
  verify(result.dir);
});

test("journal append checks only the tail; startup still validates the full journal", () => {
  fs.writeFileSync(journal(), "not JSON\n");
  const read = spyOn(fs, "readFileSync");
  spies.push(read);
  appendJournal(journal(), { event: "dispatch_ambiguous", invocation_id: "00".repeat(16), observed_at: now / 1000 });
  expect(read).not.toHaveBeenCalled();
  expect(() => checkAarJournal(journal())).toThrow("aar journal corrupt");
  fs.writeFileSync(journal(), '{"event":');
  expect(() => appendJournal(journal(), { event: "dispatch_ambiguous", invocation_id: "00".repeat(16), observed_at: now / 1000 })).toThrow("torn last line");
  expect(fs.readFileSync(journal(), "utf8")).toBe('{"event":');
});

test("failed prior-state write preserves the complete previous file", async () => {
  await producer.emit(input());
  const path = join(aar(), "prior-state.json");
  const previous = fs.readFileSync(path, "utf8");
  const open = fs.openSync, write = fs.writeFileSync;
  let priorFd: number | undefined;
  spies.push(spyOn(fs, "openSync").mockImplementation((...args: Parameters<typeof open>) => {
    const fd = open(...args);
    if (args[0] === `${path}.tmp`) priorFd = fd;
    return fd;
  }));
  spies.push(spyOn(fs, "writeFileSync").mockImplementation((...args: Parameters<typeof write>) => {
    if (args[0] === path || (priorFd !== undefined && args[0] === priorFd)) {
      write(args[0], '{"prior_emissions":');
      throw Error("partial prior write");
    }
    return write(...args);
  }));
  await expect(producer.emit(input())).rejects.toThrow("partial prior write");
  expect(fs.readFileSync(path, "utf8")).toBe(previous);
});

test("policy denial verifies and never calls send", async () => {
  const { send, ...denied } = input();
  const result = await producer.emit({ ...denied, refusal: "agent has no ptz grant" });
  expect(receipts(result.dir).some(r => r.kind === "dispatch")).toBe(false);
  expect(fs.existsSync(journal())).toBe(false);
  verify(result.dir);
});

test("startup warns for crash after durable append; torn journal exits nonzero without repair", async () => {
  const result = await producer.emit(input());
  const pending = records().filter(r => r.event !== "dispatch_completed");
  fs.writeFileSync(journal(), pending.map(r => JSON.stringify(r)).join("\n") + "\n");
  const warning = spyOn(console, "error").mockImplementation(() => {});
  spies.push(warning);
  checkAarJournal(journal());
  expect(warning.mock.calls.flat().join(" ")).toContain(pending[0].invocation_id);
  expect(warning.mock.calls.flat().join(" ")).toContain("no completion");
  verify(result.dir);
  const indexSource = fs.readFileSync(join(repo, "index.ts"), "utf8");
  const guard = indexSource.slice(indexSource.indexOf("// Recovery is read-only"), indexSource.indexOf("const AGENT ="));
  const startup = `import { checkAarJournal } from ${JSON.stringify(join(import.meta.dir, "journal.ts"))}; import { join } from "node:path"; const ROOT = process.argv[1]; ${guard} console.log("startup continued");`;
  const normal = Bun.spawnSync([process.execPath, "-e", startup, root], { env: { ...process.env }, cwd: root });
  expect(normal.exitCode).toBe(0);
  expect(normal.stdout.toString()).toContain("startup continued");
  expect(normal.stderr.toString()).toContain(pending[0].invocation_id);
  const torn = fs.readFileSync(journal(), "utf8") + '{"event":';
  fs.writeFileSync(journal(), torn);
  const proc = Bun.spawnSync([process.execPath, "-e", startup, root], { env: { ...process.env }, cwd: root });
  expect(proc.exitCode).not.toBe(0);
  expect(proc.stderr.toString()).toContain("aar journal corrupt");
  expect(proc.stderr.toString()).toContain(journal());
  expect(fs.readFileSync(journal(), "utf8")).toBe(torn);
});

test("journal marker timestamps the completed envelope fsync, not T0", async () => {
  const append = fs.appendFileSync, sync = fs.fsyncSync;
  let envelopeFd: number | undefined;
  spies.push(spyOn(fs, "appendFileSync").mockImplementation((...args: Parameters<typeof append>) => {
    if (String(args[1]).includes('"event":"attempt_envelope"')) envelopeFd = args[0] as number;
    return append(...args);
  }));
  spies.push(spyOn(fs, "fsyncSync").mockImplementation(fd => {
    sync(fd);
    if (fd === envelopeFd) { now += 2000; envelopeFd = undefined; }
  }));
  const result = await producer.emit(input());
  const attempt = receipts(result.dir).find(r => r.kind === "action_attempt");
  expect(records().find(r => r.event === "attempt_committed").envelope_synced_at).toBe(attempt.emission.committed_at + 2);
  verify(result.dir);
});

test("backwards clock after envelope fsync is a loud clock failure, not a journal refusal", async () => {
  const append = fs.appendFileSync, sync = fs.fsyncSync;
  let envelopeFd: number | undefined;
  spies.push(spyOn(fs, "appendFileSync").mockImplementation((...args: Parameters<typeof append>) => {
    if (String(args[1]).includes('"event":"attempt_envelope"')) envelopeFd = args[0] as number;
    return append(...args);
  }));
  spies.push(spyOn(fs, "fsyncSync").mockImplementation(fd => {
    sync(fd);
    if (fd === envelopeFd) { now -= 1000; envelopeFd = undefined; }
  }));
  let sent = false;
  await expect(producer.emit(input(async () => { sent = true; throw Error("unexpected"); }))).rejects.toThrow("real-clock");
  expect(sent).toBe(false);
  expect(fs.readdirSync(aar()).some(f => fs.existsSync(join(aar(), f, "bundle.cbor")))).toBe(false);
});

test("epoch reservation fsync failure never dispatches", async () => {
  spies.push(spyOn(fs, "fsyncSync").mockImplementation(() => { throw Error("reservation fsync failed"); }));
  let sent = false;
  await expect(producer.emit(input(async () => { sent = true; throw Error("unexpected"); }))).rejects.toThrow("reservation fsync failed");
  expect(sent).toBe(false);
  expect(fs.existsSync(journal())).toBe(false);
});

test("completion journal failure keeps the attempt and never retries", async () => {
  const append = fs.appendFileSync;
  spies.push(spyOn(fs, "appendFileSync").mockImplementation((...args: Parameters<typeof append>) => {
    if (String(args[1]).includes('"event":"dispatch_completed"')) throw Error("completion append failed");
    return append(...args);
  }));
  let sends = 0;
  await expect(producer.emit(input(async () => {
    sends++;
    return { dispatch, dispatchedAt: now / 1000, outcomeObservedAt: now / 1000 };
  }))).rejects.toThrow("completion append failed");
  expect(sends).toBe(1);
  expect(records().at(-1).event).toBe("attempt_committed");
  expect(fs.readdirSync(aar()).some(f => fs.existsSync(join(aar(), f, "bundle.cbor")))).toBe(false);
});

// Includes directories and bytes, including keys and all producer state.
function tree(path: string): unknown {
  if (!fs.existsSync(path)) return null;
  if (!fs.statSync(path).isDirectory()) return fs.readFileSync(path).toString("hex");
  return Object.fromEntries(fs.readdirSync(path).sort().map(name => [name, tree(join(path, name))]));
}

for (const populated of [false, true]) {
  for (const length of [15, 17]) {
    test(`W2b invocation binding: ${length}-byte ID rejects without changes on ${populated ? "populated" : "fresh"} producer`, async () => {
      if (populated) await producer.emit(input());
      const before = tree(root); // Construction has already created receipts/aar.
      let sent = false;
      const result = producer.emit({ ...input(async () => { sent = true; throw Error("unexpected send"); }), invocationId: new Uint8Array(length) });
      expect(result).toBeInstanceOf(Promise);
      await expect(result).rejects.toThrow("invocationId must be 16 bytes");
      expect(sent).toBe(false);
      expect(tree(root)).toEqual(before);
    });
  }
}

for (const mutation of ["buffer", "property"]) {
  test(`W2b invocation binding: queued ID owns its bytes despite caller ${mutation} mutation`, async () => {
    const gate = Promise.withResolvers<void>(), entered = Promise.withResolvers<void>();
    const first = producer.emit(input(async () => {
      entered.resolve();
      await gate.promise;
      return { dispatch, dispatchedAt: now / 1000, outcomeObservedAt: now / 1000 };
    }));
    await entered.promise;
    const bytes = new Uint8Array(16).fill(42);
    const expected = toHex(bytes);
    const queued = { ...input(), invocationId: bytes };
    const second = producer.emit(queued);
    if (mutation === "buffer") bytes.fill(99);
    else queued.invocationId = new Uint8Array(17).fill(99);
    gate.resolve();
    const results = await Promise.all([first, second]);
    const rs = receipts(results[1]!.dir);
    for (const r of rs) expect(toHex(r.freshness.invocation_id)).toBe(expected);
    expect(toHex(rs.find(r => r.kind === "action_attempt").body.command.idempotency_key)).toBe(expected);
    expect(toHex(rs.find(r => r.kind === "dispatch").body.adapter_invocation_id)).toBe(expected);
    expect(results[1]!.dir.endsWith(expected.slice(0, 8))).toBe(true);
    expect(records().slice(3).every(r => r.invocation_id === expected)).toBe(true);
    verify(results[1]!.dir);
  });
}

test("W2b invocation binding: omitted IDs remain independently random", async () => {
  const first = await producer.emit(input());
  const second = await producer.emit(input());
  const ids = [first, second].map(result => toHex(receipts(result.dir)[0].freshness.invocation_id));
  for (const id of ids) expect(id).toMatch(/^[0-9a-f]{32}$/);
  expect(ids[0]).not.toBe(ids[1]);
});
