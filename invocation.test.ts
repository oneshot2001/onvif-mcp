import { expect, test } from "bun:test";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { z } from "zod";
import { claimInvocationForAar, currentCommandDigest, currentInvocationId, runAsDispatch, runWithInvocation, withInvocations } from "./invocation";

test("W2a primitives: nested dispatch scopes restore digests and share the invocation claim", () => {
  const outer = "a".repeat(64), inner = "b".repeat(64), value = {};
  expect(currentCommandDigest()).toBeUndefined();
  runWithInvocation(() => {
    const id = currentInvocationId()!;
    expect(runAsDispatch(outer, () => {
      expect(currentCommandDigest()).toBe(outer);
      expect(currentInvocationId()).toBe(id);
      runAsDispatch(inner, () => {
        expect(currentCommandDigest()).toBe(inner);
        expect(currentInvocationId()).toBe(id);
        expect(claimInvocationForAar()).toBe(id);
      });
      expect(currentCommandDigest()).toBe(outer);
      expect(currentInvocationId()).toBe(id);
      expect(() => claimInvocationForAar()).toThrow("invocation already claimed for AAR emission");
      return value;
    })).toBe(value);
    expect(currentCommandDigest()).toBeUndefined();
    expect(currentInvocationId()).toBe(id);
    expect(() => claimInvocationForAar()).toThrow("invocation already claimed for AAR emission");
  });
  expect(currentCommandDigest()).toBeUndefined();
  expect(currentInvocationId()).toBeUndefined();
});

test("W2a primitives: throwing and rejecting dispatch scopes restore context without consuming claims", async () => {
  const outer = "a".repeat(64), inner = "b".repeat(64);
  await runWithInvocation(async () => {
    const id = currentInvocationId()!;
    await runAsDispatch(outer, async () => {
      expect(() => runAsDispatch(inner, () => {
        expect(currentCommandDigest()).toBe(inner);
        expect(currentInvocationId()).toBe(id);
        throw Error("sync failure");
      })).toThrow("sync failure");
      expect(currentCommandDigest()).toBe(outer);
      await expect(runAsDispatch(inner, async () => {
        await Promise.resolve();
        expect(currentCommandDigest()).toBe(inner);
        expect(currentInvocationId()).toBe(id);
        throw Error("async failure");
      })).rejects.toThrow("async failure");
      expect(currentCommandDigest()).toBe(outer);
      expect(currentInvocationId()).toBe(id);
    });
    expect(currentCommandDigest()).toBeUndefined();
    expect(currentInvocationId()).toBe(id);
    expect(claimInvocationForAar()).toBe(id);
  });
  expect(currentCommandDigest()).toBeUndefined();
  expect(currentInvocationId()).toBeUndefined();
});

test("W2a primitives: interleaved dispatch scopes isolate digests and preserve one shared claim", async () => {
  await runWithInvocation(async () => {
    const id = currentInvocationId()!;
    const started = Promise.withResolvers<void>(), claimed = Promise.withResolvers<void>();
    const first = runAsDispatch("a".repeat(64), async () => {
      await started.promise;
      expect(currentCommandDigest()).toBe("a".repeat(64));
      expect(currentInvocationId()).toBe(id);
      try { expect(claimInvocationForAar()).toBe(id); }
      finally { claimed.resolve(); }
    });
    expect(currentCommandDigest()).toBeUndefined();
    const second = runAsDispatch("b".repeat(64), async () => {
      started.resolve();
      await claimed.promise;
      expect(currentCommandDigest()).toBe("b".repeat(64));
      expect(currentInvocationId()).toBe(id);
      expect(() => claimInvocationForAar()).toThrow("invocation already claimed for AAR emission");
    });
    expect(currentCommandDigest()).toBeUndefined();
    await Promise.all([first, second]);
    expect(currentCommandDigest()).toBeUndefined();
    expect(currentInvocationId()).toBe(id);
    expect(() => claimInvocationForAar()).toThrow("invocation already claimed for AAR emission");
  });
  expect(currentCommandDigest()).toBeUndefined();
  expect(currentInvocationId()).toBeUndefined();
});

test("real MCP calls retain distinct invocation IDs while interleaved", async () => {
  const server = new McpServer({ name: "invocation-test", version: "1" });
  withInvocations(server);
  const client = new Client({ name: "invocation-client", version: "1" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const started = Promise.withResolvers<void>();
  const ids: Record<string, string[]> = {};
  const requestIds: unknown[] = [];
  const order: string[] = [];
  server.tool("interleave", "test", { label: z.string() }, async ({ label }, extra) => {
    ids[label] = [currentInvocationId()!];
    requestIds.push(extra.requestId);
    expect(extra.signal).toBeInstanceOf(AbortSignal);
    order.push(`start:${label}`);
    if (Object.keys(ids).length === 2) started.resolve();
    await started.promise;
    await Bun.sleep(5);
    ids[label]!.push(currentInvocationId()!);
    const child = Bun.spawnSync([process.execPath, "-e", "process.exit(0)"], { stdout: "ignore", stderr: "pipe" });
    expect(child.exitCode).toBe(0);
    ids[label]!.push(currentInvocationId()!);
    order.push(`end:${label}`);
    return { content: [{ type: "text", text: label }] };
  });
  server.tool("throws", () => { throw new Error("handler failed normally"); });
  server.tool("rejects", async () => { await Bun.sleep(1); throw new Error("handler rejected normally"); });
  expect(currentInvocationId()).toBeUndefined();
  expect(() => server.registerTool("bypass", {}, () => ({ content: [] }))).toThrow("use server.tool");
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const calls = ["one", "two"].map(label => client.callTool({ name: "interleave", arguments: { label } }));
    expect(currentInvocationId()).toBeUndefined();
    const results = await Promise.all(calls);
    expect(results.map(result => result.content)).toEqual([
      [{ type: "text", text: "one" }], [{ type: "text", text: "two" }],
    ]);
    expect(order.slice(0, 2).sort()).toEqual(["start:one", "start:two"]);
    for (const samples of Object.values(ids)) {
      expect(samples).toHaveLength(3);
      expect(samples[0]).toMatch(/^[0-9a-f]{32}$/);
      expect(new Set(samples).size).toBe(1);
    }
    expect(ids.one![0]).not.toBe(ids.two![0]);
    expect(new Set(requestIds).size).toBe(2);
    for (const [name, message] of [["throws", "handler failed normally"], ["rejects", "handler rejected normally"]] as const) {
      const result = await client.callTool({ name });
      expect(result.isError).toBe(true);
      expect(result.content).toEqual([{ type: "text", text: message }]);
    }
    expect(currentInvocationId()).toBeUndefined();
  } finally {
    await client.close();
    await server.close();
  }
});

test("wrapper preserves callback receiver, all arguments, return identity and rejection", async () => {
  const server = new McpServer({ name: "callback-test", version: "1" });
  withInvocations(server);
  const receiver = {}, input = {}, extra = {}, tail = {};
  const value = { content: [] };
  const registered = server.tool("identity", function (this: unknown, ...args: unknown[]) {
    expect(this).toBe(receiver);
    expect(args).toEqual([input, extra, tail]);
    expect(args[0]).toBe(input);
    expect(args[1]).toBe(extra);
    expect(args[2]).toBe(tail);
    expect(currentInvocationId()).toMatch(/^[0-9a-f]{32}$/);
    return value;
  });
  expect(Reflect.apply(registered.handler as Function, receiver, [input, extra, tail])).toBe(value);
  const error = new Error("same rejection");
  const promise = Promise.reject(error);
  const rejected = server.tool("rejection", () => promise);
  const result = Reflect.apply(rejected.handler as Function, receiver, []);
  expect(result).toBe(promise);
  await expect(result).rejects.toBe(error);
  expect(currentInvocationId()).toBeUndefined();
  await server.close();
});

test("runWithInvocation returns values and restores context after nesting and throws", () => {
  const value = {};
  expect(runWithInvocation(() => {
    const outer = currentInvocationId();
    expect(outer).toMatch(/^[0-9a-f]{32}$/);
    expect(() => runWithInvocation(() => {
      expect(currentInvocationId()).not.toBe(outer);
      throw new Error("nested failure");
    })).toThrow("nested failure");
    expect(currentInvocationId()).toBe(outer);
    return value;
  })).toBe(value);
  expect(currentInvocationId()).toBeUndefined();
});


test("W2b invocation binding: claims require context and survive nesting, awaits and failures", async () => {
  expect(() => claimInvocationForAar()).toThrow("no invocation context");
  await Promise.all([1, 2].map(() => runWithInvocation(async () => {
    const id = currentInvocationId()!;
    expect(claimInvocationForAar()).toBe(id);
    await runWithInvocation(async () => {
      expect(currentInvocationId()).not.toBe(id);
      expect(claimInvocationForAar()).toBe(currentInvocationId()!);
      await Promise.resolve();
      expect(() => claimInvocationForAar()).toThrow("invocation already claimed for AAR emission");
    });
    await expect(Promise.reject(Error("emission failed"))).rejects.toThrow("emission failed");
    expect(currentInvocationId()).toBe(id);
    expect(() => claimInvocationForAar()).toThrow("invocation already claimed for AAR emission");
  })));
  expect(currentInvocationId()).toBeUndefined();
  expect(() => claimInvocationForAar()).toThrow("no invocation context");
});
