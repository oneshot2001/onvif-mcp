import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes } from "node:crypto";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

// Correlates camera traffic within one tool call; not proof of dispatch.
const invocation = new AsyncLocalStorage<{ id: string; aarClaimed: boolean }>();
const dispatch = new AsyncLocalStorage<string>();

export function runAsDispatch<T>(commandDigest: string, fn: () => T): T {
  return dispatch.run(commandDigest, fn);
}

export function currentCommandDigest(): string | undefined {
  return dispatch.getStore();
}

export function runWithInvocation<T>(fn: () => T): T {
  return invocation.run({ id: randomBytes(16).toString("hex"), aarClaimed: false }, fn);
}

export function currentInvocationId(): string | undefined {
  return invocation.getStore()?.id;
}

export function claimInvocationForAar(): string {
  const context = invocation.getStore();
  if (!context) throw new Error("no invocation context");
  if (context.aarClaimed) throw new Error("invocation already claimed for AAR emission");
  // Never release a claim: even a failed emission may have a durable attempt.
  context.aarClaimed = true;
  return context.id;
}

export type InvocationRecord = { invocation_id: string; tool: string; ts: string };
let recorder: ((entry: InvocationRecord) => void) | undefined;

/**
 * Gateway mode: persist the actor's claim of ownership for each invocation
 * BEFORE the tool body runs (C4: the custody report joins the witness sequence
 * against this claim set). The recorder must be durable before it returns.
 */
export function setInvocationRecorder(record: ((entry: InvocationRecord) => void) | undefined): void {
  recorder = record;
}

export function withInvocations(server: McpServer): void {
  const tool = server.tool;
  server.tool = function (this: McpServer, ...args: any[]) {
    const name = args[0];
    const callback = args[args.length - 1];
    if (typeof callback !== "function") throw new Error("server.tool requires a final callback");
    args[args.length - 1] = function (this: unknown, ...handlerArgs: unknown[]) {
      return runWithInvocation(() => {
        recorder?.({ invocation_id: currentInvocationId()!, tool: String(name), ts: new Date().toISOString() });
        return callback.apply(this, handlerArgs);
      });
    };
    return Reflect.apply(tool, this, args);
  } as McpServer["tool"];
  server.registerTool = () => { throw new Error("use server.tool with invocation tracking instead of registerTool"); };
}
