import type { ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";

// Every call persists a receipt, even when it only reads camera state.
export const TOOL_HINTS = {
  list_cameras: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  clock_check: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  get_snapshot: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  ptz_preset: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  ptz_move: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  config_baseline: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  config_drift: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  config_remediate: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  get_receipts: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  commission_plan: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  commission_apply: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  commission_verify: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
} satisfies Record<string, ToolAnnotations>;
