export function parseEventMessage(data: unknown): { event?: { topic: string; timestamp?: string | number; message?: { data?: Record<string, unknown> } }; warning?: string } {
  try {
    const value = JSON.parse(typeof data === "string" ? data : Buffer.from(data as ArrayBuffer).toString()) as { method?: unknown; params?: { notification?: unknown }; error?: { message?: unknown } };
    const result: ReturnType<typeof parseEventMessage> = {};
    if (value.error) result.warning = `event stream error: ${String(value.error.message ?? "unknown")}`;
    const notification = value.method === "events:notify" ? value.params?.notification : null;
    if (notification && typeof notification === "object" && typeof (notification as { topic?: unknown }).topic === "string") result.event = notification as NonNullable<typeof result.event>;
    return result;
  } catch { return { warning: "event stream returned invalid JSON" }; }
}
