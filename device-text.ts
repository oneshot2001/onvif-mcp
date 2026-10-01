// Quote device text only at display boundaries; evidence keeps the raw value.
export function deviceText(value: unknown, max = 200): string {
  const text = String(value).replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, " ");
  return JSON.stringify(text.length > max ? text.slice(0, Math.max(0, max - 1)) + "…" : text);
}
