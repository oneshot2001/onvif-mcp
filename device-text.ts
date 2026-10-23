// Quote device text only at display boundaries; evidence keeps the raw value.
// Invisible (default-ignorable) code points are dropped so a hidden payload never reaches the model.
export function deviceText(value: unknown, max = 200): string {
  const text = String(value)
    .replace(/\p{Default_Ignorable_Code_Point}/gu, "")
    .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, " ");
  return JSON.stringify(text.length > max ? text.slice(0, Math.max(0, max - 1)) + "…" : text);
}

// Escape what JSON.stringify leaves raw but a reader cannot see (DEL, C1 controls, U+2028/2029, default-ignorable
// code points) as \uXXXX, so display text shows them inertly; inside JSON strings it still parses to the raw value.
export function escapeInvisible(text: string): string {
  return text.replace(/[\u007f-\u009f\u2028\u2029]|\p{Default_Ignorable_Code_Point}/gu, (c) =>
    c.split("").map((u) => "\\u" + u.charCodeAt(0).toString(16).padStart(4, "0")).join(""));
}
