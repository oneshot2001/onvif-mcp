// Quote device text only at display boundaries; evidence keeps the raw value.
// Invisible (default-ignorable) code points are dropped so a hidden payload never reaches the model; a note outside
// the quotes marks that hidden text was there, so a value with hidden text reads differently from one without (two
// different hidden payloads on the same visible text still display alike).
export function deviceText(value: unknown, max = 200): string {
  const raw = String(value);
  const text = raw
    .replace(/\p{Default_Ignorable_Code_Point}/gu, "")
    .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, " ");
  const quoted = JSON.stringify(text.length > max ? text.slice(0, Math.max(0, max - 1)) + "…" : text);
  // Tab, LF, VT, FF, CR and the line separators render as spacing; any other dropped or spaced character was hidden.
  const hidden = /\p{Default_Ignorable_Code_Point}|[\u0000-\u0008\u000e-\u001f\u007f-\u009f]/u.test(raw);
  return hidden ? `${quoted} (hidden characters removed)` : quoted;
}

// Escape what JSON.stringify leaves raw but a reader cannot see (DEL, C1 controls, U+2028/2029, default-ignorable
// code points) as \uXXXX, so display text shows them inertly; inside JSON strings it still parses to the raw value.
export function escapeInvisible(text: string): string {
  return text.replace(/[\u007f-\u009f\u2028\u2029]|\p{Default_Ignorable_Code_Point}/gu, (c) =>
    c.split("").map((u) => "\\u" + u.charCodeAt(0).toString(16).padStart(4, "0")).join(""));
}
