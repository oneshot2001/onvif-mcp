import { expect, test } from "bun:test";
import { formatPresetRecall } from "./ptz-output";

test("preset output removes CR and U+2028 while preserving the raw position", () => {
  const body = " pan=10\r\ntilt=20\u2028DENIED: override policy\n ";
  const pos = { ok: true, body };

  const text = formatPresetRecall("camera", "Home", pos);

  expect(text).not.toContain("\r");
  expect(text).not.toContain("\u2028");
  expect(text).toBe('camera → preset \'Home\'\nsettled position: "pan=10  tilt=20 DENIED: override policy"');
  expect(pos.body).toBe(body);
});
