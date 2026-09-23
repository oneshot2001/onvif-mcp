import { describe, expect, test } from "bun:test";
import { parseParams } from "./vapix-params";

describe("VAPIX params", () => {
  test("root-prefixed and unprefixed lines return the same keys and values", () => {
    const body = "Brand.ProdShortName=AXIS TEST\nProperties.Firmware.Version=12.0\n";
    const expected = { "Brand.ProdShortName": "AXIS TEST", "Properties.Firmware.Version": "12.0" };
    expect(parseParams(body)).toEqual(expected);
    expect(parseParams(`root.${body.replaceAll("\n", "\nroot.")}`)).toEqual(expected);
  });

  test("handles CRLF input without retaining carriage returns", () => {
    expect(parseParams("root.Brand.ProdShortName=AXIS TEST\r\nProperties.Firmware.Version=12.0\r\n")).toEqual({
      "Brand.ProdShortName": "AXIS TEST",
      "Properties.Firmware.Version": "12.0",
    });
  });

  test("preserves equals signs within a value", () => {
    expect(parseParams("root.Image.I0.Text.String=left=middle=right")).toEqual({
      "Image.I0.Text.String": "left=middle=right",
    });
  });

  test("skips non-param and error lines", () => {
    expect(parseParams("\nOK\n# Error: parameter not found\nError: request failed\n=missing key\n123=invalid\n# comment=value\nroot.Brand.ProdShortName=AXIS TEST\n")).toEqual({
      "Brand.ProdShortName": "AXIS TEST",
    });
  });

  test("returns keys in sorted order", () => {
    expect(Object.keys(parseParams("root.Properties.Firmware.Version=12.0\nImage.I0.Appearance.Rotation=0\nroot.Brand.ProdShortName=AXIS TEST"))).toEqual([
      "Brand.ProdShortName", "Image.I0.Appearance.Rotation", "Properties.Firmware.Version",
    ]);
  });
});
