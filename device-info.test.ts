import { describe, expect, test } from "bun:test";
import { formatDeviceInfo, parseDeviceMeta, parseSnapshotUri, snapshotPath } from "./device-info";

test.each([
  ["@attacker.example/x.jpg", null],
  [".attacker.example/x.jpg", null],
  [":8443/x.jpg", null],
  ["x.jpg", null],
  ["", null],
  ["//attacker.example/x.jpg", null],
  ["ftp://attacker.example/x.jpg", null],
  ["http://[invalid/x.jpg", null],
  ["http://", null],
  ["HTTP://attacker.example/x.jpg", "/x.jpg"],
  ["hTtPs://attacker.example:8443/x.jpg", "/x.jpg"],
  ["https://user:uri-password@attacker.example/x.jpg", "/x.jpg"],
  ["/axis-cgi/jpg/image.cgi", "/axis-cgi/jpg/image.cgi"],
  ["/x.jpg?a=1&b=2#fragment", "/x.jpg?a=1&b=2"],
  ["http://attacker.example/x.jpg?a=1&b=2#fragment", "/x.jpg?a=1&b=2"],
  ["http://attacker.example//other.example/x.jpg", "//other.example/x.jpg"],
  ["http://attacker.example", "/"],
])("snapshot origin: path extraction for %s", (uri, expected) => {
  expect(snapshotPath(uri!)).toBe(expected);
});

describe("ONVIF snapshot URI", () => {
  test("failed request ignores a URI echoed in SOAP Fault detail", () => {
    const r = { ok: false, body: "<s:Fault><s:Detail><tt:Uri>http://x/jpg</tt:Uri></s:Detail></s:Fault>" };
    expect(parseSnapshotUri(r)).toBeNull();
  });

  test("successful request decodes ampersands in the snapshot URI", () => {
    const r = { ok: true, body: "<tt:Uri>http://cam/axis-cgi/jpg/image.cgi?a=1&amp;b=2</tt:Uri>" };
    expect(parseSnapshotUri(r)).toBe("http://cam/axis-cgi/jpg/image.cgi?a=1&b=2");
  });

  test("successful request preserves a plain snapshot URI", () => {
    expect(parseSnapshotUri({ ok: true, body: "<tt:Uri>http://x/jpg</tt:Uri>" })).toBe("http://x/jpg");
  });

  test.each(["", "<tt:Uri></tt:Uri>"])("successful request without a URI returns null: %s", (body) => {
    expect(parseSnapshotUri({ ok: true, body })).toBeNull();
  });
});

for (const protocol of ["vapix", "onvif"] as const) {
  describe(`${protocol} device info`, () => {
    for (const body of ["<html>401 Unauthorized</html>", ""]) {
      test(`failed request ignores body ${JSON.stringify(body)}`, () => {
        const r = { ok: false, body };
        expect(formatDeviceInfo(protocol, r)).toBe(`device info unavailable (request failed) | protocol=${protocol}`);
        expect(parseDeviceMeta(protocol, "camera-id", r)).toEqual({
          manufacturer: "unavailable", model: "unavailable", firmware: "unavailable",
        });
      });
    }
  });
}

test("successful VAPIX device info preserves formatted param.cgi output", () => {
  const r = { ok: true, body: "root.Brand.ProdShortName=AXIS Q6358-LE\r\nroot.Properties.PTZ.PTZ=yes\r\n" };
  expect(formatDeviceInfo("vapix", r)).toBe('"root.Brand.ProdShortName=AXIS Q6358-LE  root.Properties.PTZ.PTZ=yes" | protocol=vapix');
});

test.each([
  ["leading", "\uFEFFroot.Brand.ProdNbr=Q6358-LE"],
  ["trailing", "root.Brand.ProdNbr=Q6358-LE\uFEFF"],
])("U3 trim hidden: VAPIX device info flags %s U+FEFF", (_, body) => {
  const r = { ok: true, body: body! };
  expect(formatDeviceInfo("vapix", r)).toBe('"root.Brand.ProdNbr=Q6358-LE" (hidden characters removed) | protocol=vapix');
  expect(r.body).toBe(body!);
});

test("successful VAPIX metadata preserves parsed param.cgi values", () => {
  const r = { ok: true, body: "root.Brand.ProdNbr=Q6358-LE\r\nroot.Properties.Firmware.Version=12.6.1\r\n" };
  expect(parseDeviceMeta("vapix", "camera-id", r)).toEqual({
    manufacturer: "AXIS", model: "Q6358-LE", firmware: "12.6.1",
  });
});

test("successful ONVIF device info and metadata preserve SOAP response values", () => {
  const r = { ok: true, body: '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><tds:GetDeviceInformationResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:Manufacturer>AXIS</tds:Manufacturer><tds:Model>Q6325-LE</tds:Model><tds:FirmwareVersion>12.6.1</tds:FirmwareVersion></tds:GetDeviceInformationResponse></s:Body></s:Envelope>' };
  expect(formatDeviceInfo("onvif", r)).toBe('Model="AXIS Q6325-LE" | Firmware="12.6.1" | protocol=onvif');
  expect(parseDeviceMeta("onvif", "camera-id", r)).toEqual({
    manufacturer: "AXIS", model: "Q6325-LE", firmware: "12.6.1",
  });
});

test("successful empty responses preserve existing fallbacks", () => {
  const r = { ok: true, body: "" };
  expect(formatDeviceInfo("vapix", r)).toBe('"" | protocol=vapix');
  expect(formatDeviceInfo("onvif", r)).toBe('Model="? ?" | Firmware="?" | protocol=onvif');
  expect(parseDeviceMeta("vapix", "camera-id", r)).toEqual({ manufacturer: "AXIS", model: "camera-id", firmware: "unknown" });
  expect(parseDeviceMeta("onvif", "camera-id", r)).toEqual({ manufacturer: "unknown", model: "unknown", firmware: "unknown" });
});
