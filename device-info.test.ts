import { describe, expect, test } from "bun:test";
import { formatDeviceInfo, parseDeviceMeta } from "./device-info";

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
