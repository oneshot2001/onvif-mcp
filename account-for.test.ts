import { describe, expect, test } from "bun:test";
import { accountFor, type CameraAccounts } from "./account-for";

const admin = { user: "root", credKey: "cam-admin" };
const viewer = { user: "viewer", credKey: "cam-viewer" };
const operator = { user: "operator", credKey: "cam-operator" };
const cam = { ...admin, accounts: { viewer, operator } };
const roles = [
  ["list_cameras", viewer],
  ["get_snapshot", viewer],
  ["config_baseline", viewer],
  ["config_drift", viewer],
  ["commission_plan", viewer],
  ["commission_verify", viewer],
  ["ptz_move", operator],
  ["ptz_preset", operator],
  ["config_remediate", admin],
  ["commission_apply", admin],
  ["get_receipts", admin],
] as const;

describe("camera account selection", () => {
  test.each(roles)("%s selects its expected account", (tool, expected) => {
    expect(accountFor(tool, cam)).toEqual(expected);
  });

  test.each(roles)("%s preserves the top-level account without roles", (tool) => {
    expect(accountFor(tool, admin)).toEqual(admin);
    expect(accountFor(tool, { ...admin, accounts: {} })).toEqual(admin);
  });

  test.each(roles)("%s falls back when its role alone is missing", (tool, expected) => {
    const partial: CameraAccounts = { ...admin, accounts: { ...cam.accounts } };
    if (expected === viewer) delete partial.accounts!.viewer;
    if (expected === operator) delete partial.accounts!.operator;
    expect(accountFor(tool, partial)).toEqual(admin);
  });

  test.each(["unknown_tool", "", "constructor", "__proto__"])("unknown tool %s falls back to top-level", (tool) => {
    expect(accountFor(tool, cam)).toEqual(admin);
  });

  test("selection leaves the camera configuration unchanged", () => {
    const before = structuredClone(cam);
    for (const [tool] of roles) accountFor(tool, cam);
    expect(cam).toEqual(before);
  });
});
