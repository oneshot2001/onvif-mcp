import { describe, expect, test } from "bun:test";
import { allowed, baselineDenied, configDenied, ptzBound, type Policy } from "./policy-check";

const policy: Policy = {
  viewer: { tools: ["get_snapshot", "config_drift"], cameras: ["cam"] },
  auditor: { tools: ["config_drift", "config_remediate"], cameras: ["cam"], config: { groups: ["Image"] } },
  operator: { tools: ["list_cameras", "config_drift", "config_remediate"], cameras: ["cam"], config: { groups: ["Image"], remediate: true } },
};

describe("baseline policy", () => {
  test("allows a first baseline without a rebaseline grant", () => {
    expect(baselineDenied({ agent: "auditor" }, false)).toBeNull();
  });

  test("denies an existing baseline without a rebaseline grant", () => {
    expect(baselineDenied({ agent: "auditor" }, true)).toBe("baseline exists; agent 'auditor' has no rebaseline grant");
    expect(baselineDenied({ agent: "viewer", rebaseline: false }, true)).toBe("baseline exists; agent 'viewer' has no rebaseline grant");
  });

  test("allows an existing baseline with an explicit rebaseline grant", () => {
    expect(baselineDenied({ agent: "operator", rebaseline: true }, true)).toBeNull();
  });

  test("a truthy non-boolean policy value is not a rebaseline grant", () => {
    const config = JSON.parse('{"agent":"auditor","rebaseline":"true"}');
    expect(baselineDenied(config, true)).toBe("baseline exists; agent 'auditor' has no rebaseline grant");
  });
});

describe("PTZ bounds", () => {
  const ptz = { maxStep: 30, maxZoomStep: 25 };

  test("allows in-bounds moves including both signed limits", () => {
    expect(ptzBound(ptz, 10, -15, 20)).toBeNull();
    expect(ptzBound(ptz, 30, -30, 25)).toBeNull();
    expect(ptzBound(ptz, -30, 30, -25)).toBeNull();
  });

  test.each([31, -31])("denies pan %i over the limit", (pan) => {
    expect(ptzBound(ptz, pan, 0, 0)).toBe("step exceeds policy maxStep 30°");
  });

  test.each([31, -31])("denies tilt %i over the limit", (tilt) => {
    expect(ptzBound(ptz, 0, tilt, 0)).toBe("step exceeds policy maxStep 30°");
  });

  test.each([26, -26])("denies zoom %i over the limit", (zoom) => {
    expect(ptzBound(ptz, 0, 0, zoom)).toBe("zoom step exceeds policy maxZoomStep 25");
  });

  test("only allows zero zoom when maxZoomStep is missing", () => {
    expect(ptzBound({ maxStep: 30 }, 10, -15, 1)).toBe("zoom step exceeds policy maxZoomStep 0");
    expect(ptzBound({ maxStep: 30 }, 10, -15, -1)).toBe("zoom step exceeds policy maxZoomStep 0");
    expect(ptzBound({ maxStep: 30 }, 10, -15, 0)).toBeNull();
  });

  test("denies without a PTZ grant", () => {
    expect(ptzBound(undefined, 0, 0, 0)).toBe("agent has no ptz grant");
  });
});

describe("policy checks", () => {
  test("unknown agent fails closed", () => {
    expect(allowed(policy, "unknown", "get_snapshot", "cam")).toBe("agent 'unknown' not in policy (fail closed)");
    expect(configDenied(policy, "unknown", "config_drift", "cam")).toBe("agent 'unknown' not in policy (fail closed)");
  });

  test("denies a tool not allowlisted", () => {
    expect(allowed(policy, "viewer", "config_remediate", "cam")).toBe("tool 'config_remediate' not allowlisted for agent 'viewer'");
    expect(configDenied(policy, "viewer", "config_remediate", "cam", true)).toBe("tool 'config_remediate' not allowlisted for agent 'viewer'");
  });

  test("denies a camera not allowlisted", () => {
    expect(allowed(policy, "viewer", "get_snapshot", "other")).toBe("camera 'other' not allowlisted for agent 'viewer'");
    expect(configDenied(policy, "viewer", "config_drift", "other")).toBe("camera 'other' not allowlisted for agent 'viewer'");
  });

  test("denies without a config grant", () => {
    expect(configDenied(policy, "viewer", "config_drift", "cam")).toBe("agent 'viewer' has no config grant");
  });

  test("denies approved remediation without a remediate grant", () => {
    expect(configDenied(policy, "auditor", "config_remediate", "cam", true)).toBe("agent 'auditor' has no config remediation grant");
  });

  test("allows remediation preview without a remediate grant", () => {
    expect(configDenied(policy, "auditor", "config_remediate", "cam")).toBeNull();
    expect(configDenied(policy, "auditor", "config_remediate", "cam", false)).toBeNull();
  });

  test("all allowed returns null", () => {
    expect(allowed(policy, "operator", "config_remediate", "cam")).toBeNull();
    expect(allowed(policy, "operator", "list_cameras")).toBeNull();
    expect(configDenied(policy, "auditor", "config_drift", "cam")).toBeNull();
    expect(configDenied(policy, "operator", "config_remediate", "cam", true)).toBeNull();
  });
});
