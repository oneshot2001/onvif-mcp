import { describe, expect, test } from "bun:test";
import { allowed, configDenied, type Policy } from "./policy-check";

const policy: Policy = {
  viewer: { tools: ["get_snapshot", "config_drift"], cameras: ["cam"] },
  auditor: { tools: ["config_drift", "config_remediate"], cameras: ["cam"], config: { groups: ["Image"] } },
  operator: { tools: ["list_cameras", "config_drift", "config_remediate"], cameras: ["cam"], config: { groups: ["Image"], remediate: true } },
};

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
