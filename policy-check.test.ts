import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { allowed, baselineDenied, configDenied, ptzBound, policyShapeProblem, unknownAgentKey, unsafeCameraId, type Policy } from "./policy-check";

test.each(["rateLimit", "rate_limit", "ratelimits", "rate ", "Rate", "ptzz", "_note"])("policy unknown agent key: rejects %s", (key) => {
  expect(unknownAgentKey({ operator: { tools: [], cameras: [], [key]: { actuationPerMin: 2 } } }))
    .toBe(`policy agent 'operator' has unknown key '${key}'`);
});

test("policy unknown agent key: checks the second agent after a clean first agent", () => {
  expect(unknownAgentKey(JSON.parse('{"viewer":{"tools":[],"cameras":[]},"operator":{"rateLimit":{"actuationPerMin":2}}}')))
    .toBe("policy agent 'operator' has unknown key 'rateLimit'");
});

test("policy unknown agent key: returns the first unknown key in agent and key JSON order", () => {
  expect(unknownAgentKey(JSON.parse('{"z-agent":{"tools":[],"ptzz":{},"Rate":{}},"a-agent":{"_note":"later"}}')))
    .toBe("policy agent 'z-agent' has unknown key 'ptzz'");
});

test("policy unknown agent key: accepts all five known keys", () => {
  expect(unknownAgentKey({ operator: {
    tools: [], cameras: [], ptz: { maxStep: 30 }, rate: { actuationPerMin: 2 }, config: { groups: [] },
  } })).toBeNull();
});

test("policy unknown agent key: accepts omitted optional keys and an empty policy", () => {
  expect(unknownAgentKey({ viewer: { tools: [], cameras: [] } })).toBeNull();
  expect(unknownAgentKey({})).toBeNull();
});

test("policy unknown agent key: ignores inherited keys and nested ptz and config keys", () => {
  const grants = Object.assign(Object.create({ rateLimit: {} }), {
    tools: [], cameras: [], ptz: { maxStep: 30, extra: true }, config: { groups: [], extra: true },
  });
  expect(unknownAgentKey({ operator: grants })).toBeNull();
});

test("policy unknown agent key: accepts the repository policy agents", () => {
  expect(unknownAgentKey(JSON.parse(readFileSync(join(import.meta.dir, "policy.json"), "utf8")).agents)).toBeNull();
});

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

const malformedLimits: [string, unknown][] = [
  ["unit string", "30deg"], ["numeric string", "30"], ["boolean", true],
  ["array", [30]], ["null", null], ["NaN", NaN], ["Infinity", Infinity],
  ["JSON overflow", JSON.parse("1e400")], ["Infinity string", "Infinity"],
  ["negative Infinity", -Infinity],
];

for (const [label, value] of [["missing", undefined], ...malformedLimits] as [string, unknown][]) {
  for (const axis of ["pan", "tilt"] as const) {
    test(`policy limit fail-closed: maxStep ${label} denies ${axis} 1`, () => {
      const ptz = (label === "missing" ? {} : { maxStep: value }) as Parameters<typeof ptzBound>[0];
      expect(ptzBound(ptz, axis === "pan" ? 1 : 0, axis === "tilt" ? 1 : 0, 0))
        .toStartWith("step exceeds policy maxStep");
    });
  }
}

for (const [label, value] of malformedLimits) {
  test(`policy limit fail-closed: maxZoomStep ${label} denies zoom 1 and 0`, () => {
    const ptz = { maxStep: 30, maxZoomStep: value } as Parameters<typeof ptzBound>[0];
    expect(ptzBound(ptz, 0, 0, 1)).toStartWith("zoom step exceeds policy maxZoomStep");
    expect(ptzBound(ptz, 0, 0, 0)).toStartWith("zoom step exceeds policy maxZoomStep");
  });
}

test("policy limit fail-closed: omitted maxZoomStep means zero", () => {
  expect(ptzBound({ maxStep: 30 }, 0, 0, 1)).toBe("zoom step exceeds policy maxZoomStep 0");
  expect(ptzBound({ maxStep: 30 }, 0, 0, 0)).toBeNull();
});

test("policy limit fail-closed: finite PTZ limits preserve signed boundaries", () => {
  const ptz = { maxStep: 30, maxZoomStep: 25 };
  for (const sign of [-1, 1]) {
    expect(ptzBound(ptz, sign * 30, 0, 0)).toBeNull();
    expect(ptzBound(ptz, 0, sign * 30, 0)).toBeNull();
    expect(ptzBound(ptz, sign * 31, 0, 0)).toBe("step exceeds policy maxStep 30°");
    expect(ptzBound(ptz, 0, sign * 31, 0)).toBe("step exceeds policy maxStep 30°");
    expect(ptzBound(ptz, 0, 0, sign * 25)).toBeNull();
    expect(ptzBound(ptz, 0, 0, sign * 26)).toBe("zoom step exceeds policy maxZoomStep 25");
  }
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

  test("a case-only camera miss is still denied and names the granted id", () => {
    const reason = "camera 'CAM' not allowlisted for agent 'viewer' (camera ids are case-sensitive; did you mean 'cam'?)";
    expect(allowed(policy, "viewer", "get_snapshot", "CAM")).toBe(reason);
    expect(configDenied(policy, "viewer", "config_drift", "CAM")).toBe(reason);
  });

  test("the camera hint names only a unique own grant, folds ASCII only, and never precedes the agent and tool checks", () => {
    const split: Policy = {
      viewer: { tools: ["get_snapshot"], cameras: ["cam"] },
      other: { tools: ["get_snapshot"], cameras: ["cam", "gate"] },
      twins: { tools: ["get_snapshot"], cameras: ["Dome", "dome"] },
      kelvin: { tools: ["get_snapshot"], cameras: ["k1"] },
    };
    expect(allowed(split, "viewer", "get_snapshot", "GATE")).toBe("camera 'GATE' not allowlisted for agent 'viewer'");
    expect(allowed(split, "twins", "get_snapshot", "DOME")).toBe("camera 'DOME' not allowlisted for agent 'twins'");
    expect(allowed({ twins: { ...split.twins!, cameras: ["dome", "Dome"] } }, "twins", "get_snapshot", "DOME")).toBe("camera 'DOME' not allowlisted for agent 'twins'");
    expect(allowed(split, "kelvin", "get_snapshot", "\u212A1")).toBe("camera '\u212A1' not allowlisted for agent 'kelvin'");
    expect(allowed(split, "viewer", "config_drift", "CAM")).toBe("tool 'config_drift' not allowlisted for agent 'viewer'");
    expect(allowed(split, "nobody", "get_snapshot", "CAM")).toBe("agent 'nobody' not in policy (fail closed)");
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

test("policy shape: a string cameras value, a string remediate and a string aoa are each refused naming the agent and the field", () => {
  expect(policyShapeProblem(JSON.parse('{"guard":{"tools":[],"cameras":"lobby2"}}')))
    .toBe("policy agent 'guard' field 'cameras' must be an array of strings");
  expect(policyShapeProblem(JSON.parse('{"guard":{"tools":[],"cameras":[],"config":{"groups":[],"remediate":"false"}}}')))
    .toBe("policy agent 'guard' field 'config.remediate' must be a boolean");
  expect(policyShapeProblem(JSON.parse('{"guard":{"tools":[],"cameras":[],"config":{"groups":[],"aoa":"no"}}}')))
    .toBe("policy agent 'guard' field 'config.aoa' must be a boolean");
});

test("policy shape: one wrong type per key is refused with the message for that key", () => {
  const cases: [string, string][] = [
    ['null', "policy 'agents' must be an object"],
    ['[]', "policy 'agents' must be an object"],
    ['"all"', "policy 'agents' must be an object"],
    ['{"guard":"all"}', "policy agent 'guard' must be an object"],
    ['{"guard":null}', "policy agent 'guard' must be an object"],
    ['{"guard":[]}', "policy agent 'guard' must be an object"],
  ];
  const fields: [string, string, string][] = [
    ['"cameras":[]', "tools", "an array of strings"],
    ['"tools":"all","cameras":[]', "tools", "an array of strings"],
    ['"tools":[1],"cameras":[]', "tools", "an array of strings"],
    ['"tools":[]', "cameras", "an array of strings"],
    ['"tools":[],"cameras":{}', "cameras", "an array of strings"],
    ['"tools":[],"cameras":[1]', "cameras", "an array of strings"],
  ];
  const grants: [string, string, string][] = [
    ['"ptz":null', "ptz", "an object"],
    ['"ptz":[]', "ptz", "an object"],
    ['"ptz":1', "ptz", "an object"],
    ['"ptz":{}', "ptz.maxStep", "a finite number"],
    ['"ptz":{"maxStep":"30"}', "ptz.maxStep", "a finite number"],
    ['"ptz":{"maxStep":1e999}', "ptz.maxStep", "a finite number"],
    ['"ptz":{"maxStep":30,"maxZoomStep":"25"}', "ptz.maxZoomStep", "a finite number"],
    ['"ptz":{"maxStep":30,"maxZoomStep":null}', "ptz.maxZoomStep", "a finite number"],
    ['"ptz":{"maxStep":30,"maxZoomStep":-1e999}', "ptz.maxZoomStep", "a finite number"],
    ['"rate":null', "rate", "an object"],
    ['"rate":[]', "rate", "an object"],
    ['"rate":1', "rate", "an object"],
    ['"rate":{"actuationPerMin":"6"}', "rate.actuationPerMin", "a finite number"],
    ['"rate":{"actuationPerMin":1e999}', "rate.actuationPerMin", "a finite number"],
    ['"rate":{"snapshotPerMin":null}', "rate.snapshotPerMin", "a finite number"],
    ['"rate":{"snapshotPerMin":true}', "rate.snapshotPerMin", "a finite number"],
    ['"config":true', "config", "an object"],
    ['"config":null', "config", "an object"],
    ['"config":[]', "config", "an object"],
    ['"config":{}', "config.groups", "an array of strings"],
    ['"config":{"groups":"Image"}', "config.groups", "an array of strings"],
    ['"config":{"groups":[1]}', "config.groups", "an array of strings"],
    ['"config":{"groups":[],"remediate":1}', "config.remediate", "a boolean"],
    ['"config":{"groups":[],"aoa":0}', "config.aoa", "a boolean"],
    ['"config":{"groups":[],"rebaseline":"true"}', "config.rebaseline", "a boolean"],
    ['"config":{"groups":[],"rebaseline":null}', "config.rebaseline", "a boolean"],
  ];
  fields.push(...grants.map(([json, field, shape]): [string, string, string] => [`"tools":[],"cameras":[],${json}`, field, shape]));
  cases.push(...fields.map(([json, field, shape]): [string, string] => [
    `{"guard":{${json}}}`, `policy agent 'guard' field '${field}' must be ${shape}`,
  ]));
  for (const [json, message] of cases) expect(policyShapeProblem(JSON.parse(json)), json).toBe(message);
});

test("policy shape: a wrong type on a later agent is caught when the first agent is clean", () => {
  expect(policyShapeProblem(JSON.parse('{"first":{"tools":[],"cameras":[]},"guard":{"tools":[],"cameras":"lobby2"}}')))
    .toBe("policy agent 'guard' field 'cameras' must be an array of strings");
  expect(policyShapeProblem(JSON.parse('{"first":{"tools":[],"cameras":[]},"second":{"tools":[],"cameras":[]},"guard":{"tools":[],"cameras":"lobby2"}}')))
    .toBe("policy agent 'guard' field 'cameras' must be an array of strings");
  expect(policyShapeProblem(JSON.parse('{"z-guard":{"tools":[],"cameras":"lobby2"},"a-guard":{"tools":"all","cameras":[]}}')))
    .toBe("policy agent 'z-guard' field 'cameras' must be an array of strings");
  expect(policyShapeProblem(JSON.parse('{"10":{"tools":"all","cameras":[]},"2":{"tools":[],"cameras":"lobby2"}}')))
    .toBe("policy agent '2' field 'cameras' must be an array of strings");
  expect(policyShapeProblem(JSON.parse('{"guard":{"config":null,"rate":null,"ptz":null,"cameras":null,"tools":null}}')))
    .toBe("policy agent 'guard' field 'tools' must be an array of strings");
  expect(policyShapeProblem(JSON.parse('{"guard":{"config":null,"rate":null,"ptz":null,"cameras":null,"tools":[]}}')))
    .toBe("policy agent 'guard' field 'cameras' must be an array of strings");
  expect(policyShapeProblem(JSON.parse('{"guard":{"config":null,"rate":null,"ptz":null,"cameras":[],"tools":[]}}')))
    .toBe("policy agent 'guard' field 'ptz' must be an object");
  expect(policyShapeProblem(JSON.parse('{"guard":{"config":null,"rate":null,"ptz":{"maxStep":30},"cameras":[],"tools":[]}}')))
    .toBe("policy agent 'guard' field 'rate' must be an object");
});

test("policy shape: valid policies return null", () => {
  expect(policyShapeProblem(JSON.parse(readFileSync(join(import.meta.dir, "policy.json"), "utf8")).agents)).toBeNull();
  expect(policyShapeProblem(JSON.parse('{}'))).toBeNull();
  expect(policyShapeProblem(JSON.parse('{"guard":{"tools":[],"cameras":[]}}'))).toBeNull();
  const readme = readFileSync(join(import.meta.dir, "README.md"), "utf8");
  const example = readme.slice(readme.indexOf("Grant agents authority in `policy.json`"))
    .match(/```json\n([\s\S]*?)\n```/)![1]!;
  expect(policyShapeProblem(JSON.parse(example).agents)).toBeNull();
  const grants = [
    '"ptz":{"maxStep":30,"maxZoomStep":25},"rate":{"actuationPerMin":6,"snapshotPerMin":30},"config":{"groups":["Image"],"remediate":true,"aoa":true,"rebaseline":true}',
    '"ptz":{"maxStep":30,"maxZoomStep":-1}',
    '"ptz":{"maxStep":0,"maxZoomStep":5}',
    '"ptz":{"maxStep":-1}',
    '"ptz":{"maxStep":0.5,"maxZoomStep":0}',
    '"rate":{}',
    '"rate":{"actuationPerMin":0,"snapshotPerMin":-1}',
    '"rate":{"actuationPerMin":-1,"snapshotPerMin":0}',
    '"config":{"groups":[]}',
    '"config":{"groups":[],"remediate":false,"aoa":false,"rebaseline":false}',
    '"ptz":{"maxStep":30,"unknown":null},"rate":{"unknown":true},"config":{"groups":[],"unknown":1}',
  ];
  for (const grant of grants) {
    expect(policyShapeProblem(JSON.parse(`{"guard":{"tools":[],"cameras":[],${grant}}}`)), grant).toBeNull();
  }
});

test("camera ids that could blur a list_cameras line, break a gateway URL or collide by case stop startup; plain ids pass", () => {
  expect(unsafeCameraId({ q6325: {}, "lobby-2.cam_1": {}, Gate: {} })).toBeNull();
  for (const id of ["west | annex", "front\nid=back", "a=b", "lobby 2", "\"cam\"", "", "-cam", "dock:west", "42", "0.0.0.42"]) {
    expect(unsafeCameraId({ ok: {}, [id]: {} })).toBe(`cameras.json camera id ${JSON.stringify(id)} must start with a letter and use only letters, digits, ".", "_" or "-"`);
  }
  expect(unsafeCameraId({ dome: {}, lobby: {}, Dome: {} })).toBe('cameras.json camera ids "dome" and "Dome" differ only in letter case');
});
