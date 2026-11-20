export type Policy = Record<string, { tools: string[]; cameras: string[]; ptz?: { maxStep: number; maxZoomStep?: number }; config?: { groups: string[]; remediate?: boolean; aoa?: boolean; rebaseline?: boolean }; rate?: { actuationPerMin?: number; snapshotPerMin?: number } }>;

export function unknownAgentKey(policy: Policy): string | null {
  for (const [agent, grants] of Object.entries(policy)) {
    for (const key of Object.keys(grants)) {
      if (!["tools", "cameras", "ptz", "rate", "config"].includes(key)) {
        return `policy agent '${agent}' has unknown key '${key}'`;
      }
    }
  }
  return null;
}

export function unknownPolicyCamera(policy: Policy, cameras: Record<string, unknown>): string | null {
  for (const [agent, grants] of Object.entries(policy)) {
    for (const camera of grants.cameras) {
      if (!Object.hasOwn(cameras, camera)) {
        return `policy agent '${agent}' names camera '${camera}' that is not in cameras.json`;
      }
    }
  }
  return null;
}

export function baselineDenied(config: { agent: string; rebaseline?: boolean }, exists: boolean): string | null {
  if (exists && config.rebaseline !== true) return `baseline exists; agent '${config.agent}' has no rebaseline grant`;
  return null;
}

export function ptzBound(ptz: { maxStep: number; maxZoomStep?: number } | undefined, pan: number, tilt: number, zoom: number): string | null {
  if (!ptz) return "agent has no ptz grant";
  if (typeof ptz.maxStep !== "number" || !Number.isFinite(ptz.maxStep) || Math.abs(pan) > ptz.maxStep || Math.abs(tilt) > ptz.maxStep) return `step exceeds policy maxStep ${ptz.maxStep}°`;
  const maxZoomStep = ptz.maxZoomStep === undefined ? 0 : ptz.maxZoomStep;
  if (typeof maxZoomStep !== "number" || !Number.isFinite(maxZoomStep) || Math.abs(zoom) > maxZoomStep) return `zoom step exceeds policy maxZoomStep ${maxZoomStep}`;
  return null;
}

export function ptzGranted(ptz: unknown): boolean {
  if (ptz === null || typeof ptz !== "object") return false;
  const { maxStep, maxZoomStep } = ptz as { maxStep?: unknown; maxZoomStep?: unknown };
  return typeof maxStep === "number" && Number.isFinite(maxStep) && maxStep > 0 &&
    (maxZoomStep === undefined || (typeof maxZoomStep === "number" && Number.isFinite(maxZoomStep)));
}

export function policyShapeProblem(agents: unknown): string | null {
  const isObject = (value: unknown): value is Record<string, unknown> =>
    value !== null && typeof value === "object" && !Array.isArray(value);
  const isStrings = (value: unknown): boolean =>
    Array.isArray(value) && value.every((entry) => typeof entry === "string");
  const isFiniteNumber = (value: unknown): boolean =>
    typeof value === "number" && Number.isFinite(value);
  if (!isObject(agents)) return "policy 'agents' must be an object";
  for (const [agent, grants] of Object.entries(agents)) {
    if (!isObject(grants)) return `policy agent '${agent}' must be an object`;
    const problem = (field: string, shape: string) => `policy agent '${agent}' field '${field}' must be ${shape}`;
    for (const field of ["tools", "cameras"]) {
      if (!isStrings(grants[field])) return problem(field, "an array of strings");
    }
    const { ptz, rate, config } = grants;
    if (ptz !== undefined) {
      if (!isObject(ptz)) return problem("ptz", "an object");
      if (!isFiniteNumber(ptz.maxStep)) return problem("ptz.maxStep", "a finite number");
      if (ptz.maxZoomStep !== undefined && !isFiniteNumber(ptz.maxZoomStep)) return problem("ptz.maxZoomStep", "a finite number");
    }
    if (rate !== undefined) {
      if (!isObject(rate)) return problem("rate", "an object");
      for (const field of ["actuationPerMin", "snapshotPerMin"]) {
        if (rate[field] !== undefined && !isFiniteNumber(rate[field])) return problem(`rate.${field}`, "a finite number");
      }
    }
    if (config !== undefined) {
      if (!isObject(config)) return problem("config", "an object");
      if (!isStrings(config.groups)) return problem("config.groups", "an array of strings");
      for (const field of ["remediate", "aoa", "rebaseline"]) {
        if (config[field] !== undefined && typeof config[field] !== "boolean") return problem(`config.${field}`, "a boolean");
      }
    }
  }
  return null;
}

export function allowed(policy: Policy, agent: string, tool: string, camera?: string): string | null {
  const p = policy[agent];
  if (!p) return `agent '${agent}' not in policy (fail closed)`;
  if (!p.tools.includes(tool)) return `tool '${tool}' not allowlisted for agent '${agent}'`;
  if (camera && !p.cameras.includes(camera)) return cameraNotAllowlisted(agent, p.cameras, camera);
  return null;
}

// Camera ids are case-sensitive. Agents copy the case from the model string that
// list_cameras prints beside the id (`q6325: Model="AXIS Q6325-LE"`), so an
// ASCII-case-only miss names the agent's own granted id when exactly one
// matches. ASCII folding only: toLowerCase would map U+212A KELVIN SIGN onto
// "k". Still a denial; the hint never covers another agent's cameras.
const asciiLower = (id: string) => id.replace(/[A-Z]/g, (c) => c.toLowerCase());
export function cameraNotAllowlisted(agent: string, granted: string[], camera: string): string {
  const matches = granted.filter((id) => asciiLower(id) === asciiLower(camera));
  const hint = matches.length === 1 ? ` (camera ids are case-sensitive; did you mean '${matches[0]}'?)` : "";
  return `camera '${camera}' not allowlisted for agent '${agent}'${hint}`;
}

export function configDenied(policy: Policy, agent: string, tool: string, camera: string, approve = false): string | null {
  const deny = allowed(policy, agent, tool, camera);
  if (deny) return deny;
  const config = policy[agent]?.config;
  if (!config) return `agent '${agent}' has no config grant`;
  if (tool === "config_remediate" && approve && !config.remediate) return `agent '${agent}' has no config remediation grant`;
  return null;
}
