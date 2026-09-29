export type Policy = Record<string, { tools: string[]; cameras: string[]; ptz?: { maxStep: number; maxZoomStep?: number }; config?: { groups: string[]; remediate?: boolean; aoa?: boolean; rebaseline?: boolean }; rate?: { actuationPerMin?: number; snapshotPerMin?: number } }>;

export function baselineDenied(config: { agent: string; rebaseline?: boolean }, exists: boolean): string | null {
  if (exists && config.rebaseline !== true) return `baseline exists; agent '${config.agent}' has no rebaseline grant`;
  return null;
}

export function ptzBound(ptz: { maxStep: number; maxZoomStep?: number } | undefined, pan: number, tilt: number, zoom: number): string | null {
  if (!ptz) return "agent has no ptz grant";
  if (Math.abs(pan) > ptz.maxStep || Math.abs(tilt) > ptz.maxStep) return `step exceeds policy maxStep ${ptz.maxStep}°`;
  const maxZoomStep = ptz.maxZoomStep ?? 0;
  if (Math.abs(zoom) > maxZoomStep) return `zoom step exceeds policy maxZoomStep ${maxZoomStep}`;
  return null;
}

export function allowed(policy: Policy, agent: string, tool: string, camera?: string): string | null {
  const p = policy[agent];
  if (!p) return `agent '${agent}' not in policy (fail closed)`;
  if (!p.tools.includes(tool)) return `tool '${tool}' not allowlisted for agent '${agent}'`;
  if (camera && !p.cameras.includes(camera)) return `camera '${camera}' not allowlisted for agent '${agent}'`;
  return null;
}

export function configDenied(policy: Policy, agent: string, tool: string, camera: string, approve = false): string | null {
  const deny = allowed(policy, agent, tool, camera);
  if (deny) return deny;
  const config = policy[agent]?.config;
  if (!config) return `agent '${agent}' has no config grant`;
  if (tool === "config_remediate" && approve && !config.remediate) return `agent '${agent}' has no config remediation grant`;
  return null;
}
