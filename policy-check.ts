export type Policy = Record<string, { tools: string[]; cameras: string[]; ptz?: { maxStep: number }; config?: { groups: string[]; remediate?: boolean; aoa?: boolean } }>;

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
