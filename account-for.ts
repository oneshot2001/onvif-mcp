export type Account = { user: string; credKey: string };
export type CameraAccounts = Account & { accounts?: { viewer?: Account; operator?: Account } };

export function accountFor(tool: string, cam: CameraAccounts): Account {
  let account: Account | undefined;
  switch (tool) {
    case "list_cameras":
    case "get_snapshot":
    case "config_baseline":
    case "config_drift":
    case "commission_plan":
    case "commission_verify":
      account = cam.accounts?.viewer;
      break;
    case "ptz_move":
    case "ptz_preset":
      account = cam.accounts?.operator;
      break;
  }
  const { user, credKey } = account ?? cam;
  return { user, credKey };
}
