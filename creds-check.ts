import type { CameraAccounts } from "./account-for";
import { hasLineBreakOrNul } from "./curl-args";

export function unsafeCredentials(cameras: Record<string, CameraAccounts>, passwords: Record<string, string>): string[] {
  const unsafe: string[] = [];
  for (const [id, cam] of Object.entries(cameras)) {
    for (const account of [cam, cam.accounts?.viewer, cam.accounts?.operator]) {
      if (!account) continue;
      const { user, credKey } = account;
      if (hasLineBreakOrNul(user)) unsafe.push(`${id} username (credKey: ${credKey})`);
      if (passwords[credKey] !== undefined && hasLineBreakOrNul(passwords[credKey])) unsafe.push(`${id} password (credKey: ${credKey})`);
    }
  }
  return unsafe;
}

export function missingPasswords(passwords: Record<string, string>): string[] {
  return Object.entries(passwords).filter(([, password]) => password.trim() === "").map(([id]) => id);
}
