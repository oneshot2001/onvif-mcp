export function missingPasswords(passwords: Record<string, string>): string[] {
  return Object.entries(passwords).filter(([, password]) => password.trim() === "").map(([id]) => id);
}
