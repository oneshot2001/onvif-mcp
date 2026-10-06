import { validatePin } from "./curl-args";

export function cameraPinProblem(cameras: Record<string, { base: string; pin?: unknown }>): string | null {
  for (const [id, cam] of Object.entries(cameras)) {
    try {
      validatePin(cam.pin);
    } catch {
      return `Invalid camera pin: ${id}`;
    }
    if (cam.pin !== undefined && !cam.base.startsWith("https://")) return `Invalid camera pin: ${id}`;
  }
  return null;
}
