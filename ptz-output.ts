import { deviceText } from "./device-text";

export function formatPresetRecall(camera: string, preset: string, pos: { body: string }): string {
  return `${camera} → preset '${preset}'\nsettled position: ${deviceText(pos.body.trim())}`;
}
