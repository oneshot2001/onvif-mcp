import { z } from "zod";

export const cameraId = z.string().min(1).max(64);
export const presetName = z.string().min(1).max(128);
export const paramName = z.string().min(1).max(128);
export const specRef = z.string().min(1).max(128);
