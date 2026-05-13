import { randomBytes } from "node:crypto";
import type { MfaMethod } from "./types";

export function maskEmail(email: string): string {
  if (!email) return "";
  const at = email.indexOf("@");
  if (at < 0) return mask(email);
  return mask(email.slice(0, at)) + email.slice(at);
}

export function maskPhone(phone: string): string {
  return mask(phone);
}

export function maskMfaValue(method: MfaMethod): string {
  switch (method.name) {
    case "email":
      return maskEmail(method.value);
    case "sms":
      return maskPhone(method.value);
    default:
      return "";
  }
}

function mask(s: string): string {
  if (!s) return "";
  if (s.length <= 2) return "***";
  const show = Math.max(1, Math.floor(s.length / 4));
  return s.slice(0, show) + "***" + s.slice(-show);
}

const DEFAULT_CHARSET =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";

export function generateSecureRandom(length: number, charset = DEFAULT_CHARSET): string {
  const bytes = randomBytes(length);
  const result: string[] = Array.from({ length });
  for (let i = 0; i < length; i++) {
    result[i] = charset[bytes[i] % charset.length];
  }
  return result.join("");
}

export function deepMerge(target: object, source: Record<string, unknown>): void {
  const t = target as Record<string, unknown>;
  for (const key of Object.keys(source)) {
    const sv = source[key];
    const tv = t[key];
    if (
      sv !== null &&
      typeof sv === "object" &&
      !Array.isArray(sv) &&
      tv !== null &&
      typeof tv === "object" &&
      !Array.isArray(tv)
    ) {
      deepMerge(tv as Record<string, unknown>, sv as Record<string, unknown>);
    } else {
      t[key] = sv;
    }
  }
}

export function setAtPath(obj: object, path: string, value: unknown): void {
  const parts = path.split(".");
  let current = obj as Record<string, unknown>;
  for (let i = 0; i < parts.length - 1; i++) {
    let next = current[parts[i]];
    if (next === undefined || next === null || typeof next !== "object") {
      next = {};
      current[parts[i]] = next;
    }
    current = next as Record<string, unknown>;
  }
  current[parts[parts.length - 1]] = value;
}

export function incrementAtPath(obj: object, path: string, amount: number): void {
  const parts = path.split(".");
  let current = obj as Record<string, unknown>;
  for (let i = 0; i < parts.length - 1; i++) {
    let next = current[parts[i]];
    if (next === undefined || next === null || typeof next !== "object") {
      next = {};
      current[parts[i]] = next;
    }
    current = next as Record<string, unknown>;
  }
  const leaf = parts[parts.length - 1];
  const existing = current[leaf];
  current[leaf] = (typeof existing === "number" ? existing : 0) + amount;
}
