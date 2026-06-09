import { createHmac, randomBytes, randomInt, timingSafeEqual } from "node:crypto";
import { base32 } from "../base-x";
import type { TotpConfig } from "../types";

export function generateTotpSecret(bytes = 20): string {
  return base32.encode(randomBytes(bytes)).toString().replace(/=+$/, "").toUpperCase();
}

export function generateTotpUri(
  secret: string,
  issuer: string,
  account: string,
  config?: Pick<TotpConfig, "period" | "digits">,
): string {
  const period = config?.period ?? 30;
  const digits = config?.digits ?? 6;
  const encodedIssuer = encodeURIComponent(issuer);
  const encodedAccount = encodeURIComponent(account);
  return `otpauth://totp/${encodedIssuer}:${encodedAccount}?secret=${secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=${digits}&period=${period}`;
}

export function generateTotpCode(secret: string, config?: TotpConfig): string {
  const period = config?.period ?? 30;
  const digits = config?.digits ?? 6;
  const now = (config?.clock ?? Date.now)();
  const counter = Math.floor(now / 1000 / period);
  return hotpCode(base32.decode(secret), counter, digits);
}

/**
 * Returns the matched HOTP counter when `code` is valid within the verification
 * window, otherwise `null`. Returning the counter (not a bool) lets the caller
 * persist `lastUsedWindow` and reject same-window replays (RFC 6238 §5.2 SHOULD).
 */
export function verifyTotpCode(secret: string, code: string, config?: TotpConfig): number | null {
  const period = config?.period ?? 30;
  const digits = config?.digits ?? 6;
  const window = config?.window ?? 1;
  const now = (config?.clock ?? Date.now)();
  const counter = Math.floor(now / 1000 / period);

  // Decode once, reuse across window checks
  const key = base32.decode(secret);
  // Submitted code must match expected `digits` length; reject otherwise so
  // `timingSafeEqual` (equal-length-buffer requirement) receives a clean input
  // and an attacker can't probe digit-count via a length-mismatch shortcut.
  if (typeof code !== "string" || code.length !== digits) return null;
  const submitted = Buffer.from(code, "utf8");

  // Constant-time per-window check: iterate the full window unconditionally so
  // a valid early-window match doesn't return faster than a late-window one.
  let matchedCounter: number | null = null;
  for (let i = -window; i <= window; i++) {
    const stepCounter = counter + i;
    const expected = Buffer.from(hotpCode(key, stepCounter, digits), "utf8");
    if (expected.length === submitted.length && timingSafeEqual(expected, submitted)) {
      matchedCounter = stepCounter;
    }
  }
  return matchedCounter;
}

export function generateMfaCode(length = 6): string {
  // CSPRNG, unbiased: randomInt() uses rejection sampling internally, so each
  // digit is uniform over 0-9 (no modulo bias). Never use Math.random() here —
  // these codes gate authentication, account recovery, and MFA.
  let code = "";
  for (let i = 0; i < length; i++) code += randomInt(10).toString();
  return code;
}

// RFC 4226 HOTP
function hotpCode(key: Buffer, counter: number, digits: number): string {
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuf.writeUInt32BE(counter >>> 0, 4);

  const hmac = createHmac("sha1", key);
  hmac.update(counterBuf);
  const hmacResult = hmac.digest();

  // Dynamic truncation
  const offset = hmacResult[hmacResult.length - 1] & 0x0f;
  const code =
    ((hmacResult[offset] & 0x7f) << 24) |
    ((hmacResult[offset + 1] & 0xff) << 16) |
    ((hmacResult[offset + 2] & 0xff) << 8) |
    (hmacResult[offset + 3] & 0xff);

  return (code % 10 ** digits).toString().padStart(digits, "0");
}
