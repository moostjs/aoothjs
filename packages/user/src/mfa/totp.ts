import { createHmac, randomBytes } from "node:crypto";
import { base32 } from "../base-x";
import type { TotpConfig } from "../types";
import { generateSecureRandom } from "../utils";

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

export function verifyTotpCode(secret: string, code: string, config?: TotpConfig): boolean {
  const period = config?.period ?? 30;
  const digits = config?.digits ?? 6;
  const window = config?.window ?? 1;
  const now = (config?.clock ?? Date.now)();
  const counter = Math.floor(now / 1000 / period);

  // Decode once, reuse across window checks
  const key = base32.decode(secret);
  for (let i = -window; i <= window; i++) {
    if (hotpCode(key, counter + i, digits) === code) return true;
  }
  return false;
}

export function generateMfaCode(length = 6): string {
  return generateSecureRandom(length, "0123456789");
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
