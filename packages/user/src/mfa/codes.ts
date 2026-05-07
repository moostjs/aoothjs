import { createHash, timingSafeEqual } from "node:crypto";

/**
 * SHA-256 hash of an MFA code (e.g. one-time email/SMS code or backup code).
 *
 * Hex-encoded for stable, comparable output regardless of input case/format.
 * Use {@link verifyMfaCode} to compare a submitted plaintext code against the
 * stored hash in constant time.
 */
export function hashMfaCode(code: string): string {
  return createHash("sha256").update(code).digest("hex");
}

/**
 * Constant-time comparison of a submitted plaintext code against an
 * expected SHA-256 hex hash (as produced by {@link hashMfaCode}).
 *
 * Returns false for malformed/empty expected hashes (timingSafeEqual
 * requires equal-length, non-empty buffers).
 */
export function verifyMfaCode(submitted: string, expectedHash: string): boolean {
  if (!expectedHash) return false;
  const a = Buffer.from(hashMfaCode(submitted), "hex");
  const b = Buffer.from(expectedHash, "hex");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
