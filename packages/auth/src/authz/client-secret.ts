import { createHash } from "node:crypto";

import { generateOpaqueToken } from "../utils/opaque-token";
import { timingSafeEqualStr } from "../utils/timing-safe";

/**
 * Mint a confidential dynamic client's secret (RFC 7591 `client_secret`) — a
 * plain {@link generateOpaqueToken} mint. Returned to the registrant ONCE in
 * the registration response; only its {@link hashClientSecret} digest is
 * stored.
 */
export function mintClientSecret(): string {
  return generateOpaqueToken();
}

/**
 * Storage digest for a client secret — plain SHA-256 (hex). No KDF/salt on
 * purpose: the secret is high-entropy server-minted material (never a human
 * password), so brute-forcing the digest is infeasible and a per-row salt
 * buys nothing.
 */
export function hashClientSecret(secret: string): string {
  return createHash("sha256").update(secret, "utf8").digest("hex");
}

/** Constant-time check of a presented secret against a stored digest. */
export function verifyClientSecret(secret: string, hash: string): boolean {
  return timingSafeEqualStr(hashClientSecret(secret), hash);
}
