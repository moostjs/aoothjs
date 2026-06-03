import { createHash, randomBytes } from "node:crypto";

/**
 * PKCE / CSRF primitives (RFC 7636 + OIDC nonce). All values are URL-safe
 * base64url with no padding, so they ride in query params and cookies without
 * escaping. Pure `node:crypto` — no I/O, fully deterministic-testable by
 * stubbing nothing (only the randomness varies).
 */

function base64url(buf: Buffer): string {
  return buf.toString("base64url");
}

export interface PkcePair {
  /** The high-entropy secret kept server-side (cookie / wf state). */
  verifier: string;
  /** `base64url(SHA-256(verifier))` — sent in the authorization request. */
  challenge: string;
  /** Always `S256` — the plain method is intentionally not offered. */
  method: "S256";
}

/**
 * Mint a fresh PKCE pair. The 32-byte verifier base64url-encodes to 43 chars,
 * comfortably inside RFC 7636's 43–128 range.
 */
export function createPkcePair(): PkcePair {
  const verifier = base64url(randomBytes(32));
  return { verifier, challenge: pkceChallengeFor(verifier), method: "S256" };
}

/** Recompute the S256 challenge for a known verifier (verification side). */
export function pkceChallengeFor(verifier: string): string {
  return base64url(createHash("sha256").update(verifier).digest());
}

/** OIDC `nonce` — minted at `/start`, bound into state, asserted in `exchange()`. */
export function generateNonce(bytes = 32): string {
  return base64url(randomBytes(bytes));
}

/** Random component bound into the signed `state` (anti-CSRF / anti-replay). */
export function generateRandomState(bytes = 32): string {
  return base64url(randomBytes(bytes));
}
