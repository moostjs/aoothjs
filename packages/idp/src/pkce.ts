import { createHash, createHmac, randomBytes } from "node:crypto";

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

export interface SeededPkce {
  /** PKCE code verifier — `HMAC(secret, "…verifier:" + seed)`, re-derivable, never stored. */
  verifier: string;
  /** OIDC nonce — `HMAC(secret, "…nonce:" + seed)`, independent of the verifier. */
  nonce: string;
  /** `base64url(SHA-256(verifier))` — sent in the authorization request. */
  challenge: string;
  /** Always `S256`. */
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

/**
 * STATELESS PKCE: deterministically DERIVE the code verifier + OIDC nonce from
 * a non-secret `seed` and the server's HMAC `secret`, instead of minting them
 * with {@link createPkcePair}/{@link generateNonce} and persisting the secret
 * half server-side.
 *
 * The `seed` is the same high-entropy value carried (in the clear) by the
 * signed-state `random` and the double-submit CSRF cookie — so the round-trip
 * needs NO server-side flow store: `/start` derives `{ verifier, nonce }` to
 * build the authorize request, and the callback re-derives the identical pair
 * from `state.random` to redeem the `code`. Because the verifier is
 * `HMAC(secret, seed)` and the secret never leaves the server, exposing the
 * seed in the URL discloses nothing — an attacker cannot recover the verifier.
 * Distinct domain-separation prefixes keep the verifier and the nonce
 * independent (neither is recoverable from the other).
 *
 * Same output range as {@link createPkcePair}: a 32-byte HMAC-SHA256 digest →
 * a 43-char base64url verifier, inside RFC 7636's 43–128.
 */
export function deriveSeededPkce(secret: string | Uint8Array, seed: string): SeededPkce {
  const verifier = base64url(
    createHmac("sha256", secret).update(`aooth/pkce-verifier:${seed}`).digest(),
  );
  const nonce = base64url(createHmac("sha256", secret).update(`aooth/oidc-nonce:${seed}`).digest());
  return { verifier, nonce, challenge: pkceChallengeFor(verifier), method: "S256" };
}
