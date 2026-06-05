import { createHash } from "node:crypto";
import {
  type CryptoKey,
  type JWTVerifyGetKey,
  SignJWT,
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
} from "jose";
import type { OidcDiscoveryDocument } from "./oidc";

/**
 * Shared OIDC test scaffolding — a real RS256 keypair, a local JWKS resolver
 * over it, and an id_token signer. No `.spec` suffix → vitest does not collect
 * it as a test; it is only imported by the provider specs.
 */
export interface TestSigner {
  privateKey: CryptoKey;
  kid: string;
  /** JWKS resolver that CONTAINS this signer's public key. */
  jwks: JWTVerifyGetKey;
  /** JWKS resolver that does NOT contain this signer's kid (→ no matching key). */
  jwksMismatched: JWTVerifyGetKey;
}

/** Build a signer for an arbitrary asymmetric alg (RS256 for OIDC, ES256 for Apple). */
export async function makeSigner(alg = "RS256", kid = "test-kid-1"): Promise<TestSigner> {
  const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true });
  const jwk = await exportJWK(publicKey);
  const jwks = createLocalJWKSet({ keys: [{ ...jwk, kid, alg, use: "sig" }] });

  const other = await generateKeyPair(alg, { extractable: true });
  const otherJwk = await exportJWK(other.publicKey);
  const jwksMismatched = createLocalJWKSet({
    keys: [{ ...otherJwk, kid: "other-kid", alg, use: "sig" }],
  });
  return { privateKey, kid, jwks, jwksMismatched };
}

export function makeRs256Signer(kid = "test-kid-1"): Promise<TestSigner> {
  return makeSigner("RS256", kid);
}

export function makeEs256Signer(kid = "test-es256-kid"): Promise<TestSigner> {
  return makeSigner("ES256", kid);
}

export interface IdTokenInput {
  iss: string;
  aud: string | string[];
  sub: string;
  email?: string;
  email_verified?: boolean | string;
  name?: string;
  picture?: string;
  nonce?: string;
  azp?: string;
  at_hash?: string;
  iat?: number;
  exp?: number;
}

const CUSTOM_CLAIMS = [
  "email",
  "email_verified",
  "name",
  "picture",
  "nonce",
  "azp",
  "at_hash",
] as const;

export async function signIdToken(
  signer: TestSigner,
  claims: IdTokenInput,
  opts: { alg?: string; key?: CryptoKey | Uint8Array; nowSec?: number } = {},
): Promise<string> {
  const now = opts.nowSec ?? 0;
  const payload: Record<string, unknown> = {};
  for (const k of CUSTOM_CLAIMS) {
    if (claims[k] !== undefined) payload[k] = claims[k];
  }
  return new SignJWT(payload)
    .setProtectedHeader({ alg: opts.alg ?? "RS256", kid: signer.kid })
    .setIssuer(claims.iss)
    .setAudience(claims.aud)
    .setSubject(claims.sub)
    .setIssuedAt(claims.iat ?? now)
    .setExpirationTime(claims.exp ?? now + 300)
    .sign(opts.key ?? signer.privateKey);
}

/** Compute a valid OIDC at_hash for an access token under the given alg. */
export function atHash(accessToken: string, alg = "RS256"): string {
  const sha = alg.endsWith("384") ? "sha384" : alg.endsWith("512") ? "sha512" : "sha256";
  const d = createHash(sha).update(accessToken).digest();
  return d.subarray(0, d.length / 2).toString("base64url");
}

export function discoveryDoc(issuer: string): OidcDiscoveryDocument {
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks`,
  };
}

/** A fake token-endpoint fetch returning a fixed JSON body. */
export function tokenFetch(body: Record<string, unknown>, status = 200) {
  return () =>
    Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      json: () => Promise.resolve(body),
      text: () => Promise.resolve(JSON.stringify(body)),
    });
}
