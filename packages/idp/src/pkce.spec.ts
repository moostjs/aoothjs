import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createPkcePair,
  deriveSeededPkce,
  generateNonce,
  generateRandomState,
  pkceChallengeFor,
} from "./pkce";

const BASE64URL = /^[A-Za-z0-9_-]+$/;

describe("createPkcePair", () => {
  it("mints an S256 pair whose challenge is base64url(SHA-256(verifier))", () => {
    const pair = createPkcePair();
    expect(pair.method).toBe("S256");
    expect(pair.verifier).toMatch(BASE64URL);
    expect(pair.challenge).toMatch(BASE64URL);
    // 32 random bytes → 43-char base64url verifier (RFC 7636 range is 43–128).
    expect(pair.verifier.length).toBe(43);

    const expected = createHash("sha256").update(pair.verifier).digest().toString("base64url");
    expect(pair.challenge).toBe(expected);
    expect(pair.challenge).toBe(pkceChallengeFor(pair.verifier));
  });

  it("is high-entropy (no two pairs collide)", () => {
    const verifiers = new Set(Array.from({ length: 64 }, () => createPkcePair().verifier));
    expect(verifiers.size).toBe(64);
  });
});

describe("pkceChallengeFor", () => {
  it("is deterministic for a known verifier", () => {
    expect(pkceChallengeFor("hello")).toBe(pkceChallengeFor("hello"));
    expect(pkceChallengeFor("hello")).not.toBe(pkceChallengeFor("world"));
  });
});

describe("generateNonce / generateRandomState", () => {
  it("produce unique base64url values", () => {
    expect(generateNonce()).toMatch(BASE64URL);
    expect(generateRandomState()).toMatch(BASE64URL);
    expect(generateNonce()).not.toBe(generateNonce());
    expect(generateRandomState()).not.toBe(generateRandomState());
  });
});

describe("deriveSeededPkce", () => {
  const SECRET = "server-state-secret-aaaaaaaaaaaaaaaa";

  it("derives an S256 pair shaped like createPkcePair (43-char base64url verifier)", () => {
    const out = deriveSeededPkce(SECRET, "seed-1");
    expect(out.method).toBe("S256");
    expect(out.verifier).toMatch(BASE64URL);
    expect(out.nonce).toMatch(BASE64URL);
    expect(out.challenge).toMatch(BASE64URL);
    // 32-byte HMAC-SHA256 digest → 43-char base64url, inside RFC 7636's 43–128.
    expect(out.verifier.length).toBe(43);
    expect(out.challenge).toBe(pkceChallengeFor(out.verifier));
  });

  it("is deterministic — /start and the callback re-derive the identical pair", () => {
    expect(deriveSeededPkce(SECRET, "seed-1")).toEqual(deriveSeededPkce(SECRET, "seed-1"));
  });

  it("keeps verifier and nonce independent (domain separation)", () => {
    const out = deriveSeededPkce(SECRET, "seed-1");
    expect(out.verifier).not.toBe(out.nonce);
  });

  it("changes with the seed", () => {
    const a = deriveSeededPkce(SECRET, "seed-1");
    const b = deriveSeededPkce(SECRET, "seed-2");
    expect(a.verifier).not.toBe(b.verifier);
    expect(a.nonce).not.toBe(b.nonce);
  });

  it("changes with the secret (a different server cannot re-derive the verifier)", () => {
    const a = deriveSeededPkce(SECRET, "seed-1");
    const b = deriveSeededPkce("a-different-server-secret-bbbbbbbb", "seed-1");
    expect(a.verifier).not.toBe(b.verifier);
    expect(a.nonce).not.toBe(b.nonce);
  });
});
