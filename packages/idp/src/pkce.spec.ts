import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createPkcePair, generateNonce, generateRandomState, pkceChallengeFor } from "./pkce";

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
