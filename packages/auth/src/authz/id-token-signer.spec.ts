import { createLocalJWKSet, exportPKCS8, exportSPKI, generateKeyPair, jwtVerify } from "jose";
import { describe, expect, it } from "vite-plus/test";

import { IdTokenSigner, type IdTokenSignerOptions } from "./id-token-signer";

// Fixed time base: the signer stamps iat/exp from this, and jwtVerify is pinned
// to the same instant via `currentDate` so the exp check is deterministic.
const NOW_MS = 1_700_000_000_000;
const NOW = new Date(NOW_MS);

async function makeSigner(over?: Partial<IdTokenSignerOptions>): Promise<IdTokenSigner> {
  const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
  return new IdTokenSigner({
    issuer: "https://idp.example/auth",
    kid: "k1",
    privateKey: await exportPKCS8(privateKey),
    publicKey: await exportSPKI(publicKey),
    clock: { now: () => NOW_MS },
    ...over,
  });
}

describe("IdTokenSigner", () => {
  it("mints an id_token a relying jose verifier accepts (iss/aud/sub/iat/exp + profile claims)", async () => {
    const signer = await makeSigner();
    const jwt = await signer.sign({
      sub: "user-1",
      aud: "client-1",
      nonce: "n0nce",
      extra: { email: "a@b.c", email_verified: true, name: "Alice" },
    });
    const jwks = createLocalJWKSet(await signer.jwks());
    const { payload, protectedHeader } = await jwtVerify(jwt, jwks, {
      issuer: "https://idp.example/auth",
      audience: "client-1",
      currentDate: NOW,
    });
    expect(protectedHeader.alg).toBe("RS256");
    expect(protectedHeader.kid).toBe("k1");
    expect(payload.sub).toBe("user-1");
    expect(payload.aud).toBe("client-1");
    expect(payload.nonce).toBe("n0nce");
    expect(payload.email).toBe("a@b.c");
    expect(payload.email_verified).toBe(true);
    expect(payload.name).toBe("Alice");
    expect(payload.iat).toBe(1_700_000_000); // clock ms / 1000
    expect(payload.exp).toBe(1_700_000_000 + 300); // default 5-min ttl
  });

  it("omits nonce when not supplied", async () => {
    const signer = await makeSigner();
    const jwt = await signer.sign({ sub: "u", aud: "c" });
    const { payload } = await jwtVerify(jwt, createLocalJWKSet(await signer.jwks()), {
      issuer: "https://idp.example/auth",
      audience: "c",
      currentDate: NOW,
    });
    expect(payload.nonce).toBeUndefined();
  });

  it("binds the audience — a token for client-1 is rejected for client-2", async () => {
    const signer = await makeSigner();
    const jwt = await signer.sign({ sub: "u", aud: "client-1" });
    const jwks = createLocalJWKSet(await signer.jwks());
    await expect(
      jwtVerify(jwt, jwks, {
        issuer: "https://idp.example/auth",
        audience: "client-2",
        currentDate: NOW,
      }),
    ).rejects.toThrow('unexpected "aud" claim value');
  });

  it("publishes a public-only JWKS (kid/alg/use, no private material)", async () => {
    const { keys } = await (await makeSigner()).jwks();
    expect(keys).toHaveLength(1);
    const jwk = keys[0];
    expect(jwk.kid).toBe("k1");
    expect(jwk.alg).toBe("RS256");
    expect(jwk.use).toBe("sig");
    expect(jwk.kty).toBe("RSA");
    expect(jwk.d).toBeUndefined(); // private exponent never leaks
    expect(jwk.p).toBeUndefined();
    expect(jwk.q).toBeUndefined();
  });

  it("honours a per-mint ttl override", async () => {
    const signer = await makeSigner({ ttlSec: 100 });
    const jwt = await signer.sign({ sub: "u", aud: "c", ttlSec: 30 });
    const { payload } = await jwtVerify(jwt, createLocalJWKSet(await signer.jwks()), {
      issuer: "https://idp.example/auth",
      audience: "c",
      currentDate: NOW,
    });
    expect(payload.exp! - payload.iat!).toBe(30);
  });

  it("supports ES256", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
    const signer = new IdTokenSigner({
      issuer: "https://i",
      kid: "e1",
      alg: "ES256",
      privateKey: await exportPKCS8(privateKey),
      publicKey: await exportSPKI(publicKey),
    });
    const jwt = await signer.sign({ sub: "u", aud: "c" });
    const { protectedHeader } = await jwtVerify(jwt, createLocalJWKSet(await signer.jwks()), {
      issuer: "https://i",
      audience: "c",
    });
    expect(protectedHeader.alg).toBe("ES256");
  });

  it("canonicalises a trailing-slash issuer (iss matches the no-slash form a verifier uses)", async () => {
    const signer = await makeSigner({ issuer: "https://idp.example/auth/" });
    expect(signer.issuer).toBe("https://idp.example/auth");
    const jwt = await signer.sign({ sub: "u", aud: "c" });
    const { payload } = await jwtVerify(jwt, createLocalJWKSet(await signer.jwks()), {
      issuer: "https://idp.example/auth",
      audience: "c",
      currentDate: NOW,
    });
    expect(payload.iss).toBe("https://idp.example/auth");
  });
});
