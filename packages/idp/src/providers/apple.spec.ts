import { type CryptoKey, exportPKCS8, generateKeyPair, jwtVerify } from "jose";
import { describe, expect, it } from "vite-plus/test";
import { OAuthError } from "../errors";
import type { FetchLike, FetchResponseLike } from "../types";
import { AppleProvider } from "./apple";
import { type TestSigner, discoveryDoc, makeEs256Signer, signIdToken } from "./oidc-test-utils";

const APPLE_ISSUER = "https://appleid.apple.com";
const NOW_SEC = 1_700_000_000;
const CLOCK = { now: () => NOW_SEC * 1000 };

const CLIENT_ID = "com.acme.service"; // Services ID
const TEAM_ID = "TEAM123456";
const KEY_ID = "KEY7654321";

interface AppleHarness {
  /** An EC P-256 `.p8` PEM that mints the client secret. */
  p8: string;
  /** The matching public key, for verifying the minted client-secret JWT. */
  p8Public: CryptoKey;
  /** Signs Apple's ES256 id_token. */
  idSigner: TestSigner;
}

async function makeHarness(): Promise<AppleHarness> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const p8 = await exportPKCS8(privateKey);
  const idSigner = await makeEs256Signer();
  return { p8, p8Public: publicKey, idSigner };
}

/** Token-endpoint fetch that CAPTURES each posted body and returns a fixed id_token. */
function tokenFetchCapturing(idToken: string): {
  fetch: FetchLike;
  secrets: string[];
} {
  const secrets: string[] = [];
  const fetch: FetchLike = (url, init) => {
    if (url.endsWith("/token")) {
      const body = new URLSearchParams(init?.body ?? "");
      const secret = body.get("client_secret");
      if (secret) secrets.push(secret);
      const res: FetchResponseLike = {
        ok: true,
        status: 200,
        json: () => Promise.resolve({ id_token: idToken }),
        text: () => Promise.resolve(JSON.stringify({ id_token: idToken })),
      };
      return Promise.resolve(res);
    }
    return Promise.resolve({
      ok: false,
      status: 404,
      json: () => Promise.resolve({}),
      text: () => Promise.resolve(""),
    });
  };
  return { fetch, secrets };
}

function makeProvider(h: AppleHarness, fetch: FetchLike, extra?: { clientSecretTtlSec?: number }) {
  return new AppleProvider({
    clientId: CLIENT_ID,
    teamId: TEAM_ID,
    keyId: KEY_ID,
    privateKey: h.p8,
    discovery: discoveryDoc(APPLE_ISSUER),
    jwks: h.idSigner.jwks,
    fetch,
    clock: CLOCK,
    clockToleranceSec: 5,
    ...extra,
  });
}

const exchangeArgs = {
  code: "the-code",
  redirectUri: "https://app.test/auth/oauth/apple/callback",
  codeVerifier: "v".repeat(43),
};

async function appleIdToken(
  h: AppleHarness,
  claims: { sub: string; email?: string; email_verified?: string | boolean },
): Promise<string> {
  return signIdToken(
    h.idSigner,
    { iss: APPLE_ISSUER, aud: CLIENT_ID, ...claims },
    { alg: "ES256", nowSec: NOW_SEC },
  );
}

describe("AppleProvider — construction", () => {
  it("requires teamId, keyId, and privateKey", async () => {
    const h = await makeHarness();
    expect(
      () => new AppleProvider({ clientId: CLIENT_ID, teamId: "", keyId: KEY_ID, privateKey: h.p8 }),
    ).toThrow(OAuthError);
    expect(
      () =>
        new AppleProvider({ clientId: CLIENT_ID, teamId: TEAM_ID, keyId: "", privateKey: h.p8 }),
    ).toThrow(OAuthError);
    expect(
      () =>
        new AppleProvider({ clientId: CLIENT_ID, teamId: TEAM_ID, keyId: KEY_ID, privateKey: "" }),
    ).toThrow(OAuthError);
  });

  it("constructs WITHOUT a static client secret (id 'apple')", async () => {
    const h = await makeHarness();
    const p = new AppleProvider({
      clientId: CLIENT_ID,
      teamId: TEAM_ID,
      keyId: KEY_ID,
      privateKey: h.p8,
    });
    expect(p.id).toBe("apple");
  });
});

describe("AppleProvider — authorizationUrl", () => {
  it("declares response_mode=form_post (required for email scope)", async () => {
    const h = await makeHarness();
    const p = makeProvider(h, tokenFetchCapturing("").fetch);
    const url = new URL(
      await p.authorizationUrl({
        redirectUri: "https://app.test/auth/oauth/apple/callback",
        state: "signed-state",
        codeChallenge: "the-challenge",
        nonce: "n0nce",
      }),
    );
    expect(url.origin + url.pathname).toBe(`${APPLE_ISSUER}/authorize`);
    expect(url.searchParams.get("response_mode")).toBe("form_post");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("scope")).toBe("openid email");
    expect(url.searchParams.get("nonce")).toBe("n0nce");
  });
});

describe("AppleProvider — client secret (ES256 .p8 JWT)", () => {
  it("mints a correctly-claimed ES256 client_secret and verifies under the .p8 public key", async () => {
    const h = await makeHarness();
    const idToken = await appleIdToken(h, { sub: "apple-sub-1", email: "a@privaterelay.test" });
    const { fetch, secrets } = tokenFetchCapturing(idToken);
    await makeProvider(h, fetch).exchange(exchangeArgs);

    expect(secrets).toHaveLength(1);
    // Verify at the SAME injected instant the secret was minted (its iat/exp are
    // stamped from CLOCK, far in the past relative to real wall-clock time).
    const { payload, protectedHeader } = await jwtVerify(secrets[0], h.p8Public, {
      algorithms: ["ES256"],
      currentDate: new Date(NOW_SEC * 1000),
    });
    expect(protectedHeader.alg).toBe("ES256");
    expect(protectedHeader.kid).toBe(KEY_ID);
    expect(payload.iss).toBe(TEAM_ID);
    expect(payload.sub).toBe(CLIENT_ID);
    expect(payload.aud).toBe(APPLE_ISSUER);
    expect(payload.iat).toBe(NOW_SEC);
    expect(payload.exp).toBe(NOW_SEC + 3600); // default TTL
  });

  it("reuses a cached secret across exchanges within its TTL", async () => {
    const h = await makeHarness();
    const idToken = await appleIdToken(h, { sub: "apple-sub-2", email: "b@x.test" });
    const { fetch, secrets } = tokenFetchCapturing(idToken);
    const p = makeProvider(h, fetch);
    await p.exchange(exchangeArgs);
    await p.exchange(exchangeArgs);
    expect(secrets).toHaveLength(2);
    expect(secrets[0]).toBe(secrets[1]); // same minted JWT reused
  });

  it("throws INVALID_CONFIG when the .p8 key cannot be imported", async () => {
    const h = await makeHarness();
    const idToken = await appleIdToken(h, { sub: "x", email: "x@x.test" });
    const p = new AppleProvider({
      clientId: CLIENT_ID,
      teamId: TEAM_ID,
      keyId: KEY_ID,
      privateKey: "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----",
      discovery: discoveryDoc(APPLE_ISSUER),
      jwks: h.idSigner.jwks,
      fetch: tokenFetchCapturing(idToken).fetch,
      clock: CLOCK,
    });
    await expect(p.exchange(exchangeArgs)).rejects.toMatchObject({ type: "INVALID_CONFIG" });
  });
});

describe("AppleProvider — normalize (string email_verified)", () => {
  it("coerces Apple's STRING 'true' to emailVerified:true", async () => {
    const h = await makeHarness();
    const idToken = await appleIdToken(h, {
      sub: "apple-sub-3",
      email: "c@privaterelay.test",
      email_verified: "true",
    });
    const profile = await makeProvider(h, tokenFetchCapturing(idToken).fetch).exchange(
      exchangeArgs,
    );
    expect(profile.provider).toBe("apple");
    expect(profile.subject).toBe("apple-sub-3");
    expect(profile.email).toBe("c@privaterelay.test");
    expect(profile.emailVerified).toBe(true);
  });

  it("coerces Apple's STRING 'false' to emailVerified:false", async () => {
    const h = await makeHarness();
    const idToken = await appleIdToken(h, {
      sub: "apple-sub-4",
      email: "d@x.test",
      email_verified: "false",
    });
    const profile = await makeProvider(h, tokenFetchCapturing(idToken).fetch).exchange(
      exchangeArgs,
    );
    expect(profile.emailVerified).toBe(false);
  });

  it("still honors a real boolean email_verified", async () => {
    const h = await makeHarness();
    const idToken = await appleIdToken(h, {
      sub: "apple-sub-5",
      email: "e@x.test",
      email_verified: true,
    });
    const profile = await makeProvider(h, tokenFetchCapturing(idToken).fetch).exchange(
      exchangeArgs,
    );
    expect(profile.emailVerified).toBe(true);
  });
});
