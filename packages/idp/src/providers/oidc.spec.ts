import { beforeAll, describe, expect, it } from "vitest";
import type { FetchLike } from "../types";
import { OidcProvider, type OidcProviderOptions } from "./oidc";
import {
  type TestSigner,
  atHash,
  discoveryDoc,
  makeRs256Signer,
  signIdToken,
  tokenFetch,
} from "./oidc-test-utils";

const ISS = "https://issuer.test";
const CLIENT = "client-123";
const at = (ms: number) => ({ now: () => ms });

let signer: TestSigner;
beforeAll(async () => {
  signer = await makeRs256Signer();
});

function makeProvider(overrides: Partial<OidcProviderOptions> = {}): OidcProvider {
  return new OidcProvider({
    issuer: ISS,
    clientId: CLIENT,
    clientSecret: "client-secret",
    authorizationEndpoint: `${ISS}/authorize`,
    tokenEndpoint: `${ISS}/token`,
    jwksUri: `${ISS}/jwks`,
    jwks: signer.jwks,
    clock: at(0),
    ...overrides,
  });
}

async function exchange(
  idToken: string,
  extra: {
    access_token?: string;
    expectedNonce?: string;
    overrides?: Partial<OidcProviderOptions>;
  } = {},
) {
  const body: Record<string, unknown> = { id_token: idToken };
  if (extra.access_token) body.access_token = extra.access_token;
  const provider = makeProvider({ fetch: tokenFetch(body), ...extra.overrides });
  return provider.exchange({
    code: "auth-code",
    redirectUri: `${ISS}/cb`,
    codeVerifier: "verifier",
    expectedNonce: extra.expectedNonce,
  });
}

describe("OidcProvider.authorizationUrl", () => {
  it("builds a PKCE+OIDC authorization URL", async () => {
    const url = new URL(
      await makeProvider().authorizationUrl({
        redirectUri: `${ISS}/cb`,
        state: "the-state",
        codeChallenge: "the-challenge",
        nonce: "the-nonce",
      }),
    );
    expect(url.origin + url.pathname).toBe(`${ISS}/authorize`);
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("client_id")).toBe(CLIENT);
    expect(url.searchParams.get("redirect_uri")).toBe(`${ISS}/cb`);
    expect(url.searchParams.get("scope")).toBe("openid email profile");
    expect(url.searchParams.get("state")).toBe("the-state");
    expect(url.searchParams.get("code_challenge")).toBe("the-challenge");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("nonce")).toBe("the-nonce");
  });

  it("defaults the provider id to oidc:<issuer>", () => {
    expect(makeProvider().id).toBe(`oidc:${ISS}`);
  });
});

describe("OidcProvider.exchange — happy path", () => {
  it("verifies a valid id_token and normalizes the profile", async () => {
    const idToken = await signIdToken(signer, {
      iss: ISS,
      aud: CLIENT,
      sub: "user-1",
      email: "u@example.com",
      email_verified: true,
      name: "Test User",
      picture: "https://cdn.test/a.png",
    });
    const profile = await exchange(idToken);
    expect(profile).toMatchObject({
      provider: `oidc:${ISS}`,
      subject: "user-1",
      email: "u@example.com",
      emailVerified: true,
      displayName: "Test User",
      avatarUrl: "https://cdn.test/a.png",
    });
    expect(profile.raw).toBeTruthy();
  });

  it("does NOT coerce a non-boolean email_verified", async () => {
    const idToken = await signIdToken(signer, {
      iss: ISS,
      aud: CLIENT,
      sub: "u",
      email: "u@example.com",
      email_verified: "true", // string, not boolean
    });
    const profile = await exchange(idToken);
    expect(profile.emailVerified).toBeUndefined();
  });

  it("posts a correct token-exchange body", async () => {
    const idToken = await signIdToken(signer, { iss: ISS, aud: CLIENT, sub: "u" });
    let body = "";
    const spy: FetchLike = (_url, init) => {
      body = init?.body ?? "";
      return tokenFetch({ id_token: idToken })();
    };
    await makeProvider({ fetch: spy }).exchange({
      code: "the-code",
      redirectUri: `${ISS}/cb`,
      codeVerifier: "the-verifier",
    });
    const params = new URLSearchParams(body);
    expect(params.get("grant_type")).toBe("authorization_code");
    expect(params.get("code")).toBe("the-code");
    expect(params.get("code_verifier")).toBe("the-verifier");
    expect(params.get("redirect_uri")).toBe(`${ISS}/cb`);
    expect(params.get("client_id")).toBe(CLIENT);
    expect(params.get("client_secret")).toBe("client-secret");
  });
});

describe("OidcProvider.exchange — §7 ID-token validation", () => {
  it("rejects a wrong issuer", async () => {
    const idToken = await signIdToken(signer, { iss: "https://evil.test", aud: CLIENT, sub: "u" });
    await expect(exchange(idToken)).rejects.toMatchObject({ type: "ID_TOKEN_INVALID" });
  });

  it("rejects a wrong audience", async () => {
    const idToken = await signIdToken(signer, { iss: ISS, aud: "other-client", sub: "u" });
    await expect(exchange(idToken)).rejects.toMatchObject({ type: "ID_TOKEN_INVALID" });
  });

  it("rejects an expired token", async () => {
    const idToken = await signIdToken(signer, {
      iss: ISS,
      aud: CLIENT,
      sub: "u",
      iat: 0,
      exp: 100,
    });
    // provider clock at 200s, default 5s tolerance → expired
    await expect(exchange(idToken, { overrides: { clock: at(200_000) } })).rejects.toMatchObject({
      type: "ID_TOKEN_INVALID",
    });
  });

  it("rejects alg confusion (HS256 instead of the pinned asymmetric set)", async () => {
    const idToken = await signIdToken(
      signer,
      { iss: ISS, aud: CLIENT, sub: "u" },
      { alg: "HS256", key: new TextEncoder().encode("shared-secret-shared-secret-1234") },
    );
    await expect(exchange(idToken)).rejects.toMatchObject({ type: "ID_TOKEN_INVALID" });
  });

  it("asserts the nonce when one is expected", async () => {
    const ok = await signIdToken(signer, { iss: ISS, aud: CLIENT, sub: "u", nonce: "n-1" });
    await expect(exchange(ok, { expectedNonce: "n-1" })).resolves.toMatchObject({ subject: "u" });
    await expect(exchange(ok, { expectedNonce: "n-2" })).rejects.toMatchObject({
      type: "ID_TOKEN_INVALID",
    });
  });

  it("requires azp === clientId when there are multiple audiences", async () => {
    const noAzp = await signIdToken(signer, { iss: ISS, aud: [CLIENT, "aud-2"], sub: "u" });
    await expect(exchange(noAzp)).rejects.toMatchObject({ type: "ID_TOKEN_INVALID" });

    const withAzp = await signIdToken(signer, {
      iss: ISS,
      aud: [CLIENT, "aud-2"],
      sub: "u",
      azp: CLIENT,
    });
    await expect(exchange(withAzp)).resolves.toMatchObject({ subject: "u" });
  });

  it("validates at_hash when an access token + at_hash are present", async () => {
    const accessToken = "the-access-token";
    const good = await signIdToken(signer, {
      iss: ISS,
      aud: CLIENT,
      sub: "u",
      at_hash: atHash(accessToken),
    });
    await expect(exchange(good, { access_token: accessToken })).resolves.toMatchObject({
      subject: "u",
    });

    const bad = await signIdToken(signer, {
      iss: ISS,
      aud: CLIENT,
      sub: "u",
      at_hash: "deadbeef",
    });
    await expect(exchange(bad, { access_token: accessToken })).rejects.toMatchObject({
      type: "ID_TOKEN_INVALID",
    });
  });

  it("fails CLOSED with JWKS_FAILED when no signing key matches", async () => {
    const idToken = await signIdToken(signer, { iss: ISS, aud: CLIENT, sub: "u" });
    await expect(
      exchange(idToken, { overrides: { jwks: signer.jwksMismatched } }),
    ).rejects.toMatchObject({
      type: "JWKS_FAILED",
    });
  });
});

describe("OidcProvider.exchange — token-endpoint failures", () => {
  it("maps a missing id_token to ID_TOKEN_INVALID", async () => {
    const provider = makeProvider({ fetch: tokenFetch({ access_token: "only-this" }) });
    await expect(
      provider.exchange({ code: "c", redirectUri: `${ISS}/cb`, codeVerifier: "v" }),
    ).rejects.toMatchObject({ type: "ID_TOKEN_INVALID" });
  });

  it("maps a non-2xx token response to EXCHANGE_FAILED", async () => {
    const provider = makeProvider({ fetch: tokenFetch({ error: "invalid_grant" }, 400) });
    await expect(
      provider.exchange({ code: "c", redirectUri: `${ISS}/cb`, codeVerifier: "v" }),
    ).rejects.toMatchObject({ type: "EXCHANGE_FAILED" });
  });

  it("maps a network failure to EXCHANGE_FAILED", async () => {
    const provider = makeProvider({
      fetch: () => Promise.reject(new Error("ECONNREFUSED")),
    });
    await expect(
      provider.exchange({ code: "c", redirectUri: `${ISS}/cb`, codeVerifier: "v" }),
    ).rejects.toMatchObject({ type: "EXCHANGE_FAILED" });
  });
});

describe("OidcProvider — discovery", () => {
  it("discovers endpoints from the issuer and caches the document", async () => {
    const idToken = await signIdToken(signer, { iss: ISS, aud: CLIENT, sub: "u" });
    let wellKnownHits = 0;
    const router: FetchLike = (url) => {
      if (url.endsWith("/.well-known/openid-configuration")) {
        wellKnownHits++;
        return jsonRes(discoveryDoc(ISS));
      }
      if (url.endsWith("/token")) return jsonRes({ id_token: idToken });
      throw new Error(`unexpected fetch: ${url}`);
    };
    // No explicit endpoints → must discover. Injected jwks → no JWKS fetch.
    const provider = new OidcProvider({
      issuer: ISS,
      clientId: CLIENT,
      clientSecret: "s",
      jwks: signer.jwks,
      clock: at(0),
      fetch: router,
    });
    await provider.exchange({ code: "c", redirectUri: `${ISS}/cb`, codeVerifier: "v" });
    await provider.exchange({ code: "c", redirectUri: `${ISS}/cb`, codeVerifier: "v" });
    expect(wellKnownHits).toBe(1); // cached after first discovery
  });

  it("rejects a discovery document whose issuer does not match (INVALID_CONFIG)", async () => {
    const provider = new OidcProvider({
      issuer: ISS,
      clientId: CLIENT,
      clientSecret: "s",
      jwks: signer.jwks,
      discovery: discoveryDoc("https://evil.test"),
      clock: at(0),
    });
    await expect(
      provider.authorizationUrl({ redirectUri: "x", state: "s", codeChallenge: "c" }),
    ).rejects.toMatchObject({ type: "INVALID_CONFIG" });
  });
});

function jsonRes(body: unknown) {
  return Promise.resolve({
    ok: true,
    status: 200,
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  });
}
