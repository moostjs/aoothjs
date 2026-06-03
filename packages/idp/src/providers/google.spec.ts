import { beforeAll, describe, expect, it } from "vitest";
import { GoogleProvider } from "./google";
import { type TestSigner, makeRs256Signer, signIdToken, tokenFetch } from "./oidc-test-utils";

const GOOGLE_ISS = "https://accounts.google.com";
const CLIENT = "google-client";
const at = (ms: number) => ({ now: () => ms });

let signer: TestSigner;
beforeAll(async () => {
  signer = await makeRs256Signer();
});

describe("GoogleProvider", () => {
  it("pins id='google' and verifies a Google-issued id_token", async () => {
    const idToken = await signIdToken(signer, {
      iss: GOOGLE_ISS,
      aud: CLIENT,
      sub: "g-1",
      email: "x@gmail.com",
      email_verified: true,
    });
    const provider = new GoogleProvider({
      clientId: CLIENT,
      clientSecret: "s",
      authorizationEndpoint: `${GOOGLE_ISS}/o/oauth2/v2/auth`,
      tokenEndpoint: "https://oauth2.googleapis.com/token",
      jwksUri: "https://www.googleapis.com/oauth2/v3/certs",
      jwks: signer.jwks,
      clock: at(0),
      fetch: tokenFetch({ id_token: idToken }),
    });
    expect(provider.id).toBe("google");
    const profile = await provider.exchange({
      code: "c",
      redirectUri: `${GOOGLE_ISS}/cb`,
      codeVerifier: "v",
    });
    expect(profile).toMatchObject({
      provider: "google",
      subject: "g-1",
      email: "x@gmail.com",
      emailVerified: true,
    });
  });

  it("rejects an id_token from a non-Google issuer", async () => {
    const idToken = await signIdToken(signer, {
      iss: "https://accounts.evil.test",
      aud: CLIENT,
      sub: "g",
    });
    const provider = new GoogleProvider({
      clientId: CLIENT,
      clientSecret: "s",
      authorizationEndpoint: `${GOOGLE_ISS}/auth`,
      tokenEndpoint: `${GOOGLE_ISS}/token`,
      jwksUri: `${GOOGLE_ISS}/jwks`,
      jwks: signer.jwks,
      clock: at(0),
      fetch: tokenFetch({ id_token: idToken }),
    });
    await expect(
      provider.exchange({ code: "c", redirectUri: "x", codeVerifier: "v" }),
    ).rejects.toMatchObject({ type: "ID_TOKEN_INVALID" });
  });
});
