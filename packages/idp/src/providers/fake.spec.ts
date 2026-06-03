import { describe, expect, it } from "vitest";
import { FakeIdentityProvider } from "./fake";

describe("FakeIdentityProvider", () => {
  it("exchanges a registered code to a provider-stamped profile", async () => {
    const fake = new FakeIdentityProvider().setProfile("code-1", {
      subject: "sub-1",
      email: "a@example.com",
      emailVerified: true,
      raw: { sub: "sub-1" },
    });
    const profile = await fake.exchange({ code: "code-1", redirectUri: "x", codeVerifier: "v" });
    expect(profile).toMatchObject({ provider: "fake", subject: "sub-1", email: "a@example.com" });
  });

  it("falls back to the default profile for unregistered codes", async () => {
    const fake = new FakeIdentityProvider({ id: "g", defaultProfile: { subject: "def", raw: {} } });
    const p = await fake.exchange({ code: "whatever", redirectUri: "x", codeVerifier: "v" });
    expect(p).toMatchObject({ provider: "g", subject: "def" });
  });

  it("rejects an unknown code with EXCHANGE_FAILED when no default", async () => {
    const fake = new FakeIdentityProvider();
    await expect(
      fake.exchange({ code: "nope", redirectUri: "x", codeVerifier: "v" }),
    ).rejects.toMatchObject({ name: "OAuthError", type: "EXCHANGE_FAILED" });
  });

  it("builds an authorization URL carrying state / redirect / challenge / nonce", async () => {
    const fake = new FakeIdentityProvider({ authorizationEndpoint: "https://idp.test/auth" });
    const url = new URL(
      await fake.authorizationUrl({
        redirectUri: "https://app.test/cb",
        state: "st",
        codeChallenge: "ch",
        nonce: "no",
      }),
    );
    expect(url.origin + url.pathname).toBe("https://idp.test/auth");
    expect(url.searchParams.get("state")).toBe("st");
    expect(url.searchParams.get("redirect_uri")).toBe("https://app.test/cb");
    expect(url.searchParams.get("code_challenge")).toBe("ch");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("nonce")).toBe("no");
  });
});
