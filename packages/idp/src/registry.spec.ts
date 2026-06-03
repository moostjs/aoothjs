import { describe, expect, it } from "vitest";
import { OAuthError } from "./errors";
import { FakeIdentityProvider } from "./providers/fake";
import { OAuthProviderRegistry } from "./registry";
import type { ConfigurableProvider, SharedProviderConfig } from "./types";

const base = { baseUrl: "https://app.test", stateSecret: "secret-secret-secret-secret-1234" };

class SpyProvider implements ConfigurableProvider {
  readonly id = "spy";
  received?: SharedProviderConfig;
  applyDefaults(shared: SharedProviderConfig): void {
    this.received = shared;
  }
  authorizationUrl(): Promise<string> {
    return Promise.resolve("https://idp.test/auth");
  }
  exchange(): Promise<never> {
    return Promise.reject(new Error("not used"));
  }
}

describe("OAuthProviderRegistry — construction", () => {
  it("rejects a missing baseUrl / stateSecret", () => {
    expect(() => new OAuthProviderRegistry({ ...base, baseUrl: "", providers: [] })).toThrow(
      /baseUrl/,
    );
    expect(() => new OAuthProviderRegistry({ ...base, stateSecret: "", providers: [] })).toThrow(
      /stateSecret/,
    );
  });

  it("rejects duplicate provider ids", () => {
    expect(
      () =>
        new OAuthProviderRegistry({
          ...base,
          providers: [new FakeIdentityProvider({ id: "x" }), new FakeIdentityProvider({ id: "x" })],
        }),
    ).toThrow(/Duplicate provider/);
  });

  it("applies safe policy defaults", () => {
    const reg = new OAuthProviderRegistry({ ...base, providers: [] });
    expect(reg.policy.emailMatch).toBe("require-interactive-link");
    expect(reg.policy.allowSignup).toBe(true);
    expect(reg.policy.trustEmailVerifiedFrom).toEqual([]);
  });

  it("injects shared config into ConfigurableProviders (ctor value still wins elsewhere)", () => {
    const spy = new SpyProvider();
    const clock = { now: () => 42 };
    const reg = new OAuthProviderRegistry({
      ...base,
      providers: [spy],
      clockToleranceSec: 11,
      clock,
      jwks: { cacheTtlMs: 5000 },
    });
    expect(reg.ids()).toEqual(["spy"]);
    expect(spy.received?.clockToleranceSec).toBe(11);
    expect(spy.received?.clock).toBe(clock);
    expect(spy.received?.jwks?.cacheTtlMs).toBe(5000);
  });
});

describe("OAuthProviderRegistry — resolution", () => {
  const reg = new OAuthProviderRegistry({
    ...base,
    providers: [
      new FakeIdentityProvider({ id: "google" }),
      new FakeIdentityProvider({ id: "oidc" }),
    ],
  });

  it("resolves a known provider and reports membership", () => {
    expect(reg.has("google")).toBe(true);
    expect(reg.get("google")?.id).toBe("google");
    expect(reg.require("oidc").id).toBe("oidc");
    expect(reg.ids()).toEqual(["google", "oidc"]);
    expect(reg.list().map((p) => p.id)).toEqual(["google", "oidc"]);
  });

  it("throws UNKNOWN_PROVIDER on a miss", () => {
    expect(() => reg.require("nope")).toThrow(OAuthError);
    let caught: OAuthError | undefined;
    try {
      reg.require("nope");
    } catch (e) {
      caught = e as OAuthError;
    }
    expect(caught?.type).toBe("UNKNOWN_PROVIDER");
    expect(reg.get("nope")).toBeUndefined();
  });
});

describe("OAuthProviderRegistry — redirect URIs", () => {
  it("builds the fixed redirect_uri from baseUrl + callback path", () => {
    const reg = new OAuthProviderRegistry({ ...base, providers: [] });
    expect(reg.callbackPath("google")).toBe("/auth/oauth/google/callback");
    expect(reg.redirectUri("google")).toBe("https://app.test/auth/oauth/google/callback");
  });

  it("strips a trailing slash on baseUrl and honours a custom template", () => {
    const reg = new OAuthProviderRegistry({
      ...base,
      baseUrl: "https://app.test/",
      callbackPathTemplate: "/sso/:provider/back",
      providers: [],
    });
    expect(reg.redirectUri("gh")).toBe("https://app.test/sso/gh/back");
  });
});

describe("OAuthProviderRegistry — state helpers", () => {
  it("round-trips state through the registry secret", async () => {
    const reg = new OAuthProviderRegistry({ ...base, providers: [] });
    const token = await reg.signState({ random: "r", provider: "google", redirect: "/home" });
    expect(await reg.verifyState(token)).toMatchObject({ provider: "google", redirect: "/home" });
  });
});
