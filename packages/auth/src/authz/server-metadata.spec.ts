import { describe, expect, it } from "vite-plus/test";

import { buildAuthorizationServerMetadata } from "./server-metadata";

describe("buildAuthorizationServerMetadata", () => {
  it("derives endpoints from the issuer and pins the fixed capability arrays", () => {
    const doc = buildAuthorizationServerMetadata({ issuer: "https://x/auth" });
    expect(doc.issuer).toBe("https://x/auth");
    expect(doc.authorization_endpoint).toBe("https://x/auth/authorize");
    expect(doc.token_endpoint).toBe("https://x/auth/token");
    expect(doc.response_types_supported).toEqual(["code"]);
    expect(doc.grant_types_supported).toEqual(["authorization_code"]);
    expect(doc.code_challenge_methods_supported).toEqual(["S256"]);
    expect(doc.token_endpoint_auth_methods_supported).toEqual(["none", "client_secret_post"]);
  });

  it("strips a trailing slash from the issuer (RFC 8414 byte-identical exactness)", () => {
    const slashed = buildAuthorizationServerMetadata({ issuer: "https://x/auth/" });
    const bare = buildAuthorizationServerMetadata({ issuer: "https://x/auth" });
    expect(slashed).toEqual(bare);
    expect(slashed.issuer).toBe("https://x/auth");
    expect(slashed.authorization_endpoint).toBe("https://x/auth/authorize");
    expect(slashed.token_endpoint).toBe("https://x/auth/token");
  });

  it("omits optional fields entirely when not configured", () => {
    const doc = buildAuthorizationServerMetadata({ issuer: "https://x/auth" });
    expect(doc).not.toHaveProperty("registration_endpoint");
    expect(doc).not.toHaveProperty("jwks_uri");
    expect(doc).not.toHaveProperty("scopes_supported");
  });

  it("emits optional fields and explicit endpoints when configured", () => {
    const doc = buildAuthorizationServerMetadata({
      issuer: "https://x/auth",
      authorizationEndpoint: "https://x/auth/oauth/authorize",
      tokenEndpoint: "https://x/auth/oauth/token",
      registrationEndpoint: "https://x/auth/register",
      jwksUri: "https://x/auth/jwks",
      scopesSupported: ["openid", "profile"],
    });
    expect(doc.authorization_endpoint).toBe("https://x/auth/oauth/authorize");
    expect(doc.token_endpoint).toBe("https://x/auth/oauth/token");
    expect(doc.registration_endpoint).toBe("https://x/auth/register");
    expect(doc.jwks_uri).toBe("https://x/auth/jwks");
    expect(doc.scopes_supported).toEqual(["openid", "profile"]);
  });

  it('always includes "none" even when a custom auth-methods list omits it', () => {
    const doc = buildAuthorizationServerMetadata({
      issuer: "https://x",
      tokenEndpointAuthMethodsSupported: ["client_secret_basic"],
    });
    expect(doc.token_endpoint_auth_methods_supported).toEqual(["none", "client_secret_basic"]);
  });

  it('keeps a custom auth-methods list as-is when it already lists "none"', () => {
    const doc = buildAuthorizationServerMetadata({
      issuer: "https://x",
      tokenEndpointAuthMethodsSupported: ["client_secret_post", "none"],
    });
    expect(doc.token_endpoint_auth_methods_supported).toEqual(["client_secret_post", "none"]);
  });
});
