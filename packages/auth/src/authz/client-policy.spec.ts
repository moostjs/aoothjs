import { describe, expect, it } from "vite-plus/test";

import { AuthorizeError } from "./authz-errors";
import { isLoopbackRedirectUri, LoopbackClientPolicy } from "./client-policy";

describe("isLoopbackRedirectUri", () => {
  it("accepts loopback hosts on any port / scheme / path", () => {
    for (const uri of [
      "http://127.0.0.1:8080/callback",
      "http://127.0.0.1/cb",
      "http://localhost:51789/callback",
      "https://localhost:3000/x",
      "http://[::1]:9000/callback",
      "http://127.0.0.1:1/",
    ]) {
      expect(isLoopbackRedirectUri(uri), uri).toBe(true);
    }
  });

  it("rejects every non-loopback target incl. the classic bypasses", () => {
    for (const uri of [
      "https://evil.com/cb",
      "http://127.0.0.1.evil.com/cb", // host-suffix
      "http://localhost.evil.com/cb", // host-suffix
      "http://127.0.0.1@evil.com/cb", // embedded credentials → host is evil.com
      "http://user:pass@127.0.0.1/cb", // credentials present
      "http://0.0.0.0:8080/cb", // not a loopback literal
      "http://169.254.169.254/cb", // link-local metadata endpoint
      "ftp://127.0.0.1/cb", // non-http scheme
      "javascript:alert(1)",
      "not-a-url",
      "//127.0.0.1/cb",
    ]) {
      expect(isLoopbackRedirectUri(uri), uri).toBe(false);
    }
  });
});

describe("LoopbackClientPolicy", () => {
  it("resolves a loopback redirect to the default full-authority cli-session policy", () => {
    const policy = new LoopbackClientPolicy();
    const resolved = policy.resolveClient({ redirectUri: "http://127.0.0.1:5000/callback" });
    expect(resolved.redirectUri).toBe("http://127.0.0.1:5000/callback");
    expect(resolved.tokenPolicy.kind).toBe("cli-session");
    expect(resolved.tokenPolicy.ttl).toBe(30 * 24 * 60 * 60_000);
    expect(resolved.tokenPolicy.payload).toBeUndefined(); // full authority
  });

  it("rejects a non-loopback redirect with invalid_redirect", () => {
    const policy = new LoopbackClientPolicy();
    try {
      policy.resolveClient({ redirectUri: "https://evil.com/cb" });
      expect.unreachable("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(AuthorizeError);
      expect((e as AuthorizeError).code).toBe("invalid_redirect");
    }
  });

  it("honours a custom token policy", () => {
    const policy = new LoopbackClientPolicy({ tokenPolicy: { kind: "cli", ttl: 1000 } });
    const resolved = policy.resolveClient({ redirectUri: "http://localhost:1234/cb" });
    expect(resolved.tokenPolicy).toEqual({ kind: "cli", ttl: 1000 });
  });
});
