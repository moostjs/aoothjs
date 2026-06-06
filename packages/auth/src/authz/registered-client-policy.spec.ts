import { describe, expect, it } from "vite-plus/test";

import { AuthorizeError } from "./authz-errors";
import { RegisteredClientPolicy } from "./registered-client-policy";

const policy = new RegisteredClientPolicy({
  clients: [
    {
      clientId: "svc",
      redirectUris: ["https://svc.example/cb"],
      scopes: ["openid", "email", "profile"],
    },
    {
      clientId: "conf",
      redirectUris: ["https://conf.example/cb"],
      type: "confidential",
      clientSecret: "s3cret-value",
      accessToken: true,
      tokenPolicy: { kind: "svc-session" },
    },
    { clientId: "prefix", redirectPrefixes: ["https://app.example/oidc/"] },
    { clientId: "prefix2", redirectPrefixes: ["https://p2.example/cb"] }, // no trailing slash
  ],
});

describe("RegisteredClientPolicy.resolveClient", () => {
  it("resolves a known client + exact redirect; aud=clientId; id_token under openid", () => {
    const r = policy.resolveClient({
      clientId: "svc",
      redirectUri: "https://svc.example/cb",
      scope: "openid email",
    });
    expect(r.clientId).toBe("svc");
    expect(r.audience).toBe("svc");
    expect(r.idToken).toBe(true);
    expect(r.accessToken).toBe(false); // pure sign-in client: identity only
    expect(r.scope).toBe("openid email");
  });

  it("grants only allowed scopes (requested ∩ allowed)", () => {
    const r = policy.resolveClient({
      clientId: "svc",
      redirectUri: "https://svc.example/cb",
      scope: "openid email admin offline_access",
    });
    expect(r.scope).toBe("openid email");
  });

  it("no id_token when the granted scope lacks openid", () => {
    const r = policy.resolveClient({
      clientId: "svc",
      redirectUri: "https://svc.example/cb",
      scope: "email",
    });
    expect(r.idToken).toBe(false);
  });

  it("rejects an unknown client (invalid_client)", () => {
    try {
      policy.resolveClient({ clientId: "nope", redirectUri: "https://svc.example/cb" });
      expect.unreachable();
    } catch (e) {
      expect((e as AuthorizeError).code).toBe("invalid_client");
    }
  });

  it("rejects a missing client_id — never inferred (invalid_client)", () => {
    expect(() => policy.resolveClient({ redirectUri: "https://svc.example/cb" })).toThrow(
      AuthorizeError,
    );
  });

  it("rejects an unregistered redirect (invalid_redirect)", () => {
    try {
      policy.resolveClient({ clientId: "svc", redirectUri: "https://svc.example/evil" });
      expect.unreachable();
    } catch (e) {
      expect((e as AuthorizeError).code).toBe("invalid_redirect");
    }
  });

  it("rejects a redirect registered to a DIFFERENT client (no cross-client redirect)", () => {
    expect(() =>
      policy.resolveClient({ clientId: "svc", redirectUri: "https://conf.example/cb" }),
    ).toThrow(AuthorizeError);
  });

  it("strict-prefix: allows under the prefix, rejects a sibling path", () => {
    expect(
      policy.resolveClient({ clientId: "prefix", redirectUri: "https://app.example/oidc/cb?x=1" })
        .clientId,
    ).toBe("prefix");
    expect(() =>
      policy.resolveClient({ clientId: "prefix", redirectUri: "https://app.example/other" }),
    ).toThrow(AuthorizeError);
  });

  it("strict-prefix resists the loose-sibling + path-traversal bypasses", () => {
    // A trailing-slash prefix ("https://app.example/oidc/"):
    // - a loose-prefix sibling must NOT match …
    expect(() =>
      policy.resolveClient({ clientId: "prefix", redirectUri: "https://app.example/oidc-evil/cb" }),
    ).toThrow(AuthorizeError);
    // - and a `..` traversal that escapes the prefix is normalised, then rejected.
    expect(() =>
      policy.resolveClient({ clientId: "prefix", redirectUri: "https://app.example/oidc/../evil" }),
    ).toThrow(AuthorizeError);

    // A NO-trailing-slash prefix ("https://p2.example/cb") needs a path boundary:
    expect(
      policy.resolveClient({ clientId: "prefix2", redirectUri: "https://p2.example/cb" }).clientId,
    ).toBe("prefix2"); // exact
    expect(
      policy.resolveClient({ clientId: "prefix2", redirectUri: "https://p2.example/cb/x" })
        .clientId,
    ).toBe("prefix2"); // boundary "/"
    expect(
      policy.resolveClient({ clientId: "prefix2", redirectUri: "https://p2.example/cb?y=1" })
        .clientId,
    ).toBe("prefix2"); // boundary "?"
    for (const evil of [
      "https://p2.example/cbcd",
      "https://p2.example/cb-evil",
      "https://p2.example/cb.evil.com/x",
    ]) {
      expect(() => policy.resolveClient({ clientId: "prefix2", redirectUri: evil }), evil).toThrow(
        AuthorizeError,
      );
    }
  });

  it("a confidential client may be granted an access token + token policy", () => {
    const r = policy.resolveClient({
      clientId: "conf",
      redirectUri: "https://conf.example/cb",
      scope: "openid",
    });
    expect(r.accessToken).toBe(true);
    expect(r.tokenPolicy.kind).toBe("svc-session");
  });
});

describe("RegisteredClientPolicy.authenticateClient", () => {
  it("public client: no secret required (PKCE is the binding)", () => {
    expect(() => policy.authenticateClient({ clientId: "svc" })).not.toThrow();
  });

  it("confidential client: the correct secret passes", () => {
    expect(() =>
      policy.authenticateClient({ clientId: "conf", clientSecret: "s3cret-value" }),
    ).not.toThrow();
  });

  it("confidential client: a wrong or absent secret fails closed (invalid_client)", () => {
    expect(() => policy.authenticateClient({ clientId: "conf", clientSecret: "wrong" })).toThrow(
      AuthorizeError,
    );
    expect(() => policy.authenticateClient({ clientId: "conf" })).toThrow(AuthorizeError);
  });

  it("unknown client → invalid_client", () => {
    expect(() => policy.authenticateClient({ clientId: "nope", clientSecret: "x" })).toThrow(
      AuthorizeError,
    );
  });
});
