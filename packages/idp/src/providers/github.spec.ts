import { describe, expect, it } from "vite-plus/test";
import { OAuthError } from "../errors";
import type { FetchLike, FetchResponseLike } from "../types";
import { GithubProvider } from "./github";

const TOKEN_URL = "https://github.com/login/oauth/access_token";
const USER_URL = "https://api.github.com/user";
const EMAILS_URL = "https://api.github.com/user/emails";

function jsonResponse(body: unknown, status = 200): FetchResponseLike {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  };
}

/** Record every request, route the response by URL. */
interface Routes {
  token?: FetchResponseLike | (() => FetchResponseLike);
  user?: FetchResponseLike | (() => FetchResponseLike);
  emails?: FetchResponseLike | (() => FetchResponseLike);
}

interface SeenRequest {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

function pick(r?: FetchResponseLike | (() => FetchResponseLike)): FetchResponseLike | undefined {
  return typeof r === "function" ? r() : r;
}

function routerFetch(routes: Routes): { fetch: FetchLike; seen: SeenRequest[] } {
  const seen: SeenRequest[] = [];
  const fetch: FetchLike = (url, init) => {
    seen.push({ url, method: init?.method, headers: init?.headers, body: init?.body });
    if (url.startsWith(TOKEN_URL)) {
      const r = pick(routes.token);
      if (r) return Promise.resolve(r);
    }
    if (url.startsWith(EMAILS_URL)) {
      const r = pick(routes.emails);
      if (r) return Promise.resolve(r);
    }
    if (url.startsWith(USER_URL)) {
      const r = pick(routes.user);
      if (r) return Promise.resolve(r);
    }
    return Promise.resolve(jsonResponse({ error: "unrouted" }, 404));
  };
  return { fetch, seen };
}

const exchangeArgs = {
  code: "the-code",
  redirectUri: "https://app.test/auth/oauth/github/callback",
  codeVerifier: "v".repeat(43),
};

describe("GithubProvider — construction", () => {
  it("requires clientId and clientSecret", () => {
    expect(() => new GithubProvider({ clientId: "", clientSecret: "s" })).toThrow(OAuthError);
    expect(() => new GithubProvider({ clientId: "c", clientSecret: "" })).toThrow(OAuthError);
  });

  it("defaults id to 'github'", () => {
    expect(new GithubProvider({ clientId: "c", clientSecret: "s" }).id).toBe("github");
  });
});

describe("GithubProvider — authorizationUrl", () => {
  it("builds the OAuth2 authorize URL with PKCE and no nonce", async () => {
    const p = new GithubProvider({ clientId: "client-123", clientSecret: "s" });
    const url = new URL(
      await p.authorizationUrl({
        redirectUri: "https://app.test/auth/oauth/github/callback",
        state: "signed-state",
        codeChallenge: "the-challenge",
        nonce: "ignored-by-oauth2",
        scopes: ["read:user", "user:email"],
      }),
    );
    expect(url.origin + url.pathname).toBe("https://github.com/login/oauth/authorize");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("client_id")).toBe("client-123");
    expect(url.searchParams.get("scope")).toBe("read:user user:email");
    expect(url.searchParams.get("state")).toBe("signed-state");
    expect(url.searchParams.get("code_challenge")).toBe("the-challenge");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    // OIDC-only — a pure-OAuth2 authorize request must NOT carry a nonce.
    expect(url.searchParams.has("nonce")).toBe(false);
  });
});

describe("GithubProvider — exchange", () => {
  it("normalizes a verified PRIMARY email to emailVerified:true", async () => {
    const { fetch, seen } = routerFetch({
      token: jsonResponse({ access_token: "gho_abc", token_type: "bearer" }),
      user: jsonResponse({
        id: 42,
        login: "octocat",
        name: "The Octocat",
        avatar_url: "https://avatars/octocat.png",
      }),
      emails: jsonResponse([
        { email: "secondary@x.test", primary: false, verified: true },
        { email: "octocat@github.test", primary: true, verified: true },
      ]),
    });
    const p = new GithubProvider({ clientId: "c", clientSecret: "s", fetch });
    const profile = await p.exchange(exchangeArgs);

    expect(profile.provider).toBe("github");
    expect(profile.subject).toBe("42"); // numeric id → string
    expect(profile.email).toBe("octocat@github.test"); // the PRIMARY, not the first
    expect(profile.emailVerified).toBe(true);
    expect(profile.displayName).toBe("The Octocat");
    expect(profile.avatarUrl).toBe("https://avatars/octocat.png");

    // The token request asked for JSON and sent the PKCE verifier + a User-Agent.
    const tokenReq = seen.find((s) => s.url.startsWith(TOKEN_URL));
    expect(tokenReq?.headers?.accept).toBe("application/json");
    expect(tokenReq?.headers?.["user-agent"]).toBeTruthy();
    expect(tokenReq?.body).toContain("code_verifier=");
    // API calls carry the bearer token + a User-Agent (GitHub rejects requests without one).
    const userReq = seen.find((s) => s.url.startsWith(USER_URL) && !s.url.startsWith(EMAILS_URL));
    expect(userReq?.headers?.authorization).toBe("Bearer gho_abc");
    expect(userReq?.headers?.["user-agent"]).toBeTruthy();
  });

  it("marks an UNVERIFIED primary email emailVerified:false", async () => {
    const { fetch } = routerFetch({
      token: jsonResponse({ access_token: "t" }),
      user: jsonResponse({ id: 7, login: "u" }),
      emails: jsonResponse([{ email: "u@x.test", primary: true, verified: false }]),
    });
    const profile = await new GithubProvider({ clientId: "c", clientSecret: "s", fetch }).exchange(
      exchangeArgs,
    );
    expect(profile.email).toBe("u@x.test");
    expect(profile.emailVerified).toBe(false);
  });

  it("falls back to the public profile email (unverified) when the emails scope is absent", async () => {
    const { fetch } = routerFetch({
      token: jsonResponse({ access_token: "t" }),
      user: jsonResponse({ id: 9, login: "u", email: "public@x.test" }),
      emails: jsonResponse({ message: "Requires user:email scope" }, 403),
    });
    const profile = await new GithubProvider({ clientId: "c", clientSecret: "s", fetch }).exchange(
      exchangeArgs,
    );
    expect(profile.email).toBe("public@x.test");
    expect(profile.emailVerified).toBe(false);
  });

  it("omits email entirely when neither emails nor a public email exist", async () => {
    const { fetch } = routerFetch({
      token: jsonResponse({ access_token: "t" }),
      user: jsonResponse({ id: 9, login: "u", email: null }),
      emails: jsonResponse([], 200),
    });
    const profile = await new GithubProvider({ clientId: "c", clientSecret: "s", fetch }).exchange(
      exchangeArgs,
    );
    expect(profile.email).toBeUndefined();
    expect(profile.emailVerified).toBeUndefined();
    expect(profile.subject).toBe("9");
  });

  it("falls back displayName to the login when name is null", async () => {
    const { fetch } = routerFetch({
      token: jsonResponse({ access_token: "t" }),
      user: jsonResponse({ id: 1, login: "loginname", name: null }),
      emails: jsonResponse([]),
    });
    const profile = await new GithubProvider({ clientId: "c", clientSecret: "s", fetch }).exchange(
      exchangeArgs,
    );
    expect(profile.displayName).toBe("loginname");
  });

  it("throws EXCHANGE_FAILED on GitHub's 200 + {error} code rejection", async () => {
    const { fetch } = routerFetch({
      token: jsonResponse({ error: "bad_verification_code" }),
    });
    await expect(
      new GithubProvider({ clientId: "c", clientSecret: "s", fetch }).exchange(exchangeArgs),
    ).rejects.toMatchObject({ type: "EXCHANGE_FAILED" });
  });

  it("throws EXCHANGE_FAILED on a non-2xx token response", async () => {
    const { fetch } = routerFetch({ token: jsonResponse({}, 500) });
    await expect(
      new GithubProvider({ clientId: "c", clientSecret: "s", fetch }).exchange(exchangeArgs),
    ).rejects.toMatchObject({ type: "EXCHANGE_FAILED" });
  });

  it("throws EXCHANGE_FAILED when the token response carries no access_token", async () => {
    const { fetch } = routerFetch({ token: jsonResponse({ token_type: "bearer" }) });
    await expect(
      new GithubProvider({ clientId: "c", clientSecret: "s", fetch }).exchange(exchangeArgs),
    ).rejects.toMatchObject({ type: "EXCHANGE_FAILED" });
  });

  it("throws EXCHANGE_FAILED when /user lacks an id", async () => {
    const { fetch } = routerFetch({
      token: jsonResponse({ access_token: "t" }),
      user: jsonResponse({ login: "u" }),
    });
    await expect(
      new GithubProvider({ clientId: "c", clientSecret: "s", fetch }).exchange(exchangeArgs),
    ).rejects.toMatchObject({ type: "EXCHANGE_FAILED" });
  });
});

describe("GithubProvider — applyDefaults", () => {
  it("adopts a registry-injected fetch when none was given to the ctor", async () => {
    const { fetch } = routerFetch({
      token: jsonResponse({ access_token: "t" }),
      user: jsonResponse({ id: 5, login: "u" }),
      emails: jsonResponse([]),
    });
    const p = new GithubProvider({ clientId: "c", clientSecret: "s" });
    p.applyDefaults({ fetch });
    const profile = await p.exchange(exchangeArgs);
    expect(profile.subject).toBe("5");
  });

  it("keeps a ctor fetch over an injected default", async () => {
    const ctor = routerFetch({
      token: jsonResponse({ access_token: "t" }),
      user: jsonResponse({ id: 111, login: "ctor" }),
      emails: jsonResponse([]),
    });
    const injected = routerFetch({
      token: jsonResponse({ access_token: "t" }),
      user: jsonResponse({ id: 999, login: "injected" }),
      emails: jsonResponse([]),
    });
    const p = new GithubProvider({ clientId: "c", clientSecret: "s", fetch: ctor.fetch });
    p.applyDefaults({ fetch: injected.fetch });
    const profile = await p.exchange(exchangeArgs);
    expect(profile.subject).toBe("111"); // ctor fetch wins
  });
});
