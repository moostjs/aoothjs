import { OAuthError } from "../errors";
import type {
  AuthorizationUrlArgs,
  ConfigurableProvider,
  ExchangeArgs,
  FetchLike,
  NormalizedProfile,
  SharedProviderConfig,
} from "../types";
import { buildAuthorizeUrl, fetchJson, resolveFetch } from "./oauth2-shared";

export interface GithubProviderOptions {
  /** Provider id. Default `'github'`. */
  id?: string;
  clientId: string;
  clientSecret: string;
  /** Requested scopes. Default `['read:user', 'user:email']` (email needs `user:email`). */
  scopes?: string[];
  /** `User-Agent` sent on the GitHub API calls (GitHub REQUIRES one). Default `'aoothjs'`. */
  userAgent?: string;

  // --- endpoints (override for tests / GitHub Enterprise) ---
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  userEndpoint?: string;
  emailsEndpoint?: string;

  // --- injectable seam (also set by the registry via applyDefaults) ---
  /** OAuth2 only — no clock is needed (no token-time validation). */
  fetch?: FetchLike;
}

const GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN = "https://github.com/login/oauth/access_token";
const GITHUB_USER = "https://api.github.com/user";
const GITHUB_EMAILS = "https://api.github.com/user/emails";
const DEFAULT_SCOPES = ["read:user", "user:email"];
const DEFAULT_USER_AGENT = "aoothjs";

/** GitHub `/user` shape — only the fields we read. */
interface GithubUser {
  id: number | string;
  login: string;
  name?: string | null;
  email?: string | null;
  avatar_url?: string;
}

/** One `/user/emails` entry. */
interface GithubEmail {
  email: string;
  primary: boolean;
  verified: boolean;
}

/**
 * Sign in with GitHub — pure **OAuth2** (no OpenID Connect): there is no
 * `id_token`, no JWKS, and no nonce. After the authorization-code + PKCE
 * exchange yields an access token, the profile is read from GitHub's REST API
 * (`GET /user` + `GET /user/emails`).
 *
 * **`emailVerified` is strict** (RFC IDP.md §3.4): it is `true` ONLY when the
 * user's PRIMARY email is GitHub-verified. A non-primary or unverified address
 * yields `false` — never trust a GitHub email as proof-of-control unless it is
 * the verified primary.
 *
 * Implements {@link ConfigurableProvider} so the registry can inject a shared
 * `fetch` (deterministic tests) / `clock`; a constructor value always wins.
 */
export class GithubProvider implements ConfigurableProvider {
  readonly id: string;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly scopes: string[];
  private readonly userAgent: string;
  private readonly authorizationEndpoint: string;
  private readonly tokenEndpoint: string;
  private readonly userEndpoint: string;
  private readonly emailsEndpoint: string;

  // undefined until set by ctor or applyDefaults; resolved at use-time.
  private fetchImpl?: FetchLike;

  constructor(opts: GithubProviderOptions) {
    if (!opts.clientId || !opts.clientSecret) {
      throw new OAuthError(
        "INVALID_CONFIG",
        "GithubProvider requires 'clientId' and 'clientSecret'",
      );
    }
    this.id = opts.id ?? "github";
    this.clientId = opts.clientId;
    this.clientSecret = opts.clientSecret;
    this.scopes = opts.scopes ?? DEFAULT_SCOPES;
    this.userAgent = opts.userAgent ?? DEFAULT_USER_AGENT;
    this.authorizationEndpoint = opts.authorizationEndpoint ?? GITHUB_AUTHORIZE;
    this.tokenEndpoint = opts.tokenEndpoint ?? GITHUB_TOKEN;
    this.userEndpoint = opts.userEndpoint ?? GITHUB_USER;
    this.emailsEndpoint = opts.emailsEndpoint ?? GITHUB_EMAILS;
    this.fetchImpl = opts.fetch;
  }

  /** Registry-injected shared config; a ctor value always wins (decision #2). */
  applyDefaults(shared: SharedProviderConfig): void {
    this.fetchImpl ??= shared.fetch;
  }

  private get fetchFn(): FetchLike {
    return resolveFetch(this.fetchImpl);
  }

  authorizationUrl(args: AuthorizationUrlArgs): Promise<string> {
    // Pure OAuth2: PKCE yes, but no `nonce` — that's OIDC-only, so we leave
    // `nonce` off (`buildAuthorizeUrl` omits it unless `nonce: true`).
    return Promise.resolve(
      buildAuthorizeUrl(this.authorizationEndpoint, args, {
        responseType: true,
        clientId: this.clientId,
        scopes: this.scopes,
      }),
    );
  }

  async exchange(args: ExchangeArgs): Promise<NormalizedProfile> {
    const accessToken = await this.redeemCode(args);
    // `/user` and `/user/emails` each need only the access token, not each
    // other — fetch them concurrently (saves a round-trip per login).
    const [user, primary] = await Promise.all([
      this.fetchUser(accessToken),
      this.fetchPrimaryEmail(accessToken),
    ]);
    // Prefer the verified PRIMARY email; otherwise degrade to the public `/user`
    // email as UNVERIFIED — never asserting control we couldn't confirm.
    const { email, emailVerified } =
      primary ?? (user.email ? { email: user.email, emailVerified: false } : {});

    const profile: NormalizedProfile = {
      provider: this.id,
      subject: String(user.id),
      raw: user,
    };
    if (email !== undefined) profile.email = email;
    if (emailVerified !== undefined) profile.emailVerified = emailVerified;
    const displayName = user.name ?? user.login;
    if (displayName) profile.displayName = displayName;
    if (user.avatar_url) profile.avatarUrl = user.avatar_url;
    return profile;
  }

  // --- internals -------------------------------------------------------

  /** POST the authorization `code` → access token (GitHub returns JSON when asked). */
  private async redeemCode(args: ExchangeArgs): Promise<string> {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: args.code,
      redirect_uri: args.redirectUri,
      client_id: this.clientId,
      client_secret: this.clientSecret,
      code_verifier: args.codeVerifier,
    });
    const json = (await fetchJson(
      this.fetchFn,
      this.tokenEndpoint,
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          // Without this header GitHub returns form-urlencoded, not JSON.
          accept: "application/json",
          "user-agent": this.userAgent,
        },
        body: body.toString(),
      },
      { label: "GitHub token endpoint" },
    )) as Record<string, unknown>;
    // GitHub signals failure with HTTP 200 + `{ error }` (e.g. bad/expired code).
    if (typeof json.error === "string") {
      throw new OAuthError("EXCHANGE_FAILED", "GitHub rejected the authorization code", {
        error: json.error,
      });
    }
    if (typeof json.access_token !== "string" || json.access_token.length === 0) {
      throw new OAuthError("EXCHANGE_FAILED", "GitHub token response carried no access_token");
    }
    return json.access_token;
  }

  private async fetchUser(accessToken: string): Promise<GithubUser> {
    const json = await this.apiGet(this.userEndpoint, accessToken);
    const user = json as Partial<GithubUser>;
    if (user.id === undefined || user.id === null || typeof user.login !== "string") {
      throw new OAuthError("EXCHANGE_FAILED", "GitHub /user response was missing id/login");
    }
    return user as GithubUser;
  }

  /**
   * Resolve the verified PRIMARY `/user/emails` entry, `emailVerified` strictly
   * from its `verified` flag. Returns `undefined` when the `user:email` scope is
   * absent (call fails), the body isn't an array, or there's no primary entry —
   * the caller then degrades to the public `/user` email (unverified).
   */
  private async fetchPrimaryEmail(
    accessToken: string,
  ): Promise<{ email: string; emailVerified: boolean } | undefined> {
    let entries: GithubEmail[];
    try {
      entries = (await this.apiGet(this.emailsEndpoint, accessToken)) as GithubEmail[];
    } catch {
      return undefined;
    }
    if (!Array.isArray(entries)) return undefined;
    const primary = entries.find((e) => e && e.primary);
    if (primary && typeof primary.email === "string") {
      return { email: primary.email, emailVerified: primary.verified };
    }
    return undefined;
  }

  private apiGet(url: string, accessToken: string): Promise<unknown> {
    return fetchJson(
      this.fetchFn,
      url,
      {
        method: "GET",
        headers: {
          authorization: `Bearer ${accessToken}`,
          accept: "application/vnd.github+json",
          "user-agent": this.userAgent,
        },
      },
      { label: `GitHub API (${url})` },
    );
  }
}
