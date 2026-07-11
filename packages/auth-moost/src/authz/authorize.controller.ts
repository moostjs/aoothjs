import { AuthCredential, generateOpaqueToken, type RefreshResult } from "@aooth/auth";
import {
  buildAuthorizationServerMetadata,
  canonicalizeIssuer,
  ClientRegistrationError,
  tokenPolicyToIssueOptions,
  type AuthCodeStore,
  type AuthorizationServerMetadata,
  type ClientRedirectPolicy,
  type DynamicClientRegistration,
  type IdTokenSigner,
  NoopOidcClaimsResolver,
  type OidcClaimsResolver,
  type PendingAuthorizationStore,
} from "@aooth/auth/authz";
import { pkceChallengeFor } from "@aooth/idp";
import { Body, Get, Post, Query } from "@moostjs/event-http";
import { current } from "@wooksjs/event-core";
import { useHeaders, useResponse, useUrlParams } from "@wooksjs/event-http";
import { Controller, Inject } from "moost";

import { useAuth } from "../auth.composables";
import { Public } from "../auth.decorator";
import { AUTHZ_BINDING_COOKIE, authzBindingCookieAttrs } from "./authz-binding";
import { authzRedirectUrl } from "./authz-redirect";
import {
  AUTH_CODE_STORE_TOKEN,
  CLIENT_REDIRECT_POLICY_TOKEN,
  PENDING_AUTHORIZATION_STORE_TOKEN,
} from "./authz-tokens";

/** RFC-6749-shaped token-endpoint error response. */
interface TokenError {
  error: string;
}

/** OIDC token-endpoint success (RFC 6749 + OIDC Core). `id_token` for OIDC clients; `access_token` per registration. */
interface TokenSuccess {
  token_type: "Bearer";
  access_token?: string;
  id_token?: string;
  expires_in?: number;
  /** Rotating refresh token — minted iff the grant's `TokenPolicy.refresh` opted in. */
  refresh_token?: string;
  /** The authenticated user id (`sub`) — convenience for a CLI; not part of the OIDC token response. */
  userId: string;
}

/** The `POST /auth/token` request body (RFC 6749 §4.1.3 / §6, form- or JSON-shaped). */
interface TokenRequestBody {
  grant_type?: string;
  code?: string;
  code_verifier?: string;
  client_id?: string;
  client_secret?: string;
  refresh_token?: string;
  resource?: string | string[];
}

/** A minimal OIDC discovery document (`/.well-known/openid-configuration`). */
interface OidcDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  registration_endpoint?: string;
  response_types_supported: string[];
  grant_types_supported: string[];
  subject_types_supported: string[];
  id_token_signing_alg_values_supported: string[];
  scopes_supported: string[];
  code_challenge_methods_supported: string[];
  token_endpoint_auth_methods_supported: string[];
}

/** RFC 7591 §3.2.1 registration response. Secret fields present iff a secret was issued. */
interface ClientRegistrationSuccess {
  client_id: string;
  /** Seconds since epoch (the RFC's unit — NOT ms). */
  client_id_issued_at: number;
  /** The minted secret (`client_secret_post` registrations) — disclosed HERE and only here. */
  client_secret?: string;
  /** REQUIRED when a secret is issued; `0` ⇒ the secret does not expire. */
  client_secret_expires_at?: number;
  redirect_uris: string[];
  token_endpoint_auth_method: string;
  grant_types: string[];
  response_types: string[];
  client_name?: string;
  scope?: string;
}

/** RFC 7591 §3.2.2 registration error response. */
interface ClientRegistrationFailure {
  error: string;
  error_description?: string;
}

/** Shared default claims resolver — stateless, so one instance is reused across requests. */
const NOOP_OIDC_CLAIMS_RESOLVER = new NoopOidcClaimsResolver();

/**
 * The authorization-server endpoints (AUTH-SERVER.md). Turns the existing login
 * workflow into an OAuth/OIDC authorization server for the app's OWN clients — a
 * local CLI on a loopback redirect (Tier 1) and registered first-party services
 * (Tier 2, `id_token` / "Sign in with <main app>"). One authorization-code + PKCE
 * flow; the only things that vary are the injected {@link ClientRedirectPolicy}
 * and whether an {@link IdTokenSigner} is wired.
 *
 * - `GET  /auth/authorize` — validate the client + `redirect_uri` (the policy),
 *   record a {@link PendingAuthorizationStore} entry (authority fixed HERE), and
 *   302 the browser to the login page carrying the opaque `handle`. The login
 *   workflow's `mint-authz-code` terminal delivers the code to the client.
 * - `POST /auth/token` — the back-channel: consume the single-use code, verify
 *   PKCE, authenticate the client (Tier 2), and mint the access token and/or the
 *   `id_token`. Minted HERE, off the browser, so nothing long-lived rides a URL.
 * - `GET /auth/.well-known/openid-configuration` + `GET /auth/jwks` — OIDC
 *   discovery + the signer's public JWKS (Tier 2 only; 404 without a signer).
 *
 * All routes are `@Public()`. The grant's authority (token policy, `id_token`
 * intent, audience, scope) is fixed at `/authorize` time and recorded on the
 * pending authorization + the issued code — never inferred at `/token`.
 */
@Controller("auth")
export class AuthorizeController {
  constructor(
    protected readonly auth: AuthCredential,
    @Inject(CLIENT_REDIRECT_POLICY_TOKEN) protected readonly policy: ClientRedirectPolicy,
    @Inject(PENDING_AUTHORIZATION_STORE_TOKEN)
    protected readonly pending: PendingAuthorizationStore,
    @Inject(AUTH_CODE_STORE_TOKEN) protected readonly codes: AuthCodeStore,
  ) {}

  /**
   * The Tier-2 OIDC `id_token` signer, or `undefined` for a Tier-1-only (CLI)
   * deployment — then discovery / `/auth/jwks` 404 and no `id_token` is minted.
   * **Override** in a subclass to enable OIDC (return one `IdTokenSigner` whose
   * issuer is `{origin}/auth`). A plain getter rather than a DI token because an
   * OPTIONAL `@Inject`/`@Optional` dependency panics in moost's `resolveMoost`
   * route-table pass (`useHandlerPaths`); a method has nothing for it to resolve.
   */
  protected getIdTokenSigner(): IdTokenSigner | undefined {
    return undefined;
  }

  /**
   * The Tier-2 OIDC profile-claims resolver. Defaults to a no-op (`sub`-only
   * tokens); **override** to emit `email` / `name` / … from your user record.
   */
  protected getOidcClaimsResolver(): OidcClaimsResolver {
    return NOOP_OIDC_CLAIMS_RESOLVER;
  }

  /**
   * The SPA login route the authorize request bounces to. The opaque pending-auth
   * `handle` is appended as `?authz=`; the SPA forwards it into the login
   * workflow's START input so `init-login` raises `ctx.authz`. Override for a
   * custom login path.
   */
  protected loginPath(): string {
    return "/login";
  }

  /**
   * The issuer identifier for the RFC 8414 metadata document. Defaults to the
   * Tier-2 signer's issuer; a SIGNER-LESS deployment that serves MCP connector
   * clients must **override** this (return `{origin}/auth`-style, byte-exact —
   * never derived from the Host header, which would let a request inject its
   * host into a cacheable discovery document). `undefined` ⇒ the
   * `oauth-authorization-server` endpoint 404s.
   */
  protected getIssuer(): string | undefined {
    return this.getIdTokenSigner()?.issuer;
  }

  /**
   * The RFC 7591 dynamic-client-registration operation, or `undefined` (the
   * default) to disable DCR — then `POST /auth/register` 404s and neither
   * discovery document advertises a `registration_endpoint`. **Override** in a
   * subclass: inject a `DynamicClientStore` (the `DYNAMIC_CLIENT_STORE_TOKEN`
   * provider) as a required ctor param, build one `DynamicClientRegistration`
   * around it, and return it here. Same plain-getter pattern as
   * {@link getIdTokenSigner} (an optional `@Inject` panics in moost's
   * route-table pass).
   */
  protected getDynamicClientRegistration(): DynamicClientRegistration | undefined {
    return undefined;
  }

  /**
   * `scopes_supported` for the RFC 8414 document (optional per the RFC; omitted
   * by default — deliberately NOT inheriting the OIDC document's hardcoded
   * list, which describes Tier-2 sign-in scopes). Override to advertise what
   * connector clients may request.
   */
  protected scopesSupported(): string[] | undefined {
    return undefined;
  }

  @Get("authorize")
  @Public()
  async authorize(
    @Query("response_type") responseType: string | undefined,
    @Query("redirect_uri") redirectUri: string | undefined,
    @Query("client_id") clientId: string | undefined,
    @Query("state") state: string | undefined,
    @Query("code_challenge") codeChallenge: string | undefined,
    @Query("code_challenge_method") codeChallengeMethod: string | undefined,
    @Query("scope") scope: string | undefined,
    @Query("nonce") nonce: string | undefined,
    @Query("resource") resource: string | undefined,
  ): Promise<string> {
    const res = useResponse(current());

    if (!redirectUri) {
      res.status = 400;
      return "missing redirect_uri";
    }

    // 1. The trust gate FIRST — resolve + authorize the client/redirect (+ scope).
    //    Until it passes we have no validated target to redirect errors to, so a
    //    failure is a benign 400 (never a reflected redirect). ONE generic body
    //    for every policy miss: with self-registered (DCR) clients, telling
    //    `invalid_client` apart from `invalid_redirect` is a client_id-existence
    //    oracle (AUTH-SERVER.md §7).
    let resolved;
    try {
      resolved = await this.policy.resolveClient({
        ...(clientId !== undefined && { clientId }),
        redirectUri,
        ...(scope !== undefined && { scope }),
      });
    } catch {
      res.status = 400;
      return "invalid request";
    }

    // 2. Param checks — now we CAN fail soft to the validated client redirect so
    //    the client fails fast instead of waiting out its timeout.
    if (responseType !== "code" || !codeChallenge || codeChallengeMethod !== "S256") {
      return this.redirectError(resolved.redirectUri, "invalid_request", state);
    }
    // RFC 8707: presence alone never errors — the single value is RECORDED on
    // the grant (consistency-checked at /token, no audience enforcement in v1,
    // OAUTH.md R4). Multiple values and oversized values are rejected rather
    // than silently truncated — `@Query` resolves only the FIRST occurrence of
    // a repeated param, so multiplicity is probed on the raw search params; a
    // future audience-enforcement pass must never enforce a partial record.
    if (resource !== undefined) {
      const repeated = useUrlParams(current()).params().getAll("resource").length > 1;
      if (repeated || resource.length > 2000) {
        return this.redirectError(resolved.redirectUri, "invalid_target", state);
      }
    }

    // 3. Mint the browser-binding secret (AUTH-SERVER.md §6). It is recorded on
    //    the pending authorization AND dropped as the `aooth_authz` cookie below;
    //    the code-minting terminal redeems the handle only when the request
    //    carries a cookie that constant-time-matches this. So a handle phished
    //    into a VICTIM's browser is inert — the secret lives only in the browser
    //    that initiated this request (the attacker's, in the takeover scenario).
    const binding = generateOpaqueToken();

    // 4. Record the in-flight request; ALL authority (token policy, id_token
    //    intent, audience, granted scope) is fixed here, copied from the policy.
    const { handle, expiresAt } = await this.pending.create({
      ...(resolved.clientId !== undefined && { clientId: resolved.clientId }),
      ...(resolved.clientName !== undefined && { clientName: resolved.clientName }),
      redirectUri: resolved.redirectUri,
      codeChallenge,
      ...(state !== undefined && { clientState: state }),
      ...(resource !== undefined && { resource }),
      ...(resolved.scope !== undefined && { scope: resolved.scope }),
      ...(nonce !== undefined && { nonce }),
      ...(resolved.idToken !== undefined && { idToken: resolved.idToken }),
      ...(resolved.accessToken !== undefined && { accessToken: resolved.accessToken }),
      ...(resolved.audience !== undefined && { audience: resolved.audience }),
      tokenPolicy: resolved.tokenPolicy,
      binding,
    });

    // 5. Bind the request to this browser (httpOnly, SameSite=Lax so it survives
    //    a "Continue with <provider>" detour) and hand off to the login page
    //    (same-origin, server-controlled path). The cookie's lifetime is the
    //    pending row's remaining TTL, so the two stay in sync for any store
    //    `ttlMs` — never a stale constant.
    const maxAgeSec = Math.max(1, Math.round((expiresAt - Date.now()) / 1000));
    res.setCookie(
      AUTHZ_BINDING_COOKIE,
      binding,
      authzBindingCookieAttrs({ secure: useAuth().options.cookie.secure, maxAgeSec }),
    );
    const loginPath = this.loginPath();
    const target = `${loginPath}${loginPath.includes("?") ? "&" : "?"}authz=${encodeURIComponent(handle)}`;
    res.status = 302;
    res.setHeader("Location", target);
    return "";
  }

  @Post("token")
  @Public()
  async token(@Body() body: TokenRequestBody | undefined): Promise<TokenSuccess | TokenError> {
    if (body?.grant_type === "refresh_token") {
      return await this.refreshTokenGrant(body);
    }
    const res = useResponse(current());
    if (body?.grant_type !== "authorization_code") {
      res.status = 400;
      return { error: "unsupported_grant_type" };
    }
    if (!body.code || !body.code_verifier) {
      res.status = 400;
      return { error: "invalid_request" };
    }

    // Single-use: consume atomically — a reuse / double-redeem misses here.
    const row = await this.codes.consume(body.code);
    if (!row) {
      res.status = 400;
      return { error: "invalid_grant" };
    }
    // PKCE: the verifier must hash to the challenge bound at authorize time.
    if (pkceChallengeFor(body.code_verifier) !== row.codeChallenge) {
      res.status = 400;
      return { error: "invalid_grant" };
    }

    // Client authentication (Tier 2): a code minted for a registered client must
    // be redeemed BY that client — the presented `client_id` must match, and a
    // confidential client must authenticate (the policy verifies its secret).
    // A code minted for a loopback (public, no-`client_id`) CLI must conversely
    // carry NO `client_id` — reject a spurious one so the binding stays symmetric.
    if (row.clientId !== undefined) {
      if (body.client_id !== row.clientId) {
        res.status = 401;
        return { error: "invalid_client" };
      }
      if (!(await this.clientAuthenticates(row.clientId, body.client_secret))) {
        res.status = 401;
        return { error: "invalid_client" };
      }
    } else if (body.client_id !== undefined) {
      res.status = 401;
      return { error: "invalid_client" };
    }

    // RFC 8707 consistency (OAUTH.md R4): when BOTH legs carry `resource`, they
    // must match; one-sided presence is accepted (the recorded value stays on
    // the grant for a future audience-enforcement pass). Multi-valued is
    // rejected like at /authorize.
    if (Array.isArray(body.resource)) {
      res.status = 400;
      return { error: "invalid_target" };
    }
    if (
      row.resource !== undefined &&
      body.resource !== undefined &&
      row.resource !== body.resource
    ) {
      res.status = 400;
      return { error: "invalid_target" };
    }

    const wantIdToken = row.idToken === true;
    const wantAccessToken = row.accessToken !== false; // omitted ⇒ minted (Tier-1 loopback)
    if (!wantIdToken && !wantAccessToken) {
      res.status = 400;
      return { error: "invalid_request" };
    }

    // Resolve + validate the id_token signing context up front, BEFORE minting
    // anything: a client registered for an id_token but no signer wired (or no
    // audience) is a server misconfiguration, not a client error — fail fast so
    // no access token is issued on the way out.
    let signing: { signer: IdTokenSigner; audience: string } | undefined;
    if (wantIdToken) {
      const signer = this.getIdTokenSigner();
      const audience = row.audience ?? row.clientId;
      if (!signer || audience === undefined) {
        res.status = 500;
        return { error: "server_error" };
      }
      signing = { signer, audience };
    }

    let accessToken: string | undefined;
    let expiresIn: number | undefined;
    let refreshToken: string | undefined;
    if (wantAccessToken) {
      const issued = await this.auth.issue(
        row.userId,
        tokenPolicyToIssueOptions(row.tokenPolicy, row.clientId),
      );
      accessToken = issued.accessToken;
      expiresIn = expiresInSeconds(issued.accessExpiresAt);
      refreshToken = issued.refreshToken;
    }

    let idToken: string | undefined;
    if (signing) {
      const extra = await this.getOidcClaimsResolver().resolveClaims(row.userId, row.scope);
      idToken = await signing.signer.sign({
        sub: row.userId,
        aud: signing.audience,
        ...(row.nonce !== undefined && { nonce: row.nonce }),
        extra,
      });
    }

    res.status = 200; // a body-returning POST otherwise defaults to 201
    return {
      token_type: "Bearer",
      ...(accessToken !== undefined && { access_token: accessToken, expires_in: expiresIn }),
      ...(refreshToken !== undefined && { refresh_token: refreshToken }),
      ...(idToken !== undefined && { id_token: idToken }),
      userId: row.userId,
    };
  }

  /**
   * `grant_type=refresh_token` (OAuth 2.1 §4.3): rotate the presented refresh
   * token into a fresh access + refresh pair. Only a family minted BY this
   * token endpoint for a registered client redeems here — the
   * `metadata.authzClientId` stamp is the binding, checked BEFORE any rotation
   * (so a browser-session refresh token, or another client's, is a plain
   * `invalid_grant` with the family untouched). Client authentication mirrors
   * the code branch; the grant's authority (kind, payload, per-mint ttl) rides
   * the credential family — nothing is re-derived here. Reuse of an
   * already-rotated token revokes the whole family inside the session layer
   * (the standard theft response) and surfaces as `invalid_grant`.
   */
  protected async refreshTokenGrant(body: TokenRequestBody): Promise<TokenSuccess | TokenError> {
    const res = useResponse(current());

    if (typeof body.refresh_token !== "string" || body.refresh_token.length === 0) {
      res.status = 400;
      return { error: "invalid_request" };
    }
    // Refresh families are always client-bound (TokenPolicy.refresh is ignored
    // for clientless loopback grants), so a request without a client_id has
    // nothing it could redeem.
    const clientId = body.client_id;
    if (typeof clientId !== "string" || clientId.length === 0) {
      res.status = 401;
      return { error: "invalid_client" };
    }
    if (!(await this.clientAuthenticates(clientId, body.client_secret))) {
      res.status = 401;
      return { error: "invalid_client" };
    }

    let issued: RefreshResult;
    try {
      issued = await this.auth.refresh(body.refresh_token, {
        guard: (state) => {
          // RFC 6749 §5.2: a refresh token issued to another client — or not
          // by this endpoint at all (no stamp) — is an invalid grant.
          if (state.metadata?.authzClientId !== clientId) {
            throw new Error("refresh token was not issued to this client");
          }
        },
      });
    } catch {
      res.status = 400;
      return { error: "invalid_grant" };
    }

    res.status = 200;
    return {
      token_type: "Bearer",
      access_token: issued.accessToken,
      expires_in: expiresInSeconds(issued.accessExpiresAt),
      ...(issued.refreshToken !== undefined && { refresh_token: issued.refreshToken }),
      userId: issued.userId,
    };
  }

  /**
   * Client authentication shared by both grant branches (RFC 6749 §2.3):
   * `true` iff the policy accepts the presented credentials (or defines no
   * `authenticateClient` hook). Callers map `false` to `401 invalid_client`.
   */
  protected async clientAuthenticates(
    clientId: string,
    clientSecret: string | undefined,
  ): Promise<boolean> {
    try {
      await this.policy.authenticateClient?.({
        clientId,
        ...(clientSecret !== undefined && { clientSecret }),
      });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * OIDC discovery (Tier 2). Derives every endpoint from the signer's `issuer`
   * (configured as `{origin}/auth`), so a relying `OidcProvider` configured with
   * the same `issuer` resolves `/authorize`, `/token`, and `/jwks` automatically.
   * 404 when no signer is wired (Tier-1-only deployment). When DCR is also
   * wired, `registration_endpoint` is advertised here too — in a combined
   * deployment a client that prefers `openid-configuration` over the RFC 8414
   * document must see the same capability set.
   */
  @Get(".well-known/openid-configuration")
  @Public()
  discovery(): OidcDiscoveryDocument | TokenError {
    const res = useResponse(current());
    const signer = this.getIdTokenSigner();
    if (!signer) {
      res.status = 404;
      return { error: "not_found" };
    }
    // `signer.issuer` is already canonical (trailing slash stripped at construction).
    const iss = signer.issuer;
    return {
      issuer: iss,
      authorization_endpoint: `${iss}/authorize`,
      token_endpoint: `${iss}/token`,
      jwks_uri: `${iss}/jwks`,
      ...(this.getDynamicClientRegistration() && { registration_endpoint: `${iss}/register` }),
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: [signer.alg],
      scopes_supported: ["openid", "email", "profile"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
    };
  }

  /**
   * RFC 8414 Authorization Server Metadata — the OAuth-flavored discovery MCP
   * connector clients fetch (OAUTH.md R1). Served signer-INDEPENDENTLY: it
   * needs only an issuer ({@link getIssuer} — overridable for a Tier-1-style
   * deployment with no `IdTokenSigner`). Mounted under the controller this is
   * the suffix form `{issuer}/.well-known/oauth-authorization-server`; the
   * RFC-correct path-insertion form at the HTTP-server ROOT
   * (`/.well-known/oauth-authorization-server/<issuer-path>`) cannot be
   * registered by a prefix-mounted controller — consumers mount it themselves
   * from the exported `buildAuthorizationServerMetadata` (re-exported by this
   * package).
   */
  @Get(".well-known/oauth-authorization-server")
  @Public()
  oauthServerMetadata(): AuthorizationServerMetadata | TokenError {
    const res = useResponse(current());
    const rawIssuer = this.getIssuer();
    if (!rawIssuer) {
      res.status = 404;
      return { error: "not_found" };
    }
    const issuer = canonicalizeIssuer(rawIssuer);
    return buildAuthorizationServerMetadata({
      issuer,
      ...(this.getDynamicClientRegistration() && {
        registrationEndpoint: `${issuer}/register`,
      }),
      ...(this.getIdTokenSigner() && { jwksUri: `${issuer}/jwks` }),
      ...(this.scopesSupported() && { scopesSupported: this.scopesSupported() }),
    });
  }

  /**
   * RFC 7591 Dynamic Client Registration (OAUTH.md R2) — anonymous by spec;
   * 404 unless a registration operation is wired ({@link
   * getDynamicClientRegistration}). A thin HTTP adapter: validation, abuse
   * knobs (guard / cap / never-used GC), secret minting and persistence live
   * in `DynamicClientRegistration` (`@aooth/auth`). A `client_secret_post`
   * registration is echoed with its minted `client_secret` +
   * `client_secret_expires_at` — the ONE disclosure (only the hash is stored);
   * public (`"none"`) registrations carry neither field (RFC 7591 §3.2.1
   * requires them only when a secret is issued).
   */
  @Post("register")
  @Public()
  async register(
    @Body() body: unknown,
  ): Promise<ClientRegistrationSuccess | ClientRegistrationFailure | TokenError> {
    const res = useResponse(current());
    const registration = this.getDynamicClientRegistration();
    if (!registration) {
      res.status = 404;
      return { error: "not_found" };
    }
    // RFC 7591 §3.1: the registration request is a JSON document.
    const contentType = useHeaders(current())["content-type"] ?? "";
    if (!contentType.includes("application/json")) {
      res.status = 400;
      return {
        error: "invalid_client_metadata",
        error_description: "registration requests must be application/json",
      };
    }
    try {
      const client = await registration.register(body);
      // §3.2.1: echo ALL registered metadata, including server-narrowed values
      // (e.g. an unsupported requested grant that was intersected away) — the
      // echo of the narrowed set IS the contract the client must honor.
      res.status = 201;
      return {
        client_id: client.clientId,
        client_id_issued_at: Math.floor(client.createdAt / 1000),
        ...(client.clientSecret !== undefined && {
          client_secret: client.clientSecret,
          // §3.2.1: REQUIRED alongside client_secret — echoed from core, which
          // owns the secret's lifecycle (0 ⇒ never expires).
          client_secret_expires_at: client.clientSecretExpiresAt,
        }),
        redirect_uris: client.redirectUris,
        token_endpoint_auth_method: client.tokenEndpointAuthMethod,
        grant_types: client.grantTypes,
        response_types: client.responseTypes,
        ...(client.clientName !== undefined && { client_name: client.clientName }),
        ...(client.scope !== undefined && { scope: client.scope }),
      };
    } catch (e) {
      if (e instanceof ClientRegistrationError) {
        res.status = 400;
        return { error: e.code, error_description: e.message };
      }
      // A guard/store fault is a server problem, never a metadata problem.
      res.status = 500;
      return { error: "server_error" };
    }
  }

  /** The signer's public JWKS (Tier 2). 404 when no signer is wired. */
  @Get("jwks")
  @Public()
  jwks(): Promise<Awaited<ReturnType<IdTokenSigner["jwks"]>>> | TokenError {
    const res = useResponse(current());
    const signer = this.getIdTokenSigner();
    if (!signer) {
      res.status = 404;
      return { error: "not_found" };
    }
    return signer.jwks();
  }

  /** Fail soft: 302 the validated client redirect with an `?error=` (+ echoed `state`). */
  protected redirectError(redirectUri: string, error: string, state: string | undefined): string {
    const res = useResponse(current());
    res.status = 302;
    res.setHeader("Location", authzRedirectUrl(redirectUri, { error, state }));
    return "";
  }
}

/** RFC 6749 `expires_in`: whole seconds from now until `expiresAt`, floored at 0. */
function expiresInSeconds(expiresAt: number): number {
  return Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));
}
