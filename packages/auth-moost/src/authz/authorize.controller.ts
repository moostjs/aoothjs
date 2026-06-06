import { AuthCredential, type IssueOptions } from "@aooth/auth";
import {
  AuthorizeError,
  type AuthCodeStore,
  type ClientRedirectPolicy,
  type IdTokenSigner,
  NoopOidcClaimsResolver,
  type OidcClaimsResolver,
  type PendingAuthorizationStore,
  type TokenPolicy,
} from "@aooth/auth/authz";
import { pkceChallengeFor } from "@aooth/idp";
import { Body, Get, Post, Query } from "@moostjs/event-http";
import { current } from "@wooksjs/event-core";
import { useResponse } from "@wooksjs/event-http";
import { Controller, Inject } from "moost";

import { Public } from "../auth.decorator";
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
  /** The authenticated user id (`sub`) — convenience for a CLI; not part of the OIDC token response. */
  userId: string;
}

/** A minimal OIDC discovery document (`/.well-known/openid-configuration`). */
interface OidcDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  response_types_supported: string[];
  grant_types_supported: string[];
  subject_types_supported: string[];
  id_token_signing_alg_values_supported: string[];
  scopes_supported: string[];
  code_challenge_methods_supported: string[];
  token_endpoint_auth_methods_supported: string[];
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
  ): Promise<string> {
    const res = useResponse(current());

    if (!redirectUri) {
      res.status = 400;
      return "missing redirect_uri";
    }

    // 1. The trust gate FIRST — resolve + authorize the client/redirect (+ scope).
    //    Until it passes we have no validated target to redirect errors to, so a
    //    failure is a benign 400 (never a reflected redirect).
    let resolved;
    try {
      resolved = await this.policy.resolveClient({
        ...(clientId !== undefined && { clientId }),
        redirectUri,
        ...(scope !== undefined && { scope }),
      });
    } catch (e) {
      res.status = 400;
      return e instanceof AuthorizeError ? `invalid request: ${e.code}` : "invalid request";
    }

    // 2. Param checks — now we CAN fail soft to the validated client redirect so
    //    the client fails fast instead of waiting out its timeout.
    if (responseType !== "code" || !codeChallenge || codeChallengeMethod !== "S256") {
      return this.redirectError(resolved.redirectUri, "invalid_request", state);
    }

    // 3. Record the in-flight request; ALL authority (token policy, id_token
    //    intent, audience, granted scope) is fixed here, copied from the policy.
    const { handle } = await this.pending.create({
      ...(resolved.clientId !== undefined && { clientId: resolved.clientId }),
      redirectUri: resolved.redirectUri,
      codeChallenge,
      ...(state !== undefined && { clientState: state }),
      ...(resolved.scope !== undefined && { scope: resolved.scope }),
      ...(nonce !== undefined && { nonce }),
      ...(resolved.idToken !== undefined && { idToken: resolved.idToken }),
      ...(resolved.accessToken !== undefined && { accessToken: resolved.accessToken }),
      ...(resolved.audience !== undefined && { audience: resolved.audience }),
      tokenPolicy: resolved.tokenPolicy,
    });

    // 4. Hand off to the login page (same-origin, server-controlled path).
    const loginPath = this.loginPath();
    const target = `${loginPath}${loginPath.includes("?") ? "&" : "?"}authz=${encodeURIComponent(handle)}`;
    res.status = 302;
    res.setHeader("Location", target);
    return "";
  }

  @Post("token")
  @Public()
  async token(
    @Body()
    body:
      | {
          grant_type?: string;
          code?: string;
          code_verifier?: string;
          client_id?: string;
          client_secret?: string;
        }
      | undefined,
  ): Promise<TokenSuccess | TokenError> {
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
      try {
        await this.policy.authenticateClient?.({
          clientId: row.clientId,
          ...(body.client_secret !== undefined && { clientSecret: body.client_secret }),
        });
      } catch {
        res.status = 401;
        return { error: "invalid_client" };
      }
    } else if (body.client_id !== undefined) {
      res.status = 401;
      return { error: "invalid_client" };
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
    if (wantAccessToken) {
      const issued = await this.auth.issue(row.userId, tokenPolicyToIssueOptions(row.tokenPolicy));
      accessToken = issued.accessToken;
      expiresIn = Math.max(0, Math.floor((issued.accessExpiresAt - Date.now()) / 1000));
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
      ...(idToken !== undefined && { id_token: idToken }),
      userId: row.userId,
    };
  }

  /**
   * OIDC discovery (Tier 2). Derives every endpoint from the signer's `issuer`
   * (configured as `{origin}/auth`), so a relying `OidcProvider` configured with
   * the same `issuer` resolves `/authorize`, `/token`, and `/jwks` automatically.
   * 404 when no signer is wired (Tier-1-only deployment).
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
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: [signer.alg],
      scopes_supported: ["openid", "email", "profile"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
    };
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
    const url = new URL(redirectUri);
    url.searchParams.set("error", error);
    if (state !== undefined) url.searchParams.set("state", state);
    const res = useResponse(current());
    res.status = 302;
    res.setHeader("Location", url.toString());
    return "";
  }
}

/** Flatten a {@link TokenPolicy} into the `issue()` options it forwards. */
function tokenPolicyToIssueOptions(policy: TokenPolicy): IssueOptions {
  return {
    ...policy.payload,
    ...(policy.kind !== undefined && { kind: policy.kind }),
    ...(policy.ttl !== undefined && { ttl: policy.ttl }),
  };
}
