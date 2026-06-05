import { AuthCredential, type IssueOptions } from "@aooth/auth";
import {
  AuthorizeError,
  type AuthCodeStore,
  type ClientRedirectPolicy,
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

/**
 * The authorization-server endpoints (AUTH-SERVER.md Tier 1). Turns the existing
 * login workflow into an OAuth authorization server for the app's OWN clients —
 * a local CLI on a loopback redirect today, a registered first-party service
 * (Tier 2) later. One authorization-code + PKCE flow; the only thing that varies
 * is the injected {@link ClientRedirectPolicy}.
 *
 * - `GET  /auth/authorize` — validate the client + `redirect_uri` (the policy),
 *   record a {@link PendingAuthorizationStore} entry, and 302 the browser to the
 *   login page carrying the opaque `handle`. The login workflow authenticates
 *   the human and its `mint-authz-code` terminal delivers the code to the client
 *   — this controller never runs the login itself.
 * - `POST /auth/token` — the back-channel: consume the single-use code, verify
 *   PKCE, and `AuthCredential.issue(userId, tokenPolicy)`. The token is minted
 *   HERE, off the browser, so nothing long-lived ever rides a redirect URL.
 *
 * Both routes are `@Public()` (anonymous). The grant's authority is fixed at
 * `/authorize` time (the policy's {@link TokenPolicy} is recorded on the pending
 * authorization and copied onto the issued code), never inferred at `/token`.
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
  ): Promise<string> {
    const res = useResponse(current());

    if (!redirectUri) {
      res.status = 400;
      return "missing redirect_uri";
    }

    // 1. The trust gate FIRST — resolve + authorize the client/redirect. Until it
    //    passes we have no validated target to redirect errors to, so a failure
    //    is a benign 400 (never a reflected redirect).
    let resolved;
    try {
      resolved = await this.policy.resolveClient({
        ...(clientId !== undefined && { clientId }),
        redirectUri,
      });
    } catch (e) {
      res.status = 400;
      return e instanceof AuthorizeError ? `invalid request: ${e.code}` : "invalid request";
    }

    // 2. Param checks — now we CAN fail soft to the validated client redirect so
    //    the CLI helper fails fast instead of waiting out its timeout.
    if (responseType !== "code" || !codeChallenge || codeChallengeMethod !== "S256") {
      return this.redirectError(resolved.redirectUri, "invalid_request", state);
    }

    // 3. Record the in-flight request; the token policy (authority) is fixed here.
    const { handle } = await this.pending.create({
      ...(resolved.clientId !== undefined && { clientId: resolved.clientId }),
      redirectUri: resolved.redirectUri,
      codeChallenge,
      ...(state !== undefined && { clientState: state }),
      ...(scope !== undefined && { scope }),
      tokenPolicy: resolved.tokenPolicy,
    });

    // 4. Hand off to the login page (same-origin, server-controlled path).
    //    `loginPath()` may already carry a query (e.g. a UI variant), so pick the
    //    right separator.
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
      | { grant_type?: string; code?: string; code_verifier?: string; client_id?: string }
      | undefined,
  ): Promise<
    { access_token: string; token_type: "Bearer"; expires_in: number; userId: string } | TokenError
  > {
    const res = useResponse(current());
    const grantType = body?.grant_type;
    const code = body?.code;
    const codeVerifier = body?.code_verifier;

    if (grantType !== "authorization_code") {
      res.status = 400;
      return { error: "unsupported_grant_type" };
    }
    if (!code || !codeVerifier) {
      res.status = 400;
      return { error: "invalid_request" };
    }

    // Single-use: consume atomically — a reuse / double-redeem misses here.
    const row = await this.codes.consume(code);
    if (!row) {
      res.status = 400;
      return { error: "invalid_grant" };
    }
    // PKCE: the verifier must hash to the challenge bound at authorize time.
    if (pkceChallengeFor(codeVerifier) !== row.codeChallenge) {
      res.status = 400;
      return { error: "invalid_grant" };
    }

    const issued = await this.auth.issue(row.userId, tokenPolicyToIssueOptions(row.tokenPolicy));
    const expiresIn = Math.max(0, Math.floor((issued.accessExpiresAt - Date.now()) / 1000));
    res.status = 200; // a body-returning POST otherwise defaults to 201
    return {
      access_token: issued.accessToken,
      token_type: "Bearer",
      expires_in: expiresIn,
      userId: row.userId,
    };
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
