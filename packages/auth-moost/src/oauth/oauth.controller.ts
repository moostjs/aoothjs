import { AuthCredential } from "@aooth/auth";
import {
  createPkcePair,
  generateNonce,
  generateRandomState,
  OAuthError,
  OAuthProviderRegistry,
} from "@aooth/idp";
import { FederatedIdentityStore, UserService } from "@aooth/user";
import { Delete, Get, HttpError, Query } from "@moostjs/event-http";
import { current } from "@wooksjs/event-core";
import { useResponse } from "@wooksjs/event-http";
import { Controller, Inject, Param } from "moost";

import { useAuth } from "../auth.composables";
import { Public } from "../auth.decorator";
import { OAUTH_CSRF_COOKIE, oauthCsrfCookieAttrs } from "./oauth-csrf";
import { OAuthFlowStore } from "./oauth-flow-store";
import { resolveOAuthRedirect } from "./oauth-redirect";
import { FEDERATED_IDENTITY_STORE_TOKEN, OAUTH_FLOW_STORE_TOKEN } from "./oauth-tokens";

/** State-token + CSRF-cookie + flow-store TTL (seconds). Matches `signState`'s default. */
const OAUTH_TTL_SEC = 600;

/**
 * REST surface for federated login (OAuth2 / OIDC), RFC IDP.md §3.7. THREE
 * routes — the interactive callback is deliberately NOT here: the provider's
 * `redirect_uri` lands on the SPA, which bridges `{ code, state }` into the
 * public `/auth/trigger` starting `auth/oauth/flow` (so MFA / consent / cookie
 * issuance all reuse the existing workflow machinery). Everything secret about
 * the round-trip — the PKCE verifier + OIDC nonce — lives server-side in
 * {@link OAuthFlowStore}; only the single-use `code` is ever exposed to the SPA
 * (strictly tighter than a classic public-SPA client, which also holds the
 * verifier).
 *
 * - `GET  /auth/oauth/:provider/start` — begin login. `@Public()`; 302s to the
 *   provider after minting PKCE + nonce + an anti-CSRF `random`, persisting the
 *   secret half in `OAuthFlowStore`, signing `{ random, provider, redirect }`
 *   into `state`, and dropping a Lax double-submit cookie.
 * - `GET  /auth/oauth/:provider/link` — begin an account-LINK for the
 *   authenticated user (binds `userId` into the server-side transaction).
 *   Self-scoped: `getUserId()` 401s an anonymous caller.
 * - `DELETE /auth/oauth/:provider/:subject` — disconnect a linked identity.
 *   Self-scoped; guards against removing the user's only sign-in method, then
 *   revokes the user's sessions.
 *
 * `start` / `link` are `@Public()` self-scoped primitives (mirroring
 * `AuthController.logout`/`status`): anonymous start is the whole point, and
 * link/unlink derive identity from the session, never from a parameter.
 * Subclass + add `@ArbacAction(...)` to gate them further.
 */
@Controller("auth/oauth")
export class OAuthController {
  // `registry` / `auth` / `users` are CONCRETE classes — their provide-registry
  // entries resolve through moost's class-reference ctor injection. The two
  // STORES are abstract, for which that path falls back to auto-instantiating a
  // body-less class; they are injected via explicit string tokens instead (see
  // oauth-tokens.ts).
  constructor(
    protected readonly registry: OAuthProviderRegistry,
    protected readonly auth: AuthCredential,
    protected readonly users: UserService,
    @Inject(OAUTH_FLOW_STORE_TOKEN) protected readonly flowStore: OAuthFlowStore,
    @Inject(FEDERATED_IDENTITY_STORE_TOKEN) protected readonly federated: FederatedIdentityStore,
  ) {}

  /** Default post-login redirect when the caller supplies none / an unsafe one. */
  protected defaultRedirect(): string {
    return "/";
  }

  @Get(":provider/start")
  @Public()
  async start(
    @Param("provider") providerId: string,
    @Query("redirect") redirect: string | undefined,
  ): Promise<string> {
    return this.begin(providerId, redirect, undefined);
  }

  @Get(":provider/link")
  @Public()
  async link(
    @Param("provider") providerId: string,
    @Query("redirect") redirect: string | undefined,
  ): Promise<string> {
    // Self-scoped: bind the link to the CURRENT user (401 if anonymous). The
    // userId rides in the SERVER-SIDE transaction (never the URL/state), so the
    // `oauth-exchange` step links to exactly this user.
    const userId = useAuth().getUserId();
    return this.begin(providerId, redirect, userId);
  }

  /**
   * Shared start machinery for login (`userId` undefined) and link (`userId`
   * set): mint PKCE + nonce + anti-CSRF random, stash the secret half + any
   * link-userId in `OAuthFlowStore`, sign `{ random, provider, redirect }` into
   * `state`, drop the Lax double-submit cookie, and 302 to the provider's
   * authorization URL. Returns an empty body (the redirect is in the headers).
   */
  protected async begin(
    providerId: string,
    redirect: string | undefined,
    userId: string | undefined,
  ): Promise<string> {
    const provider = this.requireProvider(providerId);
    const safeRedirect = resolveOAuthRedirect(redirect, this.defaultRedirect());
    const pkce = createPkcePair();
    const nonce = generateNonce();
    const random = generateRandomState();

    await this.flowStore.put(random, {
      provider: providerId,
      verifier: pkce.verifier,
      nonce,
      redirect: safeRedirect,
      ...(userId !== undefined && { userId }),
    });

    const state = await this.registry.signState(
      { random, provider: providerId, redirect: safeRedirect },
      { ttlSec: OAUTH_TTL_SEC },
    );
    const authUrl = await provider.authorizationUrl({
      redirectUri: this.registry.redirectUri(providerId),
      state,
      codeChallenge: pkce.challenge,
      nonce,
    });

    const res = useResponse(current());
    res.setCookie(
      OAUTH_CSRF_COOKIE,
      random,
      oauthCsrfCookieAttrs({ secure: useAuth().options.cookie.secure, maxAgeSec: OAUTH_TTL_SEC }),
    );
    res.status = 302;
    res.setHeader("Location", authUrl);
    return "";
  }

  /**
   * Disconnect a linked provider identity from the current user. Self-scoped
   * (`getUserId()` 401s an anonymous caller). Refuses to remove the user's ONLY
   * remaining sign-in method (no other federated identity AND no real password)
   * — that would strand them. On success revokes the user's sessions so a
   * session established through the now-removed identity can't outlive it.
   */
  @Delete(":provider/:subject")
  @Public()
  async unlink(
    @Param("provider") providerId: string,
    @Param("subject") subject: string,
  ): Promise<{ ok: true }> {
    const userId = useAuth().getUserId();
    const store = this.federated;

    const owned = await store.listForUser(userId);
    const target = owned.find((i) => i.provider === providerId && i.subject === subject);
    // 404 whether the row is absent OR owned by someone else — never confirm the
    // existence of another user's link.
    if (!target) throw new HttpError(404, "Linked identity not found");

    // Last-credential guard: block if this is the only sign-in method left.
    const otherIdentities = owned.length - 1;
    if (otherIdentities === 0) {
      const user = await this.users.getUser(userId);
      if (user.password.isInitial) {
        throw new HttpError(
          409,
          "Cannot remove your only sign-in method. Set a password first, or link another provider.",
        );
      }
    }

    await store.unlink(providerId, subject);
    // Disconnecting an identity provider invalidates the user's sessions — one
    // may have been established through the identity just removed.
    await this.auth.revokeAllForUser(userId);
    return { ok: true };
  }

  /** Resolve a provider id, mapping the idp `UNKNOWN_PROVIDER` error to HTTP 404. */
  protected requireProvider(providerId: string): ReturnType<OAuthProviderRegistry["require"]> {
    try {
      return this.registry.require(providerId);
    } catch (err) {
      if (err instanceof OAuthError && err.type === "UNKNOWN_PROVIDER") {
        throw new HttpError(404, `Unknown provider '${providerId}'`);
      }
      throw err;
    }
  }
}
