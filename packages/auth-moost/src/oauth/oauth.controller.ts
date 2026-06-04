import { AuthCredential } from "@aooth/auth";
import { OAuthError, OAuthProviderRegistry } from "@aooth/idp";
import { FederatedIdentityStore, UserService } from "@aooth/user";
import { Delete, Get, HttpError, Query } from "@moostjs/event-http";
import { current } from "@wooksjs/event-core";
import { useResponse } from "@wooksjs/event-http";
import { Controller, Inject, Param } from "moost";

import { useAuth } from "../auth.composables";
import { Public } from "../auth.decorator";
import { buildOAuthAuthorizeRequest, OAUTH_TTL_SEC } from "./oauth-authorize";
import { OAUTH_CSRF_COOKIE, oauthCsrfCookieAttrs } from "./oauth-csrf";
import { resolveOAuthRedirect } from "./oauth-redirect";
import { FEDERATED_IDENTITY_STORE_TOKEN } from "./oauth-tokens";

/**
 * REST surface for federated-login ACCOUNT MANAGEMENT (OAuth2 / OIDC), RFC
 * IDP.md §3.7. Two routes — anonymous LOGIN is NOT here: it lives in the login
 * workflow (the login form offers a "Continue with <provider>" button that ends
 * the wf with a redirect to the provider; see `AuthWorkflow.beginSso`). The
 * provider's `redirect_uri` lands on the SPA, which bridges `{ provider, code,
 * state }` into the public `/auth/trigger` STARTING `auth/login/flow` — so MFA /
 * consent / cookie issuance reuse the existing workflow machinery.
 *
 * The round-trip is STATELESS — no flow store. The PKCE verifier + OIDC nonce
 * are DERIVED from a non-secret seed carried in the signed `state` (the same
 * seed double-submitted in the CSRF cookie) and re-derived at the callback (see
 * {@link OAuthProviderRegistry.deriveSeededPkce}). Nothing secret rides in the URL.
 *
 * - `GET  /auth/oauth/:provider/link` — begin an account-LINK for the
 *   authenticated user. 302s to the provider after deriving PKCE/nonce from a
 *   fresh seed and signing `{ random, provider, redirect, userId }` into `state`
 *   (the `userId` is HS256-signed → tamper-proof, server-minted). Self-scoped:
 *   `getUserId()` 401s an anonymous caller. `sso-callback` links the verified
 *   identity to that `userId`.
 * - `DELETE /auth/oauth/:provider/:subject` — disconnect a linked identity.
 *   Self-scoped; guards against removing the user's only sign-in method, then
 *   revokes the user's sessions.
 *
 * `link` / `unlink` are `@Public()` self-scoped primitives (mirroring
 * `AuthController.logout`/`status`): they derive identity from the session,
 * never from a parameter. Subclass + add `@ArbacAction(...)` to gate them further.
 */
@Controller("auth/oauth")
export class OAuthController {
  // `registry` / `auth` / `users` are CONCRETE classes — their provide-registry
  // entries resolve through moost's class-reference ctor injection. The
  // `FederatedIdentityStore` is abstract, for which that path falls back to
  // auto-instantiating a body-less class; it is injected via an explicit string
  // token instead (see oauth-tokens.ts).
  constructor(
    protected readonly registry: OAuthProviderRegistry,
    protected readonly auth: AuthCredential,
    protected readonly users: UserService,
    @Inject(FEDERATED_IDENTITY_STORE_TOKEN) protected readonly federated: FederatedIdentityStore,
  ) {}

  /** Default post-login redirect when the caller supplies none / an unsafe one. */
  protected defaultRedirect(): string {
    return "/";
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
   * Start machinery for an account-LINK: STATELESS — mint a fresh non-secret
   * `seed`, DERIVE the PKCE verifier + OIDC nonce from it
   * (`registry.deriveSeededPkce`), sign `{ random: seed, provider, redirect,
   * userId }` into `state` (the `userId` makes the callback link to THIS user;
   * HS256-signed so it's tamper-proof), drop the Lax double-submit cookie
   * holding the seed, and 302 to the provider. The verifier is NOT persisted —
   * `sso-callback` re-derives it from `state.random`. Returns an empty body
   * (the redirect is in the headers).
   */
  protected async begin(
    providerId: string,
    redirect: string | undefined,
    userId: string | undefined,
  ): Promise<string> {
    const provider = this.requireProvider(providerId);
    const safeRedirect = resolveOAuthRedirect(redirect, this.defaultRedirect());
    const { seed, authUrl } = await buildOAuthAuthorizeRequest(this.registry, provider, {
      redirect: safeRedirect,
      ...(userId !== undefined && { userId }),
    });

    const res = useResponse(current());
    res.setCookie(
      OAUTH_CSRF_COOKIE,
      seed,
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
