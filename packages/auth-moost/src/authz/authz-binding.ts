import type { TCookieAttributesInput } from "@wooksjs/event-http";

import { oauthCsrfCookieAttrs } from "../oauth/oauth-csrf";

/**
 * Name of the double-submit cookie that binds an in-flight authorization
 * request to the browser that started it. Set at `GET /auth/authorize` (holding
 * the high-entropy `binding` secret recorded on the `PendingAuthorization`), and
 * matched — constant-time, via `safeEqual` from `oauth-csrf` — at the
 * `mint-authz-code` / `authz-consent` workflow steps before any code is minted.
 *
 * Why this closes the account-takeover (AUTH-SERVER.md §6): the opaque `authz`
 * handle alone is a bearer ticket — anyone holding it can drive it to the
 * code-minting terminal. An attacker who initiates `/auth/authorize` (to inject
 * their own client / redirect / PKCE challenge) receives the handle AND this
 * cookie in THEIR browser; phishing only the handle into a victim's browser
 * fails the match here, because the victim's browser never holds the secret. So
 * a handle can only be redeemed by the same browser that started the request.
 */
export const AUTHZ_BINDING_COOKIE = "aooth_authz";

/**
 * Cookie attributes for the authorize-binding cookie — the same httpOnly /
 * `SameSite=Lax` shape as the OAuth CSRF cookie (Lax, NOT Strict, so the
 * top-level GET navigation BACK from a "Continue with <provider>" detour still
 * carries it), so it delegates to {@link oauthCsrfCookieAttrs}. `maxAgeSec` is
 * the pending authorization's remaining lifetime — the caller derives it from
 * the row's `expiresAt` (returned by `PendingAuthorizationStore.create`), so the
 * cookie tracks the row's TTL even when a store is configured with a non-default
 * `ttlMs`. `secure` is caller-controlled (off for the http test harness, on in
 * production).
 */
export function authzBindingCookieAttrs(opts: {
  secure: boolean;
  maxAgeSec: number;
}): TCookieAttributesInput {
  return oauthCsrfCookieAttrs({ secure: opts.secure, maxAgeSec: opts.maxAgeSec });
}
