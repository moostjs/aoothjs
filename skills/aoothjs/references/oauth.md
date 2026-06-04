# Federated login (OAuth2 / OIDC) — @aooth/auth-moost wiring

The Moost integration of [`@aooth/idp`](idp.md): federated login is **merged into `auth/login/flow`** (no separate OAuth workflow, no OAuth login route). The login form offers the configured providers; one click bounces through the provider and re-enters the SAME login tail (MFA/consent/concurrency) as a password login. Core verification + `resolveUser` live in `@aooth/idp`; the `(provider, subject) → userId` store lives in `@aooth/user`.

## Quick start

```ts
import { OAuthController, FEDERATED_IDENTITY_STORE_TOKEN } from "@aooth/auth-moost";
import { FederatedLoginService, GoogleProvider, OAuthProviderRegistry } from "@aooth/idp";
import { FederatedIdentityStoreAtscriptDb } from "@aooth/user/atscript-db";

const registry = new OAuthProviderRegistry({
  baseUrl: env.PUBLIC_URL, // redirect_uri = baseUrl + /auth/oauth/:provider/callback
  stateSecret: env.OAUTH_STATE_SECRET,
  providers: [new GoogleProvider({ clientId, clientSecret })],
  policy: {
    emailMatch: "require-interactive-link",
    allowSignup: true,
    trustEmailVerifiedFrom: ["google"],
  },
});
const federatedStore = new FederatedIdentityStoreAtscriptDb({ table: federatedTable });
app.setProvideRegistry(
  createProvideRegistry(
    [AuthCredential, () => authCredential],
    [UserService, () => userService],
    [OAuthProviderRegistry, () => registry], // concrete → class token
    [
      FederatedLoginService,
      () =>
        new FederatedLoginService({
          users: userService,
          federated: federatedStore,
          policy: registry.policy,
        }),
    ],
    [FEDERATED_IDENTITY_STORE_TOKEN, () => federatedStore], // ABSTRACT → STRING token
  ),
);
app.registerControllers(OAuthController); // + AuthController, your AuthWorkflow subclass
// Offer providers on the login form: resolveAlternateCredentials → ssoProviders: { id, label, icon? }[]
```

## Invariants

| #   | Rule                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Federated login is `auth/login/flow`, not a separate workflow.** The login form's `AsSsoProviders` button fires the data-carrying `sso` action → `AuthWorkflow.beginSso` ends the wf with a 302 to the provider. An inbound callback POSTs `{ code, state }` to `/auth/trigger` STARTING `auth/login/flow`; `init-login` sees the `state` and routes to `sso-callback`.                                                                                                                      |
| 2   | **STATELESS — no flow store.** PKCE verifier + OIDC nonce are DERIVED from a non-secret `seed` carried in the signed `state` (double-submitted in a Lax httpOnly CSRF cookie) and RE-DERIVED at the callback. Nothing secret in the URL; any pod completes a callback another started. There is NO `OAuthFlowStore` / `/start` route anymore.                                                                                                                                                  |
| 3   | **Only ONE abstract store binds under a STRING token now:** `FederatedIdentityStore` under `FEDERATED_IDENTITY_STORE_TOKEN` (class-reference ctor injection auto-instantiates a body-less abstract class instead → provide under the string). Concrete `OAuthProviderRegistry` / `FederatedLoginService` bind by class reference.                                                                                                                                                              |
| 4   | **`redirect_uri` (`baseUrl` + `/auth/oauth/:provider/callback`) is YOUR route**, not a backend one. In a SPA it reads `code`/`state` and POSTs them into `/auth/trigger` as the START `input.formData` of `auth/login/flow`. `<AsWfForm :input>` wraps the object as `input.formData`, so pass `{ code, state }` (NOT nested `{ formData }`). Register the same `:components` map as the login page (a federated login can land on MFA/consent/prove-control forms).                           |
| 5   | **`sso-callback` order is security-load-bearing:** verifyState(HS256) → CSRF double-submit (`safeEqual(cookie.seed, state.random)`) → RE-DERIVE verifier from `state.random` → `provider.exchange` (verified ID token) → resolveUser → **ACCOUNT-STATE GATE (locked/inactive)** → set `ctx.subject`. The gate runs BEFORE subject is set because `issue` does not re-gate; every pre-subject failure halts on `{ break: !ctx.subject }`.                                                       |
| 6   | **`needs-link` → `prove-control` step (NOT a direct issue).** resolveUser `needs-link` (verified email matches an existing account) stashes `ctx.pendingLink` WITHOUT `ctx.subject`. The schema gates `prove-control` on `!!ctx.pendingLink && !ctx.subject` BEFORE the `{ break: !ctx.subject }`. Proof passes → `linkIdentity` → set subject → shared login tail.                                                                                                                            |
| 7   | **needs-link proof modes:** account has a real password → `ProveControlForm` (re-enter; username bound server-side from the candidate). Passwordless → `ProveControlOtpForm`, code to the account's **OWN confirmed email/SMS channel, NEVER the provider-supplied email** (circular). `resend` action re-sends to the same channel, gated by `pincodeResendTimeoutMs` cooldown (armed on every dispatch via `pending.resendAllowedAt`). `cancel`/wrong proof → generic terminal/inline error. |
| 8   | **Every failure collapses to ONE benign redirect terminal** (`finishOAuth` → `resolveOAuthErrorRedirect`, default `loginUrl?error=oauth`). No oracle distinguishing CSRF vs expiry vs unknown-provider vs exchange-failure vs denied/needs-link-cancel. needs-link discloses ONLY a masked account hint.                                                                                                                                                                                       |
| 9   | **Federated login reuses the login tail by `@Step` id** — SAME MFA/consent/concurrency/issue gates as a password login. The forced-password-change branch never fires for a federated login (`isPasswordInitial` is set only in the `credentials` step, which the federated path skips). `ctx.oauth` is the flow discriminator (`{ provider, outcome?, isNew?, redirect? }`; `outcome` includes `'interactively-linked'`).                                                                     |
| 10  | **`identities` / `link` / `unlink` are `@Public()` self-scoped** (like `logout`/`status`): identity from `useAuth().getUserId()` (401 anon), never a param. `GET /auth/oauth/identities` lists the caller's connected accounts (`listForUser`, projected — drops `id`/`userId`, keeps `(provider, subject)` for unlink). `link`'s `userId` rides the SIGNED state.                                                                                                                             |
| 11  | **`unlink` (DELETE `:provider/:subject`) guards the last credential** — refuses if removing it leaves no other federated identity AND `password.isInitial` → 409; else unlink + `revokeAllForUser`. 404 (not 403) for an identity owned by another user. Returns 202 (moost default for a body-returning DELETE). After unlink the session is revoked — UIs do optimistic local removal (a re-fetch would 401).                                                                                |
| 12  | **Library default finishes login with a `redirect` envelope** (session + trusted-device cookie ride the finish-envelope `cookies` map / Set-Cookie). The trusted-device cookie MUST be on the envelope, NOT `useResponse().setCookie` — the wf-outlet ignores response-context cookies on a redirect finish. A cookieless SPA opts out: override `resolveRedirect` to return `undefined` when `ctx.oauth` is set so the finish carries `data.accessToken`.                                     |
| 13  | **`oauthCsrfCookieAttrs` takes `maxAgeSec`** and ×1000 internally (wooks `Max-Age` is seconds). **`AsSsoProviders` `icon`** is a CSS class applied verbatim from server context → invisible to the static extractor → must be safelisted + the icon collection installed (consumer-owned).                                                                                                                                                                                                     |

## Key imports

```ts
import {
  OAuthController,
  OAuthRuntime,
  FEDERATED_IDENTITY_STORE_TOKEN,
  OAUTH_CSRF_COOKIE,
  oauthCsrfCookieAttrs,
  isSafeRelativeRedirect,
  resolveOAuthRedirect,
} from "@aooth/auth-moost";
import type { ConnectedAccount, AuthWfOAuthState } from "@aooth/auth-moost";
// core (provider/registry/service) — from @aooth/idp; the store — from @aooth/user. See idp.md.
// NO OAuthFlowStore / OAUTH_FLOW_STORE_TOKEN / OAuthFlowTransaction — the round-trip is stateless.
```

## References

| Domain         | File                             | When                                                                          |
| -------------- | -------------------------------- | ----------------------------------------------------------------------------- |
| Federated core | [idp.md](idp.md)                 | provider clients, ID-token verification, `resolveUser`/`linkIdentity`, policy |
| User stores    | [user-stores.md](user-stores.md) | the `FederatedIdentityStore` contract (`@aooth/user`)                         |
| Workflows      | [workflows.md](workflows.md)     | the shared login tail the federated leg re-enters; `prove-control` step       |
| Moost wiring   | [moost.md](moost.md)             | app bootstrap, DI, `@Public`, `AuthWorkflow` subclassing                      |

## See also

Docs: https://aoothjs.dev/moost/oauth · Source: https://github.com/moostjs/aoothjs/tree/main/packages/auth-moost
