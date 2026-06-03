# Federated login (OAuth2 / OIDC) — @aooth/auth-moost wiring

The Moost integration of [`@aooth/idp`](idp.md): mounted HTTP routes + the `auth/oauth/flow` workflow that turn a verified provider profile into a normal `auth.issue` session, through the SAME login gates (MFA/consent/concurrency) as a password login. Core verification + `resolveUser` live in `@aooth/idp`; the `(provider, subject) → userId` store lives in `@aooth/user`.

## Quick start

```ts
import {
  OAuthController,
  OAuthFlowStoreMemory,
  OAUTH_FLOW_STORE_TOKEN,
  FEDERATED_IDENTITY_STORE_TOKEN,
} from "@aooth/auth-moost";
import { FederatedLoginService, GoogleProvider, OAuthProviderRegistry } from "@aooth/idp";
import { FederatedIdentityStoreAtscriptDb } from "@aooth/user/atscript-db";

const registry = new OAuthProviderRegistry({
  baseUrl: env.PUBLIC_URL, // redirect_uri = baseUrl + /auth/oauth/:provider/callback
  stateSecret: env.OAUTH_STATE_SECRET,
  providers: [new GoogleProvider({ clientId, clientSecret })],
  policy: { emailMatch: "require-interactive-link", trustEmailVerifiedFrom: ["google"] },
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
    [OAUTH_FLOW_STORE_TOKEN, () => new OAuthFlowStoreMemory()], // ABSTRACT → STRING token
    [FEDERATED_IDENTITY_STORE_TOKEN, () => federatedStore], // ABSTRACT → STRING token
  ),
);
app.registerControllers(OAuthController); // + AuthController, your AuthWorkflow subclass
// `auth/oauth/flow` is already in DEFAULT_AUTH_WORKFLOWS → the bundled /auth/trigger accepts it.
```

## Invariants

| #   | Rule                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **The abstract stores bind under STRING tokens, NOT the class.** Provide `OAuthFlowStore` under `OAUTH_FLOW_STORE_TOKEN` and `FederatedIdentityStore` under `FEDERATED_IDENTITY_STORE_TOKEN`. moost's class-reference ctor injection auto-instantiates a body-less abstract class instead of using your factory (`flowStore.put is not a function`). Concrete `OAuthProviderRegistry` / `FederatedLoginService` bind by class reference normally.              |
| 2   | **`redirect_uri` (`baseUrl` + `/auth/oauth/:provider/callback`) is YOUR route**, not a backend one. In a SPA it is a client route that reads `code`/`state` and POSTs them into `/auth/trigger` as the START `input.formData` of `auth/oauth/flow`. `<AsWfForm :input>` already wraps the object as `input.formData`, so pass `{ code, state }` (NOT a nested `{ formData }`). Register the exact uri at the provider; `exchange()` re-sends it byte-for-byte. |
| 3   | **`/start` is a plain 302 controller**, not a workflow trigger — a wf-outlet response can't emit the raw 302 a top-level navigation needs. It mints PKCE+nonce+CSRF-random, stashes verifier+nonce server-side (`OAuthFlowStore`, keyed by the state `random`), signs `{random,provider,redirect}`, drops a Lax httpOnly `aooth_oauth` cookie, 302s to the provider.                                                                                           |
| 4   | **`oauth-exchange` order is security-load-bearing:** verifyState(HS256) → CSRF double-submit (`safeEqual(cookie.random, state.random)`) → single-use `OAuthFlowStore.take(random)` → `provider.exchange` (verified ID token) → link/resolveUser → **ACCOUNT-STATE GATE (locked/inactive)** → set `ctx.subject`. The gate runs BEFORE subject is set because `issue` does not re-gate; every pre-subject failure halts on `{ break: !ctx.subject }`.            |
| 5   | **Every failure collapses to ONE benign redirect terminal** (`finishOAuth` → `resolveOAuthErrorRedirect`, default `loginUrl?error=oauth`). No oracle distinguishing CSRF vs expiry vs unknown-provider vs exchange-failure vs denied/needs-link.                                                                                                                                                                                                               |
| 6   | **PKCE verifier + nonce NEVER reach the browser/URL** — they live in `OAuthFlowStore` (server-side, single-use). Only the single-use `code` is exposed to the SPA (tighter than a classic public-SPA client). `OAuthFlowStoreMemory` is process-local → multi-pod MUST override with a shared store.                                                                                                                                                           |
| 7   | **`auth/oauth/flow` reuses the login tail by `@Step` id** — a federated user hits the SAME MFA/consent/concurrency/issue gates as a password login. `passwordPhaseSchema` no-ops (federated never sets `newPasswordRequired`); `mfaLoopSchema` fires if the user has methods. `ctx.oauth` is the flow discriminator (`{ provider, outcome?, isNew?, redirect? }`).                                                                                             |
| 8   | **`/start` + `/link` are `@Public()` self-scoped** (like `logout`/`status`): anonymous start is the point; `/link` + `unlink` derive identity from `useAuth().getUserId()` (401 anon), never a param. `/link`'s `userId` rides in the SERVER-SIDE txn (never the URL/state); `linkIdentity` is the cross-user confused-deputy backstop.                                                                                                                        |
| 9   | **`unlink` (DELETE `:provider/:subject`) guards the last credential** — refuses if removing it leaves no other federated identity AND `password.isInitial` (would strand the user) → 409; else unlink + `revokeAllForUser`. 404 (not 403) for an identity owned by another user. Returns 202 (moost default for a body-returning DELETE).                                                                                                                      |
| 10  | **OAuth is startable from the PUBLIC `/auth/trigger`** — safe because security is the signed-state + CSRF-cookie + single-use-txn + verified-ID-token gate, NOT route gating.                                                                                                                                                                                                                                                                                  |
| 11  | **Library default finishes OAuth with a `redirect` envelope** (session rides Set-Cookie). A cookieless SPA (Bearer-from-sessionStorage) must opt out: override `resolveRedirect` to return `undefined` when `ctx.oauth` is set, so the finish carries `data.accessToken`.                                                                                                                                                                                      |
| 12  | **`oauthCsrfCookieAttrs` `maxAge` is MILLISECONDS** (wooks renders `Max-Age` seconds = ms/1000). The helper takes `maxAgeSec` and ×1000 internally.                                                                                                                                                                                                                                                                                                            |

## Key imports

```ts
import {
  OAuthController,
  OAuthFlowStore,
  OAuthFlowStoreMemory,
  OAuthRuntime,
  OAUTH_FLOW_STORE_TOKEN,
  FEDERATED_IDENTITY_STORE_TOKEN,
  OAUTH_CSRF_COOKIE,
  oauthCsrfCookieAttrs,
  isSafeRelativeRedirect,
  resolveOAuthRedirect,
} from "@aooth/auth-moost";
import type {
  OAuthFlowTransaction,
  NewOAuthFlowTransaction,
  OAuthFlowStoreMemoryOptions,
  AuthWfOAuthState,
} from "@aooth/auth-moost";
// core (provider/registry/service) — from @aooth/idp; the store — from @aooth/user. See idp.md.
```

## References

| Domain         | File                             | When                                                                          |
| -------------- | -------------------------------- | ----------------------------------------------------------------------------- |
| Federated core | [idp.md](idp.md)                 | provider clients, ID-token verification, `resolveUser`/`linkIdentity`, policy |
| User stores    | [user-stores.md](user-stores.md) | the `FederatedIdentityStore` contract (`@aooth/user`)                         |
| Workflows      | [workflows.md](workflows.md)     | the shared login tail `auth/oauth/flow` re-enters                             |
| Moost wiring   | [moost.md](moost.md)             | app bootstrap, DI, `@Public`, `AuthWorkflow` subclassing                      |

## See also

Docs: https://aoothjs.dev/moost/oauth · Source: https://github.com/moostjs/aoothjs/tree/main/packages/auth-moost
