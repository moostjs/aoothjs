# @aooth/idp (federated login — OAuth2 / OIDC)

Framework-agnostic federated-login core: provider clients (authorization URL + token exchange + ID-token verification), PKCE/state, the provider registry, and the account-resolution algorithm. NO moost/HTTP/workflow — the login-form SSO button → `/callback` bridge + login-gate re-entry are the `@aooth/auth-moost` wiring ([oauth.md](oauth.md): `OAuthController` + the federated leg of `auth/login/flow`). The account-linking **store** ships in `@aooth/user`.

## Quick start

```ts
import { FederatedLoginService, GoogleProvider, OAuthProviderRegistry } from "@aooth/idp";
import { UserService, UserStoreMemory, FederatedIdentityStoreMemory } from "@aooth/user";

const registry = new OAuthProviderRegistry({
  baseUrl: process.env.PUBLIC_URL!, // redirect_uri = baseUrl + /auth/oauth/:provider/callback
  stateSecret: process.env.AOOTH_OAUTH_STATE_SECRET!,
  providers: [new GoogleProvider({ clientId, clientSecret })],
  policy: { emailMatch: "require-interactive-link", trustEmailVerifiedFrom: ["google"] },
});

const svc = new FederatedLoginService({
  users: new UserService(new UserStoreMemory()),
  federated: new FederatedIdentityStoreMemory(),
  policy: registry.policy,
});

// after the browser bounce (the auth-moost `sso-callback` step): code → verified profile → resolve
const profile = await registry
  .require("google")
  .exchange({ code, redirectUri, codeVerifier, expectedNonce });
const outcome = await svc.resolveUser(profile);
// outcome.kind: 'linked' | 'created' | 'auto-linked' → carry outcome.userId into auth.issue()
//               'needs-link' (candidateUserId) | 'denied' (reason)
```

## Invariants

| #   | Rule                                                                                                                                                                                                                                                                                                                                                                                               |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **`resolveUser` returns a discriminated `ResolveOutcome`**, NOT `{ userId, isNew }`. Branch on `.kind`: `linked`/`created`/`auto-linked` carry `userId`; `needs-link` carries `candidateUserId`; `denied` carries `reason` (`signup-disabled` \| `email-unavailable`).                                                                                                                             |
| 2   | **`emailMatch` default = `require-interactive-link`** — a federated login matching an existing account BY EMAIL is NEVER silently merged → returns `needs-link`. `auto-link-if-verified` links only when `profile.emailVerified === true` AND `provider ∈ trustEmailVerifiedFrom`; otherwise it falls back to `needs-link` (never a silent duplicate). `create-separate` ignores the match.        |
| 3   | **Federated signup auto-activates the new account** (`created` branch calls `users.activateAccount`) — `createUser` defaults `active:false` and the active/locked gate (auth-moost `sso-callback`) would reject it. It does NOT promote the provider email to the unique login handle (gated, later phase); the email lives on the federated row.                                                  |
| 4   | **OIDC ID-token verification runs the full OIDC Core 3.1.3.7 list** — signature vs JWKS, `alg` pinned to the asymmetric set (default `['RS256','ES256']`; `none`/HS\* rejected → key-confusion defense), exact `iss`, `aud` contains clientId, `azp` on multi-aud, `exp/iat/nbf` w/ `clockToleranceSec` (5), `nonce` when expected, `at_hash` when access token + claim present. Fails CLOSED.     |
| 5   | **Error classes:** claim/sig failure → `ID_TOKEN_INVALID`; JWKS/discovery fetch failure → `JWKS_FAILED` (closed); token-endpoint network/5xx/`code`-reuse → `EXCHANGE_FAILED`. `OAuthError` `.type` taxonomy also has `UNKNOWN_PROVIDER`/`INVALID_CONFIG`/`STATE_INVALID`/`STATE_EXPIRED`/`PROVIDER_DENIED`/`EMAIL_UNAVAILABLE`. Benign default messages (no CSRF-vs-expiry leak).                 |
| 6   | **`subject` (provider `sub`) is the join key, not email.** Stored email/displayName/avatar are display-only, refreshed each login via `touchLogin`. `NormalizedProfile.raw` + provider access/refresh tokens are TRANSIENT — never persisted.                                                                                                                                                      |
| 7   | **`email_verified` is read STRICTLY as boolean** — a non-boolean (e.g. string `"true"`) yields `emailVerified: undefined` (no truthiness coercion).                                                                                                                                                                                                                                                |
| 8   | **`FederatedIdentityStore` is from `@aooth/user`** (not idp): `FederatedIdentityStore`/`FederatedIdentityStoreMemory` (root), `FederatedIdentityStoreAtscriptDb` (`/atscript-db`). `userId` is a PLAIN indexed column, NOT a hard FK; GDPR cleanup = `deleteAllForUser(userId)`. `(provider, subject)` is compound-unique → `link` throws `UserAuthError('ALREADY_EXISTS')` if linked to ANY user. |
| 9   | **`linkIdentity` (interactive-link completion):** idempotent when already that user's; throws `UserAuthError('ALREADY_EXISTS')` when `(provider, subject)` is linked to a DIFFERENT user (confused-deputy guard). The CSRF/state↔session-userId binding is the controller's job.                                                                                                                   |
| 10  | **`OAuthProviderRegistry`:** `require(id)` throws `OAuthError('UNKNOWN_PROVIDER')`; duplicate ids / missing baseUrl                                                                                                                                                                                                                                                                                | stateSecret throw `INVALID_CONFIG`. Shared config (`clockToleranceSec`/`jwks`/`clock`/`fetch`) is injected into providers via `applyDefaults` — a provider's own ctor value WINS. `redirectUri(id)` is fixed per provider; the `exchange()` `redirectUri` must byte-equal the authorization-time value. |
| 11  | **`signState`/`verifyState` pin HS256** (compact JWT). `verifyState` throws `STATE_EXPIRED` (past TTL, default 600s) vs `STATE_INVALID` (tamper/wrong-secret/malformed). Payload binds `random`+`provider`+`redirect`; `verifier`/`nonce` are optional (stateless mode carries them; server-store mode keeps them server-side and binds only a `handle`).                                          |
| 12  | **No new dependency** — uses `jose` (already in `@aooth/auth`) for JWT/JWKS and `node:crypto` for PKCE/nonce/random. `@aooth/idp` depends on the CONCRETE `UserService` + `FederatedIdentityStore`.                                                                                                                                                                                                |

## Key imports

```ts
import {
  // providers
  OidcProvider,
  GoogleProvider,
  FakeIdentityProvider,
  // registry + service
  OAuthProviderRegistry,
  FederatedLoginService,
  // PKCE / state
  createPkcePair,
  pkceChallengeFor,
  generateNonce,
  generateRandomState,
  signState,
  verifyState,
  // policy helpers + errors
  resolveFederatedPolicy,
  defaultUsernameStrategy,
  isConfigurableProvider,
  OAuthError,
} from "@aooth/idp";
import type {
  IdentityProvider,
  ConfigurableProvider,
  NormalizedProfile,
  AuthorizationUrlArgs,
  ExchangeArgs,
  FederatedPolicy,
  ResolvedFederatedPolicy,
  EmailMatchPolicy,
  ResolveOutcome,
  SharedProviderConfig,
  OidcProviderOptions,
  OidcDiscoveryDocument,
  GoogleProviderOptions,
  FakeIdentityProviderOptions,
  OAuthProviderRegistryOptions,
  FederatedLoginServiceDeps,
  PkcePair,
  OAuthStatePayload,
  SignStateOptions,
  VerifyStateOptions,
  FetchLike,
  FetchResponseLike,
  OAuthErrorType,
} from "@aooth/idp";

// account-linking store — from @aooth/user (NOT @aooth/idp)
import {
  FederatedIdentityStore,
  FederatedIdentityStoreMemory,
  pickDefinedProfile,
} from "@aooth/user";
import type {
  FederatedIdentity,
  NewFederatedIdentity,
  FederatedProfileSnapshot,
} from "@aooth/user";
import { FederatedIdentityStoreAtscriptDb } from "@aooth/user/atscript-db";
import type { FederatedIdentityTable } from "@aooth/user/atscript-db";
```

## References

| Domain        | File                             | When                                                                                                                 |
| ------------- | -------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| User stores   | [user-stores.md](user-stores.md) | the `FederatedIdentityStore` contract lives alongside `UserStore` in `@aooth/user`                                   |
| Auth (issue)  | [auth.md](auth.md)               | the credential issuance a resolved federated `userId` flows into (`auth.issue`)                                      |
| Workflows     | [workflows.md](workflows.md)     | the login-gate tail the federated leg of `auth/login/flow` re-enters (MFA/consent/enroll)                            |
| OAuth (moost) | [oauth.md](oauth.md)             | the `@aooth/auth-moost` HTTP wiring: `OAuthController`, `sso-callback`/`prove-control`, connected accounts, DI token |

## See also

Docs: https://aoothjs.dev/idp/ · Source: https://github.com/moostjs/aoothjs/tree/main/packages/idp
