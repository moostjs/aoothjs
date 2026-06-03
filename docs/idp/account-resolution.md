# Account Resolution & Linking

Once a provider returns a verified `NormalizedProfile`, `FederatedLoginService` maps it to one of your users. This is the security-critical heart of federated login — getting the account-matching policy wrong is a classic account-takeover vector — so the defaults are conservative.

## `FederatedLoginService.resolveUser`

```ts
import { FederatedLoginService } from "@aooth/idp";

const svc = new FederatedLoginService({
  users, // a concrete @aooth/user UserService
  federated, // a FederatedIdentityStore (below)
  policy, // a FederatedPolicy (below) — optional, safe defaults applied
});

const outcome = await svc.resolveUser(profile);
```

`resolveUser` returns a **discriminated outcome** so the caller (the Moost [`auth/oauth/flow`](../moost/oauth) workflow) can branch cleanly:

| `outcome.kind` | When                                                               | Carries           |
| -------------- | ------------------------------------------------------------------ | ----------------- |
| `linked`       | `(provider, subject)` is already linked.                           | `userId`          |
| `created`      | No match → a fresh account was created, **activated**, and linked. | `userId`, `isNew` |
| `auto-linked`  | Email matched an existing account and policy auto-linked it.       | `userId`          |
| `needs-link`   | Email matched, but proof-of-control is required before linking.    | `candidateUserId` |
| `denied`       | `signup-disabled` (no match, signup off) or `email-unavailable`.   | `reason`          |

The resolution order is: **(1)** known `(provider, subject)` → `linked`; **(2)** email match via `users.findByHandle(profile.email)` → governed by policy; **(3)** otherwise create. Every resolved outcome (`linked` / `created` / `auto-linked`) refreshes the row's display snapshot and stamps `lastLoginAt` via `touchLogin`.

Two deliberate behaviors on a fresh `created`:

- **The new account is activated.** `UserService.createUser` defaults to `active: false`; a federated signup auto-activates it — the IdP vouching for the identity _is_ the activation.
- **The provider email is NOT promoted to the account login handle.** The verified email is stored on the federated row; promoting it to the unique `email`/`username` handle is a gated concern for the workflow layer, not this service. This avoids a reverse auto-claim and email-uniqueness collisions.

Account-state gating (`active`/`locked`), MFA, consent, and enrollment are **not** done here — they run as the login-workflow tail after the resolved `userId` is set (the Moost integration).

## `FederatedPolicy` — the account-matching knob

```ts
interface FederatedPolicy {
  emailMatch?: "create-separate" | "auto-link-if-verified" | "require-interactive-link";
  allowSignup?: boolean; // default true
  usernameStrategy?: (p: NormalizedProfile) => string; // default: email, else `${provider}:${subject}`
  trustEmailVerifiedFrom?: string[]; // default []
}
```

`emailMatch` (default **`require-interactive-link`**) decides what happens when a federated login matches an existing local account **by email**:

- **`require-interactive-link`** (default, safest) — never silently merge. `resolveUser` returns `needs-link` with the matched `candidateUserId`; the caller must prove control before linking.
- **`auto-link-if-verified`** — link automatically, but **only** when `profile.emailVerified === true` **and** `profile.provider` is in `trustEmailVerifiedFrom`. A deliberate security downgrade; if the conditions are not met it falls back to `needs-link` (never a silent duplicate).
- **`create-separate`** — ignore the email match entirely and create a fresh account.

`allowSignup: false` (invite-only) makes an unmatched identity return `denied` instead of creating an account.

> **Only add a provider to `trustEmailVerifiedFrom` if it owns and strictly verifies the email and never recycles the `sub`↔email binding.** Generic/custom OIDC issuers should stay out by default.

## Interactive linking — `linkIdentity`

Completes a `needs-link` outcome (or a "connect account" action) by attaching `(provider, subject)` to an **already-authenticated** user:

```ts
await svc.linkIdentity({ provider: "google", subject: "sub-9", userId, profile });
```

It is idempotent when the identity is already that user's, and throws `UserAuthError('ALREADY_EXISTS')` when the identity is linked to a **different** user — the confused-deputy / account-injection guard. The CSRF / state↔session binding that proves the request truly speaks for `userId` is the controller's responsibility (the Moost integration).

## The account-linking table — `FederatedIdentityStore`

The one new piece of persistent state, exported from [`@aooth/user`](../user/). It maps a provider account `(provider, subject)` to a user `id`, with a display snapshot refreshed on each login:

```ts
import { FederatedIdentityStore, FederatedIdentityStoreMemory } from "@aooth/user";
import { FederatedIdentityStoreAtscriptDb } from "@aooth/user/atscript-db";
```

- `FederatedIdentityStoreMemory` — in-memory reference impl for tests.
- `FederatedIdentityStoreAtscriptDb` — `@atscript/db`-backed; the shipped `AoothFederatedIdentity` `.as` model declares the compound-unique `(provider, subject)` index.

The owning `userId` is a **plain indexed column, not a hard FK** — `@aooth/user` can't know your concrete user table. GDPR cleanup is an explicit `FederatedIdentityStore.deleteAllForUser(userId)`, not a DB cascade. See [User — Stores](../user/stores) for the store contract and the API reference for the full method surface.

## The registry — `OAuthProviderRegistry`

Holds the configured providers + the policy + shared verification config, resolves a provider by id, and builds the fixed `redirect_uri`:

```ts
import { OAuthProviderRegistry, GoogleProvider } from "@aooth/idp";

const registry = new OAuthProviderRegistry({
  baseUrl: process.env.PUBLIC_URL!, // redirect_uri = baseUrl + callback path
  stateSecret: process.env.AOOTH_OAUTH_STATE_SECRET!, // signs the state JWT
  providers: [new GoogleProvider({ clientId, clientSecret })],
  policy: { emailMatch: "require-interactive-link", trustEmailVerifiedFrom: ["google"] },
  // shared, injected into each provider unless it set its own: clockToleranceSec, jwks, clock, fetch
});

registry.require("google"); // → provider, or throws OAuthError('UNKNOWN_PROVIDER')
registry.redirectUri("google"); // → `${baseUrl}/auth/oauth/google/callback`
```

Shared config is injected into each provider that opts in (a provider's own constructor value always wins). The Moost integration DI-binds this registry; here it is a plain object.

## PKCE & signed state {#pkce-signed-state}

The browser-bounce primitives (used by the [`OAuthController`](../moost/oauth)):

```ts
import { createPkcePair, generateNonce, signState, verifyState } from "@aooth/idp";

const { verifier, challenge } = createPkcePair(); // S256
const state = await signState({ random, provider: "google", redirect: "/home" }, secret);
const payload = await verifyState(state, secret); // throws STATE_EXPIRED / STATE_INVALID
```

`signState` produces a compact HS256 JWT binding `random` + `provider` + `redirect` (and optionally the PKCE `verifier`, OIDC `nonce`, a server-side `handle`, or the initiating `userId` for `/link`). `verifyState` pins `HS256` and is tamper-evident.

## Errors {#errors}

`OAuthError` carries a stable `type` (RFC §8 taxonomy) with benign default messages so a controller can fail soft without leaking CSRF-vs-expiry:

`UNKNOWN_PROVIDER` · `INVALID_CONFIG` · `STATE_INVALID` · `STATE_EXPIRED` · `PROVIDER_DENIED` · `EXCHANGE_FAILED` · `JWKS_FAILED` · `ID_TOKEN_INVALID` · `EMAIL_UNAVAILABLE`.

## See also

- [Providers](./providers) — where the verified `NormalizedProfile` comes from.
- [User — Stores](../user/stores) · [User — Credentials Model](../user/credentials) — the `FederatedIdentityStore` and the user record.
- [API reference](/api/idp) — full signatures.
