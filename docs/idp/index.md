# IdP (Federated Login)

`@aooth/idp` is the **federated-login core** in the aoothjs stack — the framework-agnostic half of "Sign in with Google / OIDC". It owns the OAuth2/OIDC provider clients (authorization URL + token exchange + full ID-token verification), the PKCE / signed-state primitives, the provider registry, and the account-resolution algorithm that maps a verified external identity to one of your users.

It does **not** own credential issuance (that's [`@aooth/auth`](../auth/) — federated login ends in a normal `auth.issue`), it does **not** own the user record or the account-linking table (those live in [`@aooth/user`](../user/)), and it does **not** own the HTTP round-trip — the `/start` → provider → `/callback` controller and the workflow that re-enters the login gates (MFA, consent, enrollment) are the **Moost integration**, [`OAuthController` + `auth/oauth/flow`](../moost/oauth). This package is the portable building blocks under that wiring.

This page is the map. Every concept here has a dedicated child page.

## Where it sits

```
┌──────────────────────────────────────────────────────────────┐
│  Framework integration → see Moost · Federated Login (OAuth)   │
│  @aooth/auth-moost · OAuthController · auth/oauth/flow          │
│     /start → provider → /callback → re-enter login gates       │
└───────────────┬───────────────────────────────┬───────────────┘
                │                               │
                ▼                               ▼
┌──────────────────────────────────┐  ┌──────────────────────────┐
│  Federated-login core            │  │  Method layer             │
│  @aooth/idp                      │  │  @aooth/auth · issue()    │
│    IdentityProvider (OIDC/Google)│  └──────────────────────────┘
│    OAuthProviderRegistry         │
│    FederatedLoginService         │
│    PKCE · signState/verifyState  │
└───────────────┬──────────────────┘
                ▼
┌──────────────────────────────────────────────────────────────┐
│  Identity layer                                                │
│  @aooth/user · UserService · FederatedIdentityStore            │
└──────────────────────────────────────────────────────────────┘
```

`@aooth/idp` depends on the **concrete** `UserService` + `FederatedIdentityStore` (`@aooth/user`) and reuses the shared `Clock` from `@aooth/auth`. All JWT/JWKS work uses [`jose`](https://github.com/panva/jose) (already a dependency of `@aooth/auth`).

## The shape of a federated login

1. A provider click sends the browser to the IdP's authorization URL (with PKCE + a signed `state`).
2. The IdP redirects back with a `code`; the provider `exchange()`s it for tokens and **fully verifies** the ID token.
3. `FederatedLoginService.resolveUser(profile)` maps the verified identity to one of your users — known link, email match (per policy), or a fresh account.
4. The resolved `userId` flows into the normal login tail → `auth.issue` → the same session a password login would mint.

Steps 1–3 are this package. Step 4 is `@aooth/auth`. The browser round-trip + the re-entry into MFA/consent/enrollment gates are the Moost integration.

## Minimal example (offline, no network)

```ts
import { FederatedLoginService, FakeIdentityProvider } from "@aooth/idp";
import { UserService, UserStoreMemory, FederatedIdentityStoreMemory } from "@aooth/user";

const users = new UserService(new UserStoreMemory());
const federated = new FederatedIdentityStoreMemory();
const svc = new FederatedLoginService({ users, federated /*, policy */ });

// In production, `profile` comes from `provider.exchange({ code, ... })`.
const provider = new FakeIdentityProvider().setProfile("code-1", {
  subject: "google-sub-123",
  email: "ada@example.com",
  emailVerified: true,
  raw: {},
});
const profile = await provider.exchange({ code: "code-1", redirectUri: "x", codeVerifier: "v" });

const outcome = await svc.resolveUser(profile);
switch (outcome.kind) {
  case "linked": // known (provider, subject) → existing user
  case "created": // first login → new account, auto-activated
  case "auto-linked": // matched + policy auto-linked
    // → carry outcome.userId into auth.issue() (the login tail)
    break;
  case "needs-link": // email matched an existing account; require interactive proof
    break;
  case "denied": // signup disabled, or no usable email
    break;
}
```

## What each page covers

- [Providers](./providers) — `IdentityProvider`, `OidcProvider` (discovery + remote JWKS + the full OIDC Core ID-token validation), `GoogleProvider`, and the network-free `FakeIdentityProvider`. The verification invariants that make a forged or downgraded token fail closed.
- [Account resolution & linking](./account-resolution) — `FederatedLoginService.resolveUser` (the five outcomes), `FederatedPolicy` (the account-takeover-sensitive `emailMatch` knob), interactive linking, the `FederatedIdentityStore` account-linking table, the `OAuthProviderRegistry`, and the PKCE / signed-state primitives.

API signatures live in the [API reference](/api/idp).

## Installation

```bash
pnpm add @aooth/idp @aooth/user @aooth/auth
```

No new heavy dependency — `@aooth/idp` uses `jose`, which `@aooth/auth` already pulls in.

## Conventions used across these pages

- **Email matching is account-takeover sensitive.** The default `FederatedPolicy.emailMatch` is `require-interactive-link` — a federated login that matches an existing account **by email** is never silently merged. Relaxing to `auto-link-if-verified` is a deliberate security downgrade (see [Account resolution](./account-resolution)).
- **`subject` is the join key, not email.** A provider's stable `sub` is the durable identity; the stored email / display fields are refreshed on each login and are display-only.
- **Verification fails closed.** A JWKS or discovery fetch failure is an error, never a silent accept. ID tokens are validated against the full OIDC Core 3.1.3.7 list (pinned algs, `iss`/`aud`/`azp`, `exp`/`iat`/`nbf`, `nonce`, `at_hash`).
- **Provider access/refresh tokens are transient.** They are used to fetch the profile and then discarded — never persisted.
