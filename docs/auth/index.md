# Auth

`@aooth/auth` is the **method layer** in the aoothjs stack — it owns issuance, validation, refresh and revocation of bearer credentials, plus magic-link helpers and the email/SMS transport contracts. It does not own credentials themselves (that's [`@aooth/user`](../user/)) and it does not own HTTP wiring (that's [`@aooth/auth-moost`](../moost/)).

This page is the map. Every concept here has a dedicated child page.

## Where it sits

```
┌─────────────────────────────────────────────────────────────┐
│  Framework integration                                      │
│  @aooth/auth-moost  ·  guards · workflows · controllers   │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Method layer                                               │
│  @aooth/auth                                              │
│     AuthCredential<TClaims>                                 │
│       issue · validate · refresh · revoke                   │
│       revokeAllForUser · listForUser                        │
│     CredentialStore<TClaims>     DenylistStore              │
│     EmailSender · SmsSender · generateMagicLinkToken        │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Identity layer                                             │
│  @aooth/user  ·  password · MFA secret · lockout          │
└─────────────────────────────────────────────────────────────┘
```

The orchestrator is store-agnostic. Pick the store that matches your deployment along two axes.

## The two store axes

| Axis          | Stores                                                                       | Token shape      | Enumerable          | Revocation                                    |
| ------------- | ---------------------------------------------------------------------------- | ---------------- | ------------------- | --------------------------------------------- |
| **Stateful**  | `CredentialStoreMemory`, `CredentialStoreRedis`, `CredentialStoreAtscriptDb` | opaque UUID      | yes (`listForUser`) | row delete                                    |
| **Stateless** | `CredentialStoreJwt`, `CredentialStoreEncapsulated`                          | signed/encrypted | no                  | denylist by `jti` + per-user revocation epoch |

Stateless stores require a `DenylistStore` to support single-use operations (`consume`, `revoke`, `update`). Without one, those methods throw `STATELESS_OPERATION_UNSUPPORTED`. See [Stores](./stores).

## Minimal example

```ts
import { AuthCredential, CredentialStoreMemory } from "@aooth/auth";

const auth = new AuthCredential<{ roles: string[] }>({
  store: new CredentialStoreMemory(),
  accessTtl: 60 * 60 * 1000,
});

const { accessToken } = await auth.issue("alice", {
  claims: { roles: ["admin"] },
  metadata: { ip: "1.1.1.1" },
});

const ctx = await auth.validate(accessToken);
// { userId: 'alice', method: 'token', credentialId: '<sha256>', expiresAt, claims: { roles: ['admin'] } }
```

That's the whole API on the hot path: `issue`, `validate`, plus `refresh` / `revoke` / `revokeAllForUser` / `listForUser` for the rest of the lifecycle.

## What each page covers

- [Credentials & Sessions](./credentials) — `AuthCredential<TClaims>` orchestrator: every constructor option, every public method, the `AuthContext` shape, and how `credentialId` works as a non-replayable fingerprint. The choice between `method: 'session'` and `method: 'token'`.
- [Tokens (JWT)](./tokens) — `CredentialStoreJwt` setup with `jose`: algorithm choice (HS\* vs. asymmetric), key management, the claim layout, and the algorithm-confusion defense. Plus `CredentialStoreEncapsulated` (AES-256-GCM) and when to prefer stateless over stateful.
- [Refresh & Rotation](./refresh) — `RefreshConfig` with all three rotation modes (`'none'`, `'always'`, `'sliding'`), the grace window, reuse detection and the user-wide revocation cascade. `maxConcurrent` enforcement and `onLimit` strategies.
- [Magic Links](./magic-links) — `generateMagicLinkToken()` and `BuildMagicLinkUrl`. Storing magic-link tokens as `CredentialState` for atomic single-use consumption.
- [Password Reset](./password-reset) — How the primitives in this package compose into a recovery flow. The same-millisecond epoch gate that enables auto-login after reset. The full workflow lives in [`@aooth/auth-moost`](../moost/workflows).
- [Email & SMS Senders](./delivery) — The `EmailSender` and `SmsSender` contracts. The kind unions for templated delivery (`recovery.magicLink`, `mfa.code`, `login.pincode`, etc).
- [Stores](./stores) — Implementation matrix for `CredentialStore<TClaims>` and `DenylistStore`: `Memory`, `Redis` adapter, atscript-db adapter (with the shipped `.as` model), and how to write your own.
- [Errors](./errors) — `AuthError` and every variant of `AuthErrorType` with trigger, payload and recommended HTTP mapping.

## Installation

```bash
pnpm add @aooth/auth jose
```

`jose` is a hard peer dependency only when you use `CredentialStoreJwt`. The other stores have no extra peers. For the Redis or atscript-db adapter, add the relevant client:

```bash
# Redis adapter
pnpm add @aooth/auth ioredis

# atscript-db adapter
pnpm add @aooth/auth @atscript/db
```

## Conventions used across these pages

- All TTLs are in **milliseconds**. JWT `iat` / `exp` are seconds (RFC 7519), but the store mirrors them at ms precision in a custom `state` claim — see [Tokens](./tokens).
- `TClaims` is a free generic parameter on `AuthCredential<TClaims>`, `CredentialStore<TClaims>` and `CredentialState<TClaims>`. Pick a single shape per app and keep it stable.
- `CredentialMetadata` is open to TypeScript declaration merging. Augment it with `declare module '@aooth/auth'` to type your IP / UA / fingerprint / label keys end-to-end.
- The package never returns secrets through `validate` — `AuthContext.credentialId` is `sha256(accessToken)`, not the token itself.
