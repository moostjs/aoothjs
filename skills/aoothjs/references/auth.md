# @aooth/auth

## Quick start

```ts
import { AuthCredential, CredentialStoreJwt, DenylistStoreMemory } from "@aooth/auth";

// Stateless tokens, HS256-signed. Denylist is in-memory — swap for
// DenylistStoreRedis in production multi-instance deployments.
const denylist = new DenylistStoreMemory();
const auth = new AuthCredential<{ roles: string[] }>({
  store: new CredentialStoreJwt({
    algorithm: "HS256",
    secret: process.env.JWT_SECRET!,
    issuer: "https://api.example.com",
    audience: "example-app",
    denylist,
  }),
  accessTtl: 15 * 60 * 1000, // 15min
  refresh: { ttl: 30 * 24 * 3600 * 1000, rotation: "always" },
});

const { accessToken, refreshToken } = await auth.issue("alice", {
  roles: ["admin"], // typed payload field, flat (no `claims` container)
  metadata: { ip: "1.1.1.1", userAgent: "ua-string" },
});

const ctx = await auth.validate(accessToken);
// ctx = { userId: 'alice', method: 'token', credentialId: '<sha256>', expiresAt, roles }

const rotated = await auth.refresh(refreshToken!);
await auth.revoke(rotated.accessToken); // requires denylist
await auth.revokeAllForUser("alice"); // bumps in-memory epoch
```

## Invariants

| #   | Rule                                                                                                                                                                                                                                                                                                                                                                                 |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | **Stateless sliding refresh silently degrades to "always-once".** `CredentialStoreJwt` / `CredentialStoreEncapsulated` cannot mutate an issued token in place, so the first rotation invalidates the old refresh and the grace window is unreachable. Use `rotation: 'always'` explicitly for stateless deployments and reserve `'sliding'` for `Memory` / `Redis` / `AtscriptDb`.   |
| 2   | **`credentialId = sha256(accessToken)`** — a stable fingerprint, never the raw token. Safe to log, persist as a session id, and surface to clients. It cannot be replayed against the API.                                                                                                                                                                                           |
| 3   | **JWT / Encapsulated revocation epoch is in-memory.** `epochs: Map<userId, ms>` resets on process restart and does not sync across instances. Production multi-pod deployments back the same machinery with `CredentialStoreRedis` or `CredentialStoreAtscriptDb` for durable per-user cascades.                                                                                     |
| 4   | **Epoch gate is `>=`, not `>`.** A token whose `iatMs === epoch` passes. This is load-bearing for recovery / invite auto-login: a workflow can `revokeAllForUser(uid)` and immediately `issue(uid, …)` inside the same millisecond and the freshly minted token survives.                                                                                                            |
| 5   | **JWT verify pins `algorithms: [this.algorithm]`.** Algorithm-confusion defense — `jose`'s default infers a set from key shape, which would accept any `HS*` for a `Uint8Array` secret. Aoothjs restricts to the configured algorithm at the call site.                                                                                                                              |
| 6   | **`maxConcurrent` counts only `kind: 'access'`.** Refresh tokens never trip the limit. `listForUser` filters refresh entries before returning to callers.                                                                                                                                                                                                                            |
| 7   | **Refresh-reuse-after-rotation revokes the entire user.** Both `'sliding'` (after grace) and `'always'` (any reuse) modes invoke `store.revokeAllForUser(uid)` and throw `REFRESH_REUSE_DETECTED`. The `onRotationReuse` hook fires before the cascade so consumers can audit-log.                                                                                                   |
| 8   | **Encapsulated KDF uses a fixed library salt.** String secrets and non-32-byte buffers run through scrypt with that salt (so `secret: "hunter2"` derives the same key everywhere — domain separation only, not per-deployment uniqueness). Passing a 32-byte random buffer skips the KDF path entirely — required for maximum protection against rainbow tables on weak passphrases. |
| 9   | **`CredentialStoreRedis.persist` fails loud on already-dead credentials.** TTL <= 0 throws a plain `Error` (NOT an `AuthError('INVALID_CONFIG')`) synchronously rather than writing a phantom token. The atscript-db adapter mirrors the same posture in `update`: pushing `state.expiresAt` past `now` is treated as a revoke.                                                      |
| 10  | **`update` may return a different token.** Stateless stores re-issue (the old `jti` lands on the denylist, the new state is freshly signed); stateful stores return the same token id. Callers MUST use the returned value rather than the input.                                                                                                                                    |
| 11  | **`EmailSender.send` / `SmsSender.send` are `await`ed inline.** Workflows do not background them. Blocking transports must push onto a queue and return — otherwise issue / refresh / consume calls stall on SES / Twilio latency.                                                                                                                                                   |
| 12  | **`CredentialMetadata` is open to declaration merging.** Augment it with project-specific fields via `declare module '@aooth/auth' { interface CredentialMetadata { geoCountry?: string } }` — every store carries the extra fields through `persist` / `retrieve` / `listForUser` unchanged.                                                                                        |
| 13  | **`consume` on a stateless store without a `denylist` throws `STATELESS_OPERATION_UNSUPPORTED`.** Same for `revoke` and `update`. Magic-link flows are stateless-incompatible without a denylist — wire `DenylistStoreMemory` (single-process) or `DenylistStoreRedis` (multi-pod) before persisting magic-link state into JWT / Encapsulated.                                       |
| 14  | **`accessTtl <= 0`, missing HS `secret`, or missing asymmetric keypair throw `INVALID_CONFIG` at construction.** Boot-time fail-loud — never produce tokens that fail `validate()` the moment they exist. `refresh.ttl <= 0` does the same.                                                                                                                                          |
| 15  | **`revokeAllForUser` cascades across `kind: 'access'` AND `kind: 'refresh'`.** Stateful stores delete every row keyed on `userId`; stateless stores bump the epoch which rejects both kinds on the next `retrieve`. The return value is a count for stateful stores and sentinel `1` for stateless ("epoch bumped, count unknown").                                                  |
| 16  | **Token kind is enforced on validate.** `auth.validate()` rejects refresh tokens with `null`; `auth.refresh()` rejects access tokens with `AuthError('INVALID_TOKEN', 'Token is not a refresh credential')`. The discriminator lives on `CredentialState.kind` and is mirrored into the JWT `state` claim.                                                                           |

## Key imports

```ts
// Core orchestrator + types
import { AuthCredential, AuthError } from "@aooth/auth";
import type {
  AuthCredentialOptions,
  IssueOptions,
  AuthContext,
  CredentialMetadata,
  CredentialState,
  IssueResult,
  RefreshConfig,
  AuthErrorType,
  Clock,
} from "@aooth/auth";
import { defaultClock } from "@aooth/auth";

// Store interfaces
import type { CredentialStore, DenylistStore } from "@aooth/auth";

// In-memory + stateless stores (main subpath)
import {
  CredentialStoreMemory,
  DenylistStoreMemory,
  CredentialStoreJwt,
  CredentialStoreEncapsulated,
} from "@aooth/auth";
import type {
  CredentialStoreJwtOptions,
  CredentialStoreEncapsulatedOptions,
  JwtAlgorithm,
} from "@aooth/auth";

// Redis adapters (subpath)
import { CredentialStoreRedis, DenylistStoreRedis } from "@aooth/auth/redis";
import type { RedisLike } from "@aooth/auth/redis";

// atscript-db adapter (subpath)
import { CredentialStoreAtscriptDb } from "@aooth/auth/atscript-db";
import type { AuthCredentialRow, AuthCredentialTable } from "@aooth/auth/atscript-db";
// .as model — raw file export, consumed by `unplugin-atscript` / `asc`
import { AoothAuthCredential } from "@aooth/auth/atscript-db/model.as";

// Transport contracts (consumer ships impl)
import type {
  EmailSender,
  AuthEmailEvent,
  AuthEmailKind,
  SmsSender,
  AuthSmsEvent,
  AuthSmsKind,
} from "@aooth/auth";

// Magic-link helpers
import { generateMagicLinkToken } from "@aooth/auth";
import type { BuildMagicLinkUrl } from "@aooth/auth";
```

## References — load only what's needed

| Domain             | File                                     | When                                                                                                                                                                                                                                 |
| ------------------ | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| First contact      | [getting-started.md](getting-started.md) | Hello-world with `CredentialStoreMemory`, switching to JWT stateless, swapping in Redis, swapping in atscript-db, testing patterns with injected `Clock`                                                                             |
| Tokens & sessions  | [tokens.md](./tokens.md)                 | `CredentialStoreJwt` options, algorithm matrix (HS / RS / ES / EdDSA), JWT claim layout (`sub` / `iat` / `exp` / `jti` / `state.iatMs` / `state.expMs`), `CredentialStoreEncapsulated`, sessions vs tokens (`method` discriminator)  |
| Refresh & rotation | [refresh.md](./refresh.md)               | `RefreshConfig` (`ttl` / `rotation` / `rotationGraceMs` / `onRotationReuse`), three rotation modes with timeline diagrams, stateless degradation, `MAX_CONCURRENT_REACHED` + `onLimit`, epoch revocation, `revokeAllForUser` cascade |
| Magic links        | [magic-links.md](./magic-links.md)       | `generateMagicLinkToken()`, persistence pattern (`persist(state, ttlMs)` + `consume(token)`), stateless `DenylistStore` requirement, `BuildMagicLinkUrl`, recovery flow recipe                                                       |
| Stores             | [auth-stores.md](./auth-stores.md)       | `CredentialStore<TPayload>` + `DenylistStore` contracts, `CredentialStoreMemory`, `CredentialStoreRedis` (3 key namespaces + `RedisLike`), `CredentialStoreAtscriptDb` (`AuthCredentialTable` shape, GC), the shipped `.as` model    |

## See also

Reference docs: https://aoothjs.dev (pre-release — see `TODO.md` in repo). Source: https://github.com/moostjs/aoothjs/tree/main/packages/auth.
