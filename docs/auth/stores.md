# Stores

`@aoothjs/auth` is store-agnostic — every persistence concern is behind `CredentialStore<TClaims>` and `DenylistStore`. This page covers every shipped implementation: the interfaces, the in-memory defaults, the Redis adapter, the atscript-db adapter (with the shipped `.as` model), and the matrix you'd use to pick between them.

## The store matrix

| Store                         | Subpath                     | State location            | Token shape      | `listForUser` | `consume`           | Notes                                                            |
| ----------------------------- | --------------------------- | ------------------------- | ---------------- | ------------- | ------------------- | ---------------------------------------------------------------- |
| `CredentialStoreMemory`       | `@aoothjs/auth`             | In-process `Map`          | Opaque UUID      | yes           | yes                 | Dev, tests. Lost on restart.                                     |
| `CredentialStoreJwt`          | `@aoothjs/auth`             | The token itself          | Signed JWT       | no            | requires `denylist` | Stateless. See [Tokens](./tokens).                               |
| `CredentialStoreEncapsulated` | `@aoothjs/auth`             | The token itself          | AES-256-GCM blob | no            | requires `denylist` | Stateless + confidential.                                        |
| `CredentialStoreRedis`        | `@aoothjs/auth/redis`       | Redis                     | Opaque UUID      | yes           | yes                 | Multi-instance, fast.                                            |
| `CredentialStoreAtscriptDb`   | `@aoothjs/auth/atscript-db` | DB row via `@atscript/db` | Opaque UUID      | yes           | yes                 | Durable, queryable, integrates with the rest of your data model. |

And the denylist matrix:

| Denylist              | Subpath               | Persistence      |
| --------------------- | --------------------- | ---------------- |
| `DenylistStoreMemory` | `@aoothjs/auth`       | In-process `Map` |
| `DenylistStoreRedis`  | `@aoothjs/auth/redis` | Redis with TTL   |

## `CredentialStore<TClaims>` — the interface

Every store implements this exact shape:

```ts
interface CredentialStore<TClaims = object> {
  persist(state: CredentialState<TClaims>, ttl?: number): Promise<string>;
  retrieve(token: string): Promise<CredentialState<TClaims> | null>;
  consume(token: string): Promise<CredentialState<TClaims> | null>;
  update(token: string, state: CredentialState<TClaims>): Promise<string>;
  revoke(token: string): Promise<void>;
  revokeAllForUser(userId: string): Promise<number>;
  listForUser?(userId: string): Promise<Array<CredentialState<TClaims> & { token: string }>>;
}
```

### Method semantics

| Method             | Returns                  | On stateful store                                  | On stateless store                                                     |
| ------------------ | ------------------------ | -------------------------------------------------- | ---------------------------------------------------------------------- |
| `persist`          | the new token            | inserts row, returns generated UUID                | encodes state into token, returns it                                   |
| `retrieve`         | state or `null`          | DB lookup; null on miss / expired / epoch-shadowed | crypto verify; null on bad sig / expired / denylisted / epoch-shadowed |
| `consume`          | state or `null`          | atomic retrieve+delete                             | retrieve + `denylist.add(jti, expiresAt)`; throws without denylist     |
| `update`           | possibly-different token | updates row in place, returns same token           | re-encodes state, returns new token; throws without denylist           |
| `revoke`           | `void`                   | deletes row                                        | adds to denylist; throws without denylist                              |
| `revokeAllForUser` | count                    | `deleteMany({ userId })`, real count               | bumps epoch, returns sentinel `1`                                      |
| `listForUser`      | array                    | enumerated                                         | optional and absent on stateless                                       |

::: warning `update` may return a new token
On stateless stores, `update` re-encodes the state into a fresh token — the returned string is different from the input. **Callers must use the returned value**, not the original. The orchestrator handles this internally; if you call `update` directly, do the same.
:::

### `CredentialState<TClaims>`

The shape stored under each token:

```ts
interface CredentialState<TClaims = object> {
  userId: string;
  issuedAt: number;
  expiresAt: number;
  claims?: TClaims;
  metadata?: CredentialMetadata;
  kind?: "access" | "refresh" | string;
  parentCredentialId?: string;
  rotatedAt?: number;
}
```

`kind` is free-form when you persist directly (e.g. `'magic.recovery'`). The orchestrator only emits `'access'` and `'refresh'`.

## `DenylistStore` — the interface

```ts
interface DenylistStore {
  add(jti: string, expiresAt: number): Promise<void>;
  has(jti: string): Promise<boolean>;
  cleanup(): Promise<number>;
}
```

| Method    | Returns                  | Notes                                                                                                                    |
| --------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------------ |
| `add`     | `void`                   | Adds with absolute ms expiry. After `expiresAt`, the entry can be evicted — it's irrelevant once the JWT itself expired. |
| `has`     | boolean                  | Lazy expiry: returning `false` for an entry past its `expiresAt` is allowed.                                             |
| `cleanup` | count of removed entries | Bulk eviction sweep. May be a no-op on backends with native TTL.                                                         |

## `CredentialStoreMemory`

The default. A `Map<token, state>` keyed by token, plus a secondary `Map<userId, Set<token>>` for O(1) `revokeAllForUser` and `listForUser`.

```ts
import { CredentialStoreMemory, AuthCredential } from "@aoothjs/auth";

const auth = new AuthCredential({
  store: new CredentialStoreMemory(),
  accessTtl: 60 * 60 * 1000,
});
```

| Property                   | Value                                                               |
| -------------------------- | ------------------------------------------------------------------- |
| Token shape                | `randomUUID()`                                                      |
| TTL enforcement            | Lazy on `retrieve` — expired rows are skipped and (eventually) GC'd |
| Persistence across restart | None                                                                |
| Multi-instance             | None                                                                |
| `listForUser`              | O(1) lookup, O(n) materialisation                                   |

Use it for tests and dev. For everything else, pick Redis or atscript-db.

## `DenylistStoreMemory`

```ts
import { DenylistStoreMemory } from "@aoothjs/auth";

const denylist = new DenylistStoreMemory();
```

`Map<jti, expiresAt>` with lazy expiry on `has` and explicit `cleanup` sweep. Use only with `CredentialStoreMemory` / single-instance JWT in dev. Multi-instance JWT needs `DenylistStoreRedis`.

## Redis adapter

```bash
pnpm add @aoothjs/auth ioredis
```

```ts
import { Redis } from "ioredis";
import { CredentialStoreRedis, DenylistStoreRedis } from "@aoothjs/auth/redis";
import { AuthCredential } from "@aoothjs/auth";

const redis = new Redis(process.env.REDIS_URL!);

const auth = new AuthCredential({
  store: new CredentialStoreRedis({ redis }),
  accessTtl: 15 * 60 * 1000,
  refresh: { ttl: 30 * 24 * 3600 * 1000, rotation: "sliding" },
  maxConcurrent: 10,
});
```

### `RedisLike` — structural typing

The adapter doesn't depend on any specific Redis client. It accepts anything that implements the eight methods it uses:

```ts
interface RedisLike {
  /** `SET key value [PX ms]` — `mode` and `ttlMs` are optional. */
  set(key: string, value: string, mode?: "PX", ttlMs?: number): Promise<string | null>;
  get(key: string): Promise<string | null>;
  del(...keys: string[]): Promise<number>;
  exists(key: string): Promise<number>;
  /** `PEXPIRE key ttlMs` — ttl is in **milliseconds**, not seconds. */
  expire(key: string, ttlMs: number): Promise<number>;
  sadd(key: string, ...members: string[]): Promise<number>;
  srem(key: string, ...members: string[]): Promise<number>;
  smembers(key: string): Promise<string[]>;
}
```

`ioredis`, `redis@v4` (the official client), and `keydb` clients all satisfy this shape. Bring whichever you already have.

### Key namespaces

| Namespace               | Shape                             | TTL                                                         |
| ----------------------- | --------------------------------- | ----------------------------------------------------------- |
| `aooth:cred:t:<token>`  | JSON-serialised `CredentialState` | `PX` (ms) from `expiresAt - now`                            |
| `aooth:cred:u:<userId>` | Redis SET of tokens for the user  | None — entries are removed on `revoke` / `revokeAllForUser` |
| `aooth:dl:<jti>`        | `"1"`                             | `PX` from `expiresAt - now`                                 |

The prefix is configurable:

```ts
new CredentialStoreRedis({ redis, prefix: "app:" });
// keys become app:cred:t:<token>, app:cred:u:<userId>
```

### Operation costs

| Operation          | Redis ops                                                                            |
| ------------------ | ------------------------------------------------------------------------------------ |
| `persist`          | `set` (token) + `sadd` (user index)                                                  |
| `retrieve`         | `get`                                                                                |
| `consume`          | `get` + `del` (single-shot — small race window; sweeps with `revoke` are idempotent) |
| `update`           | `set` (token)                                                                        |
| `revoke`           | `del` + `srem`                                                                       |
| `revokeAllForUser` | `smembers` + `del`(many) + `del`(set)                                                |
| `listForUser`      | `smembers` + N × `get`                                                               |

### `persist` fails loud on dead credentials

If you call `persist` with `state.expiresAt <= now`, the Redis adapter throws a plain `Error` (not an `AuthError`) with the message `"CredentialStoreRedis.persist: refusing to persist an already-expired credential"`. It does **not** silently insert a row that's already expired. This catches clock skew and config bugs early — handle it as a non-`AuthError` exception.

```ts
await store.persist({ userId: "alice", issuedAt: now, expiresAt: now - 1000 /* ... */ });
// throws Error (NOT AuthError)
```

### `DenylistStoreRedis`

```ts
const denylist = new DenylistStoreRedis({ redis, prefix: "app:" });
```

`add` writes `app:dl:<jti>` with `PX` TTL. `has` checks `exists`. `cleanup` is a **no-op** — Redis self-evicts. The method exists only for interface conformance.

### Wiring stateless JWT against Redis

```ts
import { Redis } from "ioredis";
import { CredentialStoreJwt, AuthCredential } from "@aoothjs/auth";
import { DenylistStoreRedis } from "@aoothjs/auth/redis";

const redis = new Redis(process.env.REDIS_URL!);

const auth = new AuthCredential({
  store: new CredentialStoreJwt({
    algorithm: "EdDSA",
    privateKey,
    publicKey,
    denylist: new DenylistStoreRedis({ redis }),
  }),
  accessTtl: 5 * 60 * 1000,
  refresh: { ttl: 7 * 24 * 3600 * 1000, rotation: "always" },
});
```

The denylist is durable across pods. The per-user revocation epoch map, however, is still **in-memory** by default — see the warning in [Tokens](./tokens#revocation-on-jwt).

## atscript-db adapter

```bash
pnpm add @aoothjs/auth @atscript/db
```

```ts
import { DbSpace } from "@atscript/db";
import { CredentialStoreAtscriptDb } from "@aoothjs/auth/atscript-db";
import { AuthCredential } from "@aoothjs/auth";
import { AoothAuthCredential } from "@aoothjs/auth/atscript-db/model.as";
// Importing the raw `.as` file requires the atscript build pipeline
// (`unplugin-atscript` for Vite/Rollup, or run `asc` ahead of time). Without
// it, your bundler cannot resolve the `.as` extension.

const db = new DbSpace({
  /* adapter, models: [AoothAuthCredential] */
});
await db.sync();

const auth = new AuthCredential({
  store: new CredentialStoreAtscriptDb({
    table: db.getTable(AoothAuthCredential),
  }),
  accessTtl: 60 * 60 * 1000,
  refresh: { ttl: 30 * 24 * 3600 * 1000, rotation: "sliding" },
});
```

### The shipped `.as` model

`@aoothjs/auth/atscript-db/model.as` exports `AoothAuthCredential` — a one-table model that maps directly onto `CredentialState`:

```as
@db.table 'aooth_credentials'
@db.depth.limit 0
export interface AoothAuthCredential {
    @meta.id
    token: string

    @db.index.plain
    userId: string

    issuedAt: number.timestamp
    expiresAt: number.timestamp

    kind?: string

    @db.json
    claims?: {
        [key: string]: any
    }

    @db.json
    metadata?: {
        ip?: string
        userAgent?: string
        fingerprint?: string
        label?: string
    }

    parentCredentialId?: string
    rotatedAt?: number.timestamp
}
```

| Field                             | Purpose                                                                                                   |
| --------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `@meta.id token`                  | Row PK. `findOne({ token })` and `deleteOne(token)` are O(1).                                             |
| `@db.index.plain userId`          | Index for `revokeAllForUser` / `listForUser` scans.                                                       |
| `issuedAt`, `expiresAt`           | Both `number.timestamp` — ms since epoch.                                                                 |
| `kind`                            | Free string. Workflows use `'access'`, `'refresh'`, or magic-link discriminators like `'magic.recovery'`. |
| `claims`                          | `@db.json` — opaque JSON column.                                                                          |
| `metadata`                        | `@db.json` — IP / UA / fingerprint / label. Augment via `CredentialMetadata` declaration merging.         |
| `parentCredentialId`, `rotatedAt` | Set by refresh-token rotation.                                                                            |

The `@db.depth.limit 0` annotation prevents joins / projections from cascading through this model — credentials are an opaque storage detail, not a relational entity.

::: tip Augmenting metadata
Augment `CredentialMetadata` via declaration merging (see [Credentials](./credentials#credentialmetadata-declaration-merging)). The `.as` model accepts any JSON shape because of `@db.json`; the TypeScript surface narrows it for you.
:::

### `AuthCredentialTable<TClaims>` — structural interface

The adapter doesn't directly require the `@atscript/db` table class — it requires a structurally-typed interface that the table happens to satisfy:

```ts
interface AuthCredentialTable<TClaims = object> {
  insertOne(row: AuthCredentialRow<TClaims>): Promise<{ insertedId: unknown }>;
  findOne(query: { filter: Record<string, unknown> }): Promise<AuthCredentialRow<TClaims> | null>;
  findMany(query: {
    filter?: Record<string, unknown>;
    controls?: Record<string, unknown>;
  }): Promise<AuthCredentialRow<TClaims>[]>;
  /** Replaces by PK on the row itself — no `{ filter, row }` wrapper. */
  replaceOne(
    row: AuthCredentialRow<TClaims>,
  ): Promise<{ matchedCount: number; modifiedCount: number }>;
  /** Deletes by PK value (the token string), not by filter. */
  deleteOne(idOrPk: unknown): Promise<{ deletedCount: number }>;
  deleteMany(filter: Record<string, unknown>): Promise<{ deletedCount: number }>;
}
```

Any class with those six methods is acceptable. The atscript-db generated table type satisfies the structure naturally.

### Operation costs

| Operation          | DB ops                                                 |
| ------------------ | ------------------------------------------------------ |
| `persist`          | `insertOne`                                            |
| `retrieve`         | `findOne` (+ opportunistic `deleteOne` on expired row) |
| `consume`          | `findOne` + `deleteOne`                                |
| `update`           | `replaceOne` (or `deleteOne` if `expiresAt <= now`)    |
| `revoke`           | `deleteOne`                                            |
| `revokeAllForUser` | `deleteMany({ userId })` — **one round trip**          |
| `listForUser`      | `findMany` + background `deleteMany` for expired rows  |

### Opportunistic GC

The adapter doesn't run a background sweeper. Instead:

- `retrieve` deletes the row inline when it finds it past `expiresAt`. The call still returns `null`.
- `listForUser` issues a background `deleteMany` for any expired rows it filtered out of the result.

This keeps the table from growing unboundedly without a cron job. For high-volume deployments, also schedule an external GC sweep — see your database's TTL feature (e.g. MongoDB TTL index, Postgres partitioning).

### `update` fail-loud parity with Redis

```ts
await store.update(token, { ...state, expiresAt: now - 1000 });
// calls deleteOne, returns the original token
```

Updating a credential to be already-expired causes the row to be removed rather than rewritten. Same shape as the Redis adapter's `persist` rejection — config bugs surface as deletes, not zombie rows.

## Writing your own store

Implement `CredentialStore<TClaims>`. Match these invariants:

1. **`persist` is atomic** — either the row exists or it doesn't, never half-written.
2. **`consume` is atomic** — exactly one of two concurrent calls succeeds; the other returns `null`. This is the single-use guarantee for magic links.
3. **`revoke`** removes the row (or denylists the `jti` for stateless) such that `retrieve` immediately returns `null`.
4. **`revokeAllForUser`** must remove every credential — both `'access'` and `'refresh'` kinds. Stateless implementations can use the epoch-gate pattern.
5. **TTL is real**. Expired entries return `null` from `retrieve` even if the row hasn't been GC'd yet.
6. **`listForUser`** is optional. If you support it, return every live credential, including refresh.
7. **`update`** returns the (possibly-new) token. Document whether you mutate in place or re-issue.

Tests against your store should cover: same-millisecond `revokeAllForUser` + `issue` (the `>=` epoch gate); concurrent `consume` (only one wins); `persist` of a dead row (fail loud, in line with Redis / atscript adapters); `listForUser` returns both access and refresh kinds.

## Picking a store

| Scenario                                               | Recommended store                                                             |
| ------------------------------------------------------ | ----------------------------------------------------------------------------- |
| Tests, dev                                             | `CredentialStoreMemory`                                                       |
| Single-process Node server with a DB                   | `CredentialStoreAtscriptDb`                                                   |
| Multi-instance Node, low latency                       | `CredentialStoreRedis`                                                        |
| Stateless API, public verification, partner audience   | `CredentialStoreJwt` (RS\* / ES\* / EdDSA) + Redis denylist                   |
| Stateless with confidential claims                     | `CredentialStoreEncapsulated` + Redis denylist                                |
| Hybrid — short-lived stateless access, durable refresh | JWT for access + atscript-db for refresh (run two `AuthCredential` instances) |

## See also

- [Credentials & Sessions](./credentials) — the orchestrator that wraps all stores.
- [Tokens (JWT)](./tokens) — the stateless options.
- [Refresh](./refresh) — how rotation interacts with denylists.
- Source: [packages/auth/src/stores](https://github.com/moostjs/aoothjs/tree/main/packages/auth/src/stores).
- `.as` model: [packages/auth/src/atscript-db/auth-credential.as](https://github.com/moostjs/aoothjs/blob/main/packages/auth/src/atscript-db/auth-credential.as).
