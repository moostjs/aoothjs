# Stores

Reference for the `CredentialStore<TClaims>` + `DenylistStore` contracts, every shipped implementation, the `RedisLike` / `AuthCredentialTable` structural types, the shipped `.as` model, and the contract a custom store must satisfy. Token issuance / refresh / magic-link semantics live in [tokens.md](./tokens.md), [refresh.md](./refresh.md), [magic-links.md](./magic-links.md).

## Contents

- [`CredentialStore` contract](#credentialstore-contract)
- [`DenylistStore` contract](#denyliststore-contract)
- [`CredentialStoreMemory`](#credentialstorememory)
- [`CredentialStoreRedis`](#credentialstoreredis)
- [`CredentialStoreAtscriptDb`](#credentialstoreatscriptdb)
- [`AoothAuthCredential` `.as` model](#aoothauthcredential-as-model)
- [Custom store contract](#custom-store-contract)
- [`DenylistStoreMemory` / `DenylistStoreRedis`](#denyliststorememory--denyliststoreredis)

## `CredentialStore` contract

```ts
interface CredentialStore<TClaims extends object = object> {
  persist(state: CredentialState<TClaims>, ttl?: number): Promise<string>;
  retrieve(token: string): Promise<CredentialState<TClaims> | null>;
  consume(token: string): Promise<CredentialState<TClaims> | null>;
  update(token: string, state: CredentialState<TClaims>): Promise<string>;
  revoke(token: string): Promise<void>;
  revokeAllForUser(userId: string): Promise<number>;
  listForUser?(userId: string): Promise<Array<CredentialState<TClaims> & { token: string }>>;
}
```

Behavioural contract every implementation MUST satisfy:

| Method             | Contract                                                                                                                                                                                                |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `persist`          | Generates a fresh token id. If `ttl` is supplied it overrides `state.expiresAt`. Fail-loud on already-dead state (`ttl <= 0` or `expiresAt <= now`).                                                    |
| `retrieve`         | Returns `null` for unknown / expired / wrong-kind / denied tokens. Never throws on bad input. Opportunistically GCs expired rows.                                                                       |
| `consume`          | Atomic `retrieve` + `revoke`. Single-use guarantee. Stateless stores require a `DenylistStore` — otherwise throw `STATELESS_OPERATION_UNSUPPORTED`.                                                     |
| `update`           | Idempotent for unknown tokens (returns input token, no-op). Returned token may differ from input — stateless stores re-issue. Pushing `state.expiresAt` past `now` is treated as a revoke, not a write. |
| `revoke`           | Unknown token is a no-op. Idempotent.                                                                                                                                                                   |
| `revokeAllForUser` | Cascade across `kind: 'access'` AND `kind: 'refresh'`. Stateful returns deletion count; stateless returns sentinel `1` ("epoch bumped, count unknown").                                                 |
| `listForUser`      | Optional. When implemented, returns all live entries (access + refresh). The orchestrator filters refresh entries before returning to user code.                                                        |

`CredentialState<TClaims>`:

```ts
interface CredentialState<TClaims extends object = object> {
  userId: string;
  issuedAt: number; // ms
  expiresAt: number; // ms
  claims?: TClaims;
  metadata?: CredentialMetadata;
  kind?: "access" | "refresh"; // default treated as 'access'
  parentCredentialId?: string; // rotated refresh: id of predecessor
  rotatedAt?: number; // set by sliding rotation
}
```

## `DenylistStore` contract

```ts
interface DenylistStore {
  add(jti: string, expiresAt: number): Promise<void>;
  has(jti: string): Promise<boolean>;
  cleanup(): Promise<number>;
}
```

- `add` is idempotent — adding a `jti` twice with different `expiresAt` is unspecified; pick the larger value if you care.
- `has` returns `false` once `expiresAt` has passed (lazy expiry on memory / TTL-eviction on Redis).
- `cleanup()` returns count of removed entries. No-op on Redis (server self-evicts).

## `CredentialStoreMemory`

In-process `Map<token, state>` + `Map<userId, Set<token>>` secondary index.

```ts
import { CredentialStoreMemory } from "@aoothjs/auth";

const store = new CredentialStoreMemory<{ roles: string[] }>();
```

- Token id = `randomUUID()`.
- O(1) `revokeAllForUser` via the secondary index.
- No TTL eviction — entries persist until `retrieve` notices `expiresAt <= now` (and prunes), or `cleanup` is called externally.
- Fine for tests and single-process apps. **Lost on restart.**

## `CredentialStoreRedis`

Subpath `@aoothjs/auth/redis`. Multi-pod-safe.

```ts
import { CredentialStoreRedis } from "@aoothjs/auth/redis";

const store = new CredentialStoreRedis({
  redis, // any RedisLike
  prefix: "aooth:cred", // default
});
```

Key namespaces:

| Key                   | Type   | Lifecycle                                     |
| --------------------- | ------ | --------------------------------------------- |
| `<prefix>:t:<token>`  | string | JSON-serialised state. Written with `PX` TTL. |
| `<prefix>:u:<userId>` | SET    | Tokens for this user. NOT TTL-bounded.        |

Defaults: `prefix: 'aooth:cred'`. Token id = `randomUUID()`.

`RedisLike` is structural — exactly 8 methods consumed:

```ts
interface RedisLike {
  set(key: string, value: string, mode?: "PX", ttlMs?: number): Promise<string | null>;
  get(key: string): Promise<string | null>;
  del(...keys: string[]): Promise<number>;
  exists(key: string): Promise<number>;
  expire(key: string, ttlMs: number): Promise<number>; // PEXPIRE
  sadd(key: string, ...members: string[]): Promise<number>;
  srem(key: string, ...members: string[]): Promise<number>;
  smembers(key: string): Promise<string[]>;
}
```

- `ioredis`, `redis@4+`, `@redis/client`, `ioredis-mock`, ad-hoc test doubles — all match by shape.
- TTL is **always milliseconds via `PX`**, never `EX`. The package does not translate seconds.
- `persist` fails loud (`throw`) when computed TTL is `<= 0` — refuses to write a phantom token.
- User-index `SET` is lazily pruned on `listForUser` and `revokeAllForUser` — Redis-side expiry on the token key takes care of the source of truth.
- `revokeAllForUser` uses `SMEMBERS` → `DEL` → `SREM` (specific members only, not `DEL setKey`) to avoid racing concurrent `persist` calls.

## `CredentialStoreAtscriptDb`

Subpath `@aoothjs/auth/atscript-db`. Backed by a single table.

```ts
import { DbSpace } from "@atscript/db";
import { syncSchema } from "@atscript/db/sync";
import { SqliteAdapter, BetterSqlite3Driver } from "@atscript/db-sqlite";

import { CredentialStoreAtscriptDb } from "@aoothjs/auth/atscript-db";
import { AoothAuthCredential } from "@aoothjs/auth/atscript-db/model.as";

const db = new DbSpace(() => new SqliteAdapter(new BetterSqlite3Driver("./auth.db")));
await syncSchema(db, [AoothAuthCredential]);

const store = new CredentialStoreAtscriptDb({
  table: db.getTable(AoothAuthCredential),
});
```

`AuthCredentialTable<TClaims>` is structural — only the methods the adapter calls are required:

```ts
interface AuthCredentialTable<TClaims extends object = object> {
  insertOne(row: AuthCredentialRow<TClaims>): Promise<{ insertedId: unknown }>;
  findOne(q: { filter: Record<string, unknown> }): Promise<AuthCredentialRow<TClaims> | null>;
  findMany(q: {
    filter?: Record<string, unknown>;
    controls?: Record<string, unknown>;
  }): Promise<AuthCredentialRow<TClaims>[]>;
  replaceOne(
    row: AuthCredentialRow<TClaims>,
  ): Promise<{ matchedCount: number; modifiedCount: number }>;
  deleteOne(idOrPk: unknown): Promise<{ deletedCount: number }>;
  deleteMany(filter: Record<string, unknown>): Promise<{ deletedCount: number }>;
}
```

`AuthCredentialRow<TClaims>` mirrors the `.as` model field-for-field as a plain TS interface — re-declared so the auth package builds without `@atscript/typescript`. Shapes match by construction.

Implementation specifics:

- Token id = `randomUUID()`, written as the row PK.
- `revokeAllForUser` → `deleteMany({ userId })` — one round trip, returns `deletedCount`.
- `retrieve` opportunistically GCs the row when `expiresAt <= now`.
- `listForUser` GCs dead rows in a background `deleteMany({ token: { $in: expired } })`.
- `update` with `state.expiresAt <= now` calls `deleteOne`, not `replaceOne` — parity with Redis fail-loud posture.

## `AoothAuthCredential` `.as` model

Shipped at `@aoothjs/auth/atscript-db/model.as`:

```atscript
@db.table 'aooth_credentials'
@db.depth.limit 0
export interface AoothAuthCredential {
    @meta.id              token: string
    @db.index.plain       userId: string
                          issuedAt: number.timestamp
                          expiresAt: number.timestamp
                          kind?: string
    @db.json              claims?: { [key: string]: any }
    @db.json              metadata?: { ip?: string, userAgent?: string, fingerprint?: string, label?: string }
                          parentCredentialId?: string
                          rotatedAt?: number.timestamp
}
```

Annotations explained:

| Annotation                          | Effect                                                                                           |
| ----------------------------------- | ------------------------------------------------------------------------------------------------ |
| `@db.table 'aooth_credentials'`     | Physical table name. Override if it collides in your schema.                                     |
| `@db.depth.limit 0`                 | Refuses nested writes via the moost-db REST layer. This table is auth-internal — no FK fan-out.  |
| `@meta.id` on `token`               | Token is the PK. `findOne({ filter: { token } })` and `deleteOne(token)` are O(1).               |
| `@db.index.plain` on `userId`       | Indexed for `revokeAllForUser` / `listForUser` scans. Required for production load.              |
| `@db.json` on `claims` / `metadata` | Stored as JSON. Caveat: `@db.json` columns are not filterable / sortable on SQL adapters.        |
| `kind?: string` (not enum)          | Adapter-portable — engines without a native enum type collapse literal unions to strings anyway. |

Wiring requires `@atscript/db` (peer dep, optional). For consumers that use a different ORM, re-implement `AuthCredentialTable` against your own table — the structural type is the only contract.

## Custom store contract

Implement `CredentialStore<TClaims>` directly. Required behaviours (in addition to the method-level contracts above):

1. **`persist` generates the token id.** Never trust the caller to supply one — UUIDs / opaque blobs are the store's responsibility.
2. **Token bytes are opaque to `AuthCredential`.** The orchestrator hashes them for `credentialId` and passes them through; no parsing.
3. **`kind` is preserved through round-trips.** `persist` writes it, `retrieve` returns it, `update` overwrites it — without this `auth.validate()` cannot reject refresh tokens.
4. **`expiresAt` is the source of truth for expiry.** Stores MUST reject `retrieve` when `expiresAt <= clock.now()`, opportunistically GC'ing the entry.
5. **`revokeAllForUser` returns a count or sentinel.** Stateful stores return real counts; stateless return `1` to signal "took effect, count unknown". Zero is reserved for "no entries existed".
6. **Stateless stores DOCUMENT the missing `listForUser`.** Returning `undefined` for `listForUser` is the signal — `AuthCredential` checks `if (this.store.listForUser)` before calling it.

Minimal skeleton:

```ts
import type { CredentialStore, CredentialState } from "@aoothjs/auth";
import { randomUUID } from "node:crypto";

export class CredentialStoreCustom<
  TClaims extends object = object,
> implements CredentialStore<TClaims> {
  async persist(state: CredentialState<TClaims>, ttl?: number): Promise<string> {
    const token = randomUUID();
    const expiresAt = typeof ttl === "number" ? Date.now() + ttl : state.expiresAt;
    if (expiresAt <= Date.now()) throw new Error("dead credential");
    await this.write(token, { ...state, expiresAt });
    return token;
  }
  // retrieve / consume / update / revoke / revokeAllForUser / listForUser …
  private async write(token: string, state: CredentialState<TClaims>): Promise<void> {
    /* … */
  }
}
```

## `DenylistStoreMemory` / `DenylistStoreRedis`

```ts
import { DenylistStoreMemory } from "@aoothjs/auth";
import { DenylistStoreRedis } from "@aoothjs/auth/redis";
```

| Implementation        | Storage                                | `cleanup`                         | Use for                           |
| --------------------- | -------------------------------------- | --------------------------------- | --------------------------------- |
| `DenylistStoreMemory` | `Map<jti, expiresAt>`                  | Sweeps expired entries; returns N | Tests, single-process deployments |
| `DenylistStoreRedis`  | `<prefix>:<jti>` strings with `PX` TTL | No-op — Redis self-evicts         | Multi-pod stateless deployments   |

`DenylistStoreRedis` defaults: `prefix: 'aooth:dl'`. Wire one `RedisLike` instance and share it across `CredentialStoreRedis` + `DenylistStoreRedis` — the keyspaces are disjoint (`aooth:cred:*` vs `aooth:dl:*`).

`AuthCredentialOptions.denylist` is **separate** from the per-store `denylist`:

- The per-store denylist (`CredentialStoreJwt({ denylist })`) keys on `jti` and powers `revoke` / `consume` / `update` for stateless stores.
- The orchestrator-level denylist (`AuthCredential({ denylist })`) keys on the **raw token string** and is checked by `validate()` before delegating to `store.retrieve`. Use it to invalidate specific access tokens without involving the store.

Sharing a single `DenylistStore` instance across both is safe — the keyspaces (UUID jti vs raw token string) don't collide.
