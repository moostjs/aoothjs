# Stores

Reference for the `CredentialStore<TPayload>` + `DenylistStore` contracts, every shipped implementation, the `RedisLike` / `AuthCredentialTable` structural types, the shipped `.as` model, and the contract a custom store must satisfy. Token issuance / refresh / magic-link semantics live in [tokens.md](./tokens.md), [refresh.md](./refresh.md), [magic-links.md](./magic-links.md).

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

Every member deals in `CredentialState & TPayload` (envelope below). Behavioural contract every implementation MUST satisfy:

| Member             | Signature                                                                            | Notes                                                                                                                                                                                                   |
| ------------------ | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `persist`          | `(state: CredentialState & TPayload, ttl?: number) => Promise<string>`               | Generates a fresh token id. If `ttl` is supplied it overrides `state.expiresAt`. Fail-loud on already-dead state (`ttl <= 0` or `expiresAt <= now`).                                                    |
| `retrieve`         | `(token: string) => Promise<(CredentialState & TPayload) \| null>`                   | Returns `null` for unknown / expired / wrong-kind / denied tokens. Never throws on bad input. Opportunistically GCs expired rows.                                                                       |
| `consume`          | `(token: string) => Promise<(CredentialState & TPayload) \| null>`                   | Atomic `retrieve` + `revoke`. Single-use guarantee. Stateless stores require a `DenylistStore` — otherwise throw `STATELESS_OPERATION_UNSUPPORTED`.                                                     |
| `update`           | `(token: string, state: CredentialState & TPayload) => Promise<string>`              | Idempotent for unknown tokens (returns input token, no-op). Returned token may differ from input — stateless stores re-issue. Pushing `state.expiresAt` past `now` is treated as a revoke, not a write. |
| `revoke`           | `(token: string) => Promise<void>`                                                   | Unknown token is a no-op. Idempotent.                                                                                                                                                                   |
| `revokeAllForUser` | `(userId: string) => Promise<number>`                                                | Cascade across `kind: 'access'` AND `kind: 'refresh'`. Stateful returns deletion count; stateless returns sentinel `1` ("epoch bumped, count unknown").                                                 |
| `listForUser?`     | `(userId: string) => Promise<Array<CredentialState & TPayload & { token: string }>>` | Optional. When implemented, returns all live entries (access + refresh). The orchestrator filters refresh entries before returning to user code.                                                        |
| `touch?`           | `(token: string, at: number) => Promise<void>`                                       | Optional. Set `lastSeenAt = at` on the token if live; no-op otherwise. Backs sessions' `trackLastSeen: 'validate'`. Stateless omit (token immutable). See [sessions.md](sessions.md).                   |
| `listSessions?`    | `(userId: string) => Promise<Array<CredentialState & TPayload & { token: string }>>` | Optional native session grouping — reserved/unused (the orchestrator groups `listForUser` by `sessionId`). See [sessions.md](sessions.md).                                                              |

Exact shape: [docs api](https://aoothjs.dev/api/auth#credentialstore-tpayload).

`CredentialState & TPayload` — fixed envelope intersected with the consumer's typed payload (flat root fields; no `claims` container):

| Field                 | Type                    | Default                       | Meaning                                                                   |
| --------------------- | ----------------------- | ----------------------------- | ------------------------------------------------------------------------- |
| `userId`              | `string`                | — (required)                  | —                                                                         |
| `issuedAt`            | `number`                | — (required)                  | ms                                                                        |
| `expiresAt`           | `number`                | — (required)                  | ms                                                                        |
| `metadata?`           | `CredentialMetadata`    | unset                         | —                                                                         |
| `kind?`               | `'access' \| 'refresh'` | unset → treated as `'access'` | —                                                                         |
| `parentCredentialId?` | `string`                | unset                         | Rotated refresh: id of predecessor.                                       |
| `rotatedAt?`          | `number`                | unset                         | Set by sliding rotation.                                                  |
| `sessionId?`          | `string`                | unset                         | Token-family id, stable across rotation — see [sessions.md](sessions.md). |
| `lastSeenAt?`         | `number`                | unset                         | Activity time; only written under `trackLastSeen`.                        |

Payload fields ride flat on the same object and round-trip automatically — Memory/Redis serialize the whole state; atscript-db persists the typed columns the consumer added to their model.

Exact shape: [docs api](https://aoothjs.dev/api/auth#credentialstate).

## `DenylistStore` contract

| Member    | Signature                                           | Notes                                                                                                           |
| --------- | --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `add`     | `(jti: string, expiresAt: number) => Promise<void>` | Idempotent — adding a `jti` twice with different `expiresAt` is unspecified; pick the larger value if you care. |
| `has`     | `(jti: string) => Promise<boolean>`                 | Returns `false` once `expiresAt` has passed (lazy expiry on memory / TTL-eviction on Redis).                    |
| `cleanup` | `() => Promise<number>`                             | Returns count of removed entries. No-op on Redis (server self-evicts).                                          |

Exact shape: [docs api](https://aoothjs.dev/api/auth#denyliststore).

## `CredentialStoreMemory`

In-process `Map<token, state>` + `Map<userId, Set<token>>` secondary index.

```ts
import { CredentialStoreMemory } from "@aooth/auth";

const store = new CredentialStoreMemory<{ roles: string[] }>();
```

- Token id = `randomUUID()`.
- O(1) `revokeAllForUser` via the secondary index.
- No TTL eviction — entries persist until `retrieve` notices `expiresAt <= now` (and prunes), or `cleanup` is called externally.
- Fine for tests and single-process apps. **Lost on restart.**

## `CredentialStoreRedis`

Subpath `@aooth/auth/redis`. Multi-pod-safe.

```ts
import { CredentialStoreRedis } from "@aooth/auth/redis";

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

| Member     | Signature                                                                              | Notes                            |
| ---------- | -------------------------------------------------------------------------------------- | -------------------------------- |
| `set`      | `(key: string, value: string, mode?: 'PX', ttlMs?: number) => Promise<string \| null>` | —                                |
| `get`      | `(key: string) => Promise<string \| null>`                                             | —                                |
| `del`      | `(...keys: string[]) => Promise<number>`                                               | —                                |
| `exists`   | `(key: string) => Promise<number>`                                                     | —                                |
| `expire`   | `(key: string, ttlMs: number) => Promise<number>`                                      | `PEXPIRE` semantics (ttl in ms). |
| `sadd`     | `(key: string, ...members: string[]) => Promise<number>`                               | —                                |
| `srem`     | `(key: string, ...members: string[]) => Promise<number>`                               | —                                |
| `smembers` | `(key: string) => Promise<string[]>`                                                   | —                                |

Exact shape: [docs api](https://aoothjs.dev/api/auth#redislike).

- `ioredis`, `redis@4+`, `@redis/client`, `ioredis-mock`, ad-hoc test doubles — all match by shape.
- TTL is **always milliseconds via `PX`**, never `EX`. The package does not translate seconds.
- `persist` fails loud (`throw`) when computed TTL is `<= 0` — refuses to write a phantom token.
- User-index `SET` is lazily pruned on `listForUser` and `revokeAllForUser` — Redis-side expiry on the token key takes care of the source of truth.
- `revokeAllForUser` uses `SMEMBERS` → `DEL` → `SREM` (specific members only, not `DEL setKey`) to avoid racing concurrent `persist` calls.

## `CredentialStoreAtscriptDb`

Subpath `@aooth/auth/atscript-db`. Backed by a single table.

```ts
import { DbSpace } from "@atscript/db";
import { syncSchema } from "@atscript/db/sync";
import { SqliteAdapter, BetterSqlite3Driver } from "@atscript/db-sqlite";

import { CredentialStoreAtscriptDb } from "@aooth/auth/atscript-db";
import { AoothAuthCredential } from "@aooth/auth/atscript-db/model.as";

const db = new DbSpace(() => new SqliteAdapter(new BetterSqlite3Driver("./auth.db")));
await syncSchema(db, [AoothAuthCredential]);

const store = new CredentialStoreAtscriptDb({
  table: db.getTable(AoothAuthCredential),
  // Optional: name of YOUR @aooth.auth.metadata-annotated @db.json column
  // (resolve at boot via getAoothCredentialMetadataSpec from
  // @aooth/arbac-moost/atscript). Absent -> metadata is not persisted/read.
  metadataField: undefined,
});
```

`AuthCredentialTable<TPayload>` is structural — only the methods the adapter calls are required:

| Member       | Signature                                                                                                                 | Notes |
| ------------ | ------------------------------------------------------------------------------------------------------------------------- | ----- |
| `insertOne`  | `(row: AuthCredentialRow<TPayload>) => Promise<{ insertedId: unknown }>`                                                  | —     |
| `findOne`    | `(q: { filter: Record<string, unknown> }) => Promise<AuthCredentialRow<TPayload> \| null>`                                | —     |
| `findMany`   | `(q: { filter?: Record<string, unknown>; controls?: Record<string, unknown> }) => Promise<AuthCredentialRow<TPayload>[]>` | —     |
| `replaceOne` | `(row: AuthCredentialRow<TPayload>) => Promise<{ matchedCount: number; modifiedCount: number }>`                          | —     |
| `deleteOne`  | `(idOrPk: unknown) => Promise<{ deletedCount: number }>`                                                                  | —     |
| `deleteMany` | `(filter: Record<string, unknown>) => Promise<{ deletedCount: number }>`                                                  | —     |

Exact shape: [docs api](https://aoothjs.dev/api/auth#authcredentialtable-tpayload).

`AuthCredentialRow<TPayload>` mirrors the `.as` model field-for-field as a plain TS interface — re-declared so the auth package builds without `@atscript/typescript`. Shapes match by construction.

Implementation specifics:

- Token id = `randomUUID()`, written as the row PK.
- `revokeAllForUser` → `deleteMany({ userId })` — one round trip, returns `deletedCount`.
- `retrieve` opportunistically GCs the row when `expiresAt <= now`.
- `listForUser` GCs dead rows in a background `deleteMany({ token: { $in: expired } })`.
- `update` with `state.expiresAt <= now` calls `deleteOne`, not `replaceOne` — parity with Redis fail-loud posture.
- The envelope's `metadata` is mapped through the configured `metadataField` column on every write/read (and excluded from the extracted typed payload). No `metadataField` → metadata silently not persisted (memory/JWT stores unaffected — they carry `metadata` natively).

## `AoothAuthCredential` `.as` model

Shipped at `@aooth/auth/atscript-db/model.as`:

```atscript
@db.table 'aooth_credentials'
@db.depth.limit 0
export interface AoothAuthCredential {
    @meta.id              token: string
    @db.index.plain       userId: string
                          issuedAt: number.timestamp
                          expiresAt: number.timestamp
                          kind?: string
                          parentCredentialId?: string
                          rotatedAt?: number.timestamp
    @db.index.plain       sessionId?: string
                          lastSeenAt?: number.timestamp
}
```

Envelope only — NO free-form `claims` column. Carry per-token payload by `extends AoothAuthCredential` + your own typed columns (the adapter round-trips them); `@aooth/arbac-moost` consumers annotate them `@arbac.attenuate.role` / `@arbac.attenuate.attr "userAttr"` for restrict-only credential attenuation. NO `metadata` column either — credential metadata is consumer-declared: a fully-typed `@db.json` field on your extending model (the runtime/validation twin of your `CredentialMetadata` declaration merge), tagged `@aooth.auth.metadata`; resolve the name at boot with `getAoothCredentialMetadataSpec(Model)` (`@aooth/arbac-moost/atscript`, WeakMap-cached) and thread it as the store's `metadataField`, logging `warnings`. At most one annotated field per type (throws); without `@db.json` it is warn-and-disabled; absent → the atscript-db store persists no metadata.

Shape the column by INTERSECTING the exported `AoothCredentialMetadataBase` (same `model[.as]` subpath — the single source of the framework-written envelope keys `ip` / `userAgent` / `fingerprint` / `label` / `credentialKind`; the `.as` twin of `CredentialMetadata`, keep the two in sync) with your extension keys — never hand-mirror the base keys, or a future aooth envelope key gets rejected by your closed schema on upgrade:

```atscript
import { AoothAuthCredential, AoothCredentialMetadataBase } from '@aooth/auth/atscript-db/model'

@aooth.auth.metadata
@db.json
metadata?: AoothCredentialMetadataBase & { geoLat?: number, geoLon?: number }
```

Annotations explained:

| Annotation                        | Effect                                                                                                                                                                                                             |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `@db.table 'aooth_credentials'`   | Physical table name. Override if it collides in your schema.                                                                                                                                                       |
| `@db.depth.limit 0`               | Refuses nested writes via the moost-db REST layer. This table is auth-internal — no FK fan-out.                                                                                                                    |
| `@meta.id` on `token`             | Token is the PK. `findOne({ filter: { token } })` and `deleteOne(token)` are O(1).                                                                                                                                 |
| `@db.index.plain` on `userId`     | Indexed for `revokeAllForUser` / `listForUser` scans. Required for production load.                                                                                                                                |
| `@db.json` (consumer columns)     | Stored as JSON — required on the `@aooth.auth.metadata` column and any structured payload column. Caveat: `@db.json` columns are not filterable / sortable on SQL adapters.                                        |
| `@aooth.auth.metadata` (consumer) | Marks YOUR fully-typed credential-metadata column (`@db.json` required, warn-and-disable otherwise; at most one per type, multiple throw). Resolved by `getAoothCredentialMetadataSpec` → store's `metadataField`. |
| `kind?: string` (not enum)        | Adapter-portable — engines without a native enum type collapse literal unions to strings anyway.                                                                                                                   |

Wiring requires `@atscript/db` (peer dep, optional). For consumers that use a different ORM, re-implement `AuthCredentialTable` against your own table — the structural type is the only contract.

## Custom store contract

Implement `CredentialStore<TPayload>` directly. Required behaviours (in addition to the method-level contracts above):

1. **`persist` generates the token id.** Never trust the caller to supply one — UUIDs / opaque blobs are the store's responsibility.
2. **Token bytes are opaque to `AuthCredential`.** The orchestrator hashes them for `credentialId` and passes them through; no parsing.
3. **`kind` is preserved through round-trips.** `persist` writes it, `retrieve` returns it, `update` overwrites it — without this `auth.validate()` cannot reject refresh tokens.
4. **`expiresAt` is the source of truth for expiry.** Stores MUST reject `retrieve` when `expiresAt <= clock.now()`, opportunistically GC'ing the entry.
5. **`revokeAllForUser` returns a count or sentinel.** Stateful stores return real counts; stateless return `1` to signal "took effect, count unknown". Zero is reserved for "no entries existed".
6. **Stateless stores DOCUMENT the missing `listForUser`.** Returning `undefined` for `listForUser` is the signal — `AuthCredential` checks `if (this.store.listForUser)` before calling it.

Minimal skeleton:

```ts
import type { CredentialStore, CredentialState } from "@aooth/auth";
import { randomUUID } from "node:crypto";

export class CredentialStoreCustom<
  TPayload extends object = object,
> implements CredentialStore<TPayload> {
  async persist(state: CredentialState & TPayload, ttl?: number): Promise<string> {
    const token = randomUUID();
    const expiresAt = typeof ttl === "number" ? Date.now() + ttl : state.expiresAt;
    if (expiresAt <= Date.now()) throw new Error("dead credential");
    await this.write(token, { ...state, expiresAt });
    return token;
  }
  // retrieve / consume / update / revoke / revokeAllForUser / listForUser …
  private async write(token: string, state: CredentialState & TPayload): Promise<void> {
    /* … */
  }
}
```

## `DenylistStoreMemory` / `DenylistStoreRedis`

```ts
import { DenylistStoreMemory } from "@aooth/auth";
import { DenylistStoreRedis } from "@aooth/auth/redis";
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
