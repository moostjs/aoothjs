# Stores

`UserStore<T>` is the abstract storage contract for `UserService`. This page documents the contract, the `UserStoreUpdate { set, inc }` shape, the in-memory reference store for tests, and the shipped `@atscript/db` adapter.

## The abstract contract

```ts
// packages/user/src/store/user-store.ts
abstract class UserStore<T extends object = object> {
  abstract exists(handle: string): Promise<boolean>; // by username
  abstract findById(id: string): Promise<(UserCredentials & T) | null>;
  abstract findByHandle(handle: string): Promise<(UserCredentials & T) | null>;
  abstract findByIdentifier(value: string): Promise<(UserCredentials & T) | null>;
  abstract create(data: UserCredentials & T): Promise<void>;
  abstract update(id: string, update: UserStoreUpdate): Promise<boolean>; // false = no row
  abstract delete(id: string): Promise<boolean>; // false = no row
  abstract withCas(id, mutator, opts?): Promise<void>; // read-modify-write under OCC
}
```

Source: [`packages/user/src/store/user-store.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/store/user-store.ts).

`UserService` is the only caller of these methods in the public API surface — but the contract is small and stable, so implementing your own store is straightforward.

::: warning Reads, writes, and the stable `id`
Everything keys on the surrogate **`id`** (the token subject — what `useAuth().getUserId()` returns), **except** the three flavours of read:

| Method                    | Resolves by                                                            | Use for                                                             |
| ------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `findById(id)`            | the surrogate `id` only                                                | the canonical identity read — authenticated/session-subject lookups |
| `findByHandle(handle)`    | `username` exactly, **then** the configured handle fields in order     | the **login** path only (deterministic, ordered)                    |
| `findByIdentifier(value)` | `id`, then `username`, then the configured handle fields (first match) | permissive internal / admin / recovery lookup                       |

`findByHandle` is intentionally **not** a permissive `$or`: `username` and every handle column are all `string`, so a single permissive match could silently resolve one user's username that happens to equal another user's email/phone handle to the wrong account. Keep login on `findByHandle`. The secondary handle fields are not hardcoded — the wiring resolves them from your model's `@aooth.user.email` / `@aooth.user.phone` markers and threads the ordered list into the store, which stays name-agnostic (see [Phone, Recovery Channels & Handles](/moost/recovery-and-handles)).
:::

## `UserStoreUpdate` — the patch protocol

```ts
type UserStoreUpdate = {
  set?: DeepPartial<UserCredentials>; // deep-merge
  inc?: Record<string /* dot-path */, number>; // atomic increment
};
```

Every mutation in `UserService` translates to one of these. The two cooperate — a single `update()` call can carry both `set` and `inc`.

### What `UserService` actually emits

| Action                          | Patch                                                                                                     |
| ------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Login success                   | `{ set: { account: { lastLogin: now, failedLoginAttempts: 0 } } }`                                        |
| Login failure (below threshold) | `{ inc: { "account.failedLoginAttempts": 1 } }`                                                           |
| Login failure tripping lock     | `{ inc: { "account.failedLoginAttempts": 1 }, set: { account: { locked: true, lockReason, lockEnds } } }` |
| Password change                 | `{ set: { password: { hash, history, lastChanged: now, isInitial: false } } }`                            |
| Replace backup codes            | `{ set: { backupCodes: [hash, hash, ...] } }`                                                             |
| Trusted devices                 | `{ set: { trustedDevices: [...nextArray] } }`                                                             |
| MFA change                      | `{ set: { mfa: { methods, defaultMethod, autoSend } } }`                                                  |
| Lock / unlock                   | `{ set: { account: { locked, lockReason, lockEnds } } }`                                                  |

## What a custom store must do

A correct `UserStore<T>` implementation:

1. **`create` throws `ALREADY_EXISTS`** on a duplicate `username` — or any configured handle column — conflict (use `UserAuthError` from `@aooth/user`), mirroring the DB unique indexes.
2. **`update` deep-merges the `set` patch** for object-valued sub-keys (`password`, `account`, `mfa`, `trustedDevices`). Don't wholesale-replace those sub-objects from a partial.
3. **Arrays in `set` are wholesale replacements.** The service builds the next array client-side (e.g. `backupCodes`, `trustedDevices`) and hands you the full list.
4. **`update` applies `inc` atomically** per dot-path. SQL: `SET col = col + N`. JSON columns: equivalent atomic primitive in your engine.
5. **`update` and `delete` return `false` when no row matched.** The service uses that to throw `NOT_FOUND`.
6. **Reads return `null`**, not a thrown error, when missing — for all three of `findById`, `findByHandle`, `findByIdentifier`.
7. **`findByHandle` matches `username` first, then the configured handle fields in order** — ordered, never a permissive `$or`. The handle fields are not hardcoded; the wiring derives them from `@aooth.user.email` / `@aooth.user.phone` and passes the ordered list to the store. See the warning above.
8. **`withCas` re-reads via `findById`** each attempt and applies the patch under CAS (`expectedVersion = current.version`); it throws `NOT_FOUND` when `id` is missing and `CAS_EXHAUSTED` when retries saturate.

A minimal but valid in-memory implementation lives at [`UserStoreMemory`](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/store/memory.ts) — read that as your reference.

## `UserStoreMemory<T>`

```ts
import { UserStoreMemory } from "@aooth/user";

const store = new UserStoreMemory(); // empty
const seeded = new UserStoreMemory({ alice: existingRecord });
```

| Behavior  | Detail                                                                                                                                                                           |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Storage   | `Map<id, structuredClone(record)>` — keyed by the surrogate `id`.                                                                                                                |
| Isolation | reads return a `structuredClone` — mutating the result does **not** affect storage.                                                                                              |
| Conflicts | `create` mints an `id` if absent and throws `UserAuthError("ALREADY_EXISTS", ...)` on a duplicate `username` **or** any configured handle field (passed via `{ handleFields }`). |
| `inc`     | Atomic numeric add at dot-path via `setAtPath`.                                                                                                                                  |
| `set`     | Deep-merge for objects, wholesale-replace for arrays.                                                                                                                            |

It's the recommended fake for unit tests and for prototyping before you wire a real DB.

```ts
import { UserService, UserStoreMemory } from "@aooth/user";

const users = new UserService(new UserStoreMemory(), {
  password: { scryptN: 1024, scryptR: 1, scryptP: 1, keyLength: 32 },
});
```

## Writing a custom store

Skeleton for a SQL-backed store:

```ts
import { UserStore, UserAuthError } from "@aooth/user";
import type { UserCredentials, UserStoreUpdate, DeepPartial } from "@aooth/user";

export class PostgresUserStore<T extends object = object> extends UserStore<T> {
  // Ordered secondary handle columns (e.g. ["email", "phone"]) — the wiring
  // resolves these from your model's `@aooth.user.*` markers and hands them in.
  // The store stays name-agnostic; an empty list means username-only login.
  constructor(
    private sql: any /* your sql tag */,
    private handleFields: string[] = [],
  ) {
    super();
  }

  async exists(handle: string) {
    const r = await this.sql`SELECT 1 FROM users WHERE username = ${handle} LIMIT 1`;
    return r.length > 0;
  }

  async findById(id: string) {
    const r = await this.sql`SELECT * FROM users WHERE id = ${id} LIMIT 1`;
    return r[0] ?? null;
  }

  // LOGIN resolver — username first, then the configured handle fields in order.
  // NEVER a permissive `$or`.
  async findByHandle(handle: string) {
    const byU = await this.sql`SELECT * FROM users WHERE username = ${handle} LIMIT 1`;
    if (byU[0]) return byU[0];
    for (const field of this.handleFields) {
      // `field` is a trusted column name from the resolved handle spec, not user input.
      const byH = await this.sql`SELECT * FROM users WHERE ${this.sql(field)} = ${handle} LIMIT 1`;
      if (byH[0]) return byH[0];
    }
    return null;
  }

  // Permissive internal/admin/recovery lookup — id, then username, then the handle fields.
  async findByIdentifier(value: string) {
    return (await this.findById(value)) ?? (await this.findByHandle(value));
  }

  async create(data: UserCredentials & T) {
    try {
      await this.sql`INSERT INTO users ${this.sql(data)}`;
    } catch (e: any) {
      // structural conflict check — match your driver's shape
      if (this.isConflict(e)) throw new UserAuthError("ALREADY_EXISTS", "User exists");
      throw e;
    }
  }

  async update(id: string, patch: UserStoreUpdate) {
    // 1) deep-merge `set` into the JSON columns
    // 2) apply `inc` atomically (col = col + N) in the same statement
    // 3) WHERE id = ${id}; return r.rowCount > 0
    // (implementation depends on your schema — JSON columns vs. flat columns)
  }

  async delete(id: string) {
    const r = await this.sql`DELETE FROM users WHERE id = ${id}`;
    return r.count > 0;
  }

  async withCas(id, mutator, opts) {
    // Loop up to `opts.maxAttempts` (default 2): re-read via `findById(id)`,
    // call `mutator(current)` (may return `null` to bail), then `update` under
    // `expectedVersion = current.version`. On a CAS miss, retry; on saturation
    // throw `UserAuthError("CAS_EXHAUSTED")`, on a missing row `NOT_FOUND`.
    // See `UserStoreMemory.withCas` for the reference loop.
  }

  private isConflict(e: any) {
    return e?.code === "23505"; /* PG unique_violation — username or any handle column */
  }
}
```

::: tip Structural conflict detection
Match by error **code**, not message. Driver error messages change between versions and locales; error codes are stable.
:::

::: warning Don't replace `account` / `password` / `mfa` on partial `set`
If you store the user record as a single JSON column, your `update` must merge **deeply** into existing JSON, not replace the column outright. A patch of `{ account: { failedLoginAttempts: 0 } }` must keep all other `account.*` fields intact.
:::

## The `@atscript/db` adapter

Subpath: `@aooth/user/atscript-db` ([source](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/atscript-db/index.ts)).

Exports:

```ts
import {
  UsersStoreAtscriptDb,
  type UserCredentialsRow,
  type AuthUserTable,
} from "@aooth/user/atscript-db";
```

Shipped `.as` model (subpath export `./atscript-db/model.as`):

```ts
import { AoothUserCredentials } from "@aooth/user/atscript-db/model.as";
```

### Extend the model in your app

The shipped interface already declares the surrogate **`id`** (`@meta.id` + `@db.default.uuid`), the unique `username` index (the one base login handle), the `@db.column.version` counter, and the `@db.patch.strategy 'merge'` sub-objects. It omits `@db.table` (the model is storage-agnostic until you bind it) — and, deliberately, it ships **no** `email` or `phone`. A secondary login/recovery handle is **consumer-declared**: you add your own field, index it `@db.index.unique`, and tag it `@aooth.user.email` / `@aooth.user.phone`. So your extension names the table and declares whichever handles you want — **don't** re-declare `id`:

```ts
// app.as
import { AoothUserCredentials } from '@aooth/user/atscript-db/model.as'

@db.table 'users'
export interface AppUser extends AoothUserCredentials {
    // id, username (unique), version — all inherited.
    // Declare your own secondary login/recovery handle(s):
    @db.index.unique 'email_idx'
    @aooth.user.email
    email?: string

    // Add any other columns here.
    tenantId: string
}
```

::: warning Re-declaring `id` is redundant; declaring `email` / `phone` is required
`id` lives on the base — re-declaring it in an extending interface is at best redundant and at worst flips the unique-index or merge semantics, so inherit it. By contrast, `email` and `phone` are **not** on the base: if you want login or recovery by email/phone you **must** declare your own field, give it `@db.index.unique` (the account-takeover guard — `findByHandle` must resolve to at most one row; a missing index warns and disables the handle), and tag it `@aooth.user.email` / `@aooth.user.phone`. The wiring discovers these markers at boot and threads the ordered handle list into the store. See [Phone, Recovery Channels & Handles](/moost/recovery-and-handles).
:::

::: warning Don't re-declare merged sub-objects without `@db.patch.strategy 'merge'`
The merge strategy is what makes partial `set` patches work. Re-declaring `account`, `password`, `mfa`, or `trustedDevices` in your extending interface without the annotation flips them to wholesale replace and silently corrupts records on partial writes.
:::

### Wire it

```ts
import { DbSpace, syncSchema } from "@atscript/db";
import { SqliteAdapter, BetterSqlite3Driver } from "@atscript/db-sqlite";
import { UserService } from "@aooth/user";
import { UsersStoreAtscriptDb, type AuthUserTable } from "@aooth/user/atscript-db";
import { AppUser } from "./app.as";

const db = new DbSpace(() => new SqliteAdapter(new BetterSqlite3Driver("./app.db")));
await syncSchema(db, [AppUser]);

const store = new UsersStoreAtscriptDb({
  table: db.getTable(AppUser) as unknown as AuthUserTable,
});

const users = new UserService(store, { password: { pepper: process.env.PEPPER } });
```

The `as unknown as AuthUserTable` cast is required because `AtscriptDbTable<T>` types its row as `Record<string, unknown>`; the adapter narrows to `UserCredentialsRow<TUserCustom>` at runtime.

### What the adapter does

| `UserService` patch                             | atscript-db op                                                                                                  |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `{ set: { account: { ... } } }`                 | Deep merge into the `account` JSON column (via `@db.patch.strategy 'merge'`).                                   |
| `{ inc: { "account.failedLoginAttempts": 1 } }` | `{ $inc: 1 }` at the dot-path, emitting `account.failedLoginAttempts = account.failedLoginAttempts + 1` in SQL. |
| `{ set: { backupCodes: [...] } }`               | Wholesale array replacement.                                                                                    |
| `create` conflict                               | Adapter translates DB conflicts to `UserAuthError("ALREADY_EXISTS", ...)`.                                      |

## The federated identity store

`@aooth/user` also ships a second, independent store for **account linking** — `FederatedIdentityStore` (abstract) + `FederatedIdentityStoreMemory` + `FederatedIdentityStoreAtscriptDb` (from `@aooth/user/atscript-db`). It maps an external provider account `(provider, subject)` to a user `id` and is consumed by `@aooth/idp`'s `FederatedLoginService`. Its narrative, the matching policy, and the shipped `AoothFederatedIdentity` `.as` model live under [IdP — Account resolution](/idp/account-resolution); see the [API reference](/api/user#federated-identity-store) for the method surface.

## See also

- [Credentials Model](./credentials) — the shape `UserStore<T>` persists.
- [IdP — Account resolution](/idp/account-resolution) — the `FederatedIdentityStore` in context.
- [Errors](./errors) — what `create` / `update` / `delete` throws when things go wrong.
- [`@aooth/user/atscript-db` source](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/atscript-db/index.ts).
- [Shipped `.as` model](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/atscript-db/user-credentials.as).
