# stores

`UserStore<T>` is the abstract storage contract. `UserStoreMemory<T>` ships for tests. `UsersStoreAtscriptDb<T>` is the production adapter on top of `@atscript/db`.

## Contents

- [`UserStore<T>` contract](#userstoret-contract)
- [`UserStoreUpdate` shape](#userstoreupdate-shape)
- [`UserStoreMemory<T>`](#userstorememoryt)
- [Writing a custom store](#writing-a-custom-store)
- [`UsersStoreAtscriptDb<T>`](#usersstoreatscriptdbt)
- [`AuthUserTable` and the cast pattern](#authusertable-and-the-cast-pattern)
- [`AoothUserCredentials` — the shipped `.as` model](#aoothusercredentials--the-shipped-as-model)

## `UserStore<T>` contract

```ts
abstract class UserStore<T extends object = object> {
  abstract exists(handle: string): Promise<boolean>; // by username
  abstract findById(id: string): Promise<(UserCredentials & T) | null>;
  abstract findByHandle(handle: string): Promise<(UserCredentials & T) | null>;
  abstract findByIdentifier(value: string): Promise<(UserCredentials & T) | null>;
  abstract create(data: UserCredentials & T): Promise<void>;
  abstract update(id: string, update: UserStoreUpdate): Promise<boolean>;
  abstract delete(id: string): Promise<boolean>;
  abstract withCas(id, mutator, opts?): Promise<void>; // read-modify-write under OCC
}
```

**All reads-by-identity and ALL writes key on the surrogate `id`** (the token subject, `getUserId()`). The three reads differ by resolution:

| Method             | Resolves by                                                        | For                                                                                                            |
| ------------------ | ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| `findById`         | the surrogate `id` only                                            | canonical identity read; session-subject lookups                                                               |
| `findByHandle`     | `username` exactly, **then** the configured handle fields in order | the **login** path ONLY — ordered, never a permissive `$or`                                                    |
| `findByIdentifier` | `id`, then `username`, then the configured handle fields           | permissive internal / admin / recovery lookup                                                                  |
| `create`           | —                                                                  | Insert; mint `id` if absent; throw `ALREADY_EXISTS` on duplicate `username` **or** any configured handle value |
| `update`/`delete`  | `id`                                                               | return `false` when no row matched → service throws `NOT_FOUND`                                                |
| `withCas`          | `id`                                                               | re-read via `findById` → mutate → write under `expectedVersion`; throws `NOT_FOUND`/`CAS_EXHAUSTED`            |

The secondary handle fields are the consumer-declared, `@db.index.unique` columns tagged `@aooth.user.email` / `@aooth.user.phone` (resolved by the wiring into the store's ordered `handleFields`); `username` is the one base login handle. See [recovery-and-handles.md](recovery-and-handles.md).

`findByHandle` is NOT a permissive `$or`: `id`/`username`/handle fields are all `string`, so a permissive match could resolve one user's username that equals another's handle value to the wrong account. Keep login on `findByHandle`. The service relies on the `false` return values to throw `NOT_FOUND` — never silently succeed when a row is missing.

## `UserStoreUpdate` shape

```ts
interface UserStoreUpdate {
  set?: DeepPartial<UserCredentials>; // deep-merge target
  inc?: Record<string, number>; // dot-path → increment
}
```

Examples actually emitted by `UserService`:

```ts
// login success
{ set: { account: { lastLogin: now, failedLoginAttempts: 0 } } }

// login failure
{ inc: { "account.failedLoginAttempts": 1 } }

// login failure that trips the lock
{
  inc: { "account.failedLoginAttempts": 1 },
  set: { account: { locked: true, lockReason: "Too many login attempts", lockEnds } },
}

// password change
{ set: { password: { hash, history, lastChanged, isInitial: false } } }

// MFA method add
{ set: { mfa: { methods: [...next] } } }

// trusted-device append (full array replacement, read-modify-write at service layer)
{ set: { trustedDevices: [...next] } }
```

**Arrays in `set` are wholesale replacements**, not append/remove operations. The service computes the next array client-side and hands the whole thing over.

## `UserStoreMemory<T>`

```ts
import { UserStoreMemory } from "@aooth/user";

const store = new UserStoreMemory();
const seeded = new UserStoreMemory({
  alice: {
    /* full UserCredentials & T row */
  },
});
```

Backed by `Map<id, UserCredentials & T>` (keyed by the surrogate `id`). Features:

- `create` mints an `id` if absent and throws `UserAuthError("ALREADY_EXISTS")` on a duplicate `username` **or** any configured handle field value (it takes the same `handleFields` as the atscript-db store; omit for username-only).
- Reads (`findById`/`findByHandle`/`findByIdentifier`) return a **`structuredClone`** of the stored record — mutating it does not affect storage.
- `create` also stores a `structuredClone` — callers can keep using the object they passed in without leaking subsequent mutations into the store.
- `update.set` deep-merges via the in-package `deepMerge` (top-level fields shallow-merged, plain-object sub-fields recursively merged, arrays / null / primitives replaced).
- `update.inc` walks the dot-path with `incrementAtPath` (treats absent path components as `0`, creates intermediate objects on demand).
- `update` returns `false` when no entry exists; `delete` returns the `Map.delete` boolean.

Recommended fake for tests — the seed constructor is convenient for fixture-based scenarios.

## Writing a custom store

Start from the contract above. Rules:

1. **Reads-by-identity and writes key on `id`.** `findById` is strict-by-`id`. `findByHandle` is the LOGIN resolver — match `username` first, then the configured handle fields in order (NEVER a permissive `$or`). `findByIdentifier` is permissive (`id` → `username` → the configured handle fields) for admin/recovery only. The handle fields are the consumer-declared `@aooth.user.email` / `@aooth.user.phone` columns the wiring resolves into the store's ordered `handleFields` — the store stays name-agnostic (see [recovery-and-handles.md](recovery-and-handles.md)).
2. **`create` MUST raise `UserAuthError("ALREADY_EXISTS", message)`** on a duplicate `username` **or** any configured handle field value, and mint an `id` if the row arrives without one. The atscript-db adapter translates `DbError.code === "CONFLICT"`; SQL stores translate the engine-specific unique-violation code (e.g. `SQLITE_CONSTRAINT_UNIQUE`, `23505` on Postgres).
3. **`update` MUST treat `set` as a deep merge** for `password` / `account` / `mfa` / `trustedDevices`. The `.as` model encodes this via `@db.patch.strategy 'merge'`. Wholesale-replacing any of these sub-objects breaks partial-update semantics (e.g. a login update would clobber the user's MFA config).
4. **`update` MUST treat `inc` as atomic** per dot-path. SQL: `SET col = col + N`. atscript-db: emits `{ $inc: N }` at the dot-path so the engine handles the atomic op.
5. **`update` / `delete` return `false`** when no row matched (by `id`). The service surfaces that as `NOT_FOUND`.
6. **Arrays in `set` are full replacements.** The service has already built `next` from `prev` — your job is to persist whatever you receive.
7. **`withCas`** loops up to `opts.maxAttempts` (default 2): re-read via `findById` → `mutator(current)` (may return `null` to bail) → `update` under `expectedVersion = current.version`; throw `CAS_EXHAUSTED` on saturation, `NOT_FOUND` on a missing row. See `UserStoreMemory.withCas`.

```ts
import { UserStore, UserAuthError, type UserCredentials, type UserStoreUpdate } from "@aooth/user";

class MyStore<T extends object = object> extends UserStore<T> {
  // Ordered secondary handle columns (e.g. ["email", "phone"]) the wiring
  // resolved from the model's @aooth.user.* annotations; [] for username-only.
  constructor(private readonly handleFields: string[] = []) {
    super();
  }
  async exists(handle: string): Promise<boolean> {
    /* SELECT 1 ... WHERE username = handle */
  }
  async findById(id: string): Promise<(UserCredentials & T) | null> {
    return (await db.selectOne({ id })) ?? null;
  }
  async findByHandle(handle: string): Promise<(UserCredentials & T) | null> {
    // username first, then each configured handle field — ordered, never $or
    let row = await db.selectOne({ username: handle });
    for (const field of this.handleFields) {
      if (row) break;
      row = await db.selectOne({ [field]: handle });
    }
    return row ?? null;
  }
  async findByIdentifier(value: string): Promise<(UserCredentials & T) | null> {
    return (await this.findById(value)) ?? (await this.findByHandle(value));
  }
  async create(data: UserCredentials & T): Promise<void> {
    try {
      await db.insert(data);
    } catch (err) {
      if (isUniqueViolation(err)) {
        throw new UserAuthError("ALREADY_EXISTS", `User "${data.username}" already exists`);
      }
      throw err;
    }
  }
  async update(id: string, update: UserStoreUpdate): Promise<boolean> {
    const { matched } = await db.deepMergeAndIncrement(id, update.set, update.inc);
    return matched;
  }
  async delete(id: string): Promise<boolean> {
    const { matched } = await db.delete({ id });
    return matched;
  }
  async withCas(id, mutator, opts) {
    /* re-read findById(id) → mutate → update under expectedVersion; retry on CAS miss */
  }
}
```

## `UsersStoreAtscriptDb<T>`

The shipped production adapter (`@aooth/user/atscript-db`).

```ts
import { DbSpace } from "@atscript/db";
import { syncSchema } from "@atscript/db/sync";
import { BetterSqlite3Driver, SqliteAdapter } from "@atscript/db-sqlite";
import { UserService } from "@aooth/user";
import { type AuthUserTable, UsersStoreAtscriptDb } from "@aooth/user/atscript-db";
import { AppUser } from "./app-user.as";

const db = new DbSpace(() => new SqliteAdapter(new BetterSqlite3Driver("./app.db")));
await syncSchema(db, [AppUser]);

type CustomFields = { email?: string };
const store = new UsersStoreAtscriptDb<CustomFields>({
  table: db.getTable(AppUser) as unknown as AuthUserTable<CustomFields>,
});
const svc = new UserService<CustomFields>(store, {
  /* ... */
});
```

How it maps the contract:

- `exists` → `table.count({ filter: { username } }) > 0`.
- `findById` → `table.findOne({ filter: { id } })`.
- `findByHandle` → `table.findOne({ filter: { username } })`, then `{ filter: { [field]: handle } }` for each configured handle field if no match (ordered).
- `findByIdentifier` → `findById`, else `findByHandle`.
- `create` → `table.insertOne(data)`. Adapter translates DB conflict errors (duplicate `username` or any configured handle value) to `UserAuthError("ALREADY_EXISTS")`; any other error propagates.
- `update` → `table.updateOne` keyed by `id`; forwards `update.set` as a deep-merge patch (the `.as` model's `@db.patch.strategy 'merge'` is load-bearing) and translates each `update.inc` entry into an engine-level atomic increment at the dot-path. Returns `result.matchedCount > 0`.
- `delete` → `table.deleteMany({ id })`, returns `result.deletedCount > 0`.

## `AuthUserTable` and the cast pattern

`AuthUserTable<TUserCustom>` is the minimal structural surface of `AtscriptDbTable` that the adapter uses:

```ts
interface AuthUserTable<TUserCustom extends object = object> {
  count(query: { filter: Record<string, unknown> }): Promise<number>;
  findOne(query: {
    filter: Record<string, unknown>;
  }): Promise<UserCredentialsRow<TUserCustom> | null>;
  insertOne(row: Record<string, unknown>): Promise<{ insertedId: unknown }>;
  updateOne(
    patch: Record<string, unknown>,
  ): Promise<{ matchedCount: number; modifiedCount: number }>;
  deleteMany(filter: Record<string, unknown>): Promise<{ deletedCount: number }>;
}

type UserCredentialsRow<TUserCustom extends object = object> = UserCredentials & TUserCustom;
```

`db.getTable(AppUser)` returns `AtscriptDbTable<Record<string, unknown>>` — TypeScript doesn't know the row shape carries `UserCredentials`. The `as unknown as AuthUserTable<CustomFields>` cast is intentional and load-bearing: it tells the adapter "trust me, the row shape matches `UserCredentials & CustomFields`" — which holds by construction because `AppUser extends AoothUserCredentials`.

Keep `T` aligned across the three places it appears (`UsersStoreAtscriptDb<T>`, `AuthUserTable<T>`, `UserService<T>`) — TypeScript catches drift.

## `AoothUserCredentials` — the shipped `.as` model

The package ships `@aooth/user/atscript-db/model.as` as a literal-file export pointing at `src/atscript-db/user-credentials.as`:

```atscript
export interface AoothUserCredentials {
    @meta.id
    @db.default.uuid
    id: string

    @db.index.unique 'username_idx'
    username: string

    @db.column.version
    version: number.int

    @db.patch.strategy 'merge'
    password: { hash: string; history: string[]; lastChanged: number.timestamp; isInitial: boolean }

    @db.patch.strategy 'merge'
    account: {
        active: boolean; locked: boolean; lockReason: string
        lockEnds: number.timestamp; failedLoginAttempts: number; lastLogin: number.timestamp
        pendingInvitation?: boolean
    }

    @db.patch.strategy 'merge'
    mfa: { methods: { name: string; confirmed: boolean; value: string }[]; defaultMethod: string; autoSend: boolean }

    @db.patch.strategy 'merge'
    trustedDevices?: { token: string; ip?: string; issuedAt: number.timestamp; expiresAt: number.timestamp; name?: string }[]
}
```

Notably:

- **Ships `@meta.id` (`id`, the token subject), the unique `username` handle (the one base login handle), and `@db.column.version`.** The base has **no `email` and no `phone`** — do NOT redeclare `id`/`username`/`version` (redundant; risks flipping the unique-index/merge semantics). Add `@db.table` on your extending interface, plus any secondary login/recovery handle YOURSELF: declare your own `email` / `phone` field, give it `@db.index.unique`, and tag it `@aooth.user.email` / `@aooth.user.phone` (the unique index is the account-takeover guard; without it the handle is warn-and-disabled at boot). See [recovery-and-handles.md](recovery-and-handles.md).
- `@db.patch.strategy 'merge'` propagates through `extends`. If you re-declare any of these sub-objects in your extending interface, the annotation does NOT carry over to the redeclaration — re-add it explicitly or you'll switch to wholesale replace.
- `backupCodes?: string[]` is NOT declared in the shipped `.as` model (nor on the `UserCredentials` type) — add it on your extending interface if you store backup codes (the type is `string[]`, no per-element annotations needed).

## Federated identity store (account linking)

`@aooth/user` ships a SECOND, independent store for federated login: `FederatedIdentityStore` (abstract) + `FederatedIdentityStoreMemory` (root export) + `FederatedIdentityStoreAtscriptDb` (`/atscript-db`). It maps a provider account `(provider, subject)` → a user `id`, with a display snapshot refreshed each login (`touchLogin`). `userId` is a PLAIN indexed column, NOT a hard FK (`@aooth/user` can't know the consumer's user table); GDPR cleanup is `deleteAllForUser(userId)`. `(provider, subject)` is compound-unique → `link` throws `UserAuthError('ALREADY_EXISTS')` if linked to any user. The shipped `AoothFederatedIdentity` `.as` model is at `@aooth/user/atscript-db/federated-model.as`. It is consumed by `@aooth/idp`'s `FederatedLoginService` — full surface, the matching policy, and `linkIdentity` live in [idp.md](idp.md).
