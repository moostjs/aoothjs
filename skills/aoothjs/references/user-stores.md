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
  abstract exists(username: string): Promise<boolean>;
  abstract findByUsername(username: string): Promise<(UserCredentials & T) | null>;
  abstract create(data: UserCredentials & T): Promise<void>;
  abstract update(username: string, update: UserStoreUpdate): Promise<boolean>;
  abstract delete(username: string): Promise<boolean>;
}
```

| Method           | Required behavior                                                                                                           |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `exists`         | `true` iff a row matches `username`.                                                                                        |
| `findByUsername` | Return the full row OR `null`. Treat the returned object as caller-owned (memory store deep-clones).                        |
| `create`         | Insert. On unique-username conflict throw `UserAuthError("ALREADY_EXISTS", message)`.                                       |
| `update`         | Apply `set` as deep-merge AND `inc` as atomic increment per dot-path. Return `false` when no row matched, `true` otherwise. |
| `delete`         | Hard-delete. Return `false` when no row matched.                                                                            |

The service relies on the `false` return values to throw `NOT_FOUND` — never silently succeed when a row is missing.

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

// backup-codes batch (full replacement)
{ set: { backupCodes: hashes } }

// trusted-device append (full array replacement, read-modify-write at service layer)
{ set: { trustedDevices: [...next] } }
```

**Arrays in `set` are wholesale replacements**, not append/remove operations. The service computes the next array client-side and hands the whole thing over.

## `UserStoreMemory<T>`

```ts
import { UserStoreMemory } from "@aoothjs/user";

const store = new UserStoreMemory();
const seeded = new UserStoreMemory({
  alice: {
    /* full UserCredentials & T row */
  },
});
```

Backed by `Map<username, UserCredentials & T>`. Features:

- `create` throws `UserAuthError("ALREADY_EXISTS")` on duplicate.
- `findByUsername` returns a **`structuredClone`** of the stored record — mutating it does not affect storage. (`memory.ts:24`.)
- `create` also stores a `structuredClone` — callers can keep using the object they passed in without leaking subsequent mutations into the store.
- `update.set` deep-merges via the in-package `deepMerge` (top-level fields shallow-merged, plain-object sub-fields recursively merged, arrays / null / primitives replaced).
- `update.inc` walks the dot-path with `incrementAtPath` (treats absent path components as `0`, creates intermediate objects on demand).
- `update` returns `false` when no entry exists; `delete` returns the `Map.delete` boolean.

Recommended fake for tests — the seed constructor is convenient for fixture-based scenarios.

## Writing a custom store

Start from the contract above. Five rules:

1. **`create` MUST raise `UserAuthError("ALREADY_EXISTS", message)`** on a unique-username conflict. The atscript-db adapter translates `DbError.code === "CONFLICT"` to this; SQL stores translate the engine-specific unique-violation code (e.g. `SQLITE_CONSTRAINT_UNIQUE`, `23505` on Postgres).
2. **`update` MUST treat `set` as a deep merge** for `password` / `account` / `mfa` / `trustedDevices`. The `.as` model encodes this via `@db.patch.strategy 'merge'`. Wholesale-replacing any of these sub-objects breaks partial-update semantics (e.g. a login update would clobber the user's MFA config).
3. **`update` MUST treat `inc` as atomic** per dot-path. SQL: `SET col = col + N`. atscript-db: emits `{ $inc: N }` at the dot-path so the engine handles the atomic op.
4. **`update` / `delete` return `false`** when no row matched. The service surfaces that as `NOT_FOUND`.
5. **Arrays in `set` are full replacements.** The service has already built `next` from `prev` — your job is to persist whatever you receive.

```ts
import {
  UserStore,
  UserAuthError,
  type UserCredentials,
  type UserStoreUpdate,
} from "@aoothjs/user";

class MyStore<T extends object = object> extends UserStore<T> {
  async exists(username: string): Promise<boolean> {
    /* SELECT 1 ... */
  }
  async findByUsername(username: string): Promise<(UserCredentials & T) | null> {
    const row = await db.selectOne({ username });
    return row ?? null;
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
  async update(username: string, update: UserStoreUpdate): Promise<boolean> {
    const { matched } = await db.deepMergeAndIncrement(username, update.set, update.inc);
    return matched;
  }
  async delete(username: string): Promise<boolean> {
    const { matched } = await db.delete({ username });
    return matched;
  }
}
```

## `UsersStoreAtscriptDb<T>`

The shipped production adapter (`@aoothjs/user/atscript-db`).

```ts
import { DbSpace } from "@atscript/db";
import { syncSchema } from "@atscript/db/sync";
import { BetterSqlite3Driver, SqliteAdapter } from "@atscript/db-sqlite";
import { UserService } from "@aoothjs/user";
import { type AuthUserTable, UsersStoreAtscriptDb } from "@aoothjs/user/atscript-db";
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
- `findByUsername` → `table.findOne({ filter: { username } })`.
- `create` → `table.insertOne(data)`. Catches errors with structural `code === "CONFLICT"` via the internal `isConflict(err)` and rethrows as `UserAuthError("ALREADY_EXISTS")`. Any other error propagates.
- `update`:
  - Starts the patch with `{ username }` (used by the table to locate the row).
  - `Object.assign(patch, update.set)` — the underlying `AtscriptDbTable.updateOne` honors `@db.patch.strategy 'merge'` from the `.as` model for each sub-object.
  - For each entry in `update.inc`, `setAtPath(patch, path, { $inc: amount })` — emits the engine-level atomic increment op at the dot-path.
  - No-op when nothing besides `username` is set (early return `true`).
  - Returns `result.matchedCount > 0`.
- `delete` → `table.deleteMany({ username })`, returns `result.deletedCount > 0`.

**Conflict detection is structural, not nominal.** `isConflict` only checks `err.code === "CONFLICT"` — tests can throw any object with that shape; real `@atscript/db` `DbError` instances match by shape.

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

The package ships `@aoothjs/user/atscript-db/model.as` as a literal-file export pointing at `src/atscript-db/user-credentials.as`:

```atscript
export interface AoothUserCredentials {
    @db.index.unique 'username_idx'
    username: string

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

- **No `@meta.id` and no `@db.table`** — consumers always extend it. They pick the primary-key column, its default strategy (`@db.default.uuid`, `@db.default.increment`, etc.), and the table name.
- `@db.patch.strategy 'merge'` propagates through `extends`. If you re-declare any of these sub-objects in your extending interface, the annotation does NOT carry over to the redeclaration — re-add it explicitly or you'll switch to wholesale replace.
- `backupCodes?: string[]` (from `UserCredentials`) is NOT declared in the shipped `.as` model — add it on your extending interface if you store backup codes (the type is `string[]`, no per-element annotations needed).
