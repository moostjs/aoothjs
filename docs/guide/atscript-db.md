# Using atscript-db Models

`aoothjs` ships three `.as` models that you extend in your app. This page covers what each model contributes, how to add columns, and how to wire `syncSchema()` to materialise the tables.

The patterns below are taken from [`packages/e2e-demo/`](https://github.com/moostjs/aoothjs/blob/main/packages/e2e-demo/).

## The three shipped models

| Model                       | Subpath                                 | Purpose                                                                                                                                     |
| --------------------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `AoothUserCredentials`      | `@aooth/user/atscript-db/model.as`      | Base credential record — `username`, `password`, `account`, `mfa`, `trustedDevices`. Does NOT declare `@meta.id` or `@db.table`.            |
| `AoothArbacUserCredentials` | `@aooth/arbac-moost/atscript/models.as` | Extends `AoothUserCredentials` with `@arbac.role roles: string[]`. The default user shape when ARBAC is in play.                            |
| `AoothAuthCredential`       | `@aooth/auth/atscript-db/model.as`      | Bearer-token row — `token` (PK), `userId`, `issuedAt`, `expiresAt`, `claims`, `metadata`. Already complete — apps usually do not extend it. |

::: info Subpath form
The `package.json` exports the raw `.as` source under the `.as` suffix (e.g. `'@aooth/user/atscript-db/model.as'`). That is what `unplugin-atscript` resolves and what the e2e demo imports. There is no separate no-extension subpath — always include `.as`.
:::

## What's in `AoothUserCredentials`

```ts:line-numbers
export interface AoothUserCredentials {
    @db.index.unique 'username_idx'
    username: string

    @db.patch.strategy 'merge'
    password: { hash, history, lastChanged, isInitial }

    @db.patch.strategy 'merge'
    account: { active, locked, lockReason, lockEnds,
               failedLoginAttempts, lastLogin, pendingInvitation? }

    @db.patch.strategy 'merge'
    mfa: { methods, defaultMethod, autoSend }

    @db.patch.strategy 'merge'
    trustedDevices?: { token, ip?, issuedAt, expiresAt, name? }[]
}
```

Source: [`user-credentials.as`](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/atscript-db/user-credentials.as).

Two things to notice:

1. **No `@meta.id`**. The base model is incomplete on purpose so consumers can choose their own PK type (UUID string, integer, ULID, ...) and any `@db.default.*` annotation.
2. **`@db.patch.strategy 'merge'`** on `password`, `account`, `mfa`, `trustedDevices`. This is how the `UsersStoreAtscriptDb` adapter knows that a `set` patch like `{ account: { lastLogin } }` should merge into the existing row, not replace the whole sub-object. **Do not redeclare these sub-objects without the same annotation** — TypeScript shape inheritance does not carry the atscript annotation. See the [`@aooth/user` invariants](../user/#invariants).

## Extending for ARBAC

For ARBAC apps, extend `AoothArbacUserCredentials` instead — it pre-applies `@arbac.role` to `roles: string[]` so you do not have to remember the annotation:

```ts:line-numbers
import { AoothArbacUserCredentials } from '@aooth/arbac-moost/atscript/models'
import { Tenant } from './tenant'
import { Department } from './department'

@db.table 'users'
@db.http.path '/users'
export interface DemoUser extends AoothArbacUserCredentials {
    @meta.id
    @db.default.uuid
    id: string

    @arbac.attribute
    @meta.required
    @db.rel.FK
    tenantId: Tenant.id

    @arbac.attribute
    @db.rel.FK
    departmentId?: Department.id

    @expect.maxLength 128
    email?: string

    @expect.maxLength 80
    displayName?: string

    @db.default.now
    createdAt: number.timestamp
}
```

Source: [`e2e-demo/src/models/user.as`](https://github.com/moostjs/aoothjs/blob/main/packages/e2e-demo/src/models/user.as).

The annotations that matter:

| Annotation                              | Effect                                                                                                                                                                                                                               |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `@db.table 'users'`                     | Names the SQL/Mongo table. Required on the concrete model — the base ships without it.                                                                                                                                               |
| `@meta.id` + `@db.default.uuid`         | Marks the PK and tells the adapter to generate a UUID on insert. Letting `UserService.createUser` omit `id` is the trigger that fires this default.                                                                                  |
| `@arbac.attribute`                      | Every field marked here becomes a key in the `UserAttrs` map passed to role scopes — `attrs.tenantId` is available inside `defineRole().use(allowTableRead(..., { scope: (attrs) => ({ filter: { tenantId: attrs.tenantId } }) }))`. |
| `@db.rel.FK`                            | Optional — declares a foreign-key relationship. Not required for ARBAC to work; useful when you want `@atscript/moost-db` to validate references.                                                                                    |
| `@expect.maxLength` / `@expect.pattern` | Validation constraints surfaced through `@atscript/moost-validator`.                                                                                                                                                                 |
| `@db.default.now`                       | Adapter sets the value to current epoch ms on insert.                                                                                                                                                                                |

::: warning One `@arbac.role` field per user
The `AtscriptArbacUserProvider` fails loud if it sees more than one field with `@arbac.role`. The bundled `AoothArbacUserCredentials` already declares one — do not redeclare in your extending interface.
:::

## A pure-authn user (no ARBAC)

If you do not use the moost ARBAC layer, extend `AoothUserCredentials` directly:

```ts:line-numbers
import { AoothUserCredentials } from '@aooth/user/atscript-db/model.as'

@db.table 'users'
export interface AppUser extends AoothUserCredentials {
    @meta.id
    @db.default.uuid
    id: string

    @expect.maxLength 128
    email?: string

    @db.default.now
    createdAt: number.timestamp
}
```

Everything in `UserService`, `LoginWorkflow`, etc. still works — RBAC just is not enforced.

## The bundled credential table

For token storage, `AoothAuthCredential` is already complete — `@meta.id`, `@db.table 'aooth_credentials'`, `@db.depth.limit 0`. Import and use as-is:

```ts:line-numbers
import { AoothAuthCredential } from '@aooth/auth/atscript-db/model.as'
import { CredentialStoreAtscriptDb } from '@aooth/auth/atscript-db'
```

You normally do not extend it. The full schema is in [`auth-credential.as`](https://github.com/moostjs/aoothjs/blob/main/packages/auth/src/atscript-db/auth-credential.as).

## Sync the schema

`syncSchema()` reads the atscript-derived schema and creates / migrates the tables. Idempotent and safe to call on every boot. It acquires the `__atscript_control` lock so concurrent boots do not race.

```ts:line-numbers
import { DbSpace } from '@atscript/db'
import { syncSchema } from '@atscript/db/sync'
import { BetterSqlite3Driver, SqliteAdapter } from '@atscript/db-sqlite'
import { AoothAuthCredential } from '@aooth/auth/atscript-db/model.as'
import { DemoUser } from './models/user.as'
import { Tenant } from './models/tenant.as'
import { Department } from './models/department.as'

const driver = new BetterSqlite3Driver('./app.db')
const db = new DbSpace(() => new SqliteAdapter(driver))

const tables = {
  users:       db.getTable(DemoUser),
  credentials: db.getTable(AoothAuthCredential),
  tenants:     db.getTable(Tenant),
  departments: db.getTable(Department),
}

await syncSchema(db, [
  Tenant,
  Department,
  DemoUser,
  AoothAuthCredential,
])
```

Source: [`e2e-demo/src/db.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/e2e-demo/src/db.ts).

::: info Pass every model
`syncSchema` only touches the models you pass. Forgetting `AoothAuthCredential` is the most common cause of `"no such table: aooth_credentials"` at first login — atscript cannot infer dependent tables from a reference.
:::

## Wire the stores

The shipped adapters expect typed table handles. `AtscriptDbTable<T>` returns `Record<string, unknown>` from its structural reads, so wiring needs a single cast at the boundary:

```ts:line-numbers
import { AuthUserTable, UsersStoreAtscriptDb } from '@aooth/user/atscript-db'
import { CredentialStoreAtscriptDb } from '@aooth/auth/atscript-db'

const userStore = new UsersStoreAtscriptDb<DemoUser>({
  table: tables.users as unknown as AuthUserTable<DemoUser>,
})

const credentialStore = new CredentialStoreAtscriptDb({
  table: tables.credentials,
})
```

Source: [`e2e-demo/src/aooth.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/e2e-demo/src/aooth.ts).

## Register the atscript plugin

`atscript.config.mts` registers the plugins responsible for compiling each namespace of annotations. The `arbacPlugin()` export registers `@arbac.role`, `@arbac.attribute`, and `@arbac.userId`. Without it, the compiler emits `unknownAnnotation` warnings (or errors, depending on your config) on every `@arbac.*` reference.

```ts:line-numbers
import arbacPlugin from '@aooth/arbac-moost/plugin'
import { defineConfig } from '@atscript/core'
import dbPlugin from '@atscript/db/plugin'
import wfPlugin from '@atscript/moost-wf/plugin'
import ts from '@atscript/typescript'

export default defineConfig({
  rootDir: 'src',
  plugins: [ts(), dbPlugin(), wfPlugin(), arbacPlugin()],
  format: 'dts',
  unknownAnnotation: 'warn',
})
```

Source: [`e2e-demo/atscript.config.mts`](https://github.com/moostjs/aoothjs/blob/main/packages/e2e-demo/atscript.config.mts).

::: tip Compile-time only
`@aooth/arbac-moost/plugin` contributes no runtime code. Importing it from application code by mistake will fail — it only lives in `atscript.config.mts`. The runtime ARBAC machinery is at `@aooth/arbac-moost` (decorators, interceptor) and `@aooth/arbac-moost/atscript` (`AtscriptArbacUserProvider`).
:::

## Letting the provider read your model

`AtscriptArbacUserProvider` introspects the user `.as` type once (cached in a WeakMap per type) to find:

1. The user-id field — resolved via `@arbac.userId` → field of `@db.table.preferredId.uniqueIndex` group → `@meta.id`. Constructor throws if none resolves.
2. The single `@arbac.role` field — either an inline `string | string[]` or a `@db.rel.from` nav prop. Multi-role declarations fail loud.
3. Every `@arbac.attribute` field — each becomes a key in the `UserAttrs` map.

Apps wire the provider by subclassing and overriding `getUserId()`:

```ts:line-numbers
import { AtscriptArbacUserProvider } from '@aooth/arbac-moost/atscript'
import { useAuth } from '@aooth/auth-moost'
import { Injectable } from 'moost'
import { DemoUser } from './models/user.as'

@Injectable()
class AppArbacUserProvider extends AtscriptArbacUserProvider<DemoUser> {
  constructor() {
    super(DemoUser, {
      async findOne(q) {
        const userId = q.filter.id as string | undefined
        if (!userId) return null
        return (await userStore.findByUsername(userId)) as DemoUser | null
      },
    })
  }
  override getUserId(): string {
    return useAuth().getUserId()
  }
}
```

`@Injectable()` must be **re-applied** on the subclass — moost@0.6.x does not inherit injectable metadata across `extends`.

::: warning Username vs. id
The JWT subject (`AuthContext.userId`) is whatever string identifies the credential. The e2e demo's `DemoUser.@meta.id` is a UUID but the JWT subject is `username`. The `userStore.findByUsername` method resolves both — wrap that in your provider's `findOne` so ARBAC sees the same identity the auth layer issues. See [`app.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/e2e-demo/src/app.ts) for the demo seam.
:::

## Generated artefacts

Running `asc -f dts` (or `unplugin-atscript` in your bundler) produces three siblings per `.as` file:

| File            | Purpose                                                                                                                  |
| --------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `user.as.d.ts`  | TypeScript types — so `import { DemoUser } from './user.as'` type-checks.                                                |
| `user.as.js`    | Runtime metadata — the class object that `db.getTable(DemoUser)` and `AtscriptArbacUserProvider(DemoUser, ...)` consume. |
| `atscript.d.ts` | Project-level merged-type declarations.                                                                                  |

::: warning Re-run after every `.as` change
We recommend gitignoring the compiled artefacts. Add `gen:atscript` to your prebuild / predev hook, or rely on `unplugin-atscript` to run it automatically.
:::

## Recap

1. Extend `AoothArbacUserCredentials` (or `AoothUserCredentials`) with your PK + columns.
2. Mark scope keys with `@arbac.attribute`.
3. Pass the model to `syncSchema()` along with `AoothAuthCredential`.
4. Wire `UsersStoreAtscriptDb` and `CredentialStoreAtscriptDb` against the resulting tables.
5. Register `arbacPlugin()` in `atscript.config.mts` so `@arbac.*` annotations type-check.
6. Subclass `AtscriptArbacUserProvider` and override `getUserId()`.

## Next steps

- [Quick Start](./quick-start) — full app wiring end to end.
- [User / Credentials Model](../user/credentials) — every field of `AoothUserCredentials` explained.
- [Moost integration](../moost/) — deeper coverage of `AtscriptArbacUserProvider` internals.
- [ARBAC / Builder API](../arbac/builder) — building roles that read these attributes.
