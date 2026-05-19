# getting-started

Install, wire, and ship one authenticated + authorized endpoint with aoothjs. Covers the
no-moost path (use just `@aooth/user` + `@aooth/arbac`), the moost integration path
(production target), `.as` model wiring against `@atscript/db`, and the standard testing
patterns (`UserStoreMemory` + `FAST_SCRYPT` + injectable clock).

## Contents

- [Install](#install)
- [Minimal wiring (no moost)](#minimal-wiring-no-moost)
- [Adding moost](#adding-moost)
- [`.as` model wiring](#as-model-wiring)
- [Choosing a token store](#choosing-a-token-store)
- [Choosing a user store](#choosing-a-user-store)
- [Testing patterns](#testing-patterns)

## Install

```bash
# Core (always)
pnpm add @aooth/user @aooth/arbac

# Credential layer
pnpm add @aooth/auth

# Pick at most one persistence backend (or stay in-memory for tests)
pnpm add @atscript/db @atscript/db-sqlite better-sqlite3   # atscript-db SQLite
pnpm add ioredis                                            # Redis

# Moost integration (production target)
pnpm add @aooth/auth-moost @aooth/arbac-moost
pnpm add moost @moostjs/event-http @moostjs/event-wf @atscript/moost-wf

# Atscript build
pnpm add -D unplugin-atscript @atscript/typescript @atscript/core
```

`atscript.config.ts` — register the arbac plugin so `.as` files type-check `@arbac.*`:

```ts
import arbacPlugin from "@aooth/arbac-moost/plugin";
import { defineConfig } from "@atscript/core";
import dbPlugin from "@atscript/db/plugin";
import wfPlugin from "@atscript/moost-wf/plugin";
import ts from "@atscript/typescript";

export default defineConfig({
  rootDir: "src",
  plugins: [ts(), dbPlugin(), wfPlugin(), arbacPlugin()],
  format: "dts",
  unknownAnnotation: "warn",
});
```

## Minimal wiring (no moost)

A standalone script that creates a user, logs them in, and evaluates one ARBAC rule.

```ts
import { UserService, UserStoreMemory } from "@aooth/user";
import { Arbac, defineRole, allowTableRead } from "@aooth/arbac";

const users = new UserService(new UserStoreMemory(), {
  password: { pepper: process.env.AOOTH_PEPPER ?? "" },
});

await users.createUser("alice", "CorrectHorse42!");
await users.activateAccount("alice"); // createUser writes account.active: false
const result = await users.login("alice", "CorrectHorse42!");
// result = { user: UserCredentials, mfaRequired: false }

const arbac = new Arbac<{ dept: string }, { dept: string }>();
arbac.registerRole(
  defineRole<{ dept: string }, { dept: string }>()
    .id("reader")
    .use(allowTableRead("articles", { scope: (a) => ({ dept: a.dept }) }))
    .build(),
);

const decision = await arbac.evaluate(
  { resource: "articles", action: "query" },
  { id: "alice", roles: ["reader"], attrs: { dept: "sales" } },
);
// decision = { allowed: true, scopes: [{ dept: 'sales' }] }
```

No `@aooth/auth` involved — that layer kicks in once you need tokens / cookies / sessions.

## Adding moost

`@aooth/auth-moost` adds the four wiring concerns; `@aooth/arbac-moost` adds the fifth.

1. **Provide** `UserService`, `AuthCredential`, `MoostArbac`, and an `'EmailSender'` string token via `app.setProvideRegistry(createProvideRegistry(...))`.
2. **Replace** `ArbacUserProviderToken` with your concrete provider via `app.setReplaceRegistry(createReplaceRegistry(...))`.
3. **Apply globally** `authGuardInterceptor(opts)`, `arbacAuthorizeInterceptor`, and `formInputInterceptor()` (the last is from `@atscript/moost-wf`, required for workflow form pauses).
4. **Register controllers** — `AuthController` ships the `/auth/{logout,refresh,status,trigger}` routes; subclass it to extend the workflow allow-list.
5. **Subclass workflows** — `LoginWorkflow`, `RecoveryWorkflow`, `InviteWorkflow` are abstract w.r.t. transports. Override `protected deliver(payload)` to forward email/SMS to your sender; override `audit(event)` to fan out to your audit sink. Re-decorate the constructor — moost@0.6.x does NOT inherit `@Injectable()` across `extends`.

See the umbrella SKILL `## Quick start` for a 30-line example.

## `.as` model wiring

The atscript path:

```ts
// src/models/app-user.as
import { AoothArbacUserCredentials } from '@aooth/arbac-moost/atscript/models'

@db.table 'users'
export interface AppUser extends AoothArbacUserCredentials {
    @meta.id @db.default.uuid
    id: string

    @arbac.attribute
    department?: string

    email?: string
}
```

`AoothArbacUserCredentials` extends `AoothUserCredentials` (the shipped credential interface with `password` / `account` / `mfa` / `trustedDevices` sub-objects, all carrying `@db.patch.strategy 'merge'`) and pre-applies `@arbac.role` to a `roles: string[]` field. You add:

- A user-id field (`@meta.id` or a field of the `@db.table.preferredId.uniqueIndex` group). The atscript provider resolves the chain `@arbac.userId → preferredId group → @meta.id`. Constructor throws if none resolve.
- Zero or more `@arbac.attribute` fields — each one becomes a key on `UserAttrs`.

Then build (`asc` or `unplugin-atscript`) and sync the schema:

```ts
import { DbSpace, syncSchema } from "@atscript/db";
import { SqliteAdapter, BetterSqlite3Driver } from "@atscript/db-sqlite";
import { AppUser } from "./models/app-user.as";
import { UsersStoreAtscriptDb, type AuthUserTable } from "@aooth/user/atscript-db";
import { AoothAuthCredential } from "@aooth/auth/atscript-db/model.as";
import { CredentialStoreAtscriptDb } from "@aooth/auth/atscript-db";

const db = new DbSpace(() => new SqliteAdapter(new BetterSqlite3Driver("./app.db")));
await syncSchema(db, [AppUser, AoothAuthCredential]);

const userStore = new UsersStoreAtscriptDb<AppUser>({
  table: db.getTable(AppUser) as unknown as AuthUserTable<AppUser>,
});
const tokenStore = new CredentialStoreAtscriptDb({
  table: db.getTable(AoothAuthCredential),
});
```

The cast on `getTable(AppUser)` is required because `AtscriptDbTable` returns
`Record<string, unknown>` rows — the structural cast lets `UsersStoreAtscriptDb` type
its inputs/outputs without a runtime cost.

## Choosing a token store

| Store                         | Stateful?      | Enumerable? | Revocation                       | Use when                                                        |
| ----------------------------- | -------------- | ----------- | -------------------------------- | --------------------------------------------------------------- |
| `CredentialStoreMemory`       | yes            | yes         | direct                           | tests, dev, single-process toy apps                             |
| `CredentialStoreJwt`          | no (signed)    | no          | requires `DenylistStore` + epoch | API gateways, edge, multi-region — no DB round-trip on validate |
| `CredentialStoreEncapsulated` | no (encrypted) | no          | requires `DenylistStore` + epoch | claims must stay opaque to clients                              |
| `CredentialStoreRedis`        | yes            | yes (SET)   | `SREM`/`DEL`                     | low-latency revocation across pods                              |
| `CredentialStoreAtscriptDb`   | yes            | yes (table) | row delete                       | single source of truth = your DB                                |

For stateless stores: `rotation: 'always'` is the only sane choice. `'sliding'` requires
the store to mark `rotatedAt` and tolerate reuse within the grace window — JWT can't.
The library silently degrades `'sliding'` to "always-once" on stateless stores; the
explicit configuration is safer.

```ts
// JWT with HS256 + denylist
new AuthCredential({
  store: new CredentialStoreJwt({
    secret: process.env.AOOTH_JWT_SECRET!,
    algorithm: "HS256",
    denylist: new DenylistStoreRedis({ redis }),
  }),
  accessTtl: 60 * 60 * 1000,
  refresh: { ttl: 7 * 24 * 60 * 60 * 1000, rotation: "always" },
});
```

For asymmetric algorithms (`RS*` / `ES*` / `EdDSA`) you pass both `privateKey` and
`publicKey`; missing either throws `INVALID_CONFIG` at construction.

## Choosing a user store

| Store                  | Use when                                                                                                                                                                                                  |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `UserStoreMemory`      | tests, dev. `structuredClone` on every read/write isolates callers from mutation.                                                                                                                         |
| `UsersStoreAtscriptDb` | production. Translates `update.inc` → `{$inc:N}` and `DbError.code==='CONFLICT'` → `UserAuthError('ALREADY_EXISTS')`.                                                                                     |
| **(custom)**           | Subclass `UserStore<T>`. Must: throw `ALREADY_EXISTS` on dupe, treat `set` as deep-merge for `password`/`account`/`mfa`, treat `inc` as atomic per-path, return `false` from `update`/`delete` on no-row. |

## Testing patterns

`FAST_SCRYPT` — collapse scrypt to single-digit ms:

```ts
const FAST_SCRYPT = { scryptN: 1024, scryptR: 1, scryptP: 1, keyLength: 32 } as const;

const svc = new UserService(new UserStoreMemory(), {
  password: { pepper: "test-pepper", ...FAST_SCRYPT },
});
```

Injectable clock — deterministic lockout / TOTP / refresh-grace tests:

```ts
let now = 1_700_000_000_000;
const clock = { now: () => now };
const svc = new UserService(store, { clock: () => now });
const auth = new AuthCredential({ store: tokenStore, accessTtl: 5_000, clock });

// advance time
now += 6_000;
expect(await auth.validate(token)).toBeNull();
```

Error assertions — the discriminator is `error.type`, never `error.message`:

```ts
import { UserAuthError } from "@aooth/user";
import { AuthError } from "@aooth/auth";

await expect(svc.login("alice", "wrong")).rejects.toMatchObject({
  name: "UserAuthError",
  type: "INVALID_CREDENTIALS",
});
await expect(auth.refresh(stolenToken)).rejects.toMatchObject({
  name: "AuthError",
  type: "REFRESH_REUSE_DETECTED",
});
```

For workflow tests, use the `loginAs` harness from
`packages/e2e-demo/test/harness.ts` (`const loginAs = async (user) => …`) —
drive `POST /auth/trigger` until the `WfFinished` envelope's
`end.action === 'data'`, then extract `body.cookies` and replay them on
subsequent requests.
