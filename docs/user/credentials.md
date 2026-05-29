# Credentials Model

`UserCredentials` is the on-disk shape of a user. This page documents every sub-object, how the service patches it, and how to extend it with your own columns via the generic `T`.

## The shape

```ts
interface UserCredentials {
  id: string;
  username: string;
  password: PasswordData;
  account: AccountData;
  mfa: MfaData;
  trustedDevices?: TrustedDeviceRecord[];
  backupCodes?: string[]; // hashes only
}
```

The shipped `.as` model: [`packages/user/src/atscript-db/user-credentials.as`](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/atscript-db/user-credentials.as).

```ts
// from user-credentials.as
export interface AoothUserCredentials {
    @db.index.unique 'username_idx'
    username: string

    @db.patch.strategy 'merge'
    password: { /* … */ }

    @db.patch.strategy 'merge'
    account: { /* … */ }

    @db.patch.strategy 'merge'
    mfa: { /* … */ }

    @db.patch.strategy 'merge'
    trustedDevices?: { /* … */ }[]
}
```

::: warning `@db.patch.strategy 'merge'` is load-bearing
The service emits partial `set` patches like `{ account: { failedLoginAttempts: 0 } }`. The `'merge'` strategy tells `@atscript/db` to merge into the existing JSON, not replace it. Re-declaring `account` (or `password`, `mfa`, `trustedDevices`) in an extending interface **without** that annotation flips it back to wholesale replace — which silently corrupts records.
:::

## `account: AccountData`

The account state machine — active, locked, login counters.

| Field                 | Type                | Meaning                                                                                   |
| --------------------- | ------------------- | ----------------------------------------------------------------------------------------- |
| `active`              | `boolean`           | `false` ⇒ `INACTIVE` on login/verifyMfa. Set via `activateAccount` / `deactivateAccount`. |
| `locked`              | `boolean`           | `true` ⇒ `LOCKED` on login/verifyMfa (unless auto-unlock kicks in).                       |
| `lockReason`          | `string`            | Human-readable reason; surfaced in `LOCKED` error `details.reason`.                       |
| `lockEnds`            | `number` (ms epoch) | `0` ⇒ permanent lock. `> 0 && < now` ⇒ expired (auto-unlock).                             |
| `failedLoginAttempts` | `number`            | Shared counter across `login` and `verifyMfa`. Atomically `$inc`'d on failure.            |
| `lastLogin`           | `number` (ms epoch) | Set on successful login.                                                                  |
| `pendingInvitation`   | `boolean?`          | Reserved for the auth/invite layer; this package doesn't read it.                         |

::: warning `lockEnds: 0` is permanent, not "no lock"
The expiration check is `lockEnds > 0 && lockEnds < now`. Use `lockAccount(u, reason, duration)` and let `duration=0` mean permanent. Reaching for `lockEnds: 0` manually does the same thing.
:::

## `password: PasswordData`

| Field         | Type                | Meaning                                                                                          |
| ------------- | ------------------- | ------------------------------------------------------------------------------------------------ |
| `hash`        | `string`            | Self-describing scrypt hash. See [Password Hashing](./password).                                 |
| `history`     | `string[]`          | Previous hashes; cap of `historyLength`. Checked on `changePassword` / `setPassword`.            |
| `lastChanged` | `number` (ms epoch) | Set on every successful `change`/`set`.                                                          |
| `isInitial`   | `boolean`           | `true` when `createUser` generated the password. Flip to `false` on first user-initiated change. |

## `mfa: MfaData`

| Field           | Type          | Meaning                                                                   |
| --------------- | ------------- | ------------------------------------------------------------------------- |
| `methods`       | `MfaMethod[]` | Each: `{ name, confirmed, value }`. `name` is unique within the array.    |
| `defaultMethod` | `string`      | Pointer to a `methods[].name`. Empty string ⇒ no default.                 |
| `autoSend`      | `boolean`     | Higher layers use this to auto-send the OTP for `defaultMethod` on login. |

`MfaMethod.value` is intentionally opaque — TOTP stores the base32 secret, email/SMS stores the address/number, etc. `getAvailableMfaMethods(mfa)` returns the **confirmed** methods with `value` replaced by a masked display string (`a***@e.com`, `+1********90`).

`addMfaMethod` upserts by `name`. Removing the current `defaultMethod` clears it (sets `defaultMethod = ""`).

## `trustedDevices?: TrustedDeviceRecord[]`

| Field       | Type                | Meaning                                                                          |
| ----------- | ------------------- | -------------------------------------------------------------------------------- |
| `token`     | `string`            | Opaque HMAC-signed token bound to the user (and optionally their IP).            |
| `ip`        | `string?`           | If present, `verifyTrustedDevice` requires the request to come from the same IP. |
| `issuedAt`  | `number` (ms epoch) |                                                                                  |
| `expiresAt` | `number` (ms epoch) | Expiry; `verifyTrustedDevice` rejects past-expiry tokens.                        |
| `name`      | `string?`           | Display label ("My Laptop").                                                     |

The array is patched as a **wholesale replacement**: the service reads the current array, computes the next array client-side, and writes the full list back.

## `backupCodes?: string[]`

A reserved slot on the type for recovery-code hashes. **No bundled `UserService` API reads or writes it** — there are no `generateBackupCodes` / `consumeBackupCode` methods. If you implement recovery codes, store `hashMfaCode` hashes here via `users.update(...)` and verify with `verifyMfaCode`. See [MFA Primitives — Backup codes](./mfa#backup-codes).

## Patch strategy summary

The service never writes the full record after the initial `create`. It emits one of two patch shapes per update:

```ts
type UserStoreUpdate = {
  set?: DeepPartial<UserCredentials>;
  inc?: Record<string /* dot-path */, number>;
};
```

Custom store implementations must:

1. Treat `set` as a **deep merge** for `password`, `account`, `mfa`, `trustedDevices`. Arrays inside `set` are wholesale replacements.
2. Treat `inc` as an atomic numeric increment per dot-path. SQL: `SET col = col + N`. `@atscript/db`: `{ $inc: N }`.

See [Stores](./stores) for the full contract.

## Extending with custom columns — generic `T`

`UserService<T>` and `UserStore<T>` both accept a generic that augments the base type. Pass anything that's safe to merge into `UserCredentials`.

```ts
import { UserService, UserStoreMemory } from "@aooth/user";

interface AppUser {
  id: string;
  email?: string;
  tenantId: string;
  roles?: string[];
}

const store = new UserStoreMemory<AppUser>();
const users = new UserService<AppUser>(store);

await users.createUser("alice", "p4ssw0rd!", {
  id: crypto.randomUUID(),
  tenantId: "acme",
  email: "alice@acme.dev",
  roles: ["admin"],
});

const { user } = await users.login("alice", "p4ssw0rd!");
user.tenantId; // typed as string
user.roles; // typed as string[] | undefined
```

When using `@atscript/db`, define the extension in `.as` so it shows up at the storage layer:

```ts
// app.as
import { AoothUserCredentials } from '@aooth/user/atscript-db/model.as'

@db.table 'users'
export interface AppUser extends AoothUserCredentials {
    @meta.id
    @db.default.uuid
    id: string

    email?: string

    @db.index.regular 'tenant_idx'
    tenantId: string

    roles?: string[]
}
```

::: tip `createUser` deliberately omits `id`
The base `createUser` builds a `UserCredentials` literal **without** an `id` field, so DB defaults like `@db.default.uuid` fire. If you want a specific id (migrating data, deterministic tests), pass it via `extras.id`.
:::

::: warning `extras` shallow-merges over base
Top-level keys you pass in `extras` — including `account`, `mfa`, `password` — replace the base counterpart in full. If you need to seed a confirmed MFA method at creation, do `createUser` then `addMfaMethod` + `confirmMfaMethod`, not `extras: { mfa: {...} }`.
:::

## See also

- [Stores](./stores) — patch protocol the model relies on.
- [Errors](./errors) — what every account-state-driven failure throws.
- [`packages/user/src/types.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/types.ts) — exhaustive TypeScript declarations.
