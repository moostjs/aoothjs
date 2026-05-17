# `UserService`

`UserService<T>` is the single orchestrator for everything credential-related. Every higher-level package in aoothjs (auth, auth-moost) ultimately delegates to a `UserService`. This page is the reference for its constructor, config, and every public method.

## Constructor

```ts
import { UserService, UserStoreMemory } from "@aoothjs/user"

const users = new UserService<T extends object = object>(
  store: UserStore<T>,
  config?: UserServiceConfig,
)
```

The generic `T` extends the base `UserCredentials` with custom columns of your choice (e.g. `tenantId`, `displayName`, `email`). Those columns flow through `LoginResult.user`, the `createUser(extras)` parameter, and `update(patch)`.

Source: [`user-service.ts:74`](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/user-service.ts#L74).

### Generic example — custom user shape

```ts
interface AppUser {
  id: string;
  email?: string;
  tenantId: string;
}

const users = new UserService<AppUser>(store, {
  password: { pepper: process.env.PEPPER },
});

await users.createUser("alice", "p4ssw0rd!", {
  id: crypto.randomUUID(),
  tenantId: "acme",
});

const { user } = await users.login("alice", "p4ssw0rd!");
user.tenantId; // ← typed as string
```

## Config reference

`UserServiceConfig` is a plain object. All fields are optional.

| Field                    | Type                  | Default    | Effect                                                                                                        |
| ------------------------ | --------------------- | ---------- | ------------------------------------------------------------------------------------------------------------- |
| `password.pepper`        | `string`              | `""`       | Static prefix prepended to every password before scrypt. Store in env / secret manager — **never in the DB**. |
| `password.historyLength` | `number`              | `0`        | Number of previous hashes to keep in `password.history[]`. `0` disables history checks.                       |
| `password.scryptN`       | `number`              | `16384`    | scrypt cost parameter (CPU/memory).                                                                           |
| `password.scryptR`       | `number`              | `8`        | scrypt block size.                                                                                            |
| `password.scryptP`       | `number`              | `1`        | scrypt parallelization.                                                                                       |
| `password.keyLength`     | `number`              | `64`       | Derived key length in bytes.                                                                                  |
| `policies`               | `PasswordPolicyDef[]` | `[]`       | Password rules enforced by `changePassword`/`setPassword`. See [Policies](./policy).                          |
| `lockout.threshold`      | `number`              | `0`        | Failed-login attempts before auto-locking. `0` disables lockout.                                              |
| `lockout.duration`       | `number`              | `0`        | Lock duration in ms. `0` ⇒ permanent.                                                                         |
| `deviceTrust.secret`     | `string`              | —          | HMAC key for trusted-device tokens. Required to call any `*TrustedDevice` method.                             |
| `clock`                  | `() => number`        | `Date.now` | Time source. Override in tests for deterministic lockout/expiry.                                              |

::: warning Pepper is irrecoverable
Losing the pepper invalidates every stored hash. Treat it like a database master key: rotate via app-level dual-write, store in a secrets manager, and never commit it.
:::

## Login flow

```
UserService.login(username, password)
├─ store.findByUsername                 →  NOT_FOUND if null
├─ account.active === false             →  throw INACTIVE
├─ ensureNotLockedOrThrow               →  auto-unlock if lockEnds<now, else LOCKED
├─ PasswordHasher.verify
│    ├─ success
│    │   └─ store.update({ set: { account: { lastLogin, failedLoginAttempts: 0 } } })
│    │       → return { user, mfaRequired: hasConfirmedMfaMethods(mfa) }
│    └─ failure
│        └─ incrementAndMaybeLock
│            ├─ store.update({ inc: { "account.failedLoginAttempts": 1 } })
│            ├─ if threshold tripped → set { locked, lockReason, lockEnds }
│            └─ throw INVALID_CREDENTIALS (with details.lockEnds when lock fired)
```

`verifyMfa` shares this exact lockout counter — total tries across `login + verifyMfa` is `threshold`, not `2 × threshold`.

## Methods — overview

All methods are `async` unless explicitly marked `(sync)`.

| Method                                                                                    | Returns                    | Throws                                                                                    | Notes                                       |
| ----------------------------------------------------------------------------------------- | -------------------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------- |
| `createUser`                                                                              | `UserCredentials & T`      | `ALREADY_EXISTS`                                                                          | Omits `id` so DB defaults fire.             |
| `getUser`                                                                                 | `UserCredentials & T`      | `NOT_FOUND`                                                                               |                                             |
| `login`                                                                                   | `LoginResult<T>`           | `NOT_FOUND` / `INACTIVE` / `LOCKED` / `INVALID_CREDENTIALS`                               |                                             |
| `verifyPassword`                                                                          | `boolean`                  | `NOT_FOUND`                                                                               | No side effects, bypasses lockout.          |
| `changePassword`                                                                          | `void`                     | `INVALID_CREDENTIALS` / `PASSWORDS_MISMATCH` / `POLICY_VIOLATION` / `PASSWORD_IN_HISTORY` |                                             |
| `setPassword`                                                                             | `void`                     | `POLICY_VIOLATION` / `PASSWORD_IN_HISTORY`                                                | Admin-style — no current password required. |
| `deleteUser`                                                                              | `void`                     | `NOT_FOUND`                                                                               |                                             |
| `update`                                                                                  | `UserCredentials & T`      | `NOT_FOUND`                                                                               | Deep-merge patch.                           |
| `activateAccount` / `deactivateAccount`                                                   | `void`                     | `NOT_FOUND`                                                                               |                                             |
| `lockAccount`                                                                             | `void`                     | `NOT_FOUND`                                                                               | `duration=0` ⇒ permanent.                   |
| `unlockAccount`                                                                           | `void`                     | `NOT_FOUND`                                                                               | Resets `failedLoginAttempts` too.           |
| `getLockStatus` (sync)                                                                    | `LockStatus`               | —                                                                                         |                                             |
| `checkPolicies`                                                                           | `PolicyCheckResult`        | —                                                                                         |                                             |
| `getTransferablePolicies` (sync)                                                          | `TransferablePolicy[]`     | —                                                                                         | String-rule policies only.                  |
| `addMfaMethod` / `confirmMfaMethod` / `removeMfaMethod`                                   | `void`                     | `NOT_FOUND` / `MFA_NOT_CONFIGURED`                                                        |                                             |
| `setDefaultMfaMethod`                                                                     | `void`                     | `MFA_NOT_CONFIGURED`                                                                      | Empty `name` clears the default.            |
| `setMfaAutoSend`                                                                          | `void`                     | `NOT_FOUND`                                                                               |                                             |
| `getAvailableMfaMethods` (sync)                                                           | `MfaMethodInfo[]`          | —                                                                                         | Masks `value`.                              |
| `generateBackupCodes`                                                                     | `string[]`                 | `NOT_FOUND`                                                                               | Returns plaintext **once**.                 |
| `consumeBackupCode`                                                                       | `boolean`                  | `NOT_FOUND`                                                                               | Read-then-write, **not atomic**.            |
| `verifyMfa`                                                                               | `void`                     | `NOT_FOUND` / `INACTIVE` / `LOCKED` / `MFA_INVALID` / `MFA_NOT_CONFIGURED`                |                                             |
| `issueTrustedDevice` (sync)                                                               | `TrustedDeviceRecord`      | plain `Error` if `deviceTrust.secret` unset                                               |                                             |
| `addTrustedDevice` / `verifyTrustedDevice` / `revokeTrustedDevice` / `listTrustedDevices` | varies                     | `NOT_FOUND`                                                                               |                                             |
| `getPasswordHasher` (sync)                                                                | `PasswordHasher`           | —                                                                                         | Escape hatch.                               |
| `getConfig` (sync)                                                                        | `Readonly<ResolvedConfig>` | —                                                                                         |                                             |

## Methods — reference

### `createUser`

Creates a fresh user record. If `password` is omitted, a random password is generated and `password.isInitial` is set `true`.

```ts
createUser(
  username: string,
  password?: string,
  extras?: Partial<T>,
): Promise<UserCredentials & T>
```

```ts
// minimal
await users.createUser("alice", "S3cret!");

// generated initial password (e.g. invitation flow)
const u = await users.createUser("bob");
u.password.isInitial; // → true

// custom columns
await users.createUser("carol", "p4ss", { tenantId: "acme", email: "c@x.dev" });
```

::: warning Top-level `extras` keys replace
`extras` is shallow-merged AFTER the base record is constructed. If you pass `extras.account`, you replace the entire base `account` sub-object — you don't merge into it.
:::

### `getUser`

```ts
getUser(username: string): Promise<UserCredentials & T>
```

Throws `NOT_FOUND` when no row.

### `login`

```ts
login(username: string, password: string): Promise<LoginResult<T>>
// LoginResult<T> = { user: UserCredentials & T; mfaRequired: boolean }
```

`mfaRequired` is `true` iff the user has at least one **confirmed** MFA method. Source: [`user-service.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/user-service.ts).

```ts
try {
  const { user, mfaRequired } = await users.login("alice", input);
  if (mfaRequired) return startMfaChallenge(user);
  return issueSession(user);
} catch (e) {
  if (e instanceof UserAuthError && e.type === "LOCKED") {
    return tooManyAttempts(e.details?.lockEnds);
  }
  throw e;
}
```

### `verifyPassword`

Side-effect-free password check. Does **not** consume a lockout attempt.

```ts
verifyPassword(username: string, password: string): Promise<boolean>
```

Use this for confirm-your-password gates (delete account, change email).

### `changePassword`

```ts
changePassword(
  username: string,
  currentPassword: string,
  newPassword: string,
  repeatPassword?: string,
): Promise<void>
```

Order of checks: `PASSWORDS_MISMATCH` → `INVALID_CREDENTIALS` → policies → history. History is checked in parallel against the current hash plus every entry in `password.history[]`.

### `setPassword`

Admin path — skips current-password verification, still enforces policies and history.

```ts
setPassword(username: string, newPassword: string): Promise<void>
```

### `update`

```ts
update(username: string, patch: DeepPartial<UserCredentials & T>): Promise<UserCredentials & T>
```

Deep-merges the patch via `store.update({ set })` and returns the re-read record.

### `lockAccount` / `unlockAccount`

```ts
lockAccount(username: string, reason: string, duration?: number): Promise<void>
unlockAccount(username: string): Promise<void>
```

`duration` is milliseconds. `0` or `undefined` ⇒ permanent.

::: warning `lockEnds: 0` is permanent
The expiry check is `lockEnds > 0 && lockEnds < now`. `0` is "no expiry", not "no lock".
:::

### `getLockStatus` (sync)

```ts
getLockStatus(account: AccountData): LockStatus
// LockStatus = { locked: boolean; lockEnds?: number; expired: boolean }
```

`expired` is `true` only when `lockEnds > 0 && lockEnds < now`. Callers use that to auto-unlock at the boundary.

### `checkPolicies`

```ts
checkPolicies(
  password: string,
  passwordData?: PasswordData,
): Promise<PolicyCheckResult>
// PolicyCheckResult = { passed: boolean; policies: { description, passed, errorMessage? }[] }
```

Passing `passwordData` lets policies reason about `lastChanged` / `history`.

### `getTransferablePolicies` (sync)

```ts
getTransferablePolicies(): TransferablePolicy[]
// TransferablePolicy = { rule: string; description?: string; errorMessage?: string }
```

Returns only policies whose `rule` is a string — those can be evaluated on the client in the same `v` / `context` namespace. See [Policies](./policy).

### MFA — `addMfaMethod` / `confirmMfaMethod` / `removeMfaMethod`

```ts
addMfaMethod(username: string, method: MfaMethod): Promise<void>
confirmMfaMethod(username: string, name: string): Promise<void>
removeMfaMethod(username: string, name: string): Promise<void>
```

`addMfaMethod` upserts by `name`. Removing the current `defaultMethod` clears it.

### `verifyMfa`

```ts
verifyMfa(username: string, code: string, config?: TotpConfig): Promise<void>
```

TOTP-only path. Increments the **same** `failedLoginAttempts` counter as `login`. Throws `MFA_INVALID` (with `details.lockEnds` when the failure tripped a lock) or `MFA_NOT_CONFIGURED` when no confirmed `totp` method exists.

### `generateBackupCodes` / `consumeBackupCode`

```ts
generateBackupCodes(username: string, count?: number): Promise<string[]>  // default 10
consumeBackupCode(username: string, code: string): Promise<boolean>
```

`generateBackupCodes` **replaces the entire batch** — return value is the plaintext list. Only hashes are stored. Plaintext is unrecoverable after the call returns.

::: warning `consumeBackupCode` is not atomic
Two concurrent consumes of the same code can both succeed. Wrap in a transaction at the store layer if strict guarantees matter.
:::

### Trusted devices

```ts
issueTrustedDevice(userId: string, opts: { ip?: string; ttlMs: number; name?: string }): TrustedDeviceRecord
addTrustedDevice(username: string, record: TrustedDeviceRecord): Promise<void>
verifyTrustedDevice(username: string, token: string, ip?: string): Promise<boolean>
revokeTrustedDevice(username: string, token: string): Promise<void>
listTrustedDevices(username: string): Promise<TrustedDeviceRecord[]>
```

Token format: `<raw-b64u>.<hmac(userId|raw|ip)>`. `verifyTrustedDevice` re-computes the HMAC, checks expiry, and (when issued with an `ip`) requires the same IP.

::: warning Requires `deviceTrust.secret`
Any trusted-device call throws a plain `Error` if `config.deviceTrust.secret` was not set on the service.
:::

## Clock injection for tests

Every place that reads "now" goes through `config.clock`. That makes lockout-expiry, MFA window, and trusted-device TTL tests deterministic.

```ts
let now = 1_700_000_000_000;
const users = new UserService(store, {
  clock: () => now,
  lockout: { threshold: 3, duration: 60_000 },
});

// trip the lock
for (let i = 0; i < 3; i++) {
  await users.login("alice", "wrong").catch(() => {});
}

// fast-forward past the lock
now += 60_001;
await users.login("alice", "correct"); // ✓ auto-unlock
```

## `FAST_SCRYPT` test idiom

For unit tests, override scrypt cost to single-digit ms:

```ts
const FAST_SCRYPT = { scryptN: 1024, scryptR: 1, scryptP: 1, keyLength: 32 };
const users = new UserService(store, { password: FAST_SCRYPT });
```

The hash strings are self-describing, so production hashes (`N=16384`) and test hashes (`N=1024`) coexist without breaking verification.

## Escape hatches

```ts
users.getPasswordHasher(); // → PasswordHasher (hash/verify/generatePassword)
users.getConfig(); // → Readonly<ResolvedConfig>
```

Use sparingly — anything that should be reusable across consumers belongs as a first-class method on `UserService`.
