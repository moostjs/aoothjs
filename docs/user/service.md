# `UserService`

`UserService<T>` is the single orchestrator for everything credential-related. Every higher-level package in aoothjs (auth, auth-moost) ultimately delegates to a `UserService`. This page is the reference for its constructor, config, and every public method.

## Constructor

```ts
import { UserService, UserStoreMemory } from "@aooth/user"

const users = new UserService<T extends object = object>(
  store: UserStore<T>,
  config?: UserServiceConfig,
)
```

The generic `T` extends the base `UserCredentials` with custom columns of your choice (e.g. `tenantId`, `displayName`). `id`, `username`, and `email` are already on the base — `T` adds only the _extra_ columns. Those flow through `LoginResult.user`, the `createUser(extras)` parameter, and `update(patch)`.

Source: [`user-service.ts:74`](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/user-service.ts#L74).

::: tip Identity model — `id` vs. handle
The stable surrogate **`id`** is the token subject (`useAuth().getUserId()`) and the key for **every read-by-identity and every write** on this service (`getUser`, `update`, `setPassword`, the MFA/lock/trusted-device methods, …). The **one** exception is `login(handle, …)`, which resolves a `username`-or-`email` **handle** via `UserStore.findByHandle`. Two passthrough reads cover the rest: `findByHandle` (deterministic login resolution) and `findByIdentifier` (permissive `id`→`username`→`email`, for admin/recovery). See [Stores](./stores).
:::

### Generic example — custom user shape

```ts
interface AppUser {
  tenantId: string;
}

const users = new UserService<AppUser>(store, {
  password: { pepper: process.env.PEPPER },
});

// `id` is minted automatically; `username` is the 1st arg.
const u = await users.createUser("alice", "p4ssw0rd!", { tenantId: "acme" });

const { user } = await users.login("alice", "p4ssw0rd!"); // handle = username or email
user.tenantId; // ← typed as string
user.id; // ← base field, the token subject
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
| `password.policies`      | `PasswordPolicyDef[]` | `[]`       | Password rules enforced by `changePassword`/`setPassword`. See [Policies](./policy).                          |
| `lockout.threshold`      | `number`              | `0`        | Failed-login attempts before auto-locking. `0` disables lockout.                                              |
| `lockout.duration`       | `number`              | `0`        | Lock duration in ms. `0` ⇒ permanent.                                                                         |
| `deviceTrust.secret`     | `string`              | —          | HMAC key for trusted-device tokens. Required to call any `*TrustedDevice` method.                             |
| `clock`                  | `() => number`        | `Date.now` | Time source. Override in tests for deterministic lockout/expiry.                                              |

::: warning Pepper is irrecoverable
Losing the pepper invalidates every stored hash. Treat it like a database master key: rotate via app-level dual-write, store in a secrets manager, and never commit it.
:::

## Login flow

`UserService.login(handle, password)` — `handle` is a `username` **or** `email`, resolved via `UserStore.findByHandle` (username first, then email; never a permissive `$or`):

1. Look up the user by handle — throws `NOT_FOUND` if missing.
2. Reject if `account.active === false` — throws `INACTIVE`.
3. Reject if locked (auto-unlocks when `lockEnds` is past) — throws `LOCKED`.
4. Verify the password:
   - On success: resets `failedLoginAttempts`, stamps `lastLogin`, returns `{ user, mfaRequired }` where `mfaRequired` is `true` iff at least one confirmed MFA method exists.
   - On failure: increments `failedLoginAttempts`; if the configured threshold is hit, sets `locked`/`lockReason`/`lockEnds`; throws `INVALID_CREDENTIALS` (with `details.lockEnds` when the lock fired on this attempt).

`verifyMfa` shares this exact lockout counter — total tries across `login + verifyMfa` is `threshold`, not `2 × threshold`.

## Methods — overview

All methods are `async` unless explicitly marked `(sync)`.

| Method                                                                                    | Returns                         | Throws                                                                                    | Notes                                                                                                      |
| ----------------------------------------------------------------------------------------- | ------------------------------- | ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `createUser`                                                                              | `UserCredentials & T`           | `ALREADY_EXISTS`                                                                          | Mints `id` (`randomUUID`); `extras.id` overrides. `ALREADY_EXISTS` on duplicate `username` **or** `email`. |
| `getUser`                                                                                 | `UserCredentials & T`           | `NOT_FOUND`                                                                               | By **`id`**.                                                                                               |
| `findByHandle`                                                                            | `(UserCredentials & T) \| null` | —                                                                                         | Login resolver: `username` then `email`.                                                                   |
| `findByIdentifier`                                                                        | `(UserCredentials & T) \| null` | —                                                                                         | Permissive: `id` → `username` → `email`.                                                                   |
| `login`                                                                                   | `LoginResult<T>`                | `NOT_FOUND` / `INACTIVE` / `LOCKED` / `INVALID_CREDENTIALS`                               | Arg is a **handle** (`username`/`email`).                                                                  |
| `verifyPassword`                                                                          | `boolean`                       | `NOT_FOUND`                                                                               | No side effects, bypasses lockout.                                                                         |
| `changePassword`                                                                          | `void`                          | `INVALID_CREDENTIALS` / `PASSWORDS_MISMATCH` / `POLICY_VIOLATION` / `PASSWORD_IN_HISTORY` |                                                                                                            |
| `setPassword`                                                                             | `void`                          | `POLICY_VIOLATION` / `PASSWORD_IN_HISTORY`                                                | Admin-style — no current password required.                                                                |
| `deleteUser`                                                                              | `void`                          | `NOT_FOUND`                                                                               |                                                                                                            |
| `update`                                                                                  | `UserCredentials & T`           | `NOT_FOUND`                                                                               | Deep-merge patch.                                                                                          |
| `activateAccount` / `deactivateAccount`                                                   | `void`                          | `NOT_FOUND`                                                                               |                                                                                                            |
| `lockAccount`                                                                             | `void`                          | `NOT_FOUND`                                                                               | `duration=0` ⇒ permanent.                                                                                  |
| `unlockAccount`                                                                           | `void`                          | `NOT_FOUND`                                                                               | Resets `failedLoginAttempts` too.                                                                          |
| `getLockStatus` (sync)                                                                    | `LockStatus`                    | —                                                                                         |                                                                                                            |
| `checkPolicies`                                                                           | `PolicyCheckResult`             | —                                                                                         |                                                                                                            |
| `getTransferablePolicies` (sync)                                                          | `TransferablePolicy[]`          | —                                                                                         | String-rule policies only.                                                                                 |
| `addMfaMethod` / `confirmMfaMethod` / `removeMfaMethod`                                   | `void`                          | `NOT_FOUND` / `MFA_NOT_CONFIGURED`                                                        |                                                                                                            |
| `setDefaultMfaMethod`                                                                     | `void`                          | `MFA_NOT_CONFIGURED`                                                                      | Empty `name` clears the default.                                                                           |
| `setMfaAutoSend`                                                                          | `void`                          | `NOT_FOUND`                                                                               |                                                                                                            |
| `getAvailableMfaMethods` (sync)                                                           | `MfaMethodInfo[]`               | —                                                                                         | Masks `value`.                                                                                             |
| `verifyTotpSetupCode`                                                                     | `void`                          | `NOT_FOUND` / `MFA_NOT_CONFIGURED` / `MFA_INVALID`                                        | Verify first code + flip method to confirmed.                                                              |
| `verifyMfa`                                                                               | `void`                          | `NOT_FOUND` / `INACTIVE` / `LOCKED` / `MFA_INVALID` / `MFA_NOT_CONFIGURED`                | 4th arg `lockoutOverride?`.                                                                                |
| `isPasswordExpired` (sync)                                                                | `boolean`                       | —                                                                                         | Against `config.password` expiry policy.                                                                   |
| `issueTrustedDevice` (sync)                                                               | `TrustedDeviceRecord`           | plain `Error` if `deviceTrust.secret` unset                                               |                                                                                                            |
| `addTrustedDevice` / `verifyTrustedDevice` / `revokeTrustedDevice` / `listTrustedDevices` | varies                          | `NOT_FOUND`                                                                               |                                                                                                            |
| `getPasswordHasher` (sync)                                                                | `PasswordHasher`                | —                                                                                         | Escape hatch.                                                                                              |
| `getConfig` (sync)                                                                        | `Readonly<ResolvedConfig>`      | —                                                                                         |                                                                                                            |

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

::: warning `account.active` defaults to `false`
`AuthWorkflow`'s invite accept phase relies on this — pending invitees stay inactive until accept. For seed scripts, admin-create flows, or tests that don't go through invite, **call `activateAccount(id)` after** or `login()` throws `UserAuthError("INACTIVE")`. The login workflow deliberately re-maps `INACTIVE` to `"Invalid credentials"` (anti-enumeration), so the client-side failure looks identical to a wrong password.

```ts
const u = await users.createUser("alice", "S3cret!");
await users.activateAccount(u.id); // ← required outside the invite flow
```

:::

### `getUser` / `findByHandle` / `findByIdentifier`

```ts
getUser(id: string): Promise<UserCredentials & T> // throws NOT_FOUND
findByHandle(handle: string): Promise<(UserCredentials & T) | null>
findByIdentifier(value: string): Promise<(UserCredentials & T) | null>
```

`getUser` is the strict identity read by **`id`** (the token subject) — it throws `NOT_FOUND` when there's no row. The two `find*` passthroughs return `null` instead of throwing:

- **`findByHandle`** — the deterministic login resolver: matches `username` exactly, then `email` exactly. Use it anywhere you have a user-supplied login handle (the login workflow's `emailToUserId` default delegates here).
- **`findByIdentifier`** — permissive admin/recovery lookup: `id`, then `username`, then `email` (first match). Never use it for login — a value that is one user's username and another's email would resolve ambiguously.

### `login`

```ts
login(handle: string, password: string, lockoutOverride?: Partial<LockoutConfig>): Promise<LoginResult<T>>
// handle = username OR email (resolved via findByHandle)
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
verifyPassword(id: string, password: string): Promise<boolean>
```

Use this for confirm-your-password gates (delete account, change email).

### `changePassword`

```ts
changePassword(
  id: string,
  currentPassword: string,
  newPassword: string,
  repeatPassword?: string,
): Promise<void>
```

Order of checks: `PASSWORDS_MISMATCH` → `INVALID_CREDENTIALS` → policies → history. History is checked in parallel against the current hash plus every entry in `password.history[]`.

### `setPassword`

Admin path — skips current-password verification, still enforces policies and history.

```ts
setPassword(id: string, newPassword: string): Promise<void>
```

### `update`

```ts
update(id: string, patch: Partial<UserCredentials & T>): Promise<UserCredentials & T>
```

Deep-merges the patch via `store.update({ set })` and returns the re-read record.

### `lockAccount` / `unlockAccount`

```ts
lockAccount(id: string, reason: string, duration?: number): Promise<void>
unlockAccount(id: string): Promise<void>
```

`duration` is milliseconds. `0` or `undefined` ⇒ permanent.

::: warning `lockEnds: 0` is permanent
The expiry check is `lockEnds > 0 && lockEnds < now`. `0` is "no expiry", not "no lock".
:::

### `getLockStatus` (sync)

```ts
getLockStatus(account: AccountData): LockStatus
// LockStatus = { locked: boolean; expired: boolean; reason: string; lockEnds: number }
```

`expired` is `true` only when `lockEnds > 0 && lockEnds < now`. Callers use that to auto-unlock at the boundary.

### `checkPolicies`

```ts
checkPolicies(
  password: string,
  passwordData?: PasswordData,
): Promise<PolicyCheckResult>
// PolicyCheckResult = { passed: boolean; policies: { description: string, passed: boolean }[]; errors: string[] }
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
addMfaMethod(id: string, method: MfaMethod): Promise<void>
confirmMfaMethod(id: string, name: string): Promise<void>
removeMfaMethod(id: string, name: string): Promise<void>
```

`addMfaMethod` upserts by `name`. Removing the current `defaultMethod` clears it.

### `verifyMfa`

```ts
verifyMfa(
  id: string,
  code: string,
  config?: TotpConfig,
  lockoutOverride?: Partial<LockoutConfig>,
): Promise<void>
```

TOTP-only path. Increments the **same** `failedLoginAttempts` counter as `login`. Pass `lockoutOverride` to apply a per-call lockout posture (e.g. a stricter threshold for privileged accounts). Throws `MFA_INVALID` (with `details.lockEnds` when the failure tripped a lock) or `MFA_NOT_CONFIGURED` when no confirmed `totp` method exists.

### `verifyTotpSetupCode`

```ts
verifyTotpSetupCode(id: string, code: string, config?: TotpConfig): Promise<void>
```

Enrollment-confirm helper: verifies `code` against the user's **unconfirmed** `totp` method and flips it to `confirmed: true` in one call. Throws `MFA_INVALID` on a wrong code, `MFA_NOT_CONFIGURED` when there's no pending `totp` method. Use it instead of a manual `verifyTotpCode` + `confirmMfaMethod` pair.

### `isPasswordExpired`

```ts
isPasswordExpired(user: UserCredentials & T, now?: number): boolean
```

Sync check against the configured password-expiry policy. The `now` arg defaults to the injected clock — useful for deterministic tests.

> There are **no** `generateBackupCodes` / `consumeBackupCode` methods — backup codes are not bundled. See [MFA Primitives — Backup codes](./mfa#backup-codes).

### Trusted devices

```ts
issueTrustedDevice(userId: string, opts: { ip?: string; ttlMs: number; name?: string }): TrustedDeviceRecord
addTrustedDevice(id: string, record: TrustedDeviceRecord): Promise<void>
verifyTrustedDevice(userId: string, token: string, ip?: string): Promise<boolean>
revokeTrustedDevice(id: string, token: string): Promise<void>
listTrustedDevices(id: string): Promise<TrustedDeviceRecord[]>
```

The token is an opaque HMAC-signed string bound to the user (and optionally their IP). `verifyTrustedDevice` validates the signature, checks expiry, and (when issued with an `ip`) requires the same IP.

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

## Escape hatches

```ts
users.getPasswordHasher(); // → PasswordHasher (hash/verify/generatePassword)
users.getConfig(); // → Readonly<ResolvedConfig>
```

Use sparingly — anything that should be reusable across consumers belongs as a first-class method on `UserService`.

## Testing

For unit tests, lower the scrypt cost so each hash takes single-digit ms instead of the production ~100 ms target:

```ts
const FAST_SCRYPT = { scryptN: 1024, scryptR: 1, scryptP: 1, keyLength: 32 };
const users = new UserService(store, { password: FAST_SCRYPT });
```

Hashes are self-describing, so production and test hashes coexist without breaking verification — useful when seeding fixtures from a snapshot.
