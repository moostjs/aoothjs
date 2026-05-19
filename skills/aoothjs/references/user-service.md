# user-service

`UserService<T extends object = object>` is the orchestrator. Generic `T` adds custom user columns (`tenantId`, `roles`, ...) that flow through `LoginResult.user`, `createUser` extras, and the underlying `UserStore<T>`. Constructor: `new UserService(store, config?)`.

## Contents

- [Config defaults](#config-defaults)
- [CRUD methods](#crud-methods)
- [Login + password flow](#login--password-flow)
- [Account lifecycle](#account-lifecycle)
- [Password policy methods](#password-policy-methods)
- [MFA methods](#mfa-methods)
- [Backup codes](#backup-codes)
- [Trusted-device methods](#trusted-device-methods)
- [Escape hatches](#escape-hatches)
- [The login sequence](#the-login-sequence)

## Config defaults

`UserServiceConfig` resolves with these defaults (`user-service.ts:36`):

| Key                      | Default    | Notes                                                                          |
| ------------------------ | ---------- | ------------------------------------------------------------------------------ |
| `password.pepper`        | `""`       | Prefixed to every password before scrypt. Irrecoverable if lost.               |
| `password.historyLength` | `0`        | `0` disables password-history check.                                           |
| `password.scryptN`       | `16384`    | Stored on the hash string; per-hash forward compat on `verify`.                |
| `password.scryptR`       | `8`        |                                                                                |
| `password.scryptP`       | `1`        |                                                                                |
| `password.keyLength`     | `64`       | Hash output bytes.                                                             |
| `password.policies`      | `[]`       | Array of `PasswordPolicyDef` or `PasswordPolicyInstance` — normalized on init. |
| `lockout.threshold`      | `0`        | `0` disables lockout.                                                          |
| `lockout.duration`       | `0`        | `0` produces permanent locks when the threshold trips.                         |
| `clock`                  | `Date.now` | Injectable for tests.                                                          |
| `deviceTrust.secret`     | _(unset)_  | Required for `issueTrustedDevice` / `verifyTrustedDevice` — throws if absent.  |

`getConfig()` returns the resolved config as `Readonly<ResolvedConfig>`; `getPasswordHasher()` exposes the constructed `PasswordHasher` for escape-hatch use.

## CRUD methods

### `createUser(username, password?, extras?) → Promise<UserCredentials & T>`

If `password` is omitted, `PasswordHasher.generatePassword()` runs and `password.isInitial` is `true`. The base record omits `id` so the store / DB default fires; `extras` shallow-merges over the base AFTER it. Top-level keys (`account`, `mfa`, `password`) in `extras` are wholesale replaced — pass full sub-objects when overriding.

```ts
await svc.createUser("alice"); // system-generated, isInitial=true
await svc.createUser("alice", "Strong-Pass-1!");
await svc.createUser("alice", "Strong-Pass-1!", { tenantId: "acme" });
await svc.activateAccount("alice"); // ← required outside the invite flow
```

> **`createUser` writes `account.active: false`.** `InviteWorkflow.acceptInvite` relies on this default (pending invitees stay inactive until accept). For seed scripts, admin-create flows, or tests that don't go through invite, **call `activateAccount(username)` after** or `login()` throws `UserAuthError("INACTIVE")` — and the login workflow deliberately re-maps that to `"Invalid credentials"` (anti-enumeration), so the failure looks like a wrong password client-side.

### `getUser(username) → Promise<UserCredentials & T>`

Throws `NOT_FOUND` if missing.

### `update(username, patch) → Promise<UserCredentials & T>`

Deep-merge `patch` via `store.update({ set })`, then re-read. Top-level fields are shallow-merged; the merged sub-objects (`account` / `mfa` / `password`) follow their `@db.patch.strategy 'merge'` declaration.

### `deleteUser(username) → Promise<void>`

Hard-delete. Throws `NOT_FOUND` when no row matched (`store.delete` returned `false`).

## Login + password flow

### `login(username, password) → Promise<LoginResult<T>>`

`LoginResult<T> = { user: UserCredentials & T; mfaRequired: boolean }`. `mfaRequired` is `true` iff at least one MFA method on the user is `confirmed`. See [the login sequence](#the-login-sequence).

### `verifyPassword(username, password) → Promise<boolean>`

No side effects, bypasses lockout. Useful for re-auth confirmations (e.g. "confirm to change password" UI flows).

### `changePassword(username, current, new, repeat?) → Promise<void>`

1. `repeat !== undefined && new !== repeat` → `PASSWORDS_MISMATCH`.
2. `current` mismatch → `INVALID_CREDENTIALS`.
3. `checkPolicies(new, passwordData)` — failure throws `POLICY_VIOLATION` with `details.policies = [{description, passed}, ...]`.
4. Parallel `Promise.all` verifies `new` against `current.hash` + every `password.history[]` entry — any match throws `PASSWORD_IN_HISTORY`.
5. Persist new hash + rotate history (length capped at `historyLength`; `0` keeps history empty).

### `setPassword(username, new) → Promise<void>`

Admin-style. Same policy + history checks, no current-password verification.

## Account lifecycle

| Method                              | Behavior                                                                                                                 |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `activateAccount(username)`         | Set `account.active = true`. Throws `NOT_FOUND` if no row.                                                               |
| `deactivateAccount(username)`       | Set `account.active = false`. Throws `NOT_FOUND` if no row.                                                              |
| `lockAccount(u, reason, duration?)` | `duration` ms → `lockEnds = clock() + duration`. Omitted / `0` → `lockEnds: 0` = permanent lock.                         |
| `unlockAccount(username)`           | Clears `locked` / `lockReason` / `lockEnds` and resets `failedLoginAttempts`.                                            |
| `getLockStatus(account)`            | **Sync.** Returns `{ locked, expired, reason, lockEnds }`. `expired` is `true` iff `lockEnds > 0 && lockEnds < clock()`. |

`login` and `verifyMfa` auto-unlock when `expired` is true before throwing.

## Password policy methods

### `checkPolicies(password, passwordData?) → Promise<PolicyCheckResult>`

Runs every configured policy. `passwordData` lets a policy reason about `lastChanged` / `history` via `PasswordPolicyContext`. Result shape:

```ts
{
  passed: boolean,
  policies: { description: string, passed: boolean }[],
  errors: string[]   // every failed policy's `errorMessage`
}
```

### `getTransferablePolicies() → TransferablePolicy[]` (sync)

Filters to policies whose `rule` is a string — those compile via `@prostojs/ftring` and can be shipped to the client for pre-validation in the same `v` / `context` namespace. Function-based rules are silently excluded.

## MFA methods

| Method                                | Behavior                                                                                                                                                                                         |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `addMfaMethod(username, method)`      | Upsert by `method.name` (existing same-name method is replaced).                                                                                                                                 |
| `confirmMfaMethod(username, name)`    | Marks the method `confirmed: true`. Throws `MFA_NOT_CONFIGURED` if `name` unknown.                                                                                                               |
| `removeMfaMethod(username, name)`     | Removes the method. If it was the default, `mfa.defaultMethod` is cleared to `""`.                                                                                                               |
| `setDefaultMfaMethod(username, name)` | Sets `defaultMethod` and `autoSend: false`. Empty `name` clears the default. Throws `MFA_NOT_CONFIGURED` on non-empty unknown name.                                                              |
| `setMfaAutoSend(username, value)`     | Toggles `mfa.autoSend`. Throws `NOT_FOUND` on no row.                                                                                                                                            |
| `getAvailableMfaMethods(mfa)` (sync)  | Returns `{ name, isDefault, masked }[]` for confirmed methods. `masked` uses `maskMfaValue`.                                                                                                     |
| `verifyMfa(username, code, config?)`  | TOTP-only path. Auto-unlocks expired locks, increments **the same** `failedLoginAttempts` as `login`, throws `MFA_INVALID`, `MFA_NOT_CONFIGURED`, `INACTIVE`, `LOCKED`, or `NOT_FOUND` per case. |

`verifyMfa` finds the method via `mfa.methods.find(m => m.name === 'totp' && m.confirmed)` — no other method names participate in this path; email / SMS challenges live in `@aooth/auth`.

## Backup codes

### `generateBackupCodes(username, count = 10) → Promise<string[]>`

Generates plaintext codes via `generateBackupCodePlaintext`, hashes each with `hashMfaCode`, replaces the entire `backupCodes[]` array on the user, and returns plaintext **once**. After this call returns, plaintext is unrecoverable.

### `consumeBackupCode(username, code) → Promise<boolean>`

Linearly scans `user.backupCodes ?? []` with `verifyMfaCode`, removes the matched hash, persists the remaining array. **Not atomic** — read-then-write at the service layer; two concurrent consumes of the same code can both succeed. Wrap in a store transaction if strict guarantees are required.

## Trusted-device methods

All require `config.deviceTrust.secret`. Without it, `issueTrustedDevice` / `verifyTrustedDevice` throw a plain `Error` (not `UserAuthError`).

### `issueTrustedDevice(userId, { ip?, ttlMs, name? }) → TrustedDeviceRecord` (sync)

Mints `<raw 32-byte hex>.<hmac-sha256(userId|raw|ip-or-empty)>`. Does NOT persist — pair with `addTrustedDevice`. Returned record carries `token`, `ip` (if supplied), `issuedAt`, `expiresAt = clock() + ttlMs`, optional `name`.

### `addTrustedDevice(username, record) → Promise<void>`

Appends to `trustedDevices`. Read-modify-write — the whole array is replaced in the patch.

### `verifyTrustedDevice(username, token, ip?) → Promise<boolean>`

Returns `true` iff the HMAC verifies against `username|raw|ip ?? ""` AND a persisted record matches `token` AND `expiresAt > now` AND `(record.ip === undefined || record.ip === ip)`. Pass the same `ip` you issued with — IP-binding is enforced when the stored record carries an `ip`.

### `revokeTrustedDevice(username, token) → Promise<void>`

Filters out by `token`. No-op when absent.

### `listTrustedDevices(username) → Promise<TrustedDeviceRecord[]>`

Returns `user.trustedDevices ?? []`. Throws `NOT_FOUND` if the user is missing.

## Escape hatches

- `getPasswordHasher() → PasswordHasher` (sync) — call `.hash` / `.verify` / `.generatePassword` directly when wiring custom flows that bypass `UserService` (e.g. seeding).
- `getConfig() → Readonly<ResolvedConfig>` (sync) — read resolved scrypt/lockout/clock; useful for tests asserting wiring.

## The login sequence

`UserService.login(username, password)` runs:

1. Look up the user — throw `NOT_FOUND` if missing.
2. Reject if `account.active === false` — throw `INACTIVE`.
3. Reject if locked — auto-unlocks when `lockEnds > 0 && lockEnds < clock()`; otherwise throws `LOCKED` with `details = { reason, lockEnds }`.
4. Verify the password using the parameters baked into the stored hash + the configured pepper.
5. On success:
   - Persist `{ set: { account: { lastLogin: clock(), failedLoginAttempts: 0 } } }`.
   - Return `{ user, mfaRequired: mfa.methods.some(m => m.confirmed) }`.
6. On failure:
   - Always increment `account.failedLoginAttempts`.
   - If the configured threshold is hit, also set `locked`/`lockReason`/`lockEnds` and throw `INVALID_CREDENTIALS` with `details = { lockEnds }`.
   - Otherwise throw `INVALID_CREDENTIALS` with no details.

`verifyMfa` shares step 3 + 6 — both factors burn the same counter, so the user gets `threshold` total tries across password and TOTP, not `2 × threshold`.
