# @aooth/user

## Quick start

```atscript
// src/app-user.as
import { AoothUserCredentials } from '@aooth/user/atscript-db/model.as'

@db.table 'users'
export interface AppUser extends AoothUserCredentials {
    // id (PK / @meta.id — the token subject), username + email (unique handles),
    // and version are ALL inherited from the base. Add only @db.table + your
    // own columns; do NOT redeclare id/email.
    tenantId: string
}
```

```ts
import { DbSpace } from "@atscript/db";
import { syncSchema } from "@atscript/db/sync";
import { BetterSqlite3Driver, SqliteAdapter } from "@atscript/db-sqlite";
import {
  UserService,
  UserAuthError,
  ppHasMinLength,
  ppHasUpperCase,
  ppHasNumber,
} from "@aooth/user";
import { type AuthUserTable, UsersStoreAtscriptDb } from "@aooth/user/atscript-db";
import { AppUser } from "./app-user.as";

const db = new DbSpace(() => new SqliteAdapter(new BetterSqlite3Driver("./app.db")));
await syncSchema(db, [AppUser]);

const store = new UsersStoreAtscriptDb<{ email?: string }>({
  table: db.getTable(AppUser) as unknown as AuthUserTable<{ email?: string }>,
});

const svc = new UserService(store, {
  password: {
    pepper: process.env.PASSWORD_PEPPER ?? "",
    historyLength: 5,
    policies: [ppHasMinLength(10), ppHasUpperCase(), ppHasNumber()],
  },
  lockout: { threshold: 5, duration: 15 * 60_000 },
});

await svc.createUser("alice", "Strong-Pass-1!", { email: "alice@example.com" });
await svc.activateAccount("alice");

try {
  const { user, mfaRequired } = await svc.login("alice", "Strong-Pass-1!");
} catch (e) {
  if (e instanceof UserAuthError && e.type === "LOCKED") {
    console.warn("locked until", e.details?.lockEnds);
  }
}
```

## Invariants

| #   | Rule                                                                                                                                                                                                                                                                                                                                                                                                               |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --- | ---------------------------------------------------- |
| 0   | **The stable surrogate `id` is the token subject and the key for ALL reads-by-identity + writes** (`getUser`/`update`/`setPassword`/lock/MFA/trusted-device). The ONE handle entry point is `login(handle, …)` → `findByHandle` (`username` then `email`, ordered, never `$or`). `findByIdentifier` (`id`→`username`→`email`) is for admin/recovery only — never login. `useAuth().getUserId()` returns this `id`. |
| 1   | **`createUser` mints `id: randomUUID()`** on the base record (the model's `@db.default.uuid` is a fallback for direct inserts only). `extras.id` overrides. `create` throws `ALREADY_EXISTS` on a duplicate `username` **or** `email`. (`user-service.ts`.)                                                                                                                                                        |
| 2   | **`extras` shallow-merges over the base record.** Top-level keys (`account`, `mfa`, `password`, `id`) are wholesale replaced when present in `extras` — pass nested objects with every required sub-field if you intend to override.                                                                                                                                                                               |
| 3   | **No bundled backup-code API.** There is no `generateBackupCodes` / `consumeBackupCode` service method and no `generateBackupCodePlaintext` export. `UserCredentials.backupCodes?: string[]` is a reserved slot — compose recovery codes from `hashMfaCode` / `verifyMfaCode` + `users.update(...)`.                                                                                                               |
| 4   | **`verifyMfa` and `login` share `failedLoginAttempts`.** Total tries across both factors = `lockout.threshold`, not `2 × threshold`. A successful password followed by repeated bad TOTPs locks the account.                                                                                                                                                                                                       |
| 5   | **`account.lockEnds: 0` means permanent lock**, not "no lock". Expiration is `lockEnds > 0 && lockEnds < now`. `lockAccount(id, reason)` (no `duration`) produces a permanent lock.                                                                                                                                                                                                                                |
| 6   | **Pepper is irrecoverable.** Lose `password.pepper` → every stored hash becomes unverifiable. Store it in env / secret manager, never in the DB.                                                                                                                                                                                                                                                                   |
| 7   | **`PasswordPolicy.transferable` is purely `typeof rule === 'string'`.** Function-based rules silently won't ship to the client via `getTransferablePolicies()`. Built-in factories (`ppHasMinLength`, ...) all emit string rules by design.                                                                                                                                                                        |
| 8   | **`@db.patch.strategy 'merge'`** lives in the shipped `AoothUserCredentials` `.as` model on `password`, `account`, `mfa`, `trustedDevices?`. Re-declaring any of these sub-objects in an extending interface without the annotation flips that field to wholesale replace and breaks the partial-update contract.                                                                                                  |
| 9   | **`UserStoreMemory` reads (`findById`/`findByHandle`/`findByIdentifier`) return a `structuredClone`** — mutating the returned object does not affect storage. Treat real-store callers the same way: don't assume references are persistent.                                                                                                                                                                       |
| 10  | **`MFA_REQUIRED` is never thrown by `@aooth/user`.** The type is in the union for higher layers (`@aooth/auth`, `@aooth/auth-moost`) — `UserService.login` returns `{ mfaRequired: boolean }` and lets the caller decide.                                                                                                                                                                                          |
| 11  | **`deviceTrust.secret` is mandatory for trusted-device APIs.** `issueTrustedDevice` / `verifyTrustedDevice` throw a plain `Error` (not `UserAuthError`) when the config key is unset. The HMAC binds `userId                                                                                                                                                                                                       | raw | ip`; verify must pass the same `ip` you issued with. |
| 12  | **`verifyTotpCode` rejects mismatched-length submissions** before reaching `timingSafeEqual` (which requires equal-length buffers). It then walks the entire `[-window..window]` window unconditionally so an early match doesn't return faster than a late one. (`mfa/totp.ts:43`.)                                                                                                                               |

## Key imports

```ts
// Service + error
import { UserService, UserAuthError } from "@aooth/user";

// Stores
import { UserStore, UserStoreMemory } from "@aooth/user";
import {
  UsersStoreAtscriptDb,
  type AuthUserTable,
  type UserCredentialsRow,
} from "@aooth/user/atscript-db";

// .as model (literal-file export — load via .as-aware bundler / `asc`)
import { AoothUserCredentials } from "@aooth/user/atscript-db/model.as";

// Password
import {
  PasswordHasher,
  PasswordPolicy,
  normalizePolicies,
  ppHasMinLength,
  ppHasUpperCase,
  ppHasLowerCase,
  ppHasNumber,
  ppHasSpecialChar,
  ppMaxRepeatedChars,
} from "@aooth/user";

// MFA primitives
import {
  generateTotpSecret,
  generateTotpUri,
  generateTotpCode,
  verifyTotpCode,
  generateMfaCode,
  hashMfaCode,
  verifyMfaCode,
} from "@aooth/user";

// Utilities
import { maskEmail, maskPhone, maskMfaValue, setAtPath } from "@aooth/user";

// Types
import type {
  UserCredentials,
  PasswordData,
  AccountData,
  MfaData,
  MfaMethod,
  UserServiceConfig,
  PasswordConfig,
  LockoutConfig,
  PasswordPolicyDef,
  PasswordPolicyEvalFn,
  PasswordPolicyContext,
  PasswordPolicyInstance,
  UserStoreUpdate,
  DeepPartial,
  UserAuthErrorType,
  LoginResult,
  LockStatus,
  PolicyCheckResult,
  TransferablePolicy,
  MfaMethodInfo,
  TotpConfig,
  TrustedDeviceRecord,
} from "@aooth/user";
```

## References — load only what's needed

| Domain             | File                                     | When                                                                                                                                                                                                                                                                                                                                   |
| ------------------ | ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| First contact      | [getting-started.md](getting-started.md) | Install, hello-world with `UserStoreMemory`, upgrade to `UsersStoreAtscriptDb`, test patterns (`FAST_SCRYPT`, injectable `clock`), `UserAuthError` handling                                                                                                                                                                            |
| `UserService`      | [user-service.md](./user-service.md)     | Every public method (`createUser`, `getUser`, `login`, `verifyPassword`, `changePassword`, `setPassword`, `deleteUser`, `update`, `activate*`, `lock*`, `unlock*`, `getLockStatus`, `checkPolicies`, MFA methods, `verifyTotpSetupCode`, `verifyMfa`, `isPasswordExpired`, trusted-device APIs), config defaults, login sequence       |
| Password subsystem | [password.md](./password.md)             | `PasswordHasher` scrypt params + hash-string format, pepper warning, history rotation, `generatePassword()` guarantees, `PasswordPolicy` (string-rule DSL via `@prostojs/ftring`), built-in factories table, `getTransferablePolicies()`, custom policies, `PolicyCheckResult` shape                                                   |
| MFA                | [mfa.md](./mfa.md)                       | TOTP primitives + constant-time verification + window, otpauth URI for QR, `verifyTotpSetupCode` enroll-confirm + `EnrollConfirmForm.qrCode` → `AsQrCode`, `generateMfaCode` / `hashMfaCode` / `verifyMfaCode` for email/SMS challenges, backup-codes-not-bundled note, trusted-device tokens (HMAC, IP binding, `deviceTrust.secret`) |
| Stores             | [user-stores.md](./user-stores.md)       | `UserStore<T>` abstract contract (5 methods), `UserStoreMemory<T>` features + `structuredClone` isolation, writing a custom store (`ALREADY_EXISTS` on conflict, deep-merge `set`, atomic `inc`, `false` for no-row), `UserStoreUpdate` examples, `UsersStoreAtscriptDb` wiring + `AuthUserTable` cast, `isConflict`                   |

## See also

Source: https://github.com/moostjs/aoothjs/tree/main/packages/user. Roadmap: https://github.com/moostjs/aoothjs/blob/main/TODO.md.
