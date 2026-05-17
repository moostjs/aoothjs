# `@aoothjs/user` API Reference

Complete export reference for `@aoothjs/user`. See the [User Conceptual Guide](/user/) for narrative documentation. Every public symbol lives in `packages/user/src/index.ts`.

## Classes

### `UserService<T extends object = object>`

```ts
new UserService<T>(store: UserStore<T>, config?: UserServiceConfig)
```

Orchestrator for credential CRUD, login, lockout, password policy, MFA, backup codes, and trusted devices. Generic `T` adds custom user columns to every result. See [UserService](/user/service).

Async methods (selected): `createUser`, `getUser`, `login`, `verifyPassword`, `changePassword`, `setPassword`, `deleteUser`, `update`, `activateAccount`, `deactivateAccount`, `lockAccount`, `unlockAccount`, `checkPolicies`, `addMfaMethod`, `confirmMfaMethod`, `removeMfaMethod`, `setDefaultMfaMethod`, `setMfaAutoSend`, `generateBackupCodes`, `consumeBackupCode`, `verifyMfa`, `addTrustedDevice`, `verifyTrustedDevice`, `revokeTrustedDevice`, `listTrustedDevices`.

Sync helpers: `getLockStatus`, `getTransferablePolicies`, `getAvailableMfaMethods`, `issueTrustedDevice`, `getPasswordHasher`, `getConfig`.

### `UserStore<T extends object = object>` (abstract)

```ts
abstract class UserStore<T> {
  abstract exists(username: string): Promise<boolean>;
  abstract findByUsername(username: string): Promise<(UserCredentials & T) | null>;
  abstract create(data: UserCredentials & T): Promise<void>;
  abstract update(username: string, update: UserStoreUpdate): Promise<boolean>;
  abstract delete(username: string): Promise<boolean>;
}
```

Storage contract. `update` MUST deep-merge `set`, atomically apply `inc` per dot-path, and return `false` when no row matched. See [Stores](/user/stores).

### `UserStoreMemory<T>`

```ts
new UserStoreMemory<T>(seed?: Record<string, UserCredentials & T>)
```

In-memory reference implementation using `Map` + `structuredClone`. `create` throws `UserAuthError("ALREADY_EXISTS")`. See [Stores](/user/stores).

### `PasswordHasher`

```ts
new PasswordHasher(config?: PasswordConfig)
hasher.hash(password: string): Promise<string>
hasher.verify(password: string, encoded: string): Promise<boolean>
hasher.generatePassword(length?: number): string
```

Node `scrypt` wrapper. Hash strings are self-describing (`$scrypt$N=...,r=...,p=...,l=...$<salt-b64u>$<hash-b64u>`). Pepper is prepended to the password and never stored. See [Password Hashing](/user/password).

### `PasswordPolicy`

```ts
new PasswordPolicy(def: PasswordPolicyDef)
policy.evaluate(password: string, ctx?: PolicyContext): boolean | Promise<boolean>
policy.transferable: boolean   // true iff rule is a string
```

Wraps one rule (string compiled via `@prostojs/ftring`, or a function). String-rule policies are transferable — they ship to the client for pre-validation. See [Password Policies](/user/policy).

## Functions

### `normalizePolicies`

```ts
function normalizePolicies(defs?: (PasswordPolicyDef | PasswordPolicyInstance)[]): PasswordPolicy[];
```

Compiles an array of `PasswordPolicyDef` into ready-to-evaluate `PasswordPolicy` instances. See [Password Policies](/user/policy).

### Built-in policy factories

```ts
function ppHasMinLength(min?: number): PasswordPolicyDef;
function ppHasUpperCase(n?: number): PasswordPolicyDef;
function ppHasLowerCase(n?: number): PasswordPolicyDef;
function ppHasNumber(n?: number): PasswordPolicyDef;
function ppHasSpecialChar(n?: number): PasswordPolicyDef;
function ppMaxRepeatedChars(maxRepeated?: number): PasswordPolicyDef;
```

All emit string-rule (transferable) `PasswordPolicyDef`s. See [Password Policies](/user/policy).

### TOTP / MFA primitives

```ts
function generateTotpSecret(bytes?: number): string;
function generateTotpUri(
  secret: string,
  issuer: string,
  account: string,
  opts?: { period?: number; digits?: number },
): string;
function generateTotpCode(secret: string, config?: TotpConfig): string;
function verifyTotpCode(secret: string, code: string, config?: TotpConfig): boolean;
function generateMfaCode(length?: number): string;
function hashMfaCode(code: string): string;
function verifyMfaCode(submitted: string, expectedHash: string): boolean;
function generateBackupCodePlaintext(count?: number): string[];
```

RFC-4226/6238 TOTP, generic MFA-code hash helpers, and backup-code plaintext generator. `verifyTotpCode` is constant-time and walks the full `[-window..window]`. See [MFA Primitives](/user/mfa).

### Masking & path utilities

```ts
function maskEmail(email: string): string;
function maskPhone(phone: string): string;
function maskMfaValue(method: MfaMethod): string;
function setAtPath(obj: object, path: string, value: unknown): void;
```

`maskEmail` / `maskPhone` / `maskMfaValue` produce UI-safe display strings for MFA targets — see [MFA Primitives](/user/mfa).

`setAtPath` is **advanced — for custom store implementers only**. App code does not call this directly; it's exported so that custom `UserStore` adapters can apply the `inc` patch shape (`{ "account.failedLoginAttempts": 1 }`) against an in-memory snapshot.

## Types

### Core record shapes

```ts
interface UserCredentials {
  id: string;
  username: string;
  password: PasswordData;
  account: AccountData;
  mfa: MfaData;
  backupCodes?: string[];
  trustedDevices?: TrustedDeviceRecord[];
}
interface PasswordData {
  hash: string;
  history: string[];
  lastChanged: number;
  isInitial: boolean;
}
interface AccountData {
  active: boolean;
  locked: boolean;
  lockReason: string;
  /** 0 = permanent lock, >0 = timestamp (ms) when lock expires */
  lockEnds: number;
  failedLoginAttempts: number;
  lastLogin: number;
  /** Set by the invite workflow; cleared once the invite is accepted. */
  pendingInvitation?: boolean;
}
interface MfaData {
  methods: MfaMethod[];
  defaultMethod: string;
  autoSend: boolean;
}
interface MfaMethod {
  /** Method discriminator: 'email', 'sms', 'totp' */
  name: string;
  /** Whether this method has been verified/confirmed */
  confirmed: boolean;
  /** Email address, phone number, or TOTP secret */
  value: string;
}
```

The full record model lives at `src/types.ts`. See [Credentials Model](/user/credentials).

### Service configuration

```ts
interface UserServiceConfig {
  password?: PasswordConfig;
  lockout?: LockoutConfig;
  /** Injectable clock for testability. Defaults to Date.now */
  clock?: () => number;
  /** HMAC-SHA256 signing secret for trust-device tokens. */
  deviceTrust?: { secret: string };
}
interface LockoutConfig {
  /** Lock after this many failed attempts (0 = disabled, default) */
  threshold?: number;
  /** Lock duration in ms (0 = permanent, default) */
  duration?: number;
}
interface PasswordConfig {
  pepper?: string;
  /** Number of historical hashes to retain (0 = disabled) */
  historyLength?: number;
  scryptN?: number;
  scryptR?: number;
  scryptP?: number;
  keyLength?: number;
  policies?: (PasswordPolicyDef | PasswordPolicyInstance)[];
}
```

See [UserService](/user/service).

### Policy types

```ts
type PasswordPolicyEvalFn = (
  password: string,
  ctx?: PasswordPolicyContext,
) => boolean | Promise<boolean>;
interface PasswordPolicyDef {
  rule: string | PasswordPolicyEvalFn;
  description?: string;
  errorMessage?: string;
}
interface PasswordPolicyContext {
  passwordData?: PasswordData;
  passwordConfig?: PasswordConfig;
}
interface PasswordPolicyInstance extends PasswordPolicyDef {
  evaluate(password: string, ctx?: PasswordPolicyContext): boolean | Promise<boolean>;
  transferable: boolean;
}
interface TransferablePolicy {
  rule: string;
  description?: string;
  errorMessage?: string;
}
interface PolicyCheckResult {
  passed: boolean;
  policies: Array<{ description: string; passed: boolean }>;
  errors: string[];
}
```

See [Password Policies](/user/policy).

### Store update payload

```ts
interface UserStoreUpdate {
  set?: DeepPartial<UserCredentials>;
  inc?: Record<string, number>; // dot-path → delta
}
type DeepPartial<T> = { [K in keyof T]?: T[K] extends object ? DeepPartial<T[K]> : T[K] };
```

`set` is a deep-merge; `inc` is an atomic numeric increment per dot-path. Arrays in `set` are wholesale replacements. See [Stores](/user/stores).

### Login / lock results

```ts
interface LoginResult<T extends object = object> {
  user: UserCredentials & T;
  mfaRequired: boolean;
}
interface LockStatus {
  locked: boolean;
  /** True when lock has a non-zero lockEnds that is in the past */
  expired: boolean;
  reason: string;
  lockEnds: number;
}
```

See [UserService](/user/service).

### MFA types

```ts
interface MfaMethodInfo {
  name: string;
  isDefault: boolean;
  masked: string;
}
interface TotpConfig {
  /** Time step in seconds (default 30) */
  period?: number;
  /** Number of digits in the code (default 6) */
  digits?: number;
  /** Verification window — steps to check on each side (default 1) */
  window?: number;
  /** Injectable clock for testability */
  clock?: () => number;
}
interface TrustedDeviceRecord {
  /** `<raw>.<sig>` — opaque token round-tripped by the consumer */
  token: string;
  /** Bound IP — set when `deviceTrust.bindsTo === 'cookie+ip'` */
  ip?: string;
  issuedAt: number;
  expiresAt: number;
  /** Optional human-readable label (e.g. user-agent summary) */
  name?: string;
}
```

See [MFA Primitives](/user/mfa).

### Error type

```ts
type UserAuthErrorType =
  | "NOT_FOUND"
  | "ALREADY_EXISTS"
  | "INACTIVE"
  | "LOCKED"
  | "INVALID_CREDENTIALS"
  | "MFA_INVALID"
  | "MFA_NOT_CONFIGURED"
  | "MFA_REQUIRED"
  | "POLICY_VIOLATION"
  | "PASSWORDS_MISMATCH"
  | "PASSWORD_IN_HISTORY";
```

See [Errors](/user/errors).

## Errors

### `UserAuthError`

```ts
class UserAuthError extends Error {
  readonly name: 'UserAuthError'
  constructor(
    public type: UserAuthErrorType,
    message?: string,
    public details?: Record<string, unknown>
  )
}
```

Every error path in `@aoothjs/user` funnels through this single class. The `type` field drives HTTP mapping at the controller layer. `details` carries `{ reason, lockEnds }` for `LOCKED`, `{ policies }` for `POLICY_VIOLATION`, and `{ lockEnds }` for `INVALID_CREDENTIALS` / `MFA_INVALID` when the failure tripped the lock. See [Errors](/user/errors).

## Subpath: `@aoothjs/user/atscript-db`

```ts
import { UsersStoreAtscriptDb, AuthUserTable, UserCredentialsRow } from "@aoothjs/user/atscript-db";
```

### `UsersStoreAtscriptDb<TUserCustom>`

```ts
new UsersStoreAtscriptDb<TUserCustom>(opts: { table: AuthUserTable<TUserCustom> })
```

`@atscript/db`-backed `UserStore`. Translates `DbError.code === 'CONFLICT'` into `UserAuthError('ALREADY_EXISTS')` and emits `set` / `$inc` patches. See [Stores](/user/stores) and the [atscript-db guide](/guide/atscript-db).

### `AuthUserTable<TUserCustom>` / `UserCredentialsRow<TUserCustom>`

Structural-only types describing the subset of `AtscriptDbTable` methods the adapter needs and the row shape it expects. Apps cast their concrete `db.getTable(AppUser)` to `AuthUserTable`. See [Stores](/user/stores).

## Subpath: `@aoothjs/user/atscript-db/model.as`

Raw `.as` file export. Defines `AoothUserCredentials` — `username` (with `@db.index.unique`) plus `@db.patch.strategy 'merge'` sub-objects for `password` / `account` / `mfa` / `trustedDevices`. Consumers extend it to add `@meta.id` and `@db.table`. See [Credentials Model](/user/credentials).
