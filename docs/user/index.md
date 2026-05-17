# `@aooth/user`

This section documents the foundation of the aoothjs auth stack — the user credentials package. It answers: how do I model a user, hash a password, enforce a password policy, verify an MFA factor, and lock an account, with a storage layer I can swap out per environment.

## What this package is

`@aooth/user` is the **credential layer**. It owns the in-memory shape of a user (`UserCredentials`), the password subsystem (scrypt + history + policies), MFA primitives (TOTP, one-time codes, backup codes, trusted devices), the account state machine (active / locked / failed-attempts), and an abstract `UserStore<T>` that decouples all of the above from any specific database.

The one orchestrator is **[`UserService<T>`](./service)** — every consumer-facing API call goes through it. Internally it composes:

| Subsystem     | What it owns                                                                                                                                     |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Account state | `account.active`, `locked`, `lockEnds`, `failedLoginAttempts`, `lastLogin`                                                                       |
| Password      | `PasswordHasher` + `PasswordPolicy` — hashing, verification, history, policy DSL                                                                 |
| MFA           | `generateTotpSecret` / `generateTotpUri` / `generateTotpCode` / `verifyTotpCode`, `hashMfaCode` / `verifyMfaCode`, `generateBackupCodePlaintext` |
| Storage       | `UserStore<T>` (abstract) — `exists` / `findByUsername` / `create` / `update` / `delete`                                                         |
| Errors        | `UserAuthError` — every failure carries a discriminant `type` + structured `details`                                                             |

## What this package is not

- **No HTTP.** No controllers, no decorators, no middleware. Wire it under `@aooth/auth-moost` (or your own framework code) for that.
- **No sessions or tokens.** Issuing JWTs, refresh rotation, magic links — those live in `@aooth/auth`.
- **No MFA delivery.** `MfaMethod.value` is a string the service stores; sending the SMS / email is your job.
- **No challenge state machine.** The "issue OTP → wait → verify" loop is owned by `@aooth/auth` and workflow controllers in `@aooth/auth-moost`.
- **No RBAC.** Roles, privileges, data scopes — see [`@aooth/arbac`](../arbac/).

In short: this package gives you a correct, swappable, well-typed **user record + password engine + MFA primitives**. Everything that turns those into a request/response cycle lives a layer up.

## The `UserService` orchestrator pattern

You construct `UserService` once, hand it a `UserStore`, and call methods on it from anywhere — controllers, CLI tools, scripts, tests.

```ts
import { UserService, UserStoreMemory, ppHasMinLength, ppHasNumber } from "@aooth/user";

const store = new UserStoreMemory();

const users = new UserService(store, {
  pepper: process.env.PASSWORD_PEPPER,
  historyLength: 5,
  lockout: { threshold: 5, duration: 15 * 60_000 },
  policies: [ppHasMinLength(12), ppHasNumber(1)],
});

await users.createUser("alice", "S3cret-passphrase!");

const result = await users.login("alice", "S3cret-passphrase!");
// → { user: UserCredentials, mfaRequired: false }
```

The service is **stateless** — every call hits the store. That makes horizontal scaling trivial: multiple service instances backed by the same `UserStore` are safe.

## Submodules

- [`UserService`](./service) — the orchestrator. Constructor, config, every public method.
- [`Credentials Model`](./credentials) — what `UserCredentials` looks like on disk, the `account` / `password` / `mfa` / `trustedDevices` sub-objects, and how to extend with custom columns via generic `T`.
- [`Password Hashing`](./password) — `PasswordHasher`, self-describing hash strings, pepper, history, `generatePassword`, scrypt cost tuning, the `FAST_SCRYPT` test idiom.
- [`Password Policies`](./policy) — the `@prostojs/ftring` string DSL, function rules, built-in factories (`ppHas*`), `getTransferablePolicies()` for client-side pre-validation.
- [`MFA Primitives`](./mfa) — TOTP secret + URI + code + verify, one-time MFA-code helpers, backup codes, trusted devices. What's here and what's deliberately not.
- [`Stores`](./stores) — the `UserStore<T>` contract, `UserStoreMemory<T>` for tests, the `UserStoreUpdate { set, inc }` shape, and the `@atscript/db` adapter (`@aooth/user/atscript-db`).
- [`Errors`](./errors) — the `UserAuthError` class, every `UserAuthErrorType`, and recommended HTTP status mappings.

## Install

```bash
pnpm add @aooth/user
# optional — if you use the atscript-db storage adapter:
pnpm add @atscript/db
```

::: tip
This package has no peer dependency on `@atscript/db` unless you import the `@aooth/user/atscript-db` subpath. The plain `UserStoreMemory` works out of the box for tests and prototyping.
:::

## Source

[Browse the package source on GitHub](https://github.com/moostjs/aoothjs/tree/main/packages/user/src).
