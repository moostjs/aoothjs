# Errors

Every failure path in `@aooth/user` funnels through a single error class: `UserAuthError`. This page is the exhaustive reference for the discriminant `type` field, the `details` payload shape per type, and the HTTP status mapping you'd use in a controller.

## The class

```ts
import { UserAuthError } from "@aooth/user"

class UserAuthError extends Error {
  readonly name = "UserAuthError"
  constructor(
    public type: UserAuthErrorType,
    message?: string,
    public details?: Record<string, unknown>,
  )
}
```

Source: [`packages/user/src/errors.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/errors.ts).

```ts
type UserAuthErrorType =
  | "NOT_FOUND"
  | "ALREADY_EXISTS"
  | "INACTIVE"
  | "LOCKED"
  | "INVALID_CREDENTIALS"
  | "MFA_INVALID"
  | "MFA_NOT_CONFIGURED"
  | "POLICY_VIOLATION"
  | "PASSWORDS_MISMATCH"
  | "PASSWORD_IN_HISTORY"
  | "MFA_REQUIRED";
```

The narrowing pattern in handlers:

```ts
try {
  await users.login(u, p);
} catch (e) {
  if (e instanceof UserAuthError) {
    switch (e.type) {
      case "LOCKED":
        return tooManyAttempts(e.details?.lockEnds);
      case "INVALID_CREDENTIALS":
        return badPassword(e.details?.lockEnds);
      // ...
    }
  }
  throw e;
}
```

## Full table

| `type`                | Triggered by                                                                                                                                                                     | `details` shape                                                                                                  | Recommended HTTP                       |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| `NOT_FOUND`           | `getUser`, `login`, `verifyPassword`, `verifyMfa`, `update`, `activate*`, `deactivate*`, `lock*`, `unlock*`, `deleteUser`, MFA / trusted-device methods when the user is missing | —                                                                                                                | `404 Not Found`                        |
| `ALREADY_EXISTS`      | `createUser` when the `username` **or** any configured secondary handle field is taken (`UserStoreMemory.create` throws it directly; `UsersStoreAtscriptDb` maps CONFLICT)       | —                                                                                                                | `409 Conflict`                         |
| `INACTIVE`            | `login`, `verifyMfa` when `account.active === false`                                                                                                                             | —                                                                                                                | `403 Forbidden`                        |
| `LOCKED`              | `ensureNotLockedOrThrow` in `login` / `verifyMfa` after the auto-unlock check, before password / TOTP verification                                                               | `{ reason: string, lockEnds: number }`                                                                           | `403 Forbidden`                        |
| `INVALID_CREDENTIALS` | bad password in `login`; bad current password in `changePassword`                                                                                                                | `{ lockEnds: number }` **only** when the failure tripped the lock; otherwise absent                              | `401 Unauthorized`                     |
| `MFA_INVALID`         | bad TOTP in `verifyMfa`                                                                                                                                                          | `{ lockEnds: number }` **only** when the failure tripped the lock                                                | `401 Unauthorized`                     |
| `MFA_NOT_CONFIGURED`  | `confirmMfaMethod` / `setDefaultMfaMethod` with an unknown `name`; `verifyMfa` when no confirmed `totp` method exists                                                            | —                                                                                                                | `400 Bad Request` (or `409`)           |
| `POLICY_VIOLATION`    | failing policy in `changePassword` / `setPassword`                                                                                                                               | `{ policies: { description: string, passed: boolean }[] }` (failure reasons are joined into the error `message`) | `422 Unprocessable Entity`             |
| `PASSWORDS_MISMATCH`  | `repeatPassword !== newPassword` in `changePassword`                                                                                                                             | —                                                                                                                | `400 Bad Request`                      |
| `PASSWORD_IN_HISTORY` | new password matches current hash or any `password.history[]` entry                                                                                                              | —                                                                                                                | `400 Bad Request`                      |
| `MFA_REQUIRED`        | **never thrown by this package**; reserved for higher layers (`@aooth/auth`)                                                                                                     | —                                                                                                                | `401 Unauthorized` with challenge body |

::: warning `MFA_REQUIRED` is a contract, not a throw site
`@aooth/user` signals "MFA is needed" via the `mfaRequired: true` field on `LoginResult` — not by throwing. The `MFA_REQUIRED` enum member exists so higher layers (the auth orchestrator, controllers) can throw it when **they** decide the session must complete MFA. Don't expect this package to emit it.
:::

## Type details

### `NOT_FOUND`

```ts
throw new UserAuthError("NOT_FOUND", "User not found");
```

No `details` payload. Triggered everywhere an identity lookup is required and the store read returns `null` (`getUser`/`findById`, or `findByHandle`/`findByIdentifier` on the recovery/admin paths). `update` and `delete` translate a store-layer "no row affected" return into this.

### `ALREADY_EXISTS`

```ts
throw new UserAuthError("ALREADY_EXISTS", "User already exists");
```

No `details`. Custom stores must throw this themselves on a unique-handle conflict — duplicate `username` **or** any configured secondary handle field (`UserStoreMemory.create` and the atscript-db adapter both do). See [Credentials Model](/user/credentials) for how handle fields are declared.

### `INACTIVE`

```ts
throw new UserAuthError("INACTIVE", "Account is inactive");
```

Thrown when `account.active === false`. Used by `login` and `verifyMfa`. Toggle via `users.activateAccount(u)` / `users.deactivateAccount(u)`.

### `LOCKED`

```ts
throw new UserAuthError("LOCKED", "Account is locked", {
  reason: account.lockReason,
  lockEnds: account.lockEnds, // 0 = permanent
});
```

Thrown when `account.locked === true` and (if temporary) `lockEnds >= now`. Auto-unlock fires before this throw — a lock with `lockEnds > 0 && lockEnds < now` returns the user to the unlocked path silently.

::: warning `lockEnds: 0` is permanent
Distinguish the two surfaces:

- `lockEnds > 0 && lockEnds < now` ⇒ expired ⇒ auto-unlock (no `LOCKED` thrown).
- `lockEnds === 0` ⇒ permanent ⇒ always throws `LOCKED`.
- `lockEnds > now` ⇒ active temporary lock ⇒ throws `LOCKED` with `lockEnds` set.
  :::

### `INVALID_CREDENTIALS` / `MFA_INVALID`

Both share the lockout-counter trip semantics:

- The `failedLoginAttempts` counter is `$inc`'d.
- If the count hits `lockout.threshold`, the account is locked and `details.lockEnds` is populated on **this** error.
- Otherwise `details` is undefined.

```ts
// no lock tripped
throw new UserAuthError("INVALID_CREDENTIALS", "Invalid credentials");

// lock tripped
throw new UserAuthError("INVALID_CREDENTIALS", "Invalid credentials", {
  lockEnds: now + duration,
});
```

This lets a UI distinguish "wrong password, try again" from "wrong password, now locked until X".

::: tip `verifyMfa` shares the counter
Total failed tries across `login + verifyMfa` count toward the same threshold. A user with 2 bad logins and 3 bad TOTP attempts trips a `threshold: 5` lock, not `2/5` and `3/5` separately.
:::

### `MFA_NOT_CONFIGURED`

```ts
throw new UserAuthError("MFA_NOT_CONFIGURED", "...");
```

Two triggers:

- `confirmMfaMethod` / `setDefaultMfaMethod` with a `name` that doesn't exist in `mfa.methods[]`.
- `verifyMfa` when there's no **confirmed** `totp` method on the user.

`setDefaultMfaMethod("")` is the documented way to clear the default — empty string is not a "not configured" error.

### `POLICY_VIOLATION`

```ts
throw new UserAuthError("POLICY_VIOLATION", "Too short. Missing digit.", {
  policies: [
    { description: "at least 12 characters", passed: false },
    { description: "at least one digit", passed: true },
    // ...
  ],
});
```

The `policies` array contains **every** evaluated policy, including those that passed — UIs typically filter `passed: false`. Each entry mirrors the original `PasswordPolicyDef`'s `description`. The failed policies' `errorMessage`s (from `PolicyCheckResult.errors`) are joined into the thrown error's `message` — they do not appear in `details`.

### `PASSWORDS_MISMATCH`

```ts
throw new UserAuthError("PASSWORDS_MISMATCH", "Passwords don't match");
```

Triggered when `changePassword(u, current, new, repeat)` is called with `repeat !== new`. Pre-policy check, so the user gets this before any policy work runs.

### `PASSWORD_IN_HISTORY`

```ts
throw new UserAuthError("PASSWORD_IN_HISTORY", "Password was used recently");
```

Triggered when the new password matches the current hash or any entry in `password.history[]`. History size is `config.password.historyLength` (default `0` = current-hash only).

## HTTP mapping helper

A reasonable controller-side helper:

```ts
import { UserAuthError } from "@aooth/user";

const STATUS: Record<UserAuthErrorType, number> = {
  NOT_FOUND: 404,
  ALREADY_EXISTS: 409,
  INACTIVE: 403,
  LOCKED: 403,
  INVALID_CREDENTIALS: 401,
  MFA_INVALID: 401,
  MFA_NOT_CONFIGURED: 400,
  POLICY_VIOLATION: 422,
  PASSWORDS_MISMATCH: 400,
  PASSWORD_IN_HISTORY: 400,
  MFA_REQUIRED: 401,
};

export function httpStatusFor(err: UserAuthError): number {
  return STATUS[err.type] ?? 500;
}
```

`@aooth/auth-moost` ships a built-in mapper for this — see the moost integration docs.

## Detecting `UserAuthError` across module copies

`instanceof UserAuthError` works in the common case. If you have multiple resolved copies of `@aooth/user` (pnpm workspaces with hoisting quirks, monorepo edge cases), fall back to the `name` field:

```ts
function isUserAuthError(e: unknown): e is UserAuthError {
  return (
    !!e &&
    typeof e === "object" &&
    (e as any).name === "UserAuthError" &&
    typeof (e as any).type === "string"
  );
}
```

## See also

- [`UserService` method reference](./service#methods-overview) — which method throws which type.
- [Password Policies](./policy) — building the `POLICY_VIOLATION` `details.policies` array.
- [`packages/user/src/errors.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/errors.ts) — error class source.
