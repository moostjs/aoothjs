# Errors

Every failure path in `@aooth/user` funnels through a single error class: `UserAuthError`. This page is the exhaustive reference for the discriminant `type` field, the `details` payload shape per type, and the HTTP status mapping you'd use in a controller.

## The class

```ts
import { UserAuthError } from "@aooth/user";

class UserAuthError extends Error {
  readonly name = "UserAuthError";
  constructor(
    public type: UserAuthErrorType,
    message?: string,
    public details?: Record<string, unknown>,
  );
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
  | "MFA_REQUIRED"
  | "CAS_EXHAUSTED";
```

Without a `message` argument the error carries its default English message from `USER_AUTH_ERROR_MESSAGES`. That catalogue is keyed by the error's **message code**, `err.code` — the id its text is registered and translated by, and the `code` of the HTTP error made from it. `USER_AUTH_ERROR_CODES` maps each `type` to its code: types with a generic name get an `AOOTH_USER_` code (`LOCKED` → `AOOTH_USER_LOCKED`, `ALREADY_EXISTS` → `AOOTH_USER_ALREADY_EXISTS`, `INACTIVE` → `AOOTH_USER_INACTIVE`, `POLICY_VIOLATION` → `AOOTH_USER_POLICY_VIOLATION`, `CAS_EXHAUSTED` → `AOOTH_USER_CAS_EXHAUSTED`), the others keep their type as the code. `NOT_FOUND` ("Not found") and `INVALID_CREDENTIALS` are shared with other libraries on purpose — see [One id space](/moost/messages#one-id-space-shared-with-other-libraries). Branch on `err.type` in code; translate by `err.code`. `@aooth/auth-moost` registers the catalogue with moost, so under a moost translator `userAuthErrorToHttp()` answers in the request's language ([Messages & Localization](/moost/messages)). Using `@aooth/user` on a moost server without `@aooth/auth-moost`? Call `registerMessages(USER_AUTH_ERROR_MESSAGES)` yourself.

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

| `type`                | Triggered by                                                                                                                                                                     | `details` shape                                                                                                  | HTTP ([mapping](#http-mapping)) |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| `NOT_FOUND`           | `getUser`, `login`, `verifyPassword`, `verifyMfa`, `update`, `activate*`, `deactivate*`, `lock*`, `unlock*`, `deleteUser`, MFA / trusted-device methods when the user is missing | —                                                                                                                | `404`                           |
| `ALREADY_EXISTS`      | `createUser` when the `username` **or** any configured secondary handle field is taken (`UserStoreMemory.create` throws it directly; `UsersStoreAtscriptDb` maps CONFLICT)       | —                                                                                                                | `409`                           |
| `INACTIVE`            | `login`, `verifyMfa` when `account.active === false`                                                                                                                             | —                                                                                                                | `403`                           |
| `LOCKED`              | `ensureNotLockedOrThrow` in `login` / `verifyMfa` after the auto-unlock check, before password / TOTP verification                                                               | `{ reason: string, lockEnds: number }`                                                                           | `403`                           |
| `INVALID_CREDENTIALS` | bad password in `login`; bad current password in `changePassword`                                                                                                                | `{ lockEnds: number }` **only** when the failure tripped the lock; otherwise absent                              | `400`                           |
| `MFA_INVALID`         | bad TOTP in `verifyMfa`                                                                                                                                                          | `{ lockEnds: number }` **only** when the failure tripped the lock                                                | `400`                           |
| `MFA_NOT_CONFIGURED`  | `confirmMfaMethod` / `setDefaultMfaMethod` with an unknown `name`; `verifyMfa` when no confirmed `totp` method exists                                                            | —                                                                                                                | `400`                           |
| `POLICY_VIOLATION`    | failing policy in `changePassword` / `setPassword`                                                                                                                               | `{ policies: { description: string, passed: boolean }[] }` (failure reasons are joined into the error `message`) | `422`                           |
| `PASSWORDS_MISMATCH`  | `repeatPassword !== newPassword` in `changePassword`                                                                                                                             | —                                                                                                                | `400`                           |
| `PASSWORD_IN_HISTORY` | new password matches current hash or any `password.history[]` entry                                                                                                              | —                                                                                                                | `400`                           |
| `MFA_REQUIRED`        | **never thrown by this package**; reserved for higher layers (`@aooth/auth`)                                                                                                     | —                                                                                                                | `403`                           |
| `CAS_EXHAUSTED`       | a store write that keeps losing its optimistic-concurrency retries (`withCas`)                                                                                                   | —                                                                                                                | `409`                           |

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

## HTTP mapping {#http-mapping}

`@aooth/auth-moost` ships the mapping: `userAuthErrorToHttp(err)` turns a `UserAuthError` into an `HttpError` whose body carries `code` (the error's message code, `err.code`), the message and, for password errors, the form `field`; `userAuthErrorInterceptor` applies it to every `UserAuthError` a handler throws.

```ts
import { userAuthErrorInterceptor } from "@aooth/auth-moost";
import { UserService } from "@aooth/user";
import { Body, Post } from "@moostjs/event-http";
import { Controller, Intercept } from "moost";

@Controller("admin/users")
@Intercept(userAuthErrorInterceptor)
export class AdminUsersController {
  constructor(private readonly users: UserService) {}

  @Post("set-password")
  async setPassword(@Body() body: { id: string; password: string }) {
    await this.users.setPassword(body.id, body.password); // POLICY_VIOLATION → 422, NOT_FOUND → 404
    return { ok: true };
  }
}
```

| `type`                               | `code`                                                     | Status | `field`           | `params`       |
| ------------------------------------ | ---------------------------------------------------------- | ------ | ----------------- | -------------- |
| `NOT_FOUND`                          | `NOT_FOUND`                                                | `404`  |                   |                |
| `ALREADY_EXISTS`, `CAS_EXHAUSTED`    | `AOOTH_USER_ALREADY_EXISTS`, `AOOTH_USER_CAS_EXHAUSTED`    | `409`  |                   |                |
| `INVALID_CREDENTIALS`                | `INVALID_CREDENTIALS`                                      | `400`  | `currentPassword` |                |
| `PASSWORD_IN_HISTORY`                | `PASSWORD_IN_HISTORY`                                      | `400`  | `newPassword`     |                |
| `POLICY_VIOLATION`                   | `AOOTH_USER_POLICY_VIOLATION`                              | `422`  | `newPassword`     | `{ policies }` |
| `PASSWORDS_MISMATCH`                 | `PASSWORDS_MISMATCH`                                       | `400`  | `confirmPassword` |                |
| `MFA_INVALID`, `MFA_NOT_CONFIGURED`  | `MFA_INVALID`, `MFA_NOT_CONFIGURED`                        | `400`  |                   |                |
| `INACTIVE`, `LOCKED`, `MFA_REQUIRED` | `AOOTH_USER_INACTIVE`, `AOOTH_USER_LOCKED`, `MFA_REQUIRED` | `403`  |                   |                |

```json
{
  "statusCode": 422,
  "error": "Unprocessable Entity",
  "message": "Password must be at least 12 characters long",
  "code": "AOOTH_USER_POLICY_VIOLATION",
  "field": "newPassword",
  "params": { "policies": [{ "description": "Minimum length 12", "passed": false }] }
}
```

- **DO** use it for admin and self-service routes (set / change password, profile updates).
- **DO** attach the interceptor per controller (`@Intercept(userAuthErrorInterceptor)`) — **DON'T** install it with `app.applyGlobalInterceptors(...)`.
- **DON'T** use it on a sign-in or recovery endpoint: distinct answers for unknown, inactive and locked accounts (404 / 403 from `login()` / `verifyMfa()`) let a caller enumerate accounts and defeat `lockoutDisclosure: 'uniform'` — the bundled login workflow answers them uniformly. A global install does exactly that to every custom sign-in handler.
- Wrong passwords and codes map to `400`, not `401`: `createAuthedFetch` answers a `401` with a token refresh and a retry, which would re-submit the wrong value. `details` other than `policies` (e.g. `LOCKED`'s `reason`) are not sent.

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
