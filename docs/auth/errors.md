# Errors

`@aoothjs/auth` throws exactly one error class: `AuthError`. Every failure mode that should surface to the caller carries a typed discriminator, an optional `details` payload, and a stable message shape.

This page lists every error type, what triggers it, what the `details` look like, and the recommended HTTP mapping.

## The class

```ts
class AuthError extends Error {
  readonly name = 'AuthError';
  constructor(
    readonly type: AuthErrorType,
    message?: string,
    readonly details?: Record<string, unknown>,
  );
}

type AuthErrorType =
  | 'INVALID_TOKEN'
  | 'TOKEN_EXPIRED'
  | 'TOKEN_REVOKED'
  | 'REFRESH_REUSE_DETECTED'
  | 'STATELESS_OPERATION_UNSUPPORTED'
  | 'MAX_CONCURRENT_REACHED'
  | 'INVALID_CONFIG';
```

Catching:

```ts
import { AuthError } from "@aoothjs/auth";

try {
  await auth.refresh(refreshToken);
} catch (e) {
  if (e instanceof AuthError) {
    switch (e.type) {
      case "INVALID_TOKEN":
        return res.status(401).end();
      case "REFRESH_REUSE_DETECTED":
        return logoutAndRedirect(res);
      case "MAX_CONCURRENT_REACHED":
        return res.status(409).json({ kind: "maxConcurrent", ...e.details });
      default:
        throw e;
    }
  }
  throw e;
}
```

::: tip Never catch `Error`
Always check `e instanceof AuthError` first. The package never throws plain `Error` — anything not from `AuthError` is genuinely unexpected (network, bug, etc) and should propagate.
:::

## Full type table

| `type`                                                                | Trigger                                                                           | `details`                         | Suggested HTTP                                    |
| --------------------------------------------------------------------- | --------------------------------------------------------------------------------- | --------------------------------- | ------------------------------------------------- |
| [`INVALID_TOKEN`](#invalid_token)                                     | Unknown / malformed token, or access token presented to `refresh()`               | `{ reason?: string }`             | `401 Unauthorized`                                |
| [`TOKEN_EXPIRED`](#token_expired)                                     | Reserved (not currently thrown — `validate` collapses to `null` instead)          | —                                 | `401 Unauthorized`                                |
| [`TOKEN_REVOKED`](#token_revoked)                                     | Reserved (not currently thrown — `validate` collapses to `null` instead)          | —                                 | `401 Unauthorized`                                |
| [`REFRESH_REUSE_DETECTED`](#refresh_reuse_detected)                   | Refresh-token reuse after grace (sliding) or any reuse (always)                   | `{ userId, parentCredentialId? }` | `401 Unauthorized`, clear cookies, force re-login |
| [`STATELESS_OPERATION_UNSUPPORTED`](#stateless_operation_unsupported) | `revoke` / `consume` / `update` on JWT or Encapsulated store without a `denylist` | `{ operation, store }`            | `500 Internal Server Error`                       |
| [`MAX_CONCURRENT_REACHED`](#max_concurrent_reached)                   | `issue()` past `maxConcurrent`                                                    | `{ userId, max, current }`        | `409 Conflict` or `429 Too Many Requests`         |
| [`INVALID_CONFIG`](#invalid_config)                                   | Construction-time misconfiguration                                                | `{ option, reason }`              | `500 Internal Server Error`                       |

The rest of this page details each type.

## `INVALID_TOKEN`

The token presented to `refresh()` is unknown, malformed, or of the wrong kind.

**Triggers**

- `refresh(refreshToken)` where `refreshToken` doesn't exist in the store or has expired.
- `refresh(accessToken)` — passing an access token (`kind: 'access'`) to the refresh endpoint.
- Malformed string that can't be decoded (e.g. truncated JWT, base64url with invalid padding).

**`details`**

```ts
{ reason?: 'unknown' | 'wrong-kind' | 'malformed' }
```

**Why it's only on `refresh`**

`validate()` deliberately collapses every failure to `null` — it's a hot-path Boolean gate. `refresh()` throws because the caller (login form, mobile client) needs to distinguish "your refresh token is bad" from "your refresh token leaked and triggered a reuse detection". The former is `INVALID_TOKEN`; the latter is `REFRESH_REUSE_DETECTED`.

**HTTP mapping**

```
401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token"
```

Clear the cookie and prompt re-login. Don't reveal which sub-reason ("unknown" vs "malformed") — that's a server-side log detail.

## `TOKEN_EXPIRED`

Reserved. `validate()` returns `null` for expired tokens; `refresh()` returns `INVALID_TOKEN` for expired refresh tokens. This variant exists in the type union for future use (e.g. a strict mode that distinguishes "expired" from "unknown") but is not currently thrown by any code path.

Don't write code that depends on receiving this type — handle it identically to `INVALID_TOKEN` if you catch it at all.

## `TOKEN_REVOKED`

Reserved. Same status as `TOKEN_EXPIRED` — `validate()` returns `null`, `refresh()` throws `INVALID_TOKEN`. Reserved for future strict modes.

## `REFRESH_REUSE_DETECTED`

A refresh token was reused after its grace window (sliding mode) or after any prior use (always mode). The orchestrator interprets this as either token theft or a client bug; either way, the entire user is logged out.

**Triggers**

- `rotation: 'always'`: any second call with the same refresh token.
- `rotation: 'sliding'`: a second call outside `rotationGraceMs`.

**Side effects that fire _before_ the throw**

1. `onRotationReuse(state)` hook is called with the offending `CredentialState`.
2. `revokeAllForUser(state.userId)` is invoked. Every access and refresh credential for that user is dead.

**`details`**

```ts
{
  userId: string;
  parentCredentialId?: string;   // the original refresh that was reused
}
```

**HTTP mapping**

```
401 Unauthorized
```

Clear all cookies for the auth domain. Redirect to login. Surface a clear message — "for your security, all sessions were ended" — and **don't blame the user**. The most common cause is a token leak; the second is a buggy retry on the client.

```ts
catch (e) {
  if (e instanceof AuthError && e.type === 'REFRESH_REUSE_DETECTED') {
    res.clearCookie('access').clearCookie('refresh');
    res.redirect(`/login?reason=session-ended`);
    return;
  }
}
```

::: tip Log every reuse event
Wire the `onRotationReuse` hook to your audit log. The pattern of reuse events — IP, user agent, time of day — is signal you want to retain even after the user re-logs in.
:::

## `STATELESS_OPERATION_UNSUPPORTED`

You called `revoke`, `consume`, or `update` on a stateless store (`CredentialStoreJwt`, `CredentialStoreEncapsulated`) that wasn't given a `DenylistStore`.

**Triggers**

| Operation              | When it throws                                                              |
| ---------------------- | --------------------------------------------------------------------------- |
| `revoke(token)`        | Stateless store, no denylist.                                               |
| `consume(token)`       | Stateless store, no denylist. (Also breaks magic links and password reset.) |
| `update(token, state)` | Stateless store, no denylist (the previous token must be invalidated).      |

`persist`, `retrieve`, and `revokeAllForUser` never throw this — they work without a denylist (using the in-memory epoch map for `revokeAllForUser`).

**`details`**

```ts
{
  operation: "revoke" | "consume" | "update";
  store: "jwt" | "encapsulated";
}
```

**HTTP mapping**

```
500 Internal Server Error
```

This is a server misconfiguration, not a client error. Catch it at the framework boundary, log loudly, return a generic 500. The fix is to pass a `denylist` to the store at construction.

```ts
new CredentialStoreJwt({
  secret: process.env.JWT_SECRET!,
  denylist: new DenylistStoreRedis({ redis }), // ← required for revoke/consume/update
});
```

See [Stores](./stores) for the denylist options.

## `MAX_CONCURRENT_REACHED`

`issue()` was called but the user already has `maxConcurrent` live access credentials.

**Triggers**

- `auth.issue(userId, ...)` when `await store.listForUser(userId).filter(kind === 'access').length >= maxConcurrent`.

Only fires on stateful stores — stateless stores can't enumerate, so `maxConcurrent` is silently a no-op there (see the [Refresh page](./refresh#counting-and-stateless-stores)).

**`details`**

```ts
{
  userId: string;
  max: number;
  current: number;
}
```

**HTTP mapping**

The right status depends on policy:

| `onLimit`      | Recommended status      | Body                                                                    |
| -------------- | ----------------------- | ----------------------------------------------------------------------- |
| `'reject'`     | `429 Too Many Requests` | `{ kind: 'maxConcurrent', max, current }`                               |
| `'kickPrompt'` | `409 Conflict`          | `{ kind: 'maxConcurrent', max, current, sessions: <listForUser data> }` |

`'kickPrompt'` is a hint to the framework integration to surface a "pick a device to kick" UI. The error type is the same; the difference is in handling.

```ts
catch (e) {
  if (e instanceof AuthError && e.type === 'MAX_CONCURRENT_REACHED') {
    const sessions = await auth.listForUser(e.details!.userId as string);
    return res.status(409).json({
      kind: 'maxConcurrent',
      max: e.details!.max,
      current: e.details!.current,
      sessions: sessions.map(s => ({ credentialId: s.credentialId, label: /* … */ })),
    });
  }
}
```

The framework then prompts the user, calls `auth.revoke(theirChoice.credentialId)` (or its source token), and retries the `issue`.

## `INVALID_CONFIG`

The orchestrator or a store was constructed with bad options. This always throws at construction time, before any request hits.

**Triggers**

| Trigger                               | Where                                                                         |
| ------------------------------------- | ----------------------------------------------------------------------------- |
| `accessTtl <= 0`                      | `new AuthCredential({ accessTtl: 0 })`                                        |
| `accessTtl < 0`                       | `new AuthCredential({ accessTtl: -1 })`                                       |
| Missing HS secret                     | `new CredentialStoreJwt({ algorithm: 'HS256' })` (no `secret`)                |
| Missing key pair                      | `new CredentialStoreJwt({ algorithm: 'RS256', privateKey })` (no `publicKey`) |
| Dead row on `persist` (Redis adapter) | `store.persist({ ..., expiresAt: now - 1 })`                                  |

**`details`**

```ts
{
  option: string; // e.g. 'accessTtl', 'secret', 'privateKey', 'expiresAt'
  reason: string; // human-readable
}
```

**HTTP mapping**

```
500 Internal Server Error
```

These errors should never surface to a user — they're caught by `npm test` before deploy. If one _does_ reach production, log loudly and page on-call. The fix is always a code change.

## Where errors are vs. aren't thrown

| API                          | Throws                                                                       | Returns `null`           |
| ---------------------------- | ---------------------------------------------------------------------------- | ------------------------ |
| `validate(token)`            | Never (except programmer errors)                                             | Every failure mode       |
| `issue(userId, ...)`         | `MAX_CONCURRENT_REACHED`, `INVALID_CONFIG`                                   | —                        |
| `refresh(token)`             | `INVALID_TOKEN`, `REFRESH_REUSE_DETECTED`, `STATELESS_OPERATION_UNSUPPORTED` | —                        |
| `revoke(token)`              | `STATELESS_OPERATION_UNSUPPORTED`                                            | —                        |
| `revokeAllForUser(id)`       | Never                                                                        | —                        |
| `listForUser(id)`            | Never                                                                        | Empty array on stateless |
| `store.persist(state)`       | `INVALID_CONFIG` (Redis adapter, dead state)                                 | —                        |
| `store.retrieve(token)`      | Never                                                                        | Every failure mode       |
| `store.consume(token)`       | `STATELESS_OPERATION_UNSUPPORTED`                                            | If no state              |
| `store.update(token, state)` | `STATELESS_OPERATION_UNSUPPORTED`, `INVALID_CONFIG`                          | —                        |

The dividing line: **validation paths return `null`** (hot path, can't afford exception overhead), **mutation paths throw**.

## Idiomatic handling

A single catch at the framework boundary covers everything:

```ts
function toHttp(e: unknown): { status: number; body: object } {
  if (!(e instanceof AuthError)) return { status: 500, body: { error: "server_error" } };
  switch (e.type) {
    case "INVALID_TOKEN":
    case "REFRESH_REUSE_DETECTED":
      return { status: 401, body: { error: "invalid_token", type: e.type } };
    case "MAX_CONCURRENT_REACHED":
      return { status: 409, body: { error: "max_concurrent", ...e.details } };
    case "STATELESS_OPERATION_UNSUPPORTED":
    case "INVALID_CONFIG":
      // server-side bugs — log and 500
      logger.error({ err: e }, "auth misconfiguration");
      return { status: 500, body: { error: "server_error" } };
    default:
      return { status: 500, body: { error: "server_error" } };
  }
}
```

`@aoothjs/auth-moost` does this for you — see [Moost — AuthGuard & useAuth](../moost/auth-guard).

## See also

- [Credentials & Sessions](./credentials) — which methods throw which errors.
- [Refresh](./refresh) — the rotation modes that fire `REFRESH_REUSE_DETECTED`.
- [Stores](./stores) — `STATELESS_OPERATION_UNSUPPORTED` and how denylists fix it.
- Source: [packages/auth/src/errors.ts](https://github.com/moostjs/aoothjs/blob/main/packages/auth/src/errors.ts).
