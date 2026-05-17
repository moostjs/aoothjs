# Refresh & Rotation

`RefreshConfig` opts the orchestrator into refresh tokens and controls the rotation strategy. This page covers all three modes, the grace window, reuse detection, and the per-user revocation cascade.

## The shape

```ts
interface RefreshConfig {
  ttl: number; // ms
  rotation?: "none" | "always" | "sliding"; // default 'sliding'
  rotationGraceMs?: number; // default 30_000
  onRotationReuse?: (state: CredentialState) => void;
}
```

| Option            | Default     | Purpose                                                                                         |
| ----------------- | ----------- | ----------------------------------------------------------------------------------------------- |
| `ttl`             | (required)  | Lifetime of refresh tokens, ms.                                                                 |
| `rotation`        | `'sliding'` | Rotation strategy — see [the three modes](#the-three-modes).                                    |
| `rotationGraceMs` | `30_000`    | Sliding mode only — window after rotation during which the old refresh remains valid.           |
| `onRotationReuse` | `undefined` | Hook called when reuse is detected after the grace window. Fires _before_ the user-wide revoke. |

The minimum opt-in:

```ts
const auth = new AuthCredential({
  store: new CredentialStoreMemory(),
  accessTtl: 15 * 60 * 1000,
  refresh: { ttl: 30 * 24 * 3600 * 1000 }, // sliding by default
});
```

## The three modes

| Mode                  | Old refresh after success              | Reuse handling                                                    | Typical use                             |
| --------------------- | -------------------------------------- | ----------------------------------------------------------------- | --------------------------------------- |
| `'none'`              | Stays usable until TTL                 | No reuse detection                                                | Long-lived API keys, no rotation policy |
| `'always'`            | `consume`d (single-use)                | Any reuse → `REFRESH_REUSE_DETECTED` + user-wide revoke           | Strict rotation, stateless deployments  |
| `'sliding'` (default) | Valid for `rotationGraceMs`, then dead | Reuse _after grace_ → `REFRESH_REUSE_DETECTED` + user-wide revoke | Browsers with parallel tabs / retries   |

### `'none'` — no rotation

`refresh()` issues a new access token. The refresh token stays in place until its TTL.

**Timeline**:

```
  t=0     issue()  →  access_a, refresh_r   (both fresh)
  t=10m   refresh(refresh_r)  →  access_b  (refresh_r still valid)
  t=20m   refresh(refresh_r)  →  access_c  (refresh_r still valid)
  t=30d   refresh(refresh_r)  →  AuthError('INVALID_TOKEN')  (refresh expired)
```

**Choose when** — the refresh token is intended as a long-lived secret (API key), or rotation overhead is unacceptable. No reuse detection — a leaked refresh token is exploitable until it expires.

### `'always'` — rotate every time

Every successful `refresh()` consumes the old refresh and issues a new one. Reuse is detected immediately.

**Timeline (happy path)**:

```
  t=0     issue()  →  access_a, refresh_r1
  t=10m   refresh(refresh_r1)  →  access_b, refresh_r2   (r1 consumed)
  t=20m   refresh(refresh_r2)  →  access_c, refresh_r3   (r2 consumed)
```

**Timeline (reuse)**:

```
  t=0     issue()  →  access_a, refresh_r1
  t=10m   refresh(refresh_r1)  →  access_b, refresh_r2   (r1 consumed)
  t=11m   refresh(refresh_r1)  →  AuthError('REFRESH_REUSE_DETECTED')
                                 → onRotationReuse(state) called
                                 → revokeAllForUser(state.userId)
```

**Choose when** — strict per-request rotation matters more than tolerating brief client races. Pairs well with stateless stores (see the warning below).

### `'sliding'` — rotate with grace window

The default. The first `refresh()` marks the old token's `rotatedAt`; the old token remains valid for `rotationGraceMs`. After that window, presenting it is treated as reuse.

**Timeline (happy path)**:

```
  t=0      issue()  →  access_a, refresh_r1
  t=10m    refresh(refresh_r1)  →  access_b, refresh_r2
                                 → r1.rotatedAt = clock.now()
  t=10m+5s refresh(refresh_r1)  →  access_b', refresh_r2'   (within grace — OK)
  t=10m+35s refresh(refresh_r1) →  AuthError('REFRESH_REUSE_DETECTED')
                                 → revokeAllForUser
```

**Why the grace window** — real browsers race. A user double-taps "refresh", a service worker retries, two tabs both notice the access token is stale and call `refresh()` simultaneously. With `'always'`, the second call always loses; with `'sliding'`, both succeed inside the window. The first wins the rotation lottery; the second gets a fresh access token without invalidating anything.

**Choose when** — browsers are involved. Default for a reason.

::: warning Stateless + `'sliding'` silently degrades
On stateless stores (JWT, Encapsulated), the `rotatedAt` marker can't be written back to the token after issue. The store treats the first use after issue as the rotation and any subsequent use as reuse — effectively `'always'`-once-the-first-rotation-happens, but without the grace window doing its job.

If you're running stateless **use `rotation: 'always'` explicitly**. The intent matches the actual behavior, and the rotation timeline becomes predictable.

```ts
const auth = new AuthCredential({
  store: new CredentialStoreJwt({ /* ... */, denylist }),
  accessTtl: 5 * 60 * 1000,
  refresh: {
    ttl: 7 * 24 * 3600 * 1000,
    rotation: 'always',   // not 'sliding' on stateless
  },
});
```

:::

## Reuse detection

When the orchestrator detects a refresh-token reuse, three things happen, in order:

1. `onRotationReuse(state)` is called (if configured) — `state` is the offending `CredentialState` (the _original_, not the rotation).
2. `auth.revokeAllForUser(state.userId)` — every access _and_ refresh credential for that user is revoked.
3. `AuthError('REFRESH_REUSE_DETECTED')` is thrown with `details: { userId, parentCredentialId? }`.

**The reasoning**: a reused refresh token is taken to mean either (a) a token leak — the attacker and the legitimate user are both calling `refresh()` — or (b) a client bug. In either case, the safe response is to log every device of that user out and force a fresh login.

**Hook example** — alerting:

```ts
const auth = new AuthCredential({
  store,
  accessTtl: 15 * 60 * 1000,
  refresh: {
    ttl: 30 * 24 * 3600 * 1000,
    rotation: "sliding",
    onRotationReuse: (state) => {
      log.warn({ userId: state.userId }, "refresh reuse detected; revoking all sessions");
      audit.record({ kind: "refresh-reuse", userId: state.userId });
    },
  },
});
```

The hook fires synchronously before the revoke. It's a notification, not a veto — you cannot prevent the revoke from this hook.

::: tip Log the reuse, surface a clear UX
After `REFRESH_REUSE_DETECTED`, the user is logged out everywhere. Show a clean message at login that explains why ("for your security, all sessions were ended"). Avoid blaming the user.
:::

## The per-user revocation epoch

`revokeAllForUser` works differently across store types:

| Store kind | Mechanism                                                                             |
| ---------- | ------------------------------------------------------------------------------------- |
| Stateful   | `deleteMany({ userId })` — actual rows removed.                                       |
| Stateless  | `epochs[userId] = clock.now()` — gate every future `retrieve` against this timestamp. |

The stateless gate is: `validate` rejects any token whose `iatMs` is less than the epoch.

```
   token.iatMs < epoch[token.sub]   →  null  (rejected)
   token.iatMs >= epoch[token.sub]  →  pass through
```

Note the **`>=`** — not `>`. This is load-bearing.

### Why `>=` matters

The same-millisecond `>=` gate lets a workflow `revokeAllForUser(userId)` and **then immediately** `issue(userId, ...)` in the same millisecond, and have the newly-issued credential survive the gate. Without this, the recovery workflow would have to sleep 1ms between the revoke and the issue.

Concretely — password reset auto-login:

```ts
async function resetPassword(userId, newPassword) {
  await users.password.changeFor(userId, newPassword);
  await auth.revokeAllForUser(userId); // bumps epoch to now
  const { accessToken } = await auth.issue(userId, {
    /* ... */
  });
  // newly-issued token has iatMs >= epoch → survives the gate
  return accessToken;
}
```

::: warning Don't widen the gate
The `>=` is the minimum width needed for same-ms re-issue. Do not change this to `>` in custom store implementations — recovery, password reset, and "kick other devices then log in here" all depend on the equality.
:::

## `maxConcurrent` and refresh tokens

`maxConcurrent` enforces a cap on **access** credentials only. Refresh tokens never count toward the limit.

```ts
const auth = new AuthCredential({
  store: new CredentialStoreMemory(),
  accessTtl: 15 * 60 * 1000,
  refresh: { ttl: 30 * 24 * 3600 * 1000, rotation: "always" },
  maxConcurrent: 3,
  onLimit: "reject",
});

// Three logins on three devices — fine.
await auth.issue("alice", {
  /* ... */
});
await auth.issue("alice", {
  /* ... */
});
await auth.issue("alice", {
  /* ... */
});

// Fourth login on a fourth device — rejected.
await auth.issue("alice", {
  /* ... */
});
// AuthError('MAX_CONCURRENT_REACHED', { userId: 'alice', max: 3, current: 3 })
```

### `onLimit` strategies

| Strategy             | Behavior                                                                                                             | Use case                                                  |
| -------------------- | -------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| `'reject'` (default) | Throws `MAX_CONCURRENT_REACHED`. Caller must handle.                                                                 | Strict cap — third device on a Pro plan, fourth rejected. |
| `'kickPrompt'`       | Throws `MAX_CONCURRENT_REACHED`. Framework integrations treat this as a hint to render a "pick a device to kick" UI. | Free plan — let the user choose.                          |

Both throw the same error type. The difference is intent — `'kickPrompt'` tells `@aoothjs/auth-moost` to surface a chooser before retrying with a `revoke()`. See the [moost workflows](../moost/workflows) page.

### Counting and stateless stores

The `current` count uses `store.listForUser(userId)`. Stateless stores can't enumerate, so:

| Store                     | `maxConcurrent` enforced? |
| ------------------------- | ------------------------- |
| Memory, Redis, AtscriptDb | Yes                       |
| Jwt, Encapsulated         | No — silently a no-op     |

If you need `maxConcurrent` on JWT, run the JWT store alongside a stateful index keyed by `credentialId`, and call `listForUser` against the index — or simply pick a stateful store.

## Patterns

### Stateful + `'sliding'` (most apps)

```ts
const auth = new AuthCredential({
  store: new CredentialStoreAtscriptDb({ table }),
  accessTtl: 15 * 60 * 1000,
  refresh: {
    ttl: 30 * 24 * 3600 * 1000,
    rotation: "sliding",
    rotationGraceMs: 30_000,
    onRotationReuse: (s) => log.warn("reuse", s.userId),
  },
  maxConcurrent: 10,
});
```

### Stateless + `'always'` (high-fan-out API)

```ts
const auth = new AuthCredential({
  store: new CredentialStoreJwt({
    algorithm: "EdDSA",
    privateKey,
    publicKey,
    denylist: new DenylistStoreRedis({ redis }),
  }),
  accessTtl: 5 * 60 * 1000,
  refresh: {
    ttl: 7 * 24 * 3600 * 1000,
    rotation: "always", // explicit — not 'sliding'
    onRotationReuse: (s) => audit.record({ kind: "reuse", userId: s.userId }),
  },
});
```

### No rotation (long-lived API tokens)

```ts
const auth = new AuthCredential({
  store: new CredentialStoreAtscriptDb({ table }),
  accessTtl: 24 * 3600 * 1000,
  refresh: {
    ttl: 365 * 24 * 3600 * 1000,
    rotation: "none",
  },
});
```

Reuse detection is disabled in `'none'` mode — a leaked refresh stays exploitable until TTL. Use only when you have other mitigations (IP allowlist, mTLS, etc).

## Error mapping at the HTTP edge

| Error                             | Suggested HTTP status                                                                           |
| --------------------------------- | ----------------------------------------------------------------------------------------------- |
| `INVALID_TOKEN`                   | `401 Unauthorized`                                                                              |
| `REFRESH_REUSE_DETECTED`          | `401 Unauthorized`, clear all cookies, redirect to login with a "logged out everywhere" message |
| `STATELESS_OPERATION_UNSUPPORTED` | `500 Internal Server Error` — server misconfiguration                                           |
| `MAX_CONCURRENT_REACHED`          | `429 Too Many Requests` or `409 Conflict`, plus a body shape the client recognises              |

See [Errors](./errors) for the full table.

## See also

- [Credentials & Sessions](./credentials) — the orchestrator that wraps refresh logic.
- [Tokens (JWT)](./tokens) — why stateless `'sliding'` degrades.
- [Stores](./stores) — `DenylistStore` implementations for stateless rotation.
- The refresh logic source at [packages/auth/src/auth-credential.ts](https://github.com/moostjs/aoothjs/blob/main/packages/auth/src/auth-credential.ts).
