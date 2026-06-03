# Refresh & Rotation

`RefreshConfig` opts the orchestrator into refresh tokens and controls the rotation strategy. This page covers all three modes, the grace window, reuse detection, and the per-user revocation cascade.

## The shape

```ts
interface RefreshConfig {
  ttl: number; // ms
  rotation?: "none" | "always" | "sliding"; // default 'sliding'
  rotationGraceMs?: number; // default 30_000
  reuseResponse?: "session" | "user"; // default 'session'
  onRotationReuse?: (state: CredentialState) => void;
}
```

| Option            | Default     | Purpose                                                                                                              |
| ----------------- | ----------- | -------------------------------------------------------------------------------------------------------------------- |
| `ttl`             | (required)  | Lifetime of refresh tokens, ms.                                                                                      |
| `rotation`        | `'sliding'` | Rotation strategy — see [the three modes](#the-three-modes).                                                         |
| `rotationGraceMs` | `30_000`    | `sliding` **and** `always` — window after rotation during which the old refresh stays replay-valid.                  |
| `reuseResponse`   | `'session'` | Blast radius on detected reuse: the compromised token family (`'session'`) or every session for the user (`'user'`). |
| `onRotationReuse` | `undefined` | Hook called when reuse is detected. Fires _before_ the revoke.                                                       |

The minimum opt-in:

```ts
const auth = new AuthCredential({
  store: new CredentialStoreMemory(),
  accessTtl: 15 * 60 * 1000,
  refresh: { ttl: 30 * 24 * 3600 * 1000 }, // sliding by default
});
```

## The three modes

| Mode                  | Refresh expiry           | Old refresh after success (stateful)   | Reuse handling                                                 | Typical use                             |
| --------------------- | ------------------------ | -------------------------------------- | -------------------------------------------------------------- | --------------------------------------- |
| `'none'`              | unchanged                | Stays usable until TTL                 | No reuse detection                                             | Long-lived API keys, no rotation policy |
| `'always'`            | **fixed** ceiling        | Valid for `rotationGraceMs`, then dead | Reuse _after grace_ → `REFRESH_REUSE_DETECTED` + family revoke | Rotation with an absolute session cap   |
| `'sliding'` (default) | **slides** (`now + ttl`) | Valid for `rotationGraceMs`, then dead | Reuse _after grace_ → `REFRESH_REUSE_DETECTED` + family revoke | Browsers with parallel tabs / retries   |

`'always'` and `'sliding'` differ only in **expiry**: `'sliding'` is a rolling session (each refresh pushes the expiry to `now + ttl`); `'always'` keeps the family's original expiry as a fixed ceiling, so the session has an absolute maximum lifetime regardless of activity. Both rotate the token on every refresh and **both are grace-tolerant** on stateful stores (a benign concurrent refresh within `rotationGraceMs` is not mistaken for theft — see [the grace window](#the-grace-window-and-concurrency)). On stateless stores neither can keep the old token valid, so both fall back to single-use semantics with a process-local reuse signal.

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

### `'always'` — rotate every time, fixed session ceiling

Every successful `refresh()` rotates the refresh token, but each rotated token inherits the family's **original** `expiresAt` — the session has an absolute maximum lifetime no matter how often it refreshes. On a stateful store it shares the same grace window as `'sliding'`, so a benign concurrent refresh within `rotationGraceMs` is not mistaken for theft.

**Timeline (happy path)** — note the fixed expiry:

```
  t=0     issue()  →  access_a, refresh_r1   (refresh expires at t=30d)
  t=10m   refresh(refresh_r1)  →  access_b, refresh_r2   (still expires at t=30d)
  t=20m   refresh(refresh_r2)  →  access_c, refresh_r3   (still expires at t=30d)
  t=30d   refresh(refresh_rN)  →  AuthError('INVALID_TOKEN')  (ceiling reached)
```

**Timeline (reuse after grace)**:

```
  t=0      issue()  →  access_a, refresh_r1
  t=10m    refresh(refresh_r1)  →  access_b, refresh_r2   (r1.rotatedAt set)
  t=10m+5s refresh(refresh_r1)  →  access_b', refresh_r2'   (within grace — OK)
  t=10m+35s refresh(refresh_r1) →  AuthError('REFRESH_REUSE_DETECTED')
                                 → onRotationReuse(state) called
                                 → revokeSession(userId, sessionId)   (family only, by default)
```

**Choose when** — you want token rotation but a hard cap on how long a session can live (high-security, compliance-driven absolute timeouts). For a rolling "stay logged in while active" session, use `'sliding'`.

### `'sliding'` — rotate with grace window

The default. The first `refresh()` marks the old token's `rotatedAt`; the old token remains valid for `rotationGraceMs`. After that window, presenting it is treated as reuse.

**Timeline (happy path)**:

```
  t=0      issue()  →  access_a, refresh_r1
  t=10m    refresh(refresh_r1)  →  access_b, refresh_r2
                                 → r1.rotatedAt = clock.now()
  t=10m+5s refresh(refresh_r1)  →  access_b', refresh_r2'   (within grace — OK)
  t=10m+35s refresh(refresh_r1) →  AuthError('REFRESH_REUSE_DETECTED')
                                 → revokeSession(userId, sessionId)   (family only, by default)
```

#### The grace window and concurrency

**Why the grace window** — real browsers race. A user double-taps "refresh", a service worker retries, two tabs both notice the access token is stale and call `refresh()` simultaneously. Both `'sliding'` and `'always'` keep the just-rotated token replay-valid for `rotationGraceMs`, so the second call succeeds with a fresh pair instead of being mistaken for theft. The window is tracked in the store (`rotatedAt`), so it holds **across multiple app instances** — a refresh on instance A and a concurrent replay on instance B both land inside the window. Without it, any concurrency on a multi-instance deployment would trip the theft response and log the user out of every device on a benign race.

**Choose when** — browsers are involved. Default for a reason.

::: warning Stateless stores can't offer the grace window
On stateless stores (JWT, Encapsulated), the `rotatedAt` marker cannot resurface — the orchestrator writes the rotated state via `store.update`, which on stateless stores denylists the old `jti` and re-encodes into a brand-new token. The next presentation of the original refresh therefore looks like "unknown token" to the store (it's denylisted), so the cross-instance grace window cannot apply. Both `'sliding'` and `'always'` fall back to single-use semantics there, with a **process-local** reuse signal: a same-process replay still fires `REFRESH_REUSE_DETECTED`, but a replay that lands on a different instance just returns `INVALID_TOKEN`.

If you're running stateless **use `rotation: 'always'` explicitly** — the single-use intent matches the actual behavior and the rotation timeline becomes predictable.

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

## What rotation carries forward

Each rotated pair inherits the previous credential's `claims`, `metadata`, **and `sessionId`** — so a login stays **one session** across N refreshes (the session-family invariant the [Sessions](./sessions) APIs rely on). `parentCredentialId` chains each rotation to its predecessor for reuse detection (below); `sessionId` is the durable id that survives the whole chain.

With `trackLastSeen: 'refresh'`, each `refresh()` also stamps `lastSeenAt` on the newly-minted credentials — cheap activity tracking that piggybacks the rotation write. See [Sessions](./sessions#activity-tracking-lastseenat).

## Reuse detection

When the orchestrator detects a refresh-token reuse (a presentation after the grace window, or — on stateless stores — a replay of a single-use token), three things happen, in order:

1. `onRotationReuse(state)` is called (if configured) — `state` is the offending `CredentialState` (the _original_, not the rotation).
2. The compromised credentials are revoked per `reuseResponse`:
   - **`'session'` (default)** — `auth.revokeSession(userId, sessionId)` kills only the reused token family (the compromised session). The legitimate user and the attacker share that family, so both are ended; the user's _other_ devices keep working.
   - **`'user'`** — `auth.revokeAllForUser(userId)` revokes every session for the user.
   - When the session can't be targeted (no `sessionId`, or a store that can't enumerate sessions, e.g. stateless), `'session'` falls back to the user-wide cascade so theft is never left un-revoked.
3. `AuthError('REFRESH_REUSE_DETECTED')` is thrown with `details: { userId, sessionId?, rotatedAt? }`.

**The reasoning**: a reused refresh token is taken to mean either (a) a token leak — the attacker and the legitimate user are both calling `refresh()` — or (b) a client bug. The default response ends the compromised session (the OAuth-best-practice token-family revocation) while leaving the user's other devices alone; escalate to `'user'` when any reuse should be treated as a full-account compromise.

**Hook example** — alerting:

```ts
const auth = new AuthCredential({
  store,
  accessTtl: 15 * 60 * 1000,
  refresh: {
    ttl: 30 * 24 * 3600 * 1000,
    rotation: "sliding",
    reuseResponse: "session", // default — or "user" to revoke everything
    onRotationReuse: (state) => {
      log.warn({ userId: state.userId, sessionId: state.sessionId }, "refresh reuse detected");
      audit.record({ kind: "refresh-reuse", userId: state.userId, sessionId: state.sessionId });
    },
  },
});
```

The hook fires synchronously before the revoke. It's a notification, not a veto — you cannot prevent the revoke from this hook.

::: tip Log the reuse, surface a clear UX
After `REFRESH_REUSE_DETECTED`, the affected session (or, with `reuseResponse: 'user'`, every session) is ended. Show a clean message at login that explains why ("for your security, this session was ended"). Avoid blaming the user.
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
// AuthError('MAX_CONCURRENT_REACHED', { userId: 'alice', limit: 3, active: 3 })
```

### `onLimit` strategies

| Strategy             | Behavior                                                                                                                        | Use case                                                  |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| `'reject'` (default) | Throws `MAX_CONCURRENT_REACHED`. Caller must handle.                                                                            | Strict cap — third device on a Pro plan, fourth rejected. |
| `'evict-oldest'`     | Revokes oldest access credentials (by smallest `issuedAt`) until under the cap, then proceeds with the new `issue()`. No throw. | Free plan — silently kick the oldest session.             |

`'reject'` throws `AuthError('MAX_CONCURRENT_REACHED')` with `details: { userId, limit, active }`; `'evict-oldest'` returns the new `IssueResult` after the cascade. To render a "pick a device to kick" UI, use `'reject'` plus `listForUser` + `revoke` in the framework layer.

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

| Error                             | Suggested HTTP status                                                                                                                   |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `INVALID_TOKEN`                   | `401 Unauthorized`                                                                                                                      |
| `REFRESH_REUSE_DETECTED`          | `401 Unauthorized`, clear cookies, redirect to login (the compromised session is ended; with `reuseResponse: 'user'`, every session is) |
| `STATELESS_OPERATION_UNSUPPORTED` | `500 Internal Server Error` — server misconfiguration                                                                                   |
| `MAX_CONCURRENT_REACHED`          | `429 Too Many Requests` or `409 Conflict`, plus a body shape the client recognises                                                      |

See [Errors](./errors) for the full table.

## See also

- [Credentials & Sessions](./credentials) — the orchestrator that wraps refresh logic.
- [Client (Browser Silent Refresh)](./client) — `createAuthedFetch`, the SPA-side wrapper that calls `/auth/refresh` on a 401.
- [Tokens (JWT)](./tokens) — why stateless `'sliding'` degrades.
- [Stores](./stores) — `DenylistStore` implementations for stateless rotation.
- The refresh logic source at [packages/auth/src/auth-credential.ts](https://github.com/moostjs/aoothjs/blob/main/packages/auth/src/auth-credential.ts).
