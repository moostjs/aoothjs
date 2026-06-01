# Refresh & rotation

Reference for `RefreshConfig`, the three rotation modes, refresh-reuse detection ("theft response"), concurrency limits, and per-user revocation epochs. The orchestrator (`AuthCredential`) implements rotation; stores implement durability.

## Contents

- [`RefreshConfig`](#refreshconfig)
- [Rotation modes](#rotation-modes)
- [Refresh reuse detection](#refresh-reuse-detection)
- [Stateless degradation](#stateless-degradation)
- [Concurrency limits](#concurrency-limits)
- [`revokeAllForUser` cascade](#revokeallforuser-cascade)
- [Per-user epoch (stateless)](#per-user-epoch-stateless)

## `RefreshConfig`

```ts
interface RefreshConfig {
  ttl: number; // ms; >0 required
  rotation?: "none" | "always" | "sliding"; // default 'sliding'
  rotationGraceMs?: number; // default 30_000
  onRotationReuse?: (state: CredentialState) => void;
}
```

Omitting `refresh` from `AuthCredentialOptions` disables refresh entirely — `auth.refresh()` throws `AuthError('INVALID_CONFIG', 'Refresh not enabled')`. `refresh.ttl <= 0` throws `INVALID_CONFIG` at construction.

`onRotationReuse` runs **before** the user-wide cascade — log / page / quarantine in the hook, then let `revokeAllForUser` complete.

## Rotation modes

### `'none'`

The refresh token never changes. Each call to `auth.refresh()` mints a fresh access token; the refresh token in the response is the same one you passed in. Simple — no reuse detection possible.

```
issue       →  A1 + R1
refresh R1  →  A2 + R1
refresh R1  →  A3 + R1
…
```

Use when refresh tokens are stored in a secure server-side bag (Moost session cookie, native keychain) and reuse is effectively impossible.

### `'always'`

Single-use refresh. Every `auth.refresh()` consumes the old token and mints both a fresh access and a fresh refresh. Reuse of the consumed token triggers theft response.

```
issue       →  A1 + R1
refresh R1  →  A2 + R2   (R1 now invalid)
refresh R2  →  A3 + R3
refresh R1  →  REFRESH_REUSE_DETECTED  →  revokeAllForUser(uid)
```

Behavior: when a previously-valid refresh token is presented after it has already been consumed/rotated, the orchestrator distinguishes that from "unknown token" and throws `REFRESH_REUSE_DETECTED` (firing the per-user revocation cascade), rather than the generic `INVALID_TOKEN`.

### `'sliding'` (default)

Graceful rotation. The first `refresh` rotates and marks `rotatedAt = now` on the old refresh state. The old refresh remains usable for `rotationGraceMs` (default 30 s) — concurrent requests racing through a token rotation don't both fail. After grace, replay triggers theft response.

```
t=0     issue       →  A1 + R1
t=100   refresh R1  →  A2 + R2          (R1.rotatedAt = 100, still valid until 100+30_000)
t=200   refresh R1  →  A3 + R3          (within grace; no re-rotation)
t=31000 refresh R1  →  REFRESH_REUSE_DETECTED  (after grace → cascade)
```

Tunables:

- `rotationGraceMs: 0` collapses sliding to "always-once": rotation happens on first use, any further use trips reuse.
- The grace window is anchored to the original rotation: replays within the window return a fresh access token but do not re-rotate or extend the window.

Every rotated pair inherits `claims`, `metadata`, and **`sessionId`** from its predecessor — so N refreshes stay one session (the token-family invariant the [sessions.md](sessions.md) APIs rely on). With `trackLastSeen: 'refresh'`, rotation also stamps `lastSeenAt`.

## Refresh reuse detection

Triggered by `'always'` (any reuse) and `'sliding'` (reuse after grace). Sequence:

1. `refreshConfig.onRotationReuse?.(state)` — synchronous hook for audit-log / alert.
2. `store.revokeAllForUser(userId)` — cascade. Returns count (stateful) or sentinel `1` (stateless).
3. `consumedRefreshes.delete(token)` for `'always'` mode.
4. `throw new AuthError('REFRESH_REUSE_DETECTED', undefined, { userId, rotatedAt? })`.

The cascade revokes **both** `kind: 'access'` and `kind: 'refresh'` credentials for the user. Every existing access token will fail validation on next use.

## Stateless degradation

`'sliding'` requires the store to mutate an issued token's state in place (set `rotatedAt`). JWT and Encapsulated tokens are immutable once minted — `store.update` on those re-issues a different token instead. Concrete consequence:

```
t=0   issue       →  A1 + R1                     (JWT)
t=100 refresh R1  →  A2 + R2; R1.jti added to denylist; R1.rotatedAt is "lost"
t=200 refresh R1  →  store.retrieve(R1) returns null (denylist hit)
                   →  consumedRefreshes lookup misses (sliding never wrote)
                   →  AuthError('INVALID_TOKEN')   — NOT REUSE_DETECTED
```

The grace window is unreachable. The reuse signal is also lost (no `consumedRefreshes` entry under sliding). **Use `rotation: 'always'` explicitly for stateless deployments.** `'always'` keeps the `consumedRefreshes` map populated and detects theft cleanly.

## Concurrency limits

```ts
new AuthCredential({
  store,
  maxConcurrent: 3,
  onLimit: "reject", // default 'reject' | 'evict-oldest'
});
```

- Only `kind: 'access'` credentials count. Refresh tokens are excluded.
- Requires `store.listForUser` — `CredentialStoreMemory`, `Redis`, `AtscriptDb` support it. JWT / Encapsulated do not (`listForUser` is undefined), so `maxConcurrent` is a no-op on stateless stores.
- `onLimit: 'reject'` throws `AuthError('MAX_CONCURRENT_REACHED', undefined, { userId, limit, active })` on `issue`.
- `onLimit: 'evict-oldest'` revokes credentials with the smallest `issuedAt` until `active < maxConcurrent`, then proceeds.

## `revokeAllForUser` cascade

Single method, every-kind effect.

| Store                         | Mechanism                                                                       | Return                        |
| ----------------------------- | ------------------------------------------------------------------------------- | ----------------------------- |
| `CredentialStoreMemory`       | Iterates `userTokenIndex.get(userId)`, deletes each `tokens.Map` entry          | Count of deleted entries      |
| `CredentialStoreRedis`        | `SMEMBERS` user index, `DEL` each token key, `SREM` revoked tokens from the set | Count of deleted token keys   |
| `CredentialStoreAtscriptDb`   | `deleteMany({ userId })` — one round trip                                       | `deletedCount`                |
| `CredentialStoreJwt`          | Sets `epochs[userId] = clock.now()` — in-memory map                             | Sentinel `1` ("epoch bumped") |
| `CredentialStoreEncapsulated` | Sets `epochs[userId] = clock.now()` — in-memory map                             | Sentinel `1` ("epoch bumped") |

The orchestrator calls this in three places: (a) explicit `auth.revokeAllForUser(uid)`, (b) refresh-reuse theft response, and (c) workflow integrations (recovery / invite finalize) — after a password change every existing token must be revoked.

## Per-user epoch (stateless)

JWT / Encapsulated stores carry a `Map<userId, epochMs>` in memory:

```ts
// CredentialStoreJwt.passesEpoch
const epoch = this.epochs.get(payload.sub);
if (epoch === undefined) return true;
return iatMs >= epoch;
```

Critical detail: **the gate is `>=`, not `>`**. A `revokeAllForUser` followed by `issue` in the same millisecond produces a token that passes the gate. This is load-bearing for recovery / invite auto-login — the workflow revokes the old session and immediately issues a fresh one for the just-set password, all inside one tick.

Caveats:

- **Resets on process restart.** Multi-pod deployments lose the epoch on rollout. For durable per-user revocation, back the same machinery with `CredentialStoreRedis` / `CredentialStoreAtscriptDb` — both implement `revokeAllForUser` via real deletion, not an in-memory map.
- **Not shared across instances.** A `revokeAllForUser` call on pod A doesn't propagate to pod B's `epochs` map. Mitigation: keep `accessTtl` short (≤15 min) so re-issue on the new pod re-anchors above the old token's `iat`.
- **`'>'` would break recovery flows.** If you ever need stronger semantics (post-password-change tokens must be strictly newer), use a stateful store — the `>=` choice is intentional, not a bug.
