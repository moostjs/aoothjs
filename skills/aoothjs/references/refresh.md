# Refresh & rotation

Reference for `RefreshConfig`, the three rotation modes, refresh-reuse detection ("theft response"), concurrency limits, and per-user revocation epochs. The orchestrator (`AuthCredential`) implements rotation; stores implement durability.

## Contents

- [`RefreshConfig`](#refreshconfig)
- [Rotation modes](#rotation-modes)
- [Per-mint refresh (`IssueOptions.refresh`)](#per-mint-refresh-issueoptionsrefresh)
- [Refresh reuse detection](#refresh-reuse-detection)
- [Stateless degradation](#stateless-degradation)
- [Concurrency limits](#concurrency-limits)
- [`revokeAllForUser` cascade](#revokeallforuser-cascade)
- [Per-user epoch (stateless)](#per-user-epoch-stateless)

## `RefreshConfig`

| Field                 | Type                               | Default      | Meaning                                                                    |
| --------------------- | ---------------------------------- | ------------ | -------------------------------------------------------------------------- |
| `ttl`                 | `number`                           | — (required) | ms; `> 0` required.                                                        |
| `rotation?`           | `'none' \| 'always' \| 'sliding'`  | `'sliding'`  | See [Rotation modes](#rotation-modes).                                     |
| `rotationGraceMs?`    | `number`                           | `30_000`     | `'sliding'` AND `'always'`; `0` = strict single-use; `< 0` throws at boot. |
| `reuseResponse?`      | `'session' \| 'user'`              | `'session'`  | Theft-response blast radius — see below.                                   |
| `onRotationReuse?`    | `(state: CredentialState) => void` | unset        | Reuse (theft) hook — see below.                                            |
| `onRotationGraceHit?` | `(state: CredentialState) => void` | unset        | Benign within-grace re-delivery hook — audit twin of `onRotationReuse`.    |

Exact shape: [docs api](https://aoothjs.dev/api/auth#refreshconfig).

Omitting `refresh` from `AuthCredentialOptions` disables refresh for ordinary mints — but per-mint families ([below](#per-mint-refresh-issueoptionsrefresh)) still mint and redeem without it; an unknown token then throws `INVALID_TOKEN`, not `INVALID_CONFIG`. `refresh.ttl <= 0` throws `INVALID_CONFIG` at construction.

`onRotationReuse` runs **before** the revoke. `reuseResponse` picks the blast radius: `'session'` (default) revokes only the compromised token family (`revokeSession`); `'user'` revokes every session (`revokeAllForUser`). When the session can't be targeted (no `sessionId`, or a store without `listForUser` such as stateless), `'session'` falls back to the user-wide cascade.

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

Rotate every refresh, but keep a **fixed session ceiling**: each rotated refresh inherits the family's original `expiresAt`, so the session has an absolute maximum lifetime regardless of activity. On a **stateful** store it shares the same grace window as `'sliding'` (a benign re-presentation within `rotationGraceMs` re-delivers the same successor pair, not theft). On a **stateless** store the old token can't be kept valid, so it falls back to single-use (`consume`) with a process-local reuse signal.

```
issue        →  A1 + R1          (R1 expires at the family ceiling)
refresh R1   →  A2 + R2          (R1.rotatedAt + successor set; R2 keeps the SAME ceiling)
refresh R1   →  A2 + R2          (grace hit — SAME pair, nothing minted)   [stateful]
… after grace …
refresh R1   →  REFRESH_REUSE_DETECTED  →  revokeSession(uid, sid)   (family only, default)
```

`'always'` vs `'sliding'` differ only in **expiry**: `'always'` is a fixed ceiling, `'sliding'` slides to `now + ttl`. Both rotate every time and both are grace-tolerant on stateful stores. Choose `'always'` when you need an absolute session timeout (compliance); `'sliding'` for a rolling "stay logged in while active" session.

### `'sliding'` (default)

Rolling rotation. The first `refresh` rotates, marks `rotatedAt = now` on the old refresh state, and pins the successor pair on it; the new refresh expiry slides to `now + ttl`. Within `rotationGraceMs` (default 30 s) a re-presentation of the old refresh **re-delivers that same pair** — concurrent tabs and deploy-clipped retries don't fail AND converge on one live refresh token. The window is **store-backed** (`rotatedAt` + `successor` live in the store), so it holds across multiple app instances. After grace, replay triggers theft response.

```
t=0     issue       →  A1 + R1
t=100   refresh R1  →  A2 + R2          (R1.rotatedAt = 100, successor = A2+R2)
t=200   refresh R1  →  A2 + R2          (grace hit — SAME pair, nothing minted)
t=300   refresh R2  →  A3 + R3          (normal rotation; R1 now superseded → dead)
t=31000 refresh R1  →  REFRESH_REUSE_DETECTED  (after grace → theft response)
```

Grace-window rules (numbered — cite by #):

| #   | Rule                                                                                                                                                                                                              |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | A grace hit is **idempotent re-delivery**: N hits return N identical `RefreshResult`s; nothing is minted. An attacker capturing the old token in-window learns only what the original response would have taught. |
| 2   | No liveness side effects: a grace hit never slides the refresh expiry and never stamps `lastSeenAt` (a captured stale token is not a keep-alive).                                                                 |
| 3   | **Supersession beats the window**: once the successor itself rotates or is revoked (logout), presenting the old token is theft — never a resurrection — even inside the window.                                   |
| 4   | `rotationGraceMs: 0` = strict single-use: rotation on first use, ANY further use trips reuse. Negative throws `INVALID_CONFIG` at boot (per-mint `graceMs < 0` throws at `issue`).                                |
| 5   | `onRotationGraceHit(state)` fires on each grace hit (old row's envelope, incl. `rotatedAt`). Wire it with `onRotationReuse` to one audit sink — deploy-correlated trickle = fine, spike = replay attack.          |
| 6   | Size the window to the redeploy/retry cadence (30–60 s); it stays meaningless for offline token theft.                                                                                                            |

Every rotated pair inherits `claims`, `metadata`, and **`sessionId`** from its predecessor — so N refreshes stay one session (the token-family invariant the [sessions.md](sessions.md) APIs rely on). With `trackLastSeen: 'refresh'`, rotation also stamps `lastSeenAt` (grace hits excluded — rule 2).

## Per-mint refresh (`IssueOptions.refresh`)

Individual mints override the instance posture — the seam the [authorization server's `refresh_token` grant](authorization-server.md) rides:

```ts
await auth.issue("u1", { refresh: false }); // suppress the pair for THIS mint (no orphan refresh row)
await auth.issue("u1", { ttl: 60 * 60_000, refresh: { ttl: 60 * 24 * 3600_000 } }); // per-mint grant
```

| #   | Rule                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | `refresh: false` mints NO refresh token even when the instance config exists. `refresh: { ttl?, graceMs? }` mints one — `ttl` falls back to the instance `refresh.ttl`; with NEITHER, `INVALID_CONFIG`. Works WITHOUT an instance config.                                                                                                                                                                                                        |
| 2   | Per-mint families ALWAYS redeem fixed-ceiling: `issue()` stamps `metadata.refreshRotation: "always"` and `refresh()` honors the stamp OVER the instance rotation — an instance whose sessions rotate `'sliding'` can never extend a per-mint grant's lifetime. Ordinary (unstamped) families keep instance modes.                                                                                                                                |
| 3   | Mint-time authority rides `metadata` across every rotation: `accessTtl` (a per-mint access `ttl` minted alongside a refresh token — refreshed access tokens keep it, never the instance `accessTtl`), `authzClientId` (the OAuth client binding), and `rotationGraceMs` (a per-mint `graceMs` — the family's grace window, honored over the instance `rotationGraceMs`; `0` = strict). All four keys are in `AoothCredentialMetadataBase` (.as). |
| 4   | `refresh(token, { guard })` — the guard sees the stored refresh credential BEFORE any rotation/state change; throwing aborts with the family untouched (the binding-check seam). `refresh()` returns `RefreshResult` = `IssueResult` + `userId` (the caller held only an opaque token).                                                                                                                                                          |
| 5   | `refresh` is a RESERVED `IssueOptions` key (like `ttl`/`kind`/`metadata`) — never a payload field name.                                                                                                                                                                                                                                                                                                                                          |

## Refresh reuse detection

Triggered by reuse **after grace**, by ANY reuse under strict `rotationGraceMs: 0`, or by reuse of a **superseded** token (its successor already rotated/revoked — grace rule 3) on stateful `'always'` / `'sliding'`; on stateless, by replay of a consumed token. Sequence:

1. `refreshConfig.onRotationReuse?.(state)` — synchronous hook for audit-log / alert.
2. Revoke per `reuseResponse`: `'session'` (default) → `revokeSession(userId, sessionId)` (the compromised family only); `'user'` → `revokeAllForUser(userId)`. Falls back to `revokeAllForUser` when `sessionId` is absent or the store can't enumerate (stateless).
3. `consumedRefreshes.delete(token)` for the stateless `'always'` path.
4. `throw new AuthError('REFRESH_REUSE_DETECTED', undefined, { userId, sessionId?, rotatedAt? })`.

`'session'` (the default) revokes both `kind: 'access'` and `kind: 'refresh'` of the **compromised family** — the legitimate user and attacker share it, so both are ended while the user's other devices keep working. `'user'` widens that to every session. The default is the OAuth-best-practice token-family revocation.

## Stateless degradation

`'sliding'` requires the store to mutate an issued token's state in place (set `rotatedAt`). JWT and Encapsulated tokens are immutable once minted — `store.update` on those re-issues a different token instead. Concrete consequence:

```
t=0   issue       →  A1 + R1                     (JWT)
t=100 refresh R1  →  A2 + R2; R1.jti added to denylist; R1.rotatedAt is "lost"
t=200 refresh R1  →  store.retrieve(R1) returns null (denylist hit)
                   →  consumedRefreshes lookup misses (sliding never wrote)
                   →  AuthError('INVALID_TOKEN')   — NOT REUSE_DETECTED
```

The store-backed grace window is unreachable on stateless stores, and the reuse signal is lost under sliding (no `consumedRefreshes` entry). **Use `rotation: 'always'` explicitly for stateless deployments** ([invariants.md](invariants.md) #9). `'always'` keeps the `consumedRefreshes` map populated and detects theft — but that map is **process-local**, so on a multi-instance deployment a replay that lands on a different instance returns `INVALID_TOKEN` rather than `REFRESH_REUSE_DETECTED`. Cross-instance grace + theft detection requires a stateful store (Memory/Redis/AtscriptDb), where `rotatedAt` lives in the shared store.

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

- **Resets on process restart** — see [invariants.md](invariants.md) #10. For durable per-user revocation, back the same machinery with `CredentialStoreRedis` / `CredentialStoreAtscriptDb` — both implement `revokeAllForUser` via real deletion, not an in-memory map.
- **Not shared across instances.** A `revokeAllForUser` call on pod A doesn't propagate to pod B's `epochs` map. Mitigation: keep `accessTtl` short (≤15 min) so re-issue on the new pod re-anchors above the old token's `iat`.
- **`'>'` would break recovery flows.** If you ever need stronger semantics (post-password-change tokens must be strictly newer), use a stateful store — the `>=` choice is intentional, not a bug.

## See also

- [client.md](client.md) — `createAuthedFetch`, the browser-side wrapper that calls `/auth/refresh` on a 401 (single-flight + retry-once).
- [sessions.md](sessions.md) — the `sessionId` token-family carried across rotation.
- [controllers.md](controllers.md) — `POST /auth/refresh` HTTP surface + auto-derived refresh cookie path.
- [authorization-server.md](authorization-server.md) — the OAuth 2.1 `refresh_token` grant built on the per-mint seams (invariant 21).
