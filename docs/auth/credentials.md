# Credentials & Sessions

`AuthCredential<TClaims>` is the single orchestrator over every store. It issues, validates, refreshes and revokes bearer credentials, enforces concurrency limits, and detects refresh-token reuse. The store decides where state lives; the orchestrator decides how the lifecycle works.

This page covers every constructor option and every public method.

## Construction

```ts
import { AuthCredential, CredentialStoreMemory } from "@aoothjs/auth";

const auth = new AuthCredential<{ roles: string[] }>({
  store: new CredentialStoreMemory(),
  accessTtl: 15 * 60 * 1000,
});
```

### Constructor options

```ts
interface AuthCredentialOptions<TClaims extends object> {
  store: CredentialStore<TClaims>;
  method?: "session" | "token";
  accessTtl?: number;
  refresh?: RefreshConfig;
  denylist?: DenylistStore;
  maxConcurrent?: number;
  onLimit?: "reject" | "kickPrompt";
  clock?: Clock;
}
```

| Option          | Default                     | Purpose                                                                                                                                                      |
| --------------- | --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `store`         | (required)                  | The `CredentialStore<TClaims>` instance. See [Stores](./stores).                                                                                             |
| `method`        | `'token'`                   | Tags every issued credential. `AuthContext.method` mirrors it. Use `'session'` for long-lived server-side sessions, `'token'` for short-lived bearer access. |
| `accessTtl`     | `60 * 60 * 1000` (1 h)      | Lifetime of access credentials, ms. Validated `> 0` at construction — throws `INVALID_CONFIG` otherwise.                                                     |
| `refresh`       | `undefined`                 | Opt in to refresh tokens. See [Refresh & Rotation](./refresh).                                                                                               |
| `denylist`      | `undefined`                 | Required when using a stateless store for `revoke` / `consume` / `update`.                                                                                   |
| `maxConcurrent` | `undefined`                 | Cap on live access credentials per user. Refresh tokens don't count.                                                                                         |
| `onLimit`       | `'reject'`                  | What happens when `maxConcurrent` is reached on `issue()` — see [the limit policies](#maxconcurrent-and-onlimit).                                            |
| `clock`         | `{ now: () => Date.now() }` | Injectable clock for tests. Used everywhere — TTL expiry, JWT `iat`/`exp`, the rotation grace window, the per-user revocation epoch.                         |

::: warning `accessTtl` must be positive
`new AuthCredential({ store, accessTtl: 0 })` throws `AuthError('INVALID_CONFIG')`. So does a negative value. The default applies only when the option is omitted entirely.
:::

::: tip Tests use injected clocks
Pass a custom `clock` in unit tests to make rotation grace windows, refresh expiry and revocation epochs deterministic. The orchestrator never reads `Date.now()` directly.
:::

## Sessions vs. tokens

The package treats sessions and tokens as the _same machinery_ — same store, same orchestrator, same validation path. The `method` option is a tag on the issued context, nothing more.

| Use `method: 'session'` when                           | Use `method: 'token'` when                                           |
| ------------------------------------------------------ | -------------------------------------------------------------------- |
| Browser-first app, cookie transport, server-side state | API-first app, `Authorization: Bearer ...`, stateless or short-lived |
| Long TTL (hours to days)                               | Short TTL (minutes to hours), refresh on top                         |
| Stateful store (`Memory`, `Redis`, `AtscriptDb`)       | Either, but JWT is common                                            |

You can run both in one app — issue different credentials with different methods over different transports.

## `issue(userId, options?)`

Creates a new access credential (and optionally a refresh token).

**Signature**

```ts
issue(
  userId: string,
  options?: {
    claims?: TClaims;
    metadata?: CredentialMetadata;
    accessTtl?: number;
    refreshTtl?: number;
  },
): Promise<IssueResult>;

interface IssueResult {
  accessToken: string;
  accessExpiresAt: number;
  refreshToken?: string;
  refreshExpiresAt?: number;
}
```

**Behavior**

1. Enforces `maxConcurrent` against the user's current live count (only `kind: 'access'`).
2. Calls `store.persist(state, ttl)` with `kind: 'access'`.
3. If `refresh` is configured, also persists a `kind: 'refresh'` credential.
4. Returns both tokens plus their absolute expiry timestamps.

**Example**

```ts
const { accessToken, refreshToken, accessExpiresAt } = await auth.issue("alice", {
  claims: { roles: ["admin"], tenantId: "t-1" },
  metadata: { ip: req.ip, userAgent: req.headers["user-agent"] },
});
```

The per-call `accessTtl` / `refreshTtl` override the constructor defaults. Use sparingly — workflows like "remember me" pass a longer `refreshTtl`.

### `maxConcurrent` and `onLimit`

`maxConcurrent` is an integer cap on live **access** credentials per user. Refresh tokens are excluded from the count. The orchestrator counts via `store.listForUser(userId)` — stateful stores only. Stateless stores cannot enumerate, so `maxConcurrent` is silently a no-op on JWT / Encapsulated stores.

| `onLimit`            | Behavior                                                                                                                                                                                |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `'reject'` (default) | Throws `AuthError('MAX_CONCURRENT_REACHED')` with `details: { userId, max, current }`.                                                                                                  |
| `'kickPrompt'`       | Throws `AuthError('MAX_CONCURRENT_REACHED')` with the same payload — the framework integration uses this hint to render a "kick another device" prompt before retrying with `revoke()`. |

::: tip Refresh tokens are free
Long-lived refresh credentials don't count toward `maxConcurrent`. A user on three devices with `maxConcurrent: 3` has three access slots; the refresh tokens behind them don't tip the count.
:::

## `validate(accessToken)`

The hot path. Returns an `AuthContext` for a valid access token, or `null` for anything else — expired, revoked, malformed, unknown, wrong kind.

**Signature**

```ts
validate(accessToken: string): Promise<AuthContext<TClaims> | null>;

interface AuthContext<TClaims extends object = object> {
  userId: string;
  method: 'session' | 'token';
  credentialId: string;     // sha256(accessToken)
  expiresAt: number;
  claims?: TClaims;
}
```

**Behavior**

1. `store.retrieve(token)` — returns `null` if missing, expired or epoch-shadowed.
2. Rejects tokens with `kind: 'refresh'` (return `null`).
3. Builds `AuthContext` with `credentialId = sha256(token)`.

**Example**

```ts
const ctx = await auth.validate(bearer);
if (!ctx) throw new HttpError(401);
// ctx.userId, ctx.claims.roles, ctx.credentialId are safe to log
```

::: warning Never throws
`validate` collapses every failure mode to `null`. If you need to distinguish "expired" from "revoked" for UX, encode the reason at issue-time in metadata, not by inspecting the validation path.
:::

### The `credentialId` fingerprint

`credentialId = sha256(accessToken)` is the **non-replayable** identifier of the credential. Three properties hold:

1. **Stable.** Two calls to `validate` on the same token return the same `credentialId`. Safe to use as a cache key or DB row id.
2. **Loggable.** Logging the fingerprint never leaks the bearer token. Logging `accessToken` would.
3. **Non-replayable.** An attacker who steals the fingerprint cannot call `validate(credentialId)` — `sha256` is one-way.

Use it as the audit-log session key, the rate-limit key, and the websocket connection tag. Never use the raw `accessToken` for any of those.

## `refresh(refreshToken)`

Exchanges a refresh token for a fresh access token (and, depending on rotation mode, a fresh refresh token). See [Refresh & Rotation](./refresh) for the full state machine.

**Signature**

```ts
refresh(refreshToken: string): Promise<IssueResult>;
```

**Behavior summary**

| `refresh.rotation`    | What happens on success                                                                                                                                      |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `'none'`              | New access token issued. Old refresh stays valid until its own TTL.                                                                                          |
| `'always'`            | Old refresh is `consume`d. New access + new refresh issued. Reuse → `REFRESH_REUSE_DETECTED`.                                                                |
| `'sliding'` (default) | First call marks `rotatedAt`. Old refresh stays usable for `rotationGraceMs` (default 30s). Reuse after grace → `REFRESH_REUSE_DETECTED` + user-wide revoke. |

**Errors**

- `INVALID_TOKEN` — unknown / malformed token, or an access token presented as a refresh.
- `REFRESH_REUSE_DETECTED` — reuse outside the grace window. Triggers `revokeAllForUser`.
- `STATELESS_OPERATION_UNSUPPORTED` — `'always'` / `'sliding'` rotation on a stateless store without a `denylist`.

**Example**

```ts
try {
  const next = await auth.refresh(oldRefreshToken);
  res.cookie("access", next.accessToken, { maxAge: next.accessExpiresAt - Date.now() });
  if (next.refreshToken) {
    res.cookie("refresh", next.refreshToken, { maxAge: next.refreshExpiresAt! - Date.now() });
  }
} catch (e) {
  if (e instanceof AuthError && e.type === "REFRESH_REUSE_DETECTED") {
    // The whole user has been logged out — surface a "you've been signed out everywhere"
    res.status(401).clearCookie("access").clearCookie("refresh").end();
  }
}
```

## `revoke(token)`

Revokes a single credential by its token (access or refresh — the store doesn't care). Use this to log out a single device.

**Signature**

```ts
revoke(token: string): Promise<void>;
```

**Behavior**

- Stateful: `store.revoke(token)` — row deleted.
- Stateless: adds the credential's `jti` to the `denylist` until its natural `expiresAt`. Throws `STATELESS_OPERATION_UNSUPPORTED` if no `denylist` was passed.

**Example**

```ts
// Single-device logout
await auth.revoke(req.cookies.access);
await auth.revoke(req.cookies.refresh);
```

## `revokeAllForUser(userId)`

Logs the user out **everywhere**. Used by password reset, "sign out all devices", and reuse detection.

**Signature**

```ts
revokeAllForUser(userId: string): Promise<number>;
```

**Returns the count** of credentials revoked. Stateful stores return the actual row count. Stateless stores return the sentinel `1` to mean "the per-user revocation epoch was bumped" — the actual number of tokens affected isn't knowable without enumeration.

**The epoch gate** (stateless only). Stateless stores keep a `Map<userId, epochMs>`. On `revokeAllForUser`, the entry is set to `clock.now()`. On `retrieve`, any token with `iatMs < epoch` is rejected. The gate uses `>=` not `>` — see the next callout.

::: warning Stateless epoch is in-memory
The default `CredentialStoreJwt` keeps the epoch map in process memory. A restart loses it; multi-instance deployments lose it across nodes. For durable per-user revocation on JWT, back the epoch map with Redis or atscript — see [Stores](./stores).
:::

::: tip Same-ms `>=` gate
The gate is `iatMs < epoch`, i.e. `iatMs >= epoch` survives. This is load-bearing for recovery: the workflow can `revokeAllForUser(userId)` and then immediately `issue(userId, ...)` in the same millisecond and the new credential survives the gate. Auto-login after password reset depends on this.
:::

## `listForUser(userId)`

Returns every live `AuthContext` for the user. Useful for "active sessions" UI.

**Signature**

```ts
listForUser(userId: string): Promise<AuthContext<TClaims>[]>;
```

Stateful stores enumerate. Stateless stores **cannot enumerate** — `listForUser` returns `[]`. Don't rely on this method for JWT deployments.

**Example**

```ts
const sessions = await auth.listForUser("alice");
for (const s of sessions) {
  console.log(s.credentialId, s.method, new Date(s.expiresAt));
}
```

## `AuthContext` shape

The exact shape returned by `validate` and `listForUser`:

```ts
interface AuthContext<TClaims extends object = object> {
  userId: string;
  method: "session" | "token";
  credentialId: string;
  expiresAt: number;
  claims?: TClaims;
}
```

| Field          | Meaning                                                  |
| -------------- | -------------------------------------------------------- |
| `userId`       | Subject the credential was issued to.                    |
| `method`       | Whatever was configured at construction.                 |
| `credentialId` | `sha256(accessToken)`. Stable, loggable, non-replayable. |
| `expiresAt`    | Absolute ms timestamp.                                   |
| `claims`       | The `TClaims` object passed at `issue()` time, if any.   |

Note: `metadata` (IP, UA, fingerprint, label) is **not** on `AuthContext`. It lives in `CredentialState` server-side. The orchestrator deliberately doesn't echo it to the validation surface — keep it on the server.

## `CredentialMetadata` declaration merging

`CredentialMetadata` is the open shape used for the per-credential `metadata` field. The package ships these keys:

```ts
interface CredentialMetadata {
  ip?: string;
  userAgent?: string;
  fingerprint?: string;
  label?: string;
}
```

It is **explicitly designed for TypeScript declaration merging**. Augment it in your app to add app-specific keys with end-to-end type safety:

```ts
// types/aooth.d.ts
declare module "@aoothjs/auth" {
  interface CredentialMetadata {
    geoCountry?: string;
    deviceId?: string;
    enrolledTotp?: boolean;
  }
}
```

Then:

```ts
await auth.issue("alice", {
  metadata: {
    ip: req.ip,
    geoCountry: "PT", // typed
    deviceId: req.headers["x-device-id"] as string,
  },
});
```

The metadata is persisted by the store but never returned through `validate`. Read it via `listForUser` or directly from the underlying store when you need it.

## Full lifecycle example

```ts
import { AuthCredential, CredentialStoreMemory } from "@aoothjs/auth";

const auth = new AuthCredential<{ roles: string[] }>({
  store: new CredentialStoreMemory(),
  accessTtl: 15 * 60 * 1000,
  refresh: { ttl: 30 * 24 * 3600 * 1000, rotation: "always" },
  maxConcurrent: 5,
});

// Login
const { accessToken, refreshToken } = await auth.issue("alice", {
  claims: { roles: ["admin"] },
  metadata: { ip: "1.1.1.1", userAgent: "Mozilla/..." },
});

// Each request
const ctx = await auth.validate(accessToken);

// Token rotation
const next = await auth.refresh(refreshToken!);

// Logout this device
await auth.revoke(next.accessToken);
await auth.revoke(next.refreshToken!);

// Logout everywhere (e.g. password reset)
await auth.revokeAllForUser("alice");

// Active sessions UI
const live = await auth.listForUser("alice");
```

That covers every method on the orchestrator. Pick the right store next: see [Stores](./stores) for the implementation matrix, [Tokens](./tokens) for the stateless options, and [Refresh & Rotation](./refresh) for the rotation modes.

See the orchestrator source at [packages/auth/src/auth-credential.ts](https://github.com/moostjs/aoothjs/blob/main/packages/auth/src/auth-credential.ts).
