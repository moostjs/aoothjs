# `@aooth/auth` API Reference

Complete export reference for `@aooth/auth`. See the [Auth Conceptual Guide](/auth/) for narrative documentation. Subpaths: `./redis`, `./atscript-db`, `./atscript-db/model.as`, `./client` (browser-safe), `./authz` (authorization server — see the [Authorization Server guide](/moost/authorization-server)).

## Classes

### `AuthCredential<TPayload extends object = object>`

```ts
class AuthCredential<TPayload extends object = object> {
  constructor(opts: AuthCredentialOptions<TPayload>);
  issue(userId: string, options?: IssueOptions<TPayload>): Promise<IssueResult>;
  validate(accessToken: string): Promise<AuthContext<TPayload> | null>;
  refresh(refreshToken: string, opts?: RefreshCallOptions<TPayload>): Promise<RefreshResult>;
  revoke(token: string): Promise<void>;
  revokeAllForUser(userId: string): Promise<number>;
  listForUser(userId: string): Promise<AuthContext<TPayload>[]>;
  listSessions(
    userId: string,
    opts?: { enrich?: SessionEnricher; kind?: string | string[] },
  ): Promise<SessionInfo[] | EnrichedSession[]>;
  revokeSession(userId: string, sessionId: string): Promise<void>;
  revokeOtherSessions(userId: string, keepSessionId: string): Promise<number>;
  deriveStateKey(label?: string): Buffer; // HKDF-derived stable secret
}
```

The orchestrator. Store-agnostic — accepts any `CredentialStore` (stateful or stateless). Refresh rotation modes are `'none' | 'always' | 'sliding'` (default `'sliding'`). On reuse-after-grace, calls `onRotationReuse` and revokes the compromised token family (or every session for the user with `refresh.reuseResponse: 'user'`). `listSessions` / `revokeSession` / `revokeOtherSessions` group the user's credentials into token families by `sessionId` (no-op `[]` / `0` on stores that can't enumerate) — see [Sessions](/auth/sessions). `deriveStateKey(label = "wf-state")` HKDF-derives a stable secret from the configured auth secret — used by `@aooth/auth-moost`'s `WfTriggerProvider` as the default encapsulated wf-state token secret so it survives restarts without a separate config. See [Credentials & Sessions](/auth/credentials) and [Refresh & Rotation](/auth/refresh).

`AuthCredentialOptions<TPayload>`:

```ts
interface AuthCredentialOptions<TPayload extends object = object> {
  store: CredentialStore<TPayload>;
  method?: "session" | "token"; // default 'token'
  accessTtl?: number; // default 1h; throws INVALID_CONFIG if ≤ 0
  refresh?: RefreshConfig;
  /**
   * Raw-token denylist consulted on every `validate()`. Disjoint from the
   * store's own `jti`-keyed denylist (used by stateless `revoke`/`update`/
   * `consume`). Sharing one `DenylistStore` instance across both is safe —
   * raw tokens and UUID jtis never collide.
   */
  denylist?: DenylistStore;
  maxConcurrent?: number;
  onLimit?: "reject" | "evict-oldest"; // default 'reject'
  trackLastSeen?: "refresh" | "validate" | false; // default false — see Sessions
  clock?: Clock;
}
```

### `CredentialStoreMemory<TPayload>`

```ts
new CredentialStoreMemory<TPayload>();
```

Reference stateful store. Holds `Map<token, state>` + `Map<userId, Set<token>>` for O(1) `revokeAllForUser`. See [Stores](/auth/).

### `CredentialStoreJwt<TPayload>`

```ts
new CredentialStoreJwt<TPayload>(opts: {
  algorithm?: 'HS256'|'HS384'|'HS512'|'RS256'|'RS384'|'RS512'|'ES256'|'ES384'|'ES512'|'EdDSA'
  secret?: string | Uint8Array | CryptoKey
  privateKey?: CryptoKey | Uint8Array
  publicKey?: CryptoKey | Uint8Array
  issuer?: string
  audience?: string
  denylist?: DenylistStore
  clock?: Clock
})
```

Stateless JWT store using `jose`. Default algorithm `HS256`. JWT verify pins `algorithms: [this.algorithm]` to defend against algorithm-confusion. Custom claim `state` carries `iatMs`/`expMs` at ms precision. Throws `AuthError('INVALID_CONFIG')` if keys missing. See [Tokens (JWT)](/auth/tokens).

### `CredentialStoreEncapsulated<TPayload>`

```ts
new CredentialStoreEncapsulated<TPayload>(opts: {
  secret: string | Buffer | Uint8Array  // string → scrypt KDF; 32-byte Buffer/Uint8Array skips KDF
  denylist?: DenylistStore
  clock?: Clock
})
```

AES-256-GCM token. Format: `base64url(iv ‖ ciphertext ‖ authTag)` of `JSON.stringify({...state, jti})`. Pass a 32-byte buffer to skip the fixed-salt KDF. See [Tokens (JWT)](/auth/tokens) and [Stores](/auth/).

### `DenylistStoreMemory`

```ts
new DenylistStoreMemory();
```

In-memory `Map<jti, expiresAt>` denylist with lazy expiry on `has` and explicit `cleanup()` sweep. Required by stateless stores if `revoke` / `consume` / `update` are used. See [Stores](/auth/).

### `RateLimiter`

```ts
new RateLimiter(opts?: RateLimiterOptions)

interface RateLimiterOptions {
  store?: RateLimitStore   // default: new RateLimitStoreMemory (single process only)
  clock?: Clock
}

check(
  scope: string,           // bucket id
  subject: string,         // caller identity
  rules: RateLimitRuleInput[],
  opts?: { defaultMessage?: string },
): Promise<RateLimitDecision>
```

Fixed-window limiter with window-aligned keys — one atomic store increment per rule decides; correctness never depends on the TTL. See [Rate Limiting (Core)](/auth/rate-limit).

### `RateLimitStoreMemory`

```ts
new RateLimitStoreMemory(opts?: { clock?: Clock })
```

In-memory `RateLimitStore` — lazy eviction on access, `cleanup(): Promise<number>` sweep, `clear()` for test resets. Single process only. See [Rate Limiting (Core)](/auth/rate-limit#ratelimitstorememory).

## Functions

### `generateOpaqueToken` / `generateMagicLinkToken`

```ts
function generateOpaqueToken(): string;
function generateMagicLinkToken(): string; // alias mint for magic links
```

32 bytes CSPRNG → base64url → 43 chars. URL-safe (`[A-Za-z0-9_-]` only). `generateOpaqueToken` is the one shared mint for high-entropy opaque secrets (magic-link tokens, dynamic-client secrets, the authz binding cookie all delegate to it); use it for your own one-shot tokens instead of hand-rolling `randomBytes`. See [Magic Links](/auth/magic-links).

### `defaultClock`

```ts
const defaultClock: Clock; // { now: () => Date.now() }
```

The default `Clock` implementation injected into stores when none is supplied. Override for deterministic tests or skew-corrected clocks. See [Credentials & Sessions](/auth/credentials).

### Rate-limit rule helpers

```ts
function parseRateLimitRule(input: RateLimitRuleInput): RateLimitRule; // throws on bad grammar
function parseDurationMs(input: string): number; // '5m' | '90s' | '500ms' | '1h' | '2d' → ms
function formatDurationMs(ms: number): string; // 272_000 → '4 minutes 32 seconds'
function renderRateLimitMessage(
  template: string,
  rule: RateLimitRule,
  retryAfterMs: number,
): string;
const DEFAULT_RATE_LIMIT_MESSAGE: string; // 'Too many requests. Please try again in {{delta}}.'
```

The parsing/formatting layer behind the rule grammar and `{{limit}}` / `{{max}}` / `{{window}}` / `{{delta}}` message placeholders. All parsing is eager — invalid rules throw at config time. See [Rate Limiting (Core)](/auth/rate-limit#rules).

## Client

Exported from the browser-safe `@aooth/auth/client` subpath only (no `jose` / Node crypto). See [Client (Browser Silent Refresh)](/auth/client) for narrative.

### `createAuthedFetch`

```ts
function createAuthedFetch<TFetch extends FetchFn = DefaultFetch>(
  options?: CreateAuthedFetchOptions<TFetch>,
): TFetch;

interface CreateAuthedFetchOptions<TFetch extends FetchFn = DefaultFetch> {
  refreshPath?: string; // default '/auth/refresh'
  onLogout?: () => void; // fired once per failed refresh
  fetch?: TFetch; // default: global fetch
  refreshOn?: number[]; // default [401]
}
```

A `fetch` wrapper for cookie-transport SPAs: forwards `credentials: "include"`, single-flights `POST {refreshPath}` on a matching status (single refresh for N concurrent failures), retries the original request once on success, and calls `onLogout()` once on failure. Returns a function with the same signature as the wrapped `fetch`. See [Client](/auth/client).

### `FetchFn` / `MinimalResponse` / `MinimalRequestInit` / `DefaultFetch`

```ts
type FetchFn = (input: string | URL, init?: MinimalRequestInit) => Promise<MinimalResponse>;
interface MinimalResponse {
  readonly ok: boolean;
  readonly status: number;
}
```

Structural types so the subpath needs no DOM lib. The real DOM `fetch` / `Response` satisfy them; `DefaultFetch` resolves to the ambient `fetch` type when the consumer's tsconfig includes the DOM lib, so `createAuthedFetch()` returns a real `Response`.

## Types — Core

### `AuthContext<TPayload>`

```ts
type AuthContext<TPayload extends object = object> = {
  userId: string;
  method: "session" | "token";
  credentialId: string; // sha256(accessToken) — safe to log
  sessionId?: string; // token-family id; falls back to credentialId for legacy tokens
  expiresAt: number;
} & TPayload; // the credential's typed root fields surface FLAT — no `claims` container
```

The "who is calling" object returned by `validate`. `credentialId` is a fingerprint, not the token — cannot be replayed. `sessionId` identifies the token family ("this device") — see [Sessions](/auth/sessions). The credential's per-token **payload** `TPayload` (the typed root fields a consumer adds to their model — e.g. `@arbac.attenuate.*` fields read by `@aooth/arbac-moost`) is intersected in and read by name (`ctx.tenantId`, not `ctx.claims.tenantId`). See [Credentials & Sessions](/auth/credentials).

### `CredentialMetadata`

```ts
interface CredentialMetadata {
  ip?: string;
  userAgent?: string;
  fingerprint?: string;
  label?: string;
  // Framework-written keys (never set these directly):
  credentialKind?: string; // from IssueOptions.kind — labels the session family
  authzClientId?: string; // OAuth client binding, stamped by the authz token endpoint
  accessTtl?: number; // per-mint access ttl, kept across refresh (mint-time authority)
  refreshRotation?: "none" | "always" | "sliding"; // per-family rotation, wins over instance config
}
```

**Open to declaration merging** — augment via `declare module '@aooth/auth' { interface CredentialMetadata { ... } }`. The framework-written keys are stamped by `issue()` / the authz tier and carried across rotation; when persisting metadata via the atscript-db store, build your column's shape on `AoothCredentialMetadataBase` so they round-trip (see [`@aooth/auth/atscript-db`](#subpath-aooth-auth-atscript-db)). See [Credentials & Sessions](/auth/credentials) and [Refresh & Rotation](/auth/refresh#per-mint-refresh-control-issueoptions-refresh).

### `CredentialState`

```ts
// The fixed ENVELOPE — no generic, no `claims`. A consumer's per-token payload
// is NOT a field here; it rides as additional typed root fields intersected
// via `CredentialState & TPayload` (the orchestrator + stores are generic over
// that payload).
interface CredentialState {
  userId: string;
  issuedAt: number;
  expiresAt: number;
  metadata?: CredentialMetadata;
  kind?: "access" | "refresh";
  parentCredentialId?: string;
  rotatedAt?: number;
  sessionId?: string; // token-family id, stable across rotation
  lastSeenAt?: number; // activity time; only written under trackLastSeen
}
```

The persisted envelope stores hold. `sessionId` / `lastSeenAt` back the [Sessions](/auth/sessions) APIs. See [Stores](/auth/).

### `IssueOptions<TPayload>`

```ts
// The typed payload `TPayload` is spread FLAT alongside the framework
// hints; reserved keys `metadata`/`sessionId`/`ttl`/`expiresAt`/`kind`/`refresh`
// (and the envelope keys) must not be reused as payload field names.
type IssueOptions<TPayload extends object = object> = TPayload & {
  metadata?: CredentialMetadata;
  sessionId?: string; // omit → issue() mints a random opaque one
  ttl?: number; // per-mint access TTL (ms, > 0) — overrides accessTtl; excl. with expiresAt
  expiresAt?: number; // absolute access expiry instant (ms) — overrides ttl + accessTtl
  kind?: string; // semantic credential kind ("cli-session" / "pat") → metadata.credentialKind
  refresh?: false | { ttl?: number }; // per-mint refresh control — see Refresh & Rotation
};
```

Options for `issue`. Pass the credential's typed root fields directly (e.g. `issue(userId, { tenantId: "t-1" })`); supply `sessionId` to join an existing session family. `ttl` / `expiresAt` override the access-token lifetime for THIS mint only (refresh keeps `refresh.ttl`); `kind` labels the whole session family and feeds the `listSessions({ kind })` filter. `refresh: false` suppresses the refresh mint for this credential even when the instance config exists; a `refresh` object mints one with a per-mint lifetime (fixed-ceiling rotation, works without an instance config) — see [Per-mint refresh control](/auth/refresh#per-mint-refresh-control-issueoptions-refresh). See [Sessions](/auth/sessions) and [Credentials](/auth/credentials).

### `IssueResult` / `RefreshResult`

```ts
interface IssueResult {
  accessToken: string;
  refreshToken?: string;
  accessExpiresAt: number;
  refreshExpiresAt?: number;
}
interface RefreshResult extends IssueResult {
  userId: string; // the subject of the rotated family
}
```

`IssueResult` is returned by `issue` — `refreshToken` is present iff a refresh token was minted (instance `refresh: RefreshConfig`, or a per-mint `IssueOptions.refresh` object). `refresh()` returns `RefreshResult`: the caller presented only an opaque token, so this is where it learns the subject (the OAuth `refresh_token` grant relies on it). See [Credentials & Sessions](/auth/credentials).

### `RefreshCallOptions<TPayload>`

```ts
interface RefreshCallOptions<TPayload extends object = object> {
  guard?: (state: CredentialState & TPayload) => void | Promise<void>;
}
```

Options for `refresh`. The `guard` runs after the token resolved to a live refresh credential but **before any rotation or state change** — throwing aborts with the family untouched. The seam for caller-level binding checks (the authz token endpoint verifies `metadata.authzClientId` here). See [Refresh & Rotation](/auth/refresh#per-mint-refresh-control-issueoptions-refresh).

### `RefreshConfig`

```ts
interface RefreshConfig {
  ttl: number;
  rotation?: "none" | "always" | "sliding"; // default 'sliding'
  rotationGraceMs?: number; // default 30_000 — sliding AND always
  reuseResponse?: "session" | "user"; // default 'session'
  onRotationReuse?: (state: CredentialState) => void;
}
```

Rotation policy. Both `'sliding'` (rolling expiry) and `'always'` (fixed session ceiling) rotate every refresh, mark `rotatedAt`, and tolerate reuse within `rotationGraceMs` on stateful stores (store-backed, so the grace holds across instances); reuse after the grace fires the theft response. `reuseResponse` selects the blast radius: `'session'` (default — the compromised token family via `revokeSession`) or `'user'` (every session via `revokeAllForUser`). See [Refresh & Rotation](/auth/refresh).

## Types — Stores

### `CredentialStore<TPayload>`

```ts
interface CredentialStore<TPayload extends object = object> {
  persist(state: CredentialState & TPayload, ttl?: number): Promise<string>;
  retrieve(token: string): Promise<(CredentialState & TPayload) | null>;
  consume(token: string): Promise<(CredentialState & TPayload) | null>; // single-use
  update(token: string, state: CredentialState & TPayload): Promise<string>; // may return new token
  revoke(token: string): Promise<void>;
  revokeAllForUser(userId: string): Promise<number>;
  listForUser?(userId: string): Promise<Array<CredentialState & TPayload & { token: string }>>;
  touch?(token: string, at: number): Promise<void>; // backs trackLastSeen: 'validate'
  listSessions?(userId: string): Promise<Array<CredentialState & TPayload & { token: string }>>; // optional native grouping
}
```

The pluggable storage contract. Stateless stores throw `STATELESS_OPERATION_UNSUPPORTED` on `consume`/`revoke`/`update` unless a `DenylistStore` is configured. `update` MAY return a different token (callers MUST use the returned value). `touch` / `listSessions` are optional session capabilities — see [Sessions](/auth/sessions). See [Stores](/auth/).

### `SessionInfo`

```ts
interface SessionInfo {
  sessionId: string;
  userId: string;
  createdAt: number; // origin credential's issuedAt
  lastSeenAt?: number; // newest activity; falls back to createdAt
  expiresAt: number; // live refresh token's expiry (or access)
  current?: boolean; // set by the caller, not the store
  metadata?: CredentialMetadata;
}
```

One row per token family, returned by `listSessions`. See [Sessions](/auth/sessions).

### `EnrichedSession`

```ts
interface EnrichedSession extends SessionInfo {
  device?: string;
  browser?: string;
  os?: string;
  location?: string;
  geo?: { country?: string; city?: string };
}
```

A `SessionInfo` augmented by a `SessionEnricher` at read time. aooth ships no UA/geo derivation. See [Sessions](/auth/sessions).

### `SessionEnricher`

```ts
type SessionEnricher = (s: SessionInfo) => EnrichedSession | Promise<EnrichedSession>;
```

Consumer-supplied read-time mapper passed to `listSessions(userId, { enrich })`. See [Sessions](/auth/sessions).

### `DenylistStore`

```ts
interface DenylistStore {
  add(jti: string, expiresAt: number): Promise<void>;
  has(jti: string): Promise<boolean>;
  cleanup(): Promise<number>;
}
```

Optional sidecar for stateless stores. See [Stores](/auth/).

## Types — Rate Limiting

### `RateLimitRule` / `RateLimitRuleInput`

```ts
interface RateLimitRule {
  limit: number; // max hits per window
  window: number; // window length, ms
  message?: string; // 429 message template for THIS rule
}

type RateLimitRuleInput =
  | string // '6/5m', '6 per 5m', '6/5m | wait {{delta}}'
  | { limit: number; window: number | string; message?: string }; // window: ms or '5m'
```

Normalized rule vs. what decorators/options accept. See [Rate Limiting (Core)](/auth/rate-limit#rules).

### `RateLimitDecision`

```ts
interface RateLimitDecision {
  allowed: boolean;
  limit: number; // governing rule = violated rule, else lowest-remaining rule
  remaining: number;
  resetAt: number; // ms epoch
  resetAfterMs: number; // delta under the limiter's own clock — use for header math
  retryAfterMs?: number; // present when !allowed
  message?: string; // present when !allowed — rendered template
  policies: RateLimitRule[]; // all evaluated rules (RateLimit-Policy header)
}
```

The outcome of one `RateLimiter.check()` — everything a transport needs for headers + 429. See [Rate Limiting (Core)](/auth/rate-limit#check-and-the-decision).

### `RateLimitStore`

```ts
interface RateLimitStore {
  hit(key: string, ttlMs: number): Promise<number>; // atomic increment-and-get
  reset?(key: string): Promise<void>; // optional: drop a counter
}
```

Storage contract for the fixed-window limiter. Implementations: `RateLimitStoreMemory` (root entry), `RateLimitStoreRedis` (`@aooth/auth/redis`).

## Types — Transport

### `AuthEmailKind`

```ts
type AuthEmailKind =
  | "recovery.magicLink"
  | "invite.magicLink"
  | "mfa.code"
  | "login.pincode"
  | "recovery.pincode"
  | "invite.pincode"
  | "notifyNewDevice";
```

See [Email & SMS Senders](/auth/).

### `AuthEmailEvent`

```ts
interface AuthEmailEvent {
  kind: AuthEmailKind;
  recipient: string;
  url?: string;
  code?: string;
  expiresAt: number;
  username?: string;
  metadata?: Record<string, unknown>;
}
```

Payload handed to `EmailSender.send`. See [Email & SMS Senders](/auth/).

### `EmailSender`

```ts
interface EmailSender {
  send(event: AuthEmailEvent): Promise<void>;
}
```

Interface only — consumers ship their SES/SendGrid/Twilio implementation. Workflows `await` the call; blocking transports must queue and return. See [Email & SMS Senders](/auth/).

### `AuthSmsKind`

```ts
type AuthSmsKind = "login.pincode" | "recovery.pincode" | "invite.pincode";
```

See [Email & SMS Senders](/auth/).

### `AuthSmsEvent`

```ts
interface AuthSmsEvent {
  kind: AuthSmsKind;
  recipient: string;
  code: string;
  ttlMs: number;
  userId?: string;
}
```

See [Email & SMS Senders](/auth/).

### `SmsSender`

```ts
interface SmsSender {
  send(event: AuthSmsEvent): Promise<void>;
}
```

Interface only — provider implementation is the consumer's responsibility. See [Email & SMS Senders](/auth/).

### `BuildMagicLinkUrl`

```ts
type BuildMagicLinkUrl = (kind: AuthEmailKind, token: string, ctx?: { userId?: string }) => string;
```

Consumer-owned URL builder fed to the magic-link outlet. The optional third `{ userId }` arg is supplied for the `invite.magicLink` kind so the URL can carry the invitee id (read by `AuthController.invitePostRedemption` for the idempotent already-accepted envelope); recovery callers ignore it. See [Magic Links](/auth/magic-links).

### `Clock`

```ts
interface Clock {
  now(): number;
}
```

Time abstraction injected into stores and `AuthCredential`. Replace for tests or skew-corrected clocks. See [Credentials & Sessions](/auth/credentials).

## Errors

### `AuthError`

```ts
class AuthError extends Error {
  readonly name: 'AuthError'
  constructor(
    public type: AuthErrorType,
    message?: string,
    public details?: Record<string, unknown>
  )
}
```

Single error class. See [Errors](/auth/).

### `AuthErrorType`

```ts
type AuthErrorType =
  | "INVALID_TOKEN"
  | "TOKEN_EXPIRED"
  | "TOKEN_REVOKED"
  | "REFRESH_REUSE_DETECTED"
  | "STATELESS_OPERATION_UNSUPPORTED"
  | "MAX_CONCURRENT_REACHED"
  | "INVALID_CONFIG";
```

`REFRESH_REUSE_DETECTED` fires on `'always'` reuse and `'sliding'` reuse-after-grace; both trigger `revokeAllForUser`. See [Errors](/auth/) and [Refresh & Rotation](/auth/refresh).

## Subpath: `@aooth/auth/redis`

```ts
import {
  CredentialStoreRedis,
  DenylistStoreRedis,
  RateLimitStoreRedis,
  RedisLike,
} from "@aooth/auth/redis";
```

### `CredentialStoreRedis<TPayload>`

```ts
new CredentialStoreRedis<TPayload>(opts: {
  redis: RedisLike
  prefix?: string                  // default 'aooth:cred'
  clock?: Clock
})
```

Stateful Redis-backed store. Keys: `aooth:cred:t:<token>` (JSON state with `PX` TTL), `aooth:cred:u:<userId>` (token SET). `persist` fails loud on dead credentials. See [Stores](/auth/).

### `DenylistStoreRedis`

```ts
new DenylistStoreRedis(opts: { redis: RedisLike; prefix?: string })
```

Backing key `aooth:dl:<jti>` with `PX` TTL. `cleanup()` is a no-op — Redis self-evicts. See [Stores](/auth/).

### `RateLimitStoreRedis`

```ts
new RateLimitStoreRedis(opts: { redis: RedisLike; prefix?: string }) // default prefix 'aooth:rl'
```

Redis-backed `RateLimitStore` — `hit` is one `INCR` plus a `PEXPIRE` on a window's first increment. Correctness never depends on the TTL (the limiter's keys embed the window start). See [Rate Limiting (Core)](/auth/rate-limit#ratelimitstoreredis).

### `RedisLike`

```ts
interface RedisLike {
  set(key: string, value: string, mode?: "PX", ttlMs?: number): Promise<string | null>;
  get(key: string): Promise<string | null>;
  del(...keys: string[]): Promise<number>;
  exists(key: string): Promise<number>;
  /** `PEXPIRE key ttlMs` — ttl is **milliseconds**, not seconds. */
  pexpire(key: string, ttlMs: number): Promise<number>;
  /** `INCR key` — atomic increment-and-get; creates the key at 1. */
  incr(key: string): Promise<number>;
  sadd(key: string, ...members: string[]): Promise<number>;
  srem(key: string, ...members: string[]): Promise<number>;
  smembers(key: string): Promise<string[]>;
}
```

Structural Redis interface — only the 9 methods the adapters use. All TTLs are milliseconds (hence `pexpire`, not `expire` — a raw seconds-based client would silently set 1000× TTLs). `ioredis` matches by shape; `node-redis` (`redis@4+`) needs a small camelCase wrapper. See [Stores](/auth/stores#redislike-structural-typing).

## Subpath: `@aooth/auth/atscript-db`

```ts
import {
  CredentialStoreAtscriptDb,
  AuthCredentialRow,
  AuthCredentialTable,
  // Durable authorization-server stores (multi-pod) — see below.
  PendingAuthorizationStoreAtscriptDb,
  PendingAuthorizationTable,
  AuthCodeStoreAtscriptDb,
  AuthCodeTable,
} from "@aooth/auth/atscript-db";
import { AoothAuthCredential, AoothCredentialMetadataBase } from "@aooth/auth/atscript-db/model.as";
import { AoothPendingAuthorization } from "@aooth/auth/atscript-db/pending-authorization";
import { AoothAuthCode } from "@aooth/auth/atscript-db/auth-code";
```

### `CredentialStoreAtscriptDb<TPayload>`

```ts
new CredentialStoreAtscriptDb<TPayload>(opts: {
  table: AuthCredentialTable<TPayload>
  metadataField?: string // name of your @aooth.auth.metadata-annotated column
})
```

There is no `clock` option — time-sensitive bookkeeping (TTL checks, opportunistic GC) reads `Date.now()` directly.

`metadataField` is the name of the consumer-declared credential-metadata column: the fully-typed `@db.json` field on your `extends AoothAuthCredential` model, marked `@aooth.auth.metadata` and resolved at boot by [`getAoothCredentialMetadataSpec`](/api/arbac-moost#getaoothcredentialmetadataspec) (threaded here as plain config — same pattern as `UserStore.handleFields`). Shape the column as `AoothCredentialMetadataBase & { ...your keys }` — the exported `.as` type single-sources the framework-written envelope keys (see [Stores](/auth/stores)). The store maps the envelope's `metadata` through that column on every write/read. Absent → metadata is not persisted/read (memory/JWT stores are unaffected).

Single-table stateful store. `revokeAllForUser` uses `deleteMany({ userId })` — one round trip. `retrieve` GCs expired rows opportunistically. See [Stores](/auth/).

### `PendingAuthorizationStoreAtscriptDb` / `AuthCodeStoreAtscriptDb`

```ts
new PendingAuthorizationStoreAtscriptDb(opts: {
  table: PendingAuthorizationTable; // db.getTable(AoothPendingAuthorization)
  clock?: Clock; ttlMs?: number;    // default 15 min
})
new AuthCodeStoreAtscriptDb(opts: {
  table: AuthCodeTable;             // db.getTable(AoothAuthCode)
  clock?: Clock; ttlMs?: number;    // default 60 s
})
```

Durable (multi-pod) implementations of the two authorization-server stores from [`@aooth/auth/authz`](#authz-subpath) — drop-in under the same `PENDING_AUTHORIZATION_STORE_TOKEN` / `AUTH_CODE_STORE_TOKEN`. Back them with the raw `.as` models (`@aooth/auth/atscript-db/pending-authorization` + `…/auth-code`). The grant's `tokenPolicy` persists as a JSON string (its `payload` is an open record a closed `@db.json` would reject). `AuthCodeStoreAtscriptDb.consume` is an atomic check-and-delete — it reads the row, then `deleteOne(code)`, and only the caller whose delete reports `deletedCount === 1` wins the row (single-use under a concurrent double-redeem / back-button replay), so no version column is needed. Both models carry nullable `resource` (RFC 8707) — and pending also `clientName` (consent display) — so **run your schema sync after upgrading**: connector clients always send `resource`, and an un-synced column fails at the `/authorize` insert. See [Authorization Server](/moost/authorization-server).

### `DynamicClientStoreAtscriptDb`

```ts
new DynamicClientStoreAtscriptDb(opts: {
  table: DynamicClientTable; // db.getTable(AoothDynamicClient)
  clock?: Clock;
})
```

Durable `DynamicClientStore` (RFC 7591 registrations) over the `@aooth/auth/atscript-db/dynamic-client` model (`AoothDynamicClient`, table `aooth_dynamic_clients`) — long-lived rows, since a connector caches its `client_id` across grants. `redirectUris`/`grantTypes`/`responseTypes` persist as JSON-string columns (the `tokenPolicy` precedent — engine-portable; matching happens in `DynamicClientPolicy` after parse). `deleteUnusedBefore` is one mass delete over `createdAt < cutoff && lastUsedAt unset` (never-used GC); `touch` is a portable `findOne` + `replaceOne`. See [Wiring — MCP connectors](/moost/authorization-server#wiring-mcp-connectors).

### `AuthCredentialRow<TPayload>`

```ts
type AuthCredentialRow<TPayload extends object = object> = {
  token: string;
  userId: string;
  issuedAt: number;
  expiresAt: number;
  kind?: string;
  parentCredentialId?: string;
  rotatedAt?: number;
  sessionId?: string;
  lastSeenAt?: number;
} & TPayload; // consumer's typed columns persist flat (replaces the dropped `claims` blob)
```

Plain TS mirror of `AoothAuthCredential.as` (envelope columns) intersected with the consumer's typed payload columns. There is **no `metadata` envelope column** — credential metadata is consumer-declared (a fully-typed `@db.json` field on the extending model, marked `@aooth.auth.metadata`) and mapped dynamically through the store's `metadataField` option. `kind` is a free-form `string` (the `.as` model intentionally does not narrow it) so the row can carry magic-link discriminators like `'magic.recovery'` alongside the orchestrator's `'access'` / `'refresh'`. See [Stores](/auth/).

### `AuthCredentialTable<TPayload>`

```ts
interface AuthCredentialTable<TPayload extends object = object> {
  insertOne(row: AuthCredentialRow<TPayload>): Promise<{ insertedId: unknown }>;
  findOne(query: { filter: Record<string, unknown> }): Promise<AuthCredentialRow<TPayload> | null>;
  findMany(query: {
    filter?: Record<string, unknown>;
    controls?: Record<string, unknown>;
  }): Promise<AuthCredentialRow<TPayload>[]>;
  /** Replaces by PK on the row itself — no wrapper. */
  replaceOne(
    row: AuthCredentialRow<TPayload>,
  ): Promise<{ matchedCount: number; modifiedCount: number }>;
  /** Deletes by PK value (the token string). */
  deleteOne(idOrPk: unknown): Promise<{ deletedCount: number }>;
  deleteMany(filter: Record<string, unknown>): Promise<{ deletedCount: number }>;
}
```

Structural interface — the subset of `AtscriptDbTable` the adapter uses. Apps cast their `db.getTable(AoothAuthCredential)` to this type. See [Stores](/auth/).

## Subpath: `@aooth/auth/authz`

The framework-agnostic authorization-server layer (aoothjs AS an OAuth/OIDC provider for its own clients). Narrative + wiring: [Authorization Server](/moost/authorization-server). The moost HTTP endpoints live in [`@aooth/auth-moost`](/api/auth-moost#authorization-server).

### `IdTokenSigner`

```ts
class IdTokenSigner {
  constructor(opts: IdTokenSignerOptions);
  readonly issuer: string; // canonical (trailing slash stripped)
  readonly alg: IdTokenAlg; // 'RS256' | 'ES256'
  readonly kid: string;
  sign(claims: IdTokenClaims): Promise<string>; // a signed id_token JWS
  jwks(): Promise<{ keys: JWK[] }>; // public half, for GET /auth/jwks
}
```

Signs OIDC `id_token`s (RS256/ES256) and publishes the matching JWKS. Holds one asymmetric keypair (`privateKey` PKCS8 PEM, `publicKey` SPKI PEM); keys are imported lazily + cached, so construction is cheap and synchronous. `issuer` is canonicalised once so `iss` / discovery `issuer` / derived endpoint URLs are byte-identical (a relying party compares for exact equality). Never used for the access token. `IdTokenSignerOptions`: `{ issuer, kid, privateKey, publicKey, alg?='RS256', ttlSec?=300, clock? }`.

### `LoopbackClientPolicy`

```ts
class LoopbackClientPolicy implements ClientRedirectPolicy {
  resolveClient(args: { clientId?; redirectUri; scope? }): ResolvedClient;
}
```

Tier-1 policy: accepts any `redirect_uri` whose host is a loopback literal (`127.0.0.1` / `[::1]` / `localhost`) on any port (RFC 8252), rejects everything else. Public client (no `client_id`/secret); PKCE is the binding.

### `RegisteredClientPolicy`

```ts
class RegisteredClientPolicy implements ClientRedirectPolicy {
  constructor(opts: { clients: RegisteredClient[] });
  resolveClient(args: { clientId?; redirectUri; scope? }): ResolvedClient;
  authenticateClient(args: { clientId?; clientSecret? }): void; // confidential → constant-time secret check
}
```

Tier-2 policy: a static registry of first-party clients. Authorizes the client + `redirect_uri` against the registered allowlist, resolves granted scope (`requested ∩ allowed`) and what the grant delivers (`id_token`/`access_token`, `aud = client_id`). An unregistered client or unlisted redirect throws `AuthorizeError`.

### `CompositeClientPolicy`

```ts
class CompositeClientPolicy implements ClientRedirectPolicy {
  constructor(opts: {
    loopback: ClientRedirectPolicy;
    registered?: ClientRedirectPolicy;
    dynamic?: ClientRedirectPolicy;
  });
}
```

Runs the tiers side by side, dispatching on the **presence and ownership of `client_id`**: absent → `loopback`; present → `registered` when its `hasClient()` knows the id (static-first — a dynamic registration can never shadow a static client), else `dynamic`. `authenticateClient` routes through the same picker. At least one of `registered`/`dynamic` is required; with both, `registered` must implement `hasClient` (validated at construction). Each sub-policy still owns its own redirect validation.

### `DynamicClientPolicy`

```ts
class DynamicClientPolicy implements ClientRedirectPolicy {
  constructor(opts: {
    store: DynamicClientStore;
    tokenPolicy?: TokenPolicy; // default { kind: 'dynamic-session', ttl: 30d }
    allowedScopes?: string[]; // server-side bound: granted = requested ∩ this ∩ registration scope
    clock?: Clock;
  });
  resolveClient(args: { clientId?; redirectUri; scope? }): Promise<ResolvedClient>;
  authenticateClient(args: { clientId?; clientSecret? }): Promise<void>; // existence + secret (confidential)
  hasClient(clientId: string): Promise<boolean>;
}
```

Policy for RFC 7591 dynamically-registered clients (MCP connectors) — the `dynamic` slot of `CompositeClientPolicy`. `https` redirects are exact-matched; loopback entries are port-agnostic (RFC 8252). Mints an access token only — **no `id_token`** — plus a rotating refresh token when `tokenPolicy.refresh` is set. `authenticateClient` re-checks existence (a registration deleted/GC'd between authorize and redemption fails closed at `/token`) and, for a `client_secret_post` registration, constant-time-verifies the presented secret against the stored digest; public (`"none"`) clients keep PKCE-only. See [Wiring — MCP connectors](/moost/authorization-server#wiring-mcp-connectors).

### `DynamicClientRegistration`

```ts
class DynamicClientRegistration {
  constructor(opts: {
    store: DynamicClientStore;
    maxClients?: number; // default 1000 — reject-when-full, never evicts
    unusedClientTtlMs?: number; // lazy GC of never-used registrations; omit = off
    guard?: (args: { metadata: NewDynamicClient }) => void | Promise<void>;
    validation?: ClientRegistrationValidationOptions;
    clock?: Clock;
  });
  register(body: unknown): Promise<RegisteredDynamicClient>; // validate → guard → GC → cap → mint secret → persist
}
```

The RFC 7591 registration operation behind `POST {issuer}/register` — `@aooth/auth-moost`'s endpoint is a thin HTTP adapter over `register()`, and non-moost servers call it directly. For a `client_secret_post` registration the returned `RegisteredDynamicClient` additionally carries the plaintext `clientSecret` + `clientSecretExpiresAt: 0` — the ONE disclosure; only the SHA-256 digest is persisted. Throws `ClientRegistrationError` on invalid metadata; the guard throws one to reject with a custom reason (any other throw is a server fault). `validateClientRegistration(body, opts?)` is also exported standalone.

### Discovery / challenge builders

```ts
function buildAuthorizationServerMetadata(
  opts: BuildAuthorizationServerMetadataOptions,
): AuthorizationServerMetadata;
function buildProtectedResourceMetadata(
  opts: BuildProtectedResourceMetadataOptions,
): ProtectedResourceMetadata;
function buildWwwAuthenticateBearerChallenge(opts?: WwwAuthenticateBearerChallengeOptions): string;
function canonicalizeIssuer(issuer: string): string; // trailing-slash strip (RFC 8414 exactness)
```

Pure, framework-free builders for the RFC 8414 AS-metadata document, the RFC 9728 protected-resource document, and the RFC 6750 `WWW-Authenticate: Bearer …` header **value** (every value sanitized — control characters stripped, quotes escaped). Re-exported by `@aooth/auth-moost`; consumers use them to mount the root-level discovery forms a prefix-mounted controller can't serve. See [Root-mounted discovery](/moost/authorization-server#wiring-mcp-connectors).

### `OidcClaimsResolver` / `NoopOidcClaimsResolver`

```ts
abstract class OidcClaimsResolver {
  abstract resolveClaims(
    userId: string,
    scope: string | undefined,
  ): Record<string, unknown> | Promise<Record<string, unknown>>;
}
class NoopOidcClaimsResolver extends OidcClaimsResolver {} // emits {} → sub-only id_token
```

Supplies the **profile** claims (`email`/`email_verified`/`name`/…) for an `id_token` — the part that depends on the consumer's user shape. The registered claims (`iss`/`aud`/`sub`/`iat`/`exp`/`nonce`) are owned by the controller. Honour the granted `scope` with `scopeGrants`.

### `PendingAuthorizationStoreMemory` / `AuthCodeStoreMemory` / `DynamicClientStoreMemory`

```ts
class PendingAuthorizationStoreMemory extends PendingAuthorizationStore {}
class AuthCodeStoreMemory extends AuthCodeStore {}
class DynamicClientStoreMemory extends DynamicClientStore {}
```

In-memory implementations of the server-side stores (for tests / single-process). `AuthCodeStore.consume()` is single-use + atomic. `DynamicClientStore` is the long-lived RFC 7591 registration store (`create`/`get`/`delete`/`count`/`touch`/`deleteUnusedBefore` — GC targets **never-used** rows only). A multi-pod deployment swaps the durable `…AtscriptDb` adapters (see the [`@aooth/auth/atscript-db` subpath](#subpath-aooth-auth-atscript-db)) under the same DI tokens.

### Functions

- `scopeGrants(scope: string | undefined, claim: string): boolean` — `true` when the space-joined `scope` grants `claim` (`"email"` / `"profile"` / …).
- `isLoopbackRedirectUri(uri: string): boolean` — the host check `LoopbackClientPolicy` uses.
- `tokenPolicyToIssueOptions(policy: TokenPolicy, clientId: string | undefined): IssueOptions` — flattens a grant's policy into `AuthCredential.issue()` options, applying the refresh-dimension rules (client binding stamp, loopback ignores `refresh`, the 30-day default). The mapping every token endpoint should use — `@aooth/auth-moost`'s does.
- `mintClientSecret(): string` / `hashClientSecret(secret): string` / `verifyClientSecret(secret, hash): boolean` — the confidential-client secret lifecycle: CSPRNG mint, SHA-256 hex digest (no KDF — the secret is high-entropy server-minted material), constant-time verify. Used by `DynamicClientRegistration` / `DynamicClientPolicy`; exported for custom stores and probes.

### Types

- `TokenPolicy` — `{ kind?, ttl?, payload?, refresh? }`. What the grant mints, decided by the policy (never the client request) and recorded at `/authorize` time. `payload` carries `@arbac.attenuate.*` fields for a scoped token; omit for full authority. `refresh?: { ttl? }` opts the grant into the OAuth 2.1 `refresh_token` grant (default lifetime `DEFAULT_AUTHZ_REFRESH_TTL_MS` = 30 days); honored only for client-bound grants — see [the refresh grant](/moost/authorization-server#refresh-token-grant).
- `ResolvedClient` — the policy's verdict: `{ clientId?, clientName?, redirectUri, tokenPolicy, scope?, idToken?, accessToken?, audience? }`. `clientName` is untrusted display text for the consent prompt (rendered as text, paired with the validated redirect host).
- `RegisteredClient` — `{ clientId, clientName?, redirectUris?, redirectPrefixes?, type?='public', clientSecret?, idToken?=true, accessToken?=false, scopes?, tokenPolicy? }`.
- `DynamicClient` / `NewDynamicClient` — a stored RFC 7591 registration: `{ clientId, clientName?, redirectUris, tokenEndpointAuthMethod, clientSecretHash?, grantTypes, responseTypes, scope?, createdAt, lastUsedAt? }` (`lastUsedAt` unset = never used, the GC target). `clientSecretHash` is set iff the auth method is `"client_secret_post"` — the plaintext is never stored.
- `DynamicClientAuthMethod` — `'none' | 'client_secret_post'`.
- `RegisteredDynamicClient` — `DynamicClient & { clientSecret?, clientSecretExpiresAt? }`: `register()`'s return shape; the plaintext secret appears HERE and only here (`clientSecretExpiresAt: 0` ⇒ never expires).
- `ClientRegistrationValidationOptions` — registration caps: `{ maxRedirectUris?=5, maxRedirectUriLength?=512, maxClientNameLength?=128, maxScopeLength?=256, allowedScopes?, allowedTokenEndpointAuthMethods? }`. The last narrows which auth methods registrations may use (default both; `["none"]` = public-only deployment — an explicit disallowed ask is rejected, never downgraded).
- `IdTokenClaims` — `{ sub, aud, nonce?, ttlSec?, extra? }` (the `extra` map is the resolver's profile claims).
- `IdTokenAlg` — `'RS256' | 'ES256'`.
- `ClientRedirectPolicy` — the policy interface (`resolveClient` + optional `authenticateClient` + optional `hasClient` — the known-ness probe `CompositeClientPolicy` dispatches by).
- `PendingAuthorizationStore` / `AuthCodeStore` / `DynamicClientStore` — the abstract store contracts. A pending-authorization record carries a `binding` secret (the value of the `aooth_authz` browser-binding cookie), plus `clientName?` (consent display, snapshot at authorize) and `resource?` (RFC 8707, consistency-checked at `/token`); the auth-code record carries `resource?` too. A custom durable store **must** round-trip `binding`, or the consent gate's binding check fails closed. See [Consent gate & browser binding](/moost/authorization-server#consent-gate-browser-binding).
- `AuthorizationServerMetadata` / `ProtectedResourceMetadata` (+ the `Build…Options` inputs) and `WwwAuthenticateBearerChallengeOptions` — the builders' wire-document / option shapes.

### Errors

- `AuthorizeError` (`code: AuthorizeErrorCode`) — `'invalid_request' | 'invalid_client' | 'invalid_grant' | 'invalid_redirect' | 'access_denied' | 'unauthorized_client' | 'invalid_target' | 'server_error'`. Thrown by the policies; mapped to the OAuth error responses by the controller. `invalid_target` is RFC 8707's code (repeated/oversized `resource`, or a `/token`-leg mismatch).
- `ClientRegistrationError` (`code: ClientRegistrationErrorCode`) — `'invalid_redirect_uri' | 'invalid_client_metadata'`, the RFC 7591 §3.2.2 vocabulary; `message` becomes the response's `error_description`. Thrown by `validateClientRegistration` / `DynamicClientRegistration.register` (and by a `guard` to reject a registration).
