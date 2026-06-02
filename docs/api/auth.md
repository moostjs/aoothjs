# `@aooth/auth` API Reference

Complete export reference for `@aooth/auth`. See the [Auth Conceptual Guide](/auth/) for narrative documentation. Subpaths: `./redis`, `./atscript-db`, `./atscript-db/model.as`.

## Classes

### `AuthCredential<TClaims extends object = object>`

```ts
class AuthCredential<TClaims extends object = object> {
  constructor(opts: AuthCredentialOptions<TClaims>);
  issue(userId: string, options?: IssueOptions<TClaims>): Promise<IssueResult>;
  validate(accessToken: string): Promise<AuthContext<TClaims> | null>;
  refresh(refreshToken: string): Promise<IssueResult>;
  revoke(token: string): Promise<void>;
  revokeAllForUser(userId: string): Promise<number>;
  listForUser(userId: string): Promise<AuthContext<TClaims>[]>;
  listSessions(
    userId: string,
    opts?: { enrich?: SessionEnricher },
  ): Promise<SessionInfo[] | EnrichedSession[]>;
  revokeSession(userId: string, sessionId: string): Promise<void>;
  revokeOtherSessions(userId: string, keepSessionId: string): Promise<number>;
  deriveStateKey(label?: string): Buffer; // HKDF-derived stable secret
}
```

The orchestrator. Store-agnostic — accepts any `CredentialStore` (stateful or stateless). Refresh rotation modes are `'none' | 'always' | 'sliding'` (default `'sliding'`). On reuse-after-grace, calls `onRotationReuse` and revokes the compromised token family (or every session for the user with `refresh.reuseResponse: 'user'`). `listSessions` / `revokeSession` / `revokeOtherSessions` group the user's credentials into token families by `sessionId` (no-op `[]` / `0` on stores that can't enumerate) — see [Sessions](/auth/sessions). `deriveStateKey(label = "wf-state")` HKDF-derives a stable secret from the configured auth secret — used by `@aooth/auth-moost`'s `WfTriggerProvider` as the default encapsulated wf-state token secret so it survives restarts without a separate config. See [Credentials & Sessions](/auth/credentials) and [Refresh & Rotation](/auth/refresh).

`AuthCredentialOptions<TClaims>`:

```ts
interface AuthCredentialOptions<TClaims extends object = object> {
  store: CredentialStore<TClaims>;
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

### `CredentialStoreMemory<TClaims>`

```ts
new CredentialStoreMemory<TClaims>();
```

Reference stateful store. Holds `Map<token, state>` + `Map<userId, Set<token>>` for O(1) `revokeAllForUser`. See [Stores](/auth/).

### `CredentialStoreJwt<TClaims>`

```ts
new CredentialStoreJwt<TClaims>(opts: {
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

### `CredentialStoreEncapsulated<TClaims>`

```ts
new CredentialStoreEncapsulated<TClaims>(opts: {
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

## Functions

### `generateMagicLinkToken`

```ts
function generateMagicLinkToken(): string;
```

32 bytes CSPRNG → base64url → 43 chars. URL-safe (`[A-Za-z0-9_-]` only). See [Magic Links](/auth/magic-links).

### `defaultClock`

```ts
const defaultClock: Clock; // { now: () => Date.now() }
```

The default `Clock` implementation injected into stores when none is supplied. Override for deterministic tests or skew-corrected clocks. See [Credentials & Sessions](/auth/credentials).

## Types — Core

### `AuthContext<TClaims>`

```ts
interface AuthContext<TClaims extends object = object> {
  userId: string;
  method: "session" | "token";
  credentialId: string; // sha256(accessToken) — safe to log
  sessionId?: string; // token-family id; falls back to credentialId for legacy tokens
  expiresAt: number;
  claims?: TClaims;
}
```

The "who is calling" object returned by `validate`. `credentialId` is a fingerprint, not the token — cannot be replayed. `sessionId` identifies the token family ("this device") — see [Sessions](/auth/sessions). See [Credentials & Sessions](/auth/credentials).

### `CredentialMetadata`

```ts
interface CredentialMetadata {
  ip?: string;
  userAgent?: string;
  fingerprint?: string;
  label?: string;
}
```

**Open to declaration merging** — augment via `declare module '@aooth/auth' { interface CredentialMetadata { ... } }`. See [Credentials & Sessions](/auth/credentials).

### `CredentialState<TClaims>`

```ts
interface CredentialState<TClaims extends object = object> {
  userId: string;
  issuedAt: number;
  expiresAt: number;
  claims?: TClaims;
  metadata?: CredentialMetadata;
  kind?: "access" | "refresh";
  parentCredentialId?: string;
  rotatedAt?: number;
  sessionId?: string; // token-family id, stable across rotation
  lastSeenAt?: number; // activity time; only written under trackLastSeen
}
```

The persisted shape stores hold. `sessionId` / `lastSeenAt` back the [Sessions](/auth/sessions) APIs. See [Stores](/auth/).

### `IssueOptions<TClaims>`

```ts
interface IssueOptions<TClaims extends object = object> {
  claims?: TClaims;
  metadata?: CredentialMetadata;
  sessionId?: string; // omit → issue() mints a random opaque one
}
```

Options for `issue`. Supply `sessionId` to join an existing session family; omit to mint a fresh one. See [Sessions](/auth/sessions).

### `IssueResult`

```ts
interface IssueResult {
  accessToken: string;
  refreshToken?: string;
  accessExpiresAt: number;
  refreshExpiresAt?: number;
}
```

Returned by `issue` and `refresh`. `refreshToken` is present iff `refresh: RefreshConfig` is configured. See [Credentials & Sessions](/auth/credentials).

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

### `CredentialStore<TClaims>`

```ts
interface CredentialStore<TClaims extends object = object> {
  persist(state: CredentialState<TClaims>, ttl?: number): Promise<string>;
  retrieve(token: string): Promise<CredentialState<TClaims> | null>;
  consume(token: string): Promise<CredentialState<TClaims> | null>; // single-use
  update(token: string, state: CredentialState<TClaims>): Promise<string>; // may return new token
  revoke(token: string): Promise<void>;
  revokeAllForUser(userId: string): Promise<number>;
  listForUser?(userId: string): Promise<Array<CredentialState<TClaims> & { token: string }>>;
  touch?(token: string, at: number): Promise<void>; // backs trackLastSeen: 'validate'
  listSessions?(userId: string): Promise<Array<CredentialState<TClaims> & { token: string }>>; // optional native grouping
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
import { CredentialStoreRedis, DenylistStoreRedis, RedisLike } from "@aooth/auth/redis";
```

### `CredentialStoreRedis<TClaims>`

```ts
new CredentialStoreRedis<TClaims>(opts: {
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

### `RedisLike`

```ts
interface RedisLike {
  set(key: string, value: string, mode?: "PX", ttlMs?: number): Promise<string | null>;
  get(key: string): Promise<string | null>;
  del(...keys: string[]): Promise<number>;
  exists(key: string): Promise<number>;
  /** `PEXPIRE key ttlMs` — ttl is **milliseconds**, not seconds. */
  expire(key: string, ttlMs: number): Promise<number>;
  sadd(key: string, ...members: string[]): Promise<number>;
  srem(key: string, ...members: string[]): Promise<number>;
  smembers(key: string): Promise<string[]>;
}
```

Structural Redis interface — only the 8 methods the adapters use. Works with `ioredis`, `redis@4`, etc. See [Stores](/auth/).

## Subpath: `@aooth/auth/atscript-db`

```ts
import {
  CredentialStoreAtscriptDb,
  AuthCredentialRow,
  AuthCredentialTable,
} from "@aooth/auth/atscript-db";
import { AoothAuthCredential } from "@aooth/auth/atscript-db/model.as";
```

### `CredentialStoreAtscriptDb<TClaims>`

```ts
new CredentialStoreAtscriptDb<TClaims>(opts: {
  table: AuthCredentialTable<TClaims>
})
```

The adapter takes only `{ table }` — there is no `clock` option. Time-sensitive bookkeeping (TTL checks, opportunistic GC) reads `Date.now()` directly.

Single-table stateful store. `revokeAllForUser` uses `deleteMany({ userId })` — one round trip. `retrieve` GCs expired rows opportunistically. See [Stores](/auth/).

### `AuthCredentialRow<TClaims>`

```ts
interface AuthCredentialRow<TClaims extends object = object> {
  token: string;
  userId: string;
  issuedAt: number;
  expiresAt: number;
  kind?: string;
  claims?: TClaims;
  metadata?: {
    ip?: string;
    userAgent?: string;
    fingerprint?: string;
    label?: string;
  };
  parentCredentialId?: string;
  rotatedAt?: number;
}
```

Plain TS mirror of `AoothAuthCredential.as`. `kind` is a free-form `string` (the `.as` model intentionally does not narrow it) so the row can carry magic-link discriminators like `'magic.recovery'` alongside the orchestrator's `'access'` / `'refresh'`. See [Stores](/auth/).

### `AuthCredentialTable<TClaims>`

```ts
interface AuthCredentialTable<TClaims extends object = object> {
  insertOne(row: AuthCredentialRow<TClaims>): Promise<{ insertedId: unknown }>;
  findOne(query: { filter: Record<string, unknown> }): Promise<AuthCredentialRow<TClaims> | null>;
  findMany(query: {
    filter?: Record<string, unknown>;
    controls?: Record<string, unknown>;
  }): Promise<AuthCredentialRow<TClaims>[]>;
  /** Replaces by PK on the row itself — no wrapper. */
  replaceOne(
    row: AuthCredentialRow<TClaims>,
  ): Promise<{ matchedCount: number; modifiedCount: number }>;
  /** Deletes by PK value (the token string). */
  deleteOne(idOrPk: unknown): Promise<{ deletedCount: number }>;
  deleteMany(filter: Record<string, unknown>): Promise<{ deletedCount: number }>;
}
```

Structural interface — the subset of `AtscriptDbTable` the adapter uses. Apps cast their `db.getTable(AoothAuthCredential)` to this type. See [Stores](/auth/).
