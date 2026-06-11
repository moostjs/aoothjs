# `@aooth/auth` API Reference

Complete export reference for `@aooth/auth`. See the [Auth Conceptual Guide](/auth/) for narrative documentation. Subpaths: `./redis`, `./atscript-db`, `./atscript-db/model.as`, `./client` (browser-safe), `./authz` (authorization server — see the [Authorization Server guide](/moost/authorization-server)).

## Classes

### `AuthCredential<TPayload extends object = object>`

```ts
class AuthCredential<TPayload extends object = object> {
  constructor(opts: AuthCredentialOptions<TPayload>);
  issue(userId: string, options?: IssueOptions<TPayload>): Promise<IssueResult>;
  validate(accessToken: string): Promise<AuthContext<TPayload> | null>;
  refresh(refreshToken: string): Promise<IssueResult>;
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
}
```

**Open to declaration merging** — augment via `declare module '@aooth/auth' { interface CredentialMetadata { ... } }`. See [Credentials & Sessions](/auth/credentials).

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
// hints; reserved keys `metadata`/`sessionId`/`ttl`/`expiresAt`/`kind` (and
// the envelope keys) must not be reused as payload field names.
type IssueOptions<TPayload extends object = object> = TPayload & {
  metadata?: CredentialMetadata;
  sessionId?: string; // omit → issue() mints a random opaque one
  ttl?: number; // per-mint access TTL (ms, > 0) — overrides accessTtl; excl. with expiresAt
  expiresAt?: number; // absolute access expiry instant (ms) — overrides ttl + accessTtl
  kind?: string; // semantic credential kind ("cli-session" / "pat") → metadata.credentialKind
};
```

Options for `issue`. Pass the credential's typed root fields directly (e.g. `issue(userId, { tenantId: "t-1" })`); supply `sessionId` to join an existing session family. `ttl` / `expiresAt` override the access-token lifetime for THIS mint only (refresh keeps `refresh.ttl`); `kind` labels the whole session family and feeds the `listSessions({ kind })` filter. See [Sessions](/auth/sessions) and [Credentials](/auth/credentials).

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
  // Durable authorization-server stores (multi-pod) — see below.
  PendingAuthorizationStoreAtscriptDb,
  PendingAuthorizationTable,
  AuthCodeStoreAtscriptDb,
  AuthCodeTable,
} from "@aooth/auth/atscript-db";
import { AoothAuthCredential } from "@aooth/auth/atscript-db/model.as";
import { AoothPendingAuthorization } from "@aooth/auth/atscript-db/pending-authorization";
import { AoothAuthCode } from "@aooth/auth/atscript-db/auth-code";
```

### `CredentialStoreAtscriptDb<TPayload>`

```ts
new CredentialStoreAtscriptDb<TPayload>(opts: {
  table: AuthCredentialTable<TPayload>
})
```

The adapter takes only `{ table }` — there is no `clock` option. Time-sensitive bookkeeping (TTL checks, opportunistic GC) reads `Date.now()` directly.

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

Durable (multi-pod) implementations of the two authorization-server stores from [`@aooth/auth/authz`](#authz-subpath) — drop-in under the same `PENDING_AUTHORIZATION_STORE_TOKEN` / `AUTH_CODE_STORE_TOKEN`. Back them with the raw `.as` models (`@aooth/auth/atscript-db/pending-authorization` + `…/auth-code`). The grant's `tokenPolicy` persists as a JSON string (its `payload` is an open record a closed `@db.json` would reject). `AuthCodeStoreAtscriptDb.consume` is an atomic check-and-delete — it reads the row, then `deleteOne(code)`, and only the caller whose delete reports `deletedCount === 1` wins the row (single-use under a concurrent double-redeem / back-button replay), so no version column is needed. See [Authorization Server](/moost/authorization-server).

### `AuthCredentialRow<TPayload>`

```ts
type AuthCredentialRow<TPayload extends object = object> = {
  token: string;
  userId: string;
  issuedAt: number;
  expiresAt: number;
  kind?: string;
  metadata?: {
    ip?: string;
    userAgent?: string;
    fingerprint?: string;
    label?: string;
  };
  parentCredentialId?: string;
  rotatedAt?: number;
  sessionId?: string;
  lastSeenAt?: number;
} & TPayload; // consumer's typed columns persist flat (replaces the dropped `claims` blob)
```

Plain TS mirror of `AoothAuthCredential.as` (envelope columns) intersected with the consumer's typed payload columns. `kind` is a free-form `string` (the `.as` model intentionally does not narrow it) so the row can carry magic-link discriminators like `'magic.recovery'` alongside the orchestrator's `'access'` / `'refresh'`. See [Stores](/auth/).

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
  constructor(opts: { loopback: ClientRedirectPolicy; registered: ClientRedirectPolicy });
}
```

Runs Tier 1 + Tier 2 side by side, dispatching on the **presence of `client_id`** (a request with one → `registered`, without → `loopback`). Each sub-policy still owns its own redirect validation.

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

### `PendingAuthorizationStoreMemory` / `AuthCodeStoreMemory`

```ts
class PendingAuthorizationStoreMemory extends PendingAuthorizationStore {}
class AuthCodeStoreMemory extends AuthCodeStore {}
```

In-memory implementations of the two short-lived server-side stores (for tests / single-process). `AuthCodeStore.consume()` is single-use + atomic. A multi-pod deployment swaps the durable `PendingAuthorizationStoreAtscriptDb` / `AuthCodeStoreAtscriptDb` (see the [`@aooth/auth/atscript-db` subpath](#subpath-aooth-auth-atscript-db)) under the same DI tokens.

### Functions

- `scopeGrants(scope: string | undefined, claim: string): boolean` — `true` when the space-joined `scope` grants `claim` (`"email"` / `"profile"` / …).
- `isLoopbackRedirectUri(uri: string): boolean` — the host check `LoopbackClientPolicy` uses.

### Types

- `TokenPolicy` — `{ kind?, ttl?, payload? }`. What the grant mints, decided by the policy (never the client request) and recorded at `/authorize` time. `payload` carries `@arbac.attenuate.*` fields for a scoped token; omit for full authority.
- `ResolvedClient` — the policy's verdict: `{ clientId?, redirectUri, tokenPolicy, scope?, idToken?, accessToken?, audience? }`.
- `RegisteredClient` — `{ clientId, redirectUris?, redirectPrefixes?, type?='public', clientSecret?, idToken?=true, accessToken?=false, scopes?, tokenPolicy? }`.
- `IdTokenClaims` — `{ sub, aud, nonce?, ttlSec?, extra? }` (the `extra` map is the resolver's profile claims).
- `IdTokenAlg` — `'RS256' | 'ES256'`.
- `ClientRedirectPolicy` — the policy interface (`resolveClient` + optional `authenticateClient`).
- `PendingAuthorizationStore` / `AuthCodeStore` — the abstract store contracts. A pending-authorization record carries a `binding` secret (the value of the `aooth_authz` browser-binding cookie) alongside the request fields — a custom durable store **must** round-trip it, or the consent gate's binding check fails closed. See [Consent gate & browser binding](/moost/authorization-server#consent-gate-browser-binding).

### Errors

- `AuthorizeError` (`code: AuthorizeErrorCode`) — `'invalid_request' | 'invalid_client' | 'invalid_grant' | 'invalid_redirect' | 'access_denied' | 'unauthorized_client' | 'server_error'`. Thrown by the policies; mapped to the OAuth error responses by the controller.
