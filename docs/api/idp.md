# `@aooth/idp` API Reference

Complete export reference for `@aooth/idp`. See the [IdP Conceptual Guide](/idp/) for narrative documentation. Every public symbol lives in `packages/idp/src/index.ts`.

## Classes

### `OidcProvider`

```ts
new OidcProvider(opts: OidcProviderOptions)
provider.authorizationUrl(args: AuthorizationUrlArgs): Promise<string>
provider.exchange(args: ExchangeArgs): Promise<NormalizedProfile>
```

Generic OpenID Connect provider — discovery + remote JWKS + the full OIDC Core 3.1.3.7 ID-token validation (fails closed on JWKS/discovery errors). See [Providers](/idp/providers).

### `GoogleProvider`

```ts
new GoogleProvider(opts: GoogleProviderOptions) // = OidcProviderOptions without id/issuer
```

`OidcProvider` pinned to Google's issuer + `RS256`; `id === 'google'`. See [Providers](/idp/providers).

### `FakeIdentityProvider`

```ts
new FakeIdentityProvider(opts?: FakeIdentityProviderOptions)
fake.setProfile(code: string, profile: Omit<NormalizedProfile, "provider">): this
```

Deterministic, network-free provider for tests — `exchange()` resolves a `code` to a registered (or default) profile. Does not verify nonce. See [Providers](/idp/providers).

### `OAuthProviderRegistry`

```ts
new OAuthProviderRegistry(opts: OAuthProviderRegistryOptions)
registry.has(id) / get(id) / require(id) / ids() / list()
registry.callbackPath(providerId): string
registry.redirectUri(providerId): string         // baseUrl + callback path
registry.signState(payload, opts?) / verifyState(token, opts?)
registry.policy: ResolvedFederatedPolicy
```

Holds providers + policy + shared verification config (injected into each provider via `applyDefaults`); resolves `:provider` (throws `OAuthError('UNKNOWN_PROVIDER')` on a miss). See [Account resolution](/idp/account-resolution).

### `FederatedLoginService<T extends object = object>`

```ts
new FederatedLoginService<T>(deps: FederatedLoginServiceDeps<T>)
svc.resolveUser(profile: NormalizedProfile): Promise<ResolveOutcome>
svc.linkIdentity(params: { provider; subject; userId; profile? }): Promise<FederatedIdentity>
svc.policy: ResolvedFederatedPolicy
```

Maps a verified profile to a user (known → email-match → new); `linkIdentity` completes an interactive link with the cross-user guard. See [Account resolution](/idp/account-resolution).

### `OAuthError`

```ts
class OAuthError extends Error {
  readonly name: "OAuthError";
  constructor(type: OAuthErrorType, message?: string, details?: Record<string, unknown>);
}
```

Federated-login failure taxonomy. See [Errors](/idp/account-resolution#errors).

## Functions

### PKCE / nonce / state

```ts
function createPkcePair(): PkcePair; // { verifier, challenge, method: 'S256' }
function pkceChallengeFor(verifier: string): string;
function generateNonce(bytes?: number): string;
function generateRandomState(bytes?: number): string;
function signState(
  payload: OAuthStatePayload,
  secret: string | Uint8Array,
  opts?: SignStateOptions,
): Promise<string>;
function verifyState(
  token: string,
  secret: string | Uint8Array,
  opts?: VerifyStateOptions,
): Promise<OAuthStatePayload>;
```

PKCE S256 primitives + the compact HS256 signed-state binding (`verifyState` pins `HS256`, throws `STATE_EXPIRED` / `STATE_INVALID`). See [Account resolution](/idp/account-resolution#pkce-signed-state).

### Policy helpers

```ts
function resolveFederatedPolicy(policy?: FederatedPolicy): ResolvedFederatedPolicy;
function defaultUsernameStrategy(p: NormalizedProfile): string; // email ?? `${provider}:${subject}`
function isConfigurableProvider(p: IdentityProvider): p is ConfigurableProvider;
```

## Types

### Provider contract

```ts
interface IdentityProvider {
  readonly id: string;
  authorizationUrl(args: AuthorizationUrlArgs): Promise<string>;
  exchange(args: ExchangeArgs): Promise<NormalizedProfile>;
}
interface ConfigurableProvider extends IdentityProvider {
  applyDefaults(shared: SharedProviderConfig): void;
}
interface NormalizedProfile {
  provider: string;
  subject: string; // the IdP's stable `sub` — the durable join key
  email?: string;
  emailVerified?: boolean;
  displayName?: string;
  avatarUrl?: string;
  raw: unknown; // transient — never persisted
}
interface AuthorizationUrlArgs {
  redirectUri: string;
  state: string;
  codeChallenge: string;
  nonce?: string;
  scopes?: string[];
}
interface ExchangeArgs {
  code: string;
  redirectUri: string; // MUST byte-equal the authorization-time value
  codeVerifier: string;
  expectedNonce?: string;
}
```

### Provider / registry options

```ts
interface OidcProviderOptions {
  issuer: string;
  clientId: string;
  clientSecret: string;
  id?: string;
  scopes?: string[];
  idTokenSigningAlgs?: string[]; // default ['RS256','ES256']; none/HS* always rejected
  authorizationEndpoint?: string; // explicit endpoints skip discovery
  tokenEndpoint?: string;
  jwksUri?: string;
  discovery?: OidcDiscoveryDocument; // inject (skip .well-known fetch)
  jwks?: JWTVerifyGetKey; // inject (skip remote JWKS fetch)
  clockToleranceSec?: number; // default 5
  jwksCacheTtlMs?: number; // default 3_600_000
  clock?: Clock;
  fetch?: FetchLike;
}
type GoogleProviderOptions = Omit<OidcProviderOptions, "id" | "issuer">;
interface FakeIdentityProviderOptions {
  id?: string;
  authorizationEndpoint?: string;
  defaultProfile?: Omit<NormalizedProfile, "provider">;
}
interface OidcDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}
interface OAuthProviderRegistryOptions {
  baseUrl: string;
  stateSecret: string;
  providers: IdentityProvider[];
  policy?: FederatedPolicy;
  callbackPathTemplate?: string; // default '/auth/oauth/:provider/callback'
  clockToleranceSec?: number;
  jwks?: { cacheTtlMs?: number; refreshOnUnknownKid?: boolean };
  clock?: Clock;
  fetch?: FetchLike;
}
interface SharedProviderConfig {
  clockToleranceSec?: number;
  jwks?: { cacheTtlMs?: number; refreshOnUnknownKid?: boolean };
  clock?: Clock;
  fetch?: FetchLike;
}
```

### Policy & resolution

```ts
type EmailMatchPolicy = "create-separate" | "auto-link-if-verified" | "require-interactive-link";
interface FederatedPolicy {
  emailMatch?: EmailMatchPolicy; // default 'require-interactive-link'
  allowSignup?: boolean; // default true
  usernameStrategy?: (p: NormalizedProfile) => string;
  trustEmailVerifiedFrom?: string[]; // default []
}
type ResolvedFederatedPolicy = Required<FederatedPolicy>;
type ResolveOutcome =
  | { kind: "linked"; userId: string; isNew: false }
  | { kind: "created"; userId: string; isNew: true }
  | { kind: "auto-linked"; userId: string; isNew: false }
  | { kind: "needs-link"; candidateUserId: string }
  | { kind: "denied"; reason: "signup-disabled" | "email-unavailable" };
interface FederatedLoginServiceDeps<T extends object = object> {
  users: UserService<T>;
  federated: FederatedIdentityStore;
  policy?: FederatedPolicy;
}
```

### State / PKCE / fetch

```ts
interface PkcePair {
  verifier: string;
  challenge: string;
  method: "S256";
}
interface OAuthStatePayload {
  random: string;
  provider: string;
  redirect: string;
  verifier?: string;
  nonce?: string;
  handle?: string;
  userId?: string;
}
interface SignStateOptions {
  ttlSec?: number; // default 600
  clock?: Clock;
}
interface VerifyStateOptions {
  clock?: Clock;
}
type FetchLike = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<FetchResponseLike>;
interface FetchResponseLike {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}
```

### Error type

```ts
type OAuthErrorType =
  | "UNKNOWN_PROVIDER"
  | "INVALID_CONFIG"
  | "STATE_INVALID"
  | "STATE_EXPIRED"
  | "PROVIDER_DENIED"
  | "EXCHANGE_FAILED"
  | "JWKS_FAILED"
  | "ID_TOKEN_INVALID"
  | "EMAIL_UNAVAILABLE";
```

See [Errors](/idp/account-resolution#errors).
