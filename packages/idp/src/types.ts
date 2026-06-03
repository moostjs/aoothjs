import type { Clock } from "@aooth/auth";
import type { FederatedProfileSnapshot } from "@aooth/user";

/**
 * A provider profile normalized to a single shape across Google / OIDC / etc.
 * Structural superset of `@aooth/user`'s {@link FederatedProfileSnapshot} (the
 * display fields stored on the federated row) plus the join keys and the
 * transient `raw` claims.
 */
export interface NormalizedProfile extends FederatedProfileSnapshot {
  /** Provider id — `'google'`, `'oidc:<issuer>'`, … (matches `IdentityProvider.id`). */
  provider: string;
  /** The IdP's stable subject id (`sub`) — the durable join key. */
  subject: string;
  // email? / emailVerified? / displayName? / avatarUrl? inherited from FederatedProfileSnapshot.
  /**
   * The raw verified claims / userinfo. **Transient** — handed to a (future)
   * claims-mapper hook, NEVER persisted on the federated row (RFC §7). Typed
   * `unknown` so consumers narrow it explicitly.
   */
  raw: unknown;
}

export interface AuthorizationUrlArgs {
  /**
   * FIXED per provider (`baseUrl` + the constant callback path); exact-match
   * registered at the provider. The `exchange()` `redirectUri` MUST byte-equal
   * this value.
   */
  redirectUri: string;
  /** Opaque CSRF/binding token (a signed-state JWT — see `signState`). */
  state: string;
  /** PKCE S256 code challenge (base64url of SHA-256(verifier)). */
  codeChallenge: string;
  /** OIDC nonce minted at `/start`, asserted in `exchange()`. Ignored by pure OAuth2. */
  nonce?: string;
  /** Override the provider's default scope set. */
  scopes?: string[];
}

export interface ExchangeArgs {
  /** Authorization `code` returned on the callback. */
  code: string;
  /** MUST byte-equal the `redirectUri` used to build the authorization URL. */
  redirectUri: string;
  /** The PKCE code verifier matching the challenge sent at `/start`. */
  codeVerifier: string;
  /** OIDC: assert `id_token.nonce === expectedNonce`. Omit for pure OAuth2. */
  expectedNonce?: string;
}

/**
 * A pluggable identity provider. Three members (RFC §3.4); built-ins
 * additionally implement {@link ConfigurableProvider.applyDefaults} so the
 * registry can inject shared verification config.
 */
export interface IdentityProvider {
  /** Stable id used in `:provider` routes, the federated `provider` column, and state binding. */
  readonly id: string;
  /** Build the `302`-target authorization URL. Async because OIDC discovers its endpoints. */
  authorizationUrl(args: AuthorizationUrlArgs): Promise<string>;
  /**
   * Exchange the `code` for tokens, fully verify them (OIDC: §7 list), and
   * normalize. Throws {@link OAuthError} (`EXCHANGE_FAILED` / `ID_TOKEN_INVALID`
   * / `JWKS_FAILED` / `EMAIL_UNAVAILABLE`) on failure.
   */
  exchange(args: ExchangeArgs): Promise<NormalizedProfile>;
}

/**
 * Minimal structural `fetch` — the global `fetch` satisfies it, and tests
 * inject a deterministic fake. Only the members the OIDC client uses are
 * declared.
 */
export type FetchLike = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<FetchResponseLike>;

export interface FetchResponseLike {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}

/**
 * Verification config the {@link OAuthProviderRegistry} sets once and injects
 * into each provider that opts in via {@link ConfigurableProvider.applyDefaults}
 * (decision #2 — registry holds the shared config, providers stay standalone).
 * A provider's own constructor value always wins over an injected default.
 */
export interface SharedProviderConfig {
  /** Bounded clock skew for OIDC `exp`/`iat`/`nbf`, seconds. Default `5`. */
  clockToleranceSec?: number;
  /** JWKS caching/rotation knobs. */
  jwks?: { cacheTtlMs?: number; refreshOnUnknownKid?: boolean };
  /** Shared injectable clock (deterministic tests). */
  clock?: Clock;
  /** Shared injectable fetch (deterministic tests / custom agent). */
  fetch?: FetchLike;
}

/** A provider that accepts registry-injected {@link SharedProviderConfig}. */
export interface ConfigurableProvider extends IdentityProvider {
  applyDefaults(shared: SharedProviderConfig): void;
}

/** Structural check used by the registry to feature-detect `applyDefaults`. */
export function isConfigurableProvider(p: IdentityProvider): p is ConfigurableProvider {
  return typeof (p as ConfigurableProvider).applyDefaults === "function";
}

/**
 * How a federated login that matches an existing local account **by email**
 * is handled (RFC §4 — the account-takeover-sensitive knob).
 */
export type EmailMatchPolicy =
  /** Never match by email — always create a fresh account. */
  | "create-separate"
  /**
   * Auto-link only when the provider's `email_verified === true` AND the
   * provider is in `trustEmailVerifiedFrom`. A deliberate security downgrade.
   */
  | "auto-link-if-verified"
  /** Default & safest: surface the candidate; require interactive proof-of-control to link. */
  | "require-interactive-link";

export interface FederatedPolicy {
  /** Default `'require-interactive-link'`. */
  emailMatch?: EmailMatchPolicy;
  /** `false` → unknown subjects with no link are rejected (invite-only). Default `true`. */
  allowSignup?: boolean;
  /** Derives the new account's username. Default: `email`, else `${provider}:${subject}`. */
  usernameStrategy?: (p: NormalizedProfile) => string;
  /** Providers whose `email_verified` we trust for `auto-link-if-verified`. Default `[]`. */
  trustEmailVerifiedFrom?: string[];
}

export type ResolvedFederatedPolicy = Required<FederatedPolicy>;

/** Default username strategy: the verified email, else the stable `provider:subject`. */
export function defaultUsernameStrategy(p: NormalizedProfile): string {
  return p.email ?? `${p.provider}:${p.subject}`;
}

/** Apply RFC §4 safe defaults over a partial policy. */
export function resolveFederatedPolicy(policy: FederatedPolicy = {}): ResolvedFederatedPolicy {
  return {
    emailMatch: policy.emailMatch ?? "require-interactive-link",
    allowSignup: policy.allowSignup ?? true,
    usernameStrategy: policy.usernameStrategy ?? defaultUsernameStrategy,
    trustEmailVerifiedFrom: policy.trustEmailVerifiedFrom ?? [],
  };
}

/**
 * The outcome of {@link FederatedLoginService.resolveUser} (decision #1). A
 * discriminated union — richer than the RFC's `{ userId, isNew }` sketch — so
 * the phase-3 `oauth-exchange` step can branch: proceed into the gates
 * (`linked`/`created`/`auto-linked`), divert to an interactive link sub-flow
 * (`needs-link`), or fail soft (`denied`).
 */
export type ResolveOutcome =
  /** Known `(provider, subject)` → its owning user. */
  | { kind: "linked"; userId: string; isNew: false }
  /** No match → a fresh account was created and linked. */
  | { kind: "created"; userId: string; isNew: true }
  /** Email matched an existing account and policy auto-linked it. */
  | { kind: "auto-linked"; userId: string; isNew: false }
  /** Email matched an existing account; interactive proof-of-control required to link. */
  | { kind: "needs-link"; candidateUserId: string }
  /** Refused: signup disabled with no match, or policy needed an email the provider lacked. */
  | { kind: "denied"; reason: "signup-disabled" | "email-unavailable" };
