import type { Clock } from "@aooth/auth";
import { OAuthError } from "./errors";
import {
  type OAuthStatePayload,
  type SignStateOptions,
  type VerifyStateOptions,
  signState,
  verifyState,
} from "./state";
import {
  type FederatedPolicy,
  type FetchLike,
  type IdentityProvider,
  type ResolvedFederatedPolicy,
  type SharedProviderConfig,
  isConfigurableProvider,
  resolveFederatedPolicy,
} from "./types";

export interface OAuthProviderRegistryOptions {
  /** Public origin — `redirect_uri` is built as `baseUrl` + the callback path (§3.7). */
  baseUrl: string;
  /** HMAC secret that signs the `state` JWT (and, in phase 3, the Lax PKCE cookie). */
  stateSecret: string;
  /** The configured providers. Duplicate ids are rejected. */
  providers: IdentityProvider[];
  /** Account-matching policy (RFC §4). Safe defaults applied. */
  policy?: FederatedPolicy;
  /**
   * Callback path template; `:provider` is substituted per provider. Default
   * `/auth/oauth/:provider/callback` (matches the phase-3 `OAuthController`).
   */
  callbackPathTemplate?: string;

  // --- shared verification config injected into every ConfigurableProvider ---
  clockToleranceSec?: number;
  jwks?: { cacheTtlMs?: number; refreshOnUnknownKid?: boolean };
  clock?: Clock;
  fetch?: FetchLike;
}

const DEFAULT_CALLBACK_TEMPLATE = "/auth/oauth/:provider/callback";

/**
 * Holds the configured {@link IdentityProvider}s + {@link FederatedPolicy} +
 * the shared signing/verification config (decision #2). Framework-agnostic —
 * phase 3 only DI-binds it. On construction it injects the shared config into
 * each provider that implements `applyDefaults`, and builds the per-provider
 * fixed redirect URIs.
 */
export class OAuthProviderRegistry {
  readonly baseUrl: string;
  readonly stateSecret: string;
  readonly policy: ResolvedFederatedPolicy;
  private readonly providers = new Map<string, IdentityProvider>();
  private readonly callbackPathTemplate: string;

  constructor(opts: OAuthProviderRegistryOptions) {
    if (!opts.baseUrl)
      throw new OAuthError("INVALID_CONFIG", "OAuthProviderRegistry requires a 'baseUrl'");
    if (!opts.stateSecret) {
      throw new OAuthError("INVALID_CONFIG", "OAuthProviderRegistry requires a 'stateSecret'");
    }
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.stateSecret = opts.stateSecret;
    this.policy = resolveFederatedPolicy(opts.policy);
    this.callbackPathTemplate = opts.callbackPathTemplate ?? DEFAULT_CALLBACK_TEMPLATE;

    const shared: SharedProviderConfig = {
      clockToleranceSec: opts.clockToleranceSec,
      jwks: opts.jwks,
      clock: opts.clock,
      fetch: opts.fetch,
    };
    for (const p of opts.providers) {
      if (this.providers.has(p.id)) {
        throw new OAuthError("INVALID_CONFIG", `Duplicate provider id '${p.id}'`);
      }
      if (isConfigurableProvider(p)) p.applyDefaults(shared);
      this.providers.set(p.id, p);
    }
  }

  /** Is a provider with this id registered? */
  has(id: string): boolean {
    return this.providers.has(id);
  }

  /** Resolve a provider, or `undefined`. */
  get(id: string): IdentityProvider | undefined {
    return this.providers.get(id);
  }

  /** Resolve a provider, or throw `OAuthError('UNKNOWN_PROVIDER')` (→ HTTP 404 in phase 3). */
  require(id: string): IdentityProvider {
    const p = this.providers.get(id);
    if (!p) throw new OAuthError("UNKNOWN_PROVIDER", undefined, { provider: id });
    return p;
  }

  /** Registered provider ids, in insertion order. */
  ids(): string[] {
    return [...this.providers.keys()];
  }

  /** All registered providers, in insertion order. */
  list(): IdentityProvider[] {
    return [...this.providers.values()];
  }

  /** The callback path for a provider (template with `:provider` substituted). */
  callbackPath(providerId: string): string {
    return this.callbackPathTemplate.replace(":provider", encodeURIComponent(providerId));
  }

  /** The FIXED, exact-match-registered `redirect_uri` for a provider (`baseUrl` + callback path). */
  redirectUri(providerId: string): string {
    return `${this.baseUrl}${this.callbackPath(providerId)}`;
  }

  /** Sign a state payload with the registry's `stateSecret`. */
  signState(payload: OAuthStatePayload, opts?: SignStateOptions): Promise<string> {
    return signState(payload, this.stateSecret, opts);
  }

  /** Verify + decode a state token against the registry's `stateSecret`. */
  verifyState(token: string, opts?: VerifyStateOptions): Promise<OAuthStatePayload> {
    return verifyState(token, this.stateSecret, opts);
  }
}
