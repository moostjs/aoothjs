import { OAuthError } from "../errors";
import type {
  AuthorizationUrlArgs,
  ExchangeArgs,
  IdentityProvider,
  NormalizedProfile,
} from "../types";
import { buildAuthorizeUrl } from "./oauth2-shared";

export interface FakeIdentityProviderOptions {
  /** Provider id. Default `'fake'`. */
  id?: string;
  /** The fake authorization endpoint a phase-3 e2e route bounces through. */
  authorizationEndpoint?: string;
  /** Profile returned for any `code` with no specific registration. */
  defaultProfile?: Omit<NormalizedProfile, "provider">;
}

/**
 * Deterministic, network-free {@link IdentityProvider} for unit tests and the
 * `DEMO_MODE=test` fake-IdP e2e route (RFC §9). `exchange` resolves a `code`
 * to a pre-registered profile (or the default), so the whole
 * `start → callback → resolveUser → gates` round trip runs offline.
 *
 * It does NOT verify a nonce — it is the trusted test double; the real §7
 * nonce/JWKS assertions are exercised against {@link OidcProvider} with `jose`.
 */
export class FakeIdentityProvider implements IdentityProvider {
  readonly id: string;
  private readonly authorizationEndpoint: string;
  private readonly defaultProfile?: Omit<NormalizedProfile, "provider">;
  private readonly profiles = new Map<string, Omit<NormalizedProfile, "provider">>();

  constructor(opts: FakeIdentityProviderOptions = {}) {
    this.id = opts.id ?? "fake";
    this.authorizationEndpoint = opts.authorizationEndpoint ?? "https://fake-idp.test/authorize";
    this.defaultProfile = opts.defaultProfile;
  }

  /** Register the profile a given `code` resolves to. Returns `this` for chaining. */
  setProfile(code: string, profile: Omit<NormalizedProfile, "provider">): this {
    this.profiles.set(code, profile);
    return this;
  }

  authorizationUrl(args: AuthorizationUrlArgs): Promise<string> {
    // Mimics an OIDC authorize request (carries the nonce) but is otherwise the
    // bare PKCE core — no client_id / scope, the e2e bounce doesn't need them.
    return Promise.resolve(buildAuthorizeUrl(this.authorizationEndpoint, args, { nonce: true }));
  }

  exchange(args: ExchangeArgs): Promise<NormalizedProfile> {
    const base = this.profiles.get(args.code) ?? this.defaultProfile;
    if (!base) {
      return Promise.reject(
        new OAuthError("EXCHANGE_FAILED", `Fake IdP has no profile for code '${args.code}'`),
      );
    }
    return Promise.resolve({ ...base, provider: this.id });
  }
}
