import { createHash } from "node:crypto";
import { type Clock, defaultClock } from "@aooth/auth";
import { type JWTPayload, type JWTVerifyGetKey, createRemoteJWKSet, jwtVerify } from "jose";
import { OAuthError } from "../errors";
import type {
  AuthorizationUrlArgs,
  ConfigurableProvider,
  ExchangeArgs,
  FetchLike,
  NormalizedProfile,
  SharedProviderConfig,
} from "../types";

/** The four endpoints the OIDC client needs — discovered or supplied explicitly. */
export interface OidcDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

export interface OidcProviderOptions {
  /** Provider id. Default `oidc:<issuer>`; `GoogleProvider` pins `'google'`. */
  id?: string;
  /** The exact issuer — used for discovery AND `iss` validation (must match). */
  issuer: string;
  clientId: string;
  clientSecret: string;
  /** Requested scopes. Default `['openid', 'email', 'profile']`. */
  scopes?: string[];
  /**
   * ID-token signing algs to accept (RFC §7: pin to asymmetric, reject
   * `none`/HMAC). Default `['RS256', 'ES256']`. `none`/HS* are rejected purely
   * by never appearing in this list.
   */
  idTokenSigningAlgs?: string[];

  // --- explicit endpoints / injected seams (skip network — tests & non-discovery IdPs) ---
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  jwksUri?: string;
  /** Inject a discovery document (skips the `.well-known` fetch). */
  discovery?: OidcDiscoveryDocument;
  /** Inject a JWKS key resolver (e.g. `createLocalJWKSet`) — skips the remote JWKS fetch. */
  jwks?: JWTVerifyGetKey;

  // --- tunables (also injectable by the registry via applyDefaults) ---
  /** Bounded clock skew for `exp`/`iat`/`nbf`, seconds. Default `5`. */
  clockToleranceSec?: number;
  /** Remote-JWKS cache lifetime, ms. Default `3_600_000` (1h). */
  jwksCacheTtlMs?: number;
  clock?: Clock;
  fetch?: FetchLike;
}

const DEFAULT_SCOPES = ["openid", "email", "profile"];
const DEFAULT_SIGNING_ALGS = ["RS256", "ES256"];
const DEFAULT_CLOCK_TOLERANCE_SEC = 5;
const DEFAULT_JWKS_CACHE_MS = 3_600_000;

/**
 * Generic OpenID Connect provider: authorization-code + PKCE, full discovery,
 * remote JWKS, and the OIDC Core 3.1.3.7 ID-token validation list (RFC §7).
 * Verification fails CLOSED — a JWKS/discovery fetch failure is an
 * `OAuthError('JWKS_FAILED')`, never a silent accept.
 *
 * `GoogleProvider` is a thin subclass pinning the issuer + algs.
 */
export class OidcProvider implements ConfigurableProvider {
  readonly id: string;
  protected readonly issuer: string;
  protected readonly clientId: string;
  protected readonly clientSecret: string;
  protected readonly scopes: string[];
  protected readonly signingAlgs: string[];

  private readonly explicitEndpoints?: OidcDiscoveryDocument;
  private readonly injectedDiscovery?: OidcDiscoveryDocument;
  private readonly injectedJwks?: JWTVerifyGetKey;

  // Tunables: undefined until set by ctor or applyDefaults; resolved with
  // defaults at use-time. A ctor-set value is non-undefined, so `applyDefaults`
  // fills only still-unset fields (`??=`) — a registry default never clobbers
  // an explicit constructor value.
  private clockToleranceSec?: number;
  private jwksCacheTtlMs?: number;
  private clockImpl?: Clock;
  private fetchImpl?: FetchLike;

  // caches
  private discoveryCache?: OidcDiscoveryDocument;
  private jwksCache?: { uri: string; resolver: JWTVerifyGetKey };

  constructor(opts: OidcProviderOptions) {
    if (!opts.issuer) throw new OAuthError("INVALID_CONFIG", "OIDC provider requires an 'issuer'");
    if (!opts.clientId || !opts.clientSecret) {
      throw new OAuthError(
        "INVALID_CONFIG",
        "OIDC provider requires 'clientId' and 'clientSecret'",
      );
    }
    this.id = opts.id ?? `oidc:${opts.issuer}`;
    this.issuer = opts.issuer;
    this.clientId = opts.clientId;
    this.clientSecret = opts.clientSecret;
    this.scopes = opts.scopes ?? DEFAULT_SCOPES;
    this.signingAlgs = opts.idTokenSigningAlgs ?? DEFAULT_SIGNING_ALGS;

    if (opts.authorizationEndpoint && opts.tokenEndpoint && opts.jwksUri) {
      this.explicitEndpoints = {
        issuer: opts.issuer,
        authorization_endpoint: opts.authorizationEndpoint,
        token_endpoint: opts.tokenEndpoint,
        jwks_uri: opts.jwksUri,
      };
    }
    this.injectedDiscovery = opts.discovery;
    this.injectedJwks = opts.jwks;

    this.clockToleranceSec = opts.clockToleranceSec;
    this.jwksCacheTtlMs = opts.jwksCacheTtlMs;
    this.clockImpl = opts.clock;
    this.fetchImpl = opts.fetch;
  }

  /** Registry-injected shared config; a ctor value always wins (decision #2). */
  applyDefaults(shared: SharedProviderConfig): void {
    this.clockToleranceSec ??= shared.clockToleranceSec;
    this.jwksCacheTtlMs ??= shared.jwks?.cacheTtlMs;
    this.clockImpl ??= shared.clock;
    this.fetchImpl ??= shared.fetch;
  }

  private get clock(): Clock {
    return this.clockImpl ?? defaultClock;
  }

  private get fetchFn(): FetchLike {
    return this.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  }

  async authorizationUrl(args: AuthorizationUrlArgs): Promise<string> {
    const { authorization_endpoint } = await this.resolveEndpoints();
    const url = new URL(authorization_endpoint);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", this.clientId);
    url.searchParams.set("redirect_uri", args.redirectUri);
    url.searchParams.set("scope", (args.scopes ?? this.scopes).join(" "));
    url.searchParams.set("state", args.state);
    url.searchParams.set("code_challenge", args.codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
    if (args.nonce) url.searchParams.set("nonce", args.nonce);
    return url.toString();
  }

  async exchange(args: ExchangeArgs): Promise<NormalizedProfile> {
    const { token_endpoint, jwks_uri } = await this.resolveEndpoints();
    const tokens = await this.postToken(token_endpoint, args);
    const idToken = tokens.id_token;
    if (typeof idToken !== "string") {
      throw new OAuthError("ID_TOKEN_INVALID", "Token response carried no id_token");
    }
    const accessToken = typeof tokens.access_token === "string" ? tokens.access_token : undefined;
    return this.verifyIdToken(idToken, accessToken, jwks_uri, args.expectedNonce);
  }

  // --- internals -------------------------------------------------------

  private async postToken(
    tokenEndpoint: string,
    args: ExchangeArgs,
  ): Promise<Record<string, unknown>> {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: args.code,
      redirect_uri: args.redirectUri,
      client_id: this.clientId,
      client_secret: this.clientSecret,
      code_verifier: args.codeVerifier,
    });
    let res: Awaited<ReturnType<FetchLike>>;
    try {
      res = await this.fetchFn(tokenEndpoint, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          accept: "application/json",
        },
        body: body.toString(),
      });
    } catch (err) {
      throw new OAuthError("EXCHANGE_FAILED", "Token endpoint request failed", {
        cause: String(err),
      });
    }
    if (!res.ok) {
      throw new OAuthError("EXCHANGE_FAILED", `Token endpoint returned ${res.status}`, {
        status: res.status,
      });
    }
    try {
      return (await res.json()) as Record<string, unknown>;
    } catch {
      throw new OAuthError("EXCHANGE_FAILED", "Token endpoint returned a non-JSON body");
    }
  }

  private async verifyIdToken(
    idToken: string,
    accessToken: string | undefined,
    jwksUri: string,
    expectedNonce: string | undefined,
  ): Promise<NormalizedProfile> {
    const keyResolver = await this.getJwks(jwksUri);

    let payload: JWTPayload;
    let alg: string;
    try {
      const result = await jwtVerify(idToken, keyResolver, {
        issuer: this.issuer,
        audience: this.clientId,
        algorithms: this.signingAlgs,
        clockTolerance: this.clockToleranceSec ?? DEFAULT_CLOCK_TOLERANCE_SEC,
        currentDate: new Date(this.clock.now()),
      });
      payload = result.payload;
      alg = result.protectedHeader.alg;
    } catch (err) {
      const code = (err as { code?: string })?.code ?? "";
      // JWKS fetch/lookup failures fail CLOSED as a distinct, retryable class;
      // everything else is a token-validation failure.
      if (code.startsWith("ERR_JWKS")) {
        throw new OAuthError("JWKS_FAILED", "Could not resolve the provider's signing key", {
          code,
        });
      }
      throw new OAuthError("ID_TOKEN_INVALID", "ID token failed verification", { code });
    }

    // --- §7 checks jose does not perform ---
    if (typeof payload.sub !== "string" || payload.sub.length === 0) {
      throw new OAuthError("ID_TOKEN_INVALID", "ID token has no subject");
    }
    // nonce: assert when one was minted at /start.
    if (expectedNonce !== undefined && payload.nonce !== expectedNonce) {
      throw new OAuthError("ID_TOKEN_INVALID", "ID token nonce mismatch");
    }
    // azp: required when the token has multiple audiences.
    if (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== this.clientId) {
      throw new OAuthError("ID_TOKEN_INVALID", "ID token azp does not match client");
    }
    // at_hash: validate when both an access token and the claim are present.
    if (accessToken !== undefined && typeof payload.at_hash === "string") {
      if (payload.at_hash !== atHash(accessToken, alg)) {
        throw new OAuthError("ID_TOKEN_INVALID", "ID token at_hash mismatch");
      }
    }

    return this.normalize(payload);
  }

  private normalize(payload: JWTPayload): NormalizedProfile {
    const profile: NormalizedProfile = {
      provider: this.id,
      subject: payload.sub as string,
      raw: payload,
    };
    if (typeof payload.email === "string") profile.email = payload.email;
    // OIDC mandates a boolean; we deliberately do NOT coerce string truthiness.
    if (typeof payload.email_verified === "boolean") profile.emailVerified = payload.email_verified;
    if (typeof payload.name === "string") profile.displayName = payload.name;
    if (typeof payload.picture === "string") profile.avatarUrl = payload.picture;
    return profile;
  }

  private async resolveEndpoints(): Promise<OidcDiscoveryDocument> {
    if (this.explicitEndpoints) return this.explicitEndpoints;
    if (this.injectedDiscovery) return this.validateDiscovery(this.injectedDiscovery);
    if (this.discoveryCache) return this.discoveryCache;

    const wellKnown = `${this.issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
    let doc: OidcDiscoveryDocument;
    try {
      const res = await this.fetchFn(wellKnown, { headers: { accept: "application/json" } });
      if (!res.ok) throw new Error(`discovery ${res.status}`);
      doc = (await res.json()) as OidcDiscoveryDocument;
    } catch (err) {
      // Fail closed: without endpoints we cannot verify anything.
      throw new OAuthError("JWKS_FAILED", "OIDC discovery failed", { cause: String(err) });
    }
    this.discoveryCache = this.validateDiscovery(doc);
    return this.discoveryCache;
  }

  /** OIDC discovery MUST echo the requested issuer (guards a swapped doc). */
  private validateDiscovery(doc: OidcDiscoveryDocument): OidcDiscoveryDocument {
    if (doc.issuer !== this.issuer) {
      throw new OAuthError("INVALID_CONFIG", "Discovery issuer does not match configured issuer", {
        expected: this.issuer,
        got: doc.issuer,
      });
    }
    if (!doc.authorization_endpoint || !doc.token_endpoint || !doc.jwks_uri) {
      throw new OAuthError("INVALID_CONFIG", "Discovery document is missing required endpoints");
    }
    return doc;
  }

  private async getJwks(jwksUri: string): Promise<JWTVerifyGetKey> {
    if (this.injectedJwks) return this.injectedJwks;
    if (this.jwksCache?.uri === jwksUri) return this.jwksCache.resolver;
    const resolver = createRemoteJWKSet(new URL(jwksUri), {
      cacheMaxAge: this.jwksCacheTtlMs ?? DEFAULT_JWKS_CACHE_MS,
    });
    this.jwksCache = { uri: jwksUri, resolver };
    return resolver;
  }
}

/**
 * OIDC at_hash (Core 3.1.3.6): base64url of the left-most half of the access
 * token's hash, the hash chosen by the id_token's `alg` (RS256 → SHA-256).
 */
function atHash(accessToken: string, alg: string): string {
  const sha = alg.endsWith("384") ? "sha384" : alg.endsWith("512") ? "sha512" : "sha256";
  const digest = createHash(sha).update(accessToken).digest();
  return digest.subarray(0, digest.length / 2).toString("base64url");
}
