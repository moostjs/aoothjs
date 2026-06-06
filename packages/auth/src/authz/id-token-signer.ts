import { type CryptoKey, type JWK, SignJWT, exportJWK, importPKCS8, importSPKI } from "jose";

import { type Clock, defaultClock } from "../utils/clock";

/** Asymmetric signing algorithms an OIDC `id_token` may use (AUTH-SERVER.md §4.9). */
export type IdTokenAlg = "RS256" | "ES256";

export interface IdTokenSignerOptions {
  /**
   * The OIDC issuer — the `iss` claim AND the discovery `issuer`. A relying
   * `OidcProvider` checks `id_token.iss` against this exactly, so it must match
   * the value it was configured with (typically `{origin}/auth`).
   */
  issuer: string;
  /** Signature algorithm. Default `"RS256"` (most universally accepted; `OidcProvider` accepts RS256/ES256). */
  alg?: IdTokenAlg;
  /** Key id — stamped in the JWS header AND the published JWKS entry, so a verifier matches the right key. */
  kid: string;
  /** PKCS8 PEM private key (lazily imported + cached). */
  privateKey: string;
  /** SPKI PEM public key — published in the JWKS so verifiers fetch it (lazily imported + cached). */
  publicKey: string;
  /** `id_token` lifetime in seconds. Default 300 (5 min — it is exchanged immediately). */
  ttlSec?: number;
  /** Injectable clock for deterministic `iat`/`exp` in tests. Defaults to wall-clock. */
  clock?: Clock;
}

/** The claims the authorization server controls per-mint; profile claims ride `extra`. */
export interface IdTokenClaims {
  /** Subject — the stable user id (the token subject). */
  sub: string;
  /** Audience — the requesting `client_id`. Binds the token to one client (§6 audience binding). */
  aud: string;
  /** Echoed from the `/authorize` request when present; a relying party checks it to defeat replay. */
  nonce?: string;
  /** Per-mint lifetime override (seconds). */
  ttlSec?: number;
  /** Profile/standard claims merged into the payload (e.g. `email`, `email_verified`, `name`). MUST be JSON-safe. */
  extra?: Record<string, unknown>;
}

/**
 * Signs OIDC `id_token`s and publishes the matching JWKS (AUTH-SERVER.md §4.9).
 * Holds one asymmetric keypair; mints short-lived RS256/ES256 tokens with the
 * issuer + audience + subject a relying `OidcProvider` validates, and exports the
 * public half as a JWKS for `GET /auth/jwks`. Keys are imported lazily and cached
 * (the Apple-client-secret pattern), so construction is cheap and synchronous.
 *
 * Never used for the access token (that stays in `AuthCredential`'s store) — the
 * `id_token` is a separate, audience-bound identity assertion.
 */
export class IdTokenSigner {
  /** The `iss` claim + discovery `issuer` (read by `/.well-known/openid-configuration`). */
  readonly issuer: string;
  /** Signature algorithm — published in discovery's `id_token_signing_alg_values_supported`. */
  readonly alg: IdTokenAlg;
  /** Key id — the JWS header + JWKS entry `kid`. */
  readonly kid: string;
  private readonly privateKeyPem: string;
  private readonly publicKeyPem: string;
  private readonly ttlSec: number;
  private readonly clock: Clock;

  private privateKeyPromise?: Promise<CryptoKey>;
  private jwksPromise?: Promise<{ keys: JWK[] }>;

  constructor(opts: IdTokenSignerOptions) {
    // Canonicalise once (strip a trailing slash) so the `iss` claim, the discovery
    // `issuer`, and the derived endpoint URLs are all byte-identical — a relying
    // OidcProvider compares `iss` / `doc.issuer` for EXACT string equality (RFC 8414).
    this.issuer = opts.issuer.replace(/\/$/u, "");
    this.alg = opts.alg ?? "RS256";
    this.kid = opts.kid;
    this.privateKeyPem = opts.privateKey;
    this.publicKeyPem = opts.publicKey;
    this.ttlSec = opts.ttlSec ?? 300;
    this.clock = opts.clock ?? defaultClock;
  }

  /** Mint a signed `id_token` JWT. Iat/exp come from the injected clock. */
  async sign(claims: IdTokenClaims): Promise<string> {
    const key = await this.importPrivateKey();
    const nowSec = Math.floor(this.clock.now() / 1000);
    const ttl = claims.ttlSec ?? this.ttlSec;
    const payload: Record<string, unknown> = { ...claims.extra };
    if (claims.nonce !== undefined) payload.nonce = claims.nonce;
    return new SignJWT(payload)
      .setProtectedHeader({ alg: this.alg, kid: this.kid, typ: "JWT" })
      .setIssuer(this.issuer)
      .setSubject(claims.sub)
      .setAudience(claims.aud)
      .setIssuedAt(nowSec)
      .setExpirationTime(nowSec + ttl)
      .sign(key);
  }

  /**
   * The JWKS document served at `/auth/jwks` — the public key as a single
   * `use: "sig"` entry tagged with the same `kid`/`alg` as the minted tokens, so
   * a verifier selects it by `kid`. Computed once and cached.
   */
  async jwks(): Promise<{ keys: JWK[] }> {
    this.jwksPromise ??= (async () => {
      const pub = await importSPKI(this.publicKeyPem, this.alg, { extractable: true });
      const jwk = await exportJWK(pub);
      jwk.kid = this.kid;
      jwk.alg = this.alg;
      jwk.use = "sig";
      return { keys: [jwk] };
    })();
    return this.jwksPromise;
  }

  private importPrivateKey(): Promise<CryptoKey> {
    this.privateKeyPromise ??= importPKCS8(this.privateKeyPem, this.alg);
    return this.privateKeyPromise;
  }
}
