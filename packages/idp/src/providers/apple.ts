import { type CryptoKey, type JWTPayload, SignJWT, importPKCS8 } from "jose";
import { OAuthError } from "../errors";
import type { AuthorizationUrlArgs, NormalizedProfile } from "../types";
import { type ClientSecretFactory, OidcProvider, type OidcProviderOptions } from "./oidc";

/** Apple's stable OIDC issuer — endpoints + JWKS are discovered from it. */
const APPLE_ISSUER = "https://appleid.apple.com";

/** Apple ID tokens are always ES256. */
const APPLE_SIGNING_ALGS = ["ES256"];

/** Default scope — `openid email`; `name` is omitted (Apple sends it once, out-of-band; deferred). */
const DEFAULT_APPLE_SCOPES = ["openid", "email"];

/** Default client-secret JWT lifetime (1h). Apple's hard ceiling is ~6 months (15777000s). */
const DEFAULT_SECRET_TTL_SEC = 3600;

/** A minute of slack so a cached secret is never served right at its expiry. */
const SECRET_RENEW_SLACK_SEC = 60;

export interface AppleProviderOptions extends Omit<
  OidcProviderOptions,
  "id" | "issuer" | "clientSecret" | "idTokenSigningAlgs" | "scopes"
> {
  /** The Services ID — Sign in with Apple's OAuth `client_id` (and the id_token `aud`). */
  clientId: string;
  /** Apple Developer Team ID (10 chars) — the client-secret JWT `iss`. */
  teamId: string;
  /** The `.p8` private key's Key ID — the client-secret JWT header `kid`. */
  keyId: string;
  /** The `.p8` EC P-256 private key in PKCS#8 PEM form — mints the ES256 client secret. */
  privateKey: string;
  /** Requested scopes. Default `['openid', 'email']`. */
  scopes?: string[];
  /** Client-secret JWT lifetime, seconds (Apple max ≈ 6 months). Default `3600`. */
  clientSecretTtlSec?: number;
}

/**
 * Build Apple's dynamic `client_secret` source: a closure that mints — and
 * caches — a short-lived ES256 JWT signed with the `.p8` key. Header
 * `{ alg: 'ES256', kid }`, claims `{ iss: teamId, iat, exp, aud: APPLE_ISSUER,
 * sub: clientId }`. The signed JWT is reused until shortly before its `exp`, and
 * the (comparatively costly) `.p8` import is memoized — so a burst of exchanges
 * shares one signature and parses the key at most once. The clock comes from the
 * per-call context, so a registry-injected clock still drives `iat`/`exp`.
 */
function makeAppleClientSecretFactory(cfg: {
  clientId: string;
  teamId: string;
  keyId: string;
  privateKey: string;
  ttlSec: number;
}): ClientSecretFactory {
  let cachedSecret: { jwt: string; expSec: number } | undefined;
  let importedKey: Promise<CryptoKey> | undefined;

  return async ({ clock }) => {
    const nowSec = Math.floor(clock.now() / 1000);
    if (cachedSecret && cachedSecret.expSec - nowSec > SECRET_RENEW_SLACK_SEC) {
      return cachedSecret.jwt;
    }
    let key: CryptoKey;
    try {
      importedKey ??= importPKCS8(cfg.privateKey, "ES256");
      key = await importedKey;
    } catch (err) {
      importedKey = undefined; // don't cache a rejected import
      throw new OAuthError(
        "INVALID_CONFIG",
        "AppleProvider could not import the '.p8' private key",
        { cause: String(err) },
      );
    }
    const expSec = nowSec + cfg.ttlSec;
    const jwt = await new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: cfg.keyId })
      .setIssuer(cfg.teamId)
      .setIssuedAt(nowSec)
      .setExpirationTime(expSec)
      .setAudience(APPLE_ISSUER)
      .setSubject(cfg.clientId)
      .sign(key);
    cachedSecret = { jwt, expSec };
    return jwt;
  };
}

/**
 * Sign in with Apple (OIDC). A thin subclass of {@link OidcProvider} — Apple IS
 * an OpenID Connect provider (issuer `https://appleid.apple.com`, discoverable
 * endpoints + JWKS), so the whole §7 ID-token validation, JWKS rotation, PKCE,
 * and discovery are inherited. Only the things Apple does differently are
 * wired/overridden here:
 *
 * 1. **No static client secret.** Apple's `client_secret` is a short-lived
 *    **ES256 JWT** signed with the developer's `.p8` key. The constructor wires
 *    a {@link ClientSecretFactory} ({@link makeAppleClientSecretFactory}) that
 *    mints + caches it per token exchange — no base seam to override.
 * 2. **`response_mode=form_post`.** Apple requires it whenever `email`/`name`
 *    scope is requested, so the callback is a cross-site **POST**. The
 *    `@aooth/auth-moost` `OAuthController` bounces that POST back to the normal
 *    GET callback path, so everything downstream (state, CSRF, exchange) is
 *    byte-identical to Google/GitHub.
 * 3. **String `email_verified`.** Apple violates OIDC by sending
 *    `email_verified` (and `is_private_email`) as the STRING `"true"`/`"false"`;
 *    {@link normalize} coerces it after the base's strict boolean-only pass.
 *
 * NOTE: the user's NAME arrives only on the FIRST authorization, in the
 * form_post `user` field (never in the id_token) — v1 deliberately does not
 * capture it, so `displayName` is undefined for Apple. Collect a display name
 * post-signup if you need one.
 */
export class AppleProvider extends OidcProvider {
  constructor(opts: AppleProviderOptions) {
    if (!opts.teamId || !opts.keyId || !opts.privateKey) {
      throw new OAuthError(
        "INVALID_CONFIG",
        "AppleProvider requires 'teamId', 'keyId', and 'privateKey'",
      );
    }
    super({
      ...opts,
      id: "apple",
      issuer: APPLE_ISSUER,
      // Apple has no static secret — mint a fresh ES256 JWT per request.
      clientSecret: makeAppleClientSecretFactory({
        clientId: opts.clientId,
        teamId: opts.teamId,
        keyId: opts.keyId,
        privateKey: opts.privateKey,
        ttlSec: opts.clientSecretTtlSec ?? DEFAULT_SECRET_TTL_SEC,
      }),
      idTokenSigningAlgs: APPLE_SIGNING_ALGS,
      scopes: opts.scopes ?? DEFAULT_APPLE_SCOPES,
    });
  }

  /** `email`/`name` scope makes Apple POST the callback — declare `form_post`. */
  protected override extraAuthorizationParams(_args: AuthorizationUrlArgs): Record<string, string> {
    return { response_mode: "form_post" };
  }

  /** Coerce Apple's STRING `email_verified` (the base sets only a real boolean). */
  protected override normalize(payload: JWTPayload): NormalizedProfile {
    const profile = super.normalize(payload);
    if (profile.emailVerified === undefined) {
      // Reached only when the base left it unset, i.e. the claim was NOT a real
      // boolean — so the STRING form is the only case left to coerce here.
      const ev = (payload as Record<string, unknown>).email_verified;
      if (ev === "true") profile.emailVerified = true;
      else if (ev === "false") profile.emailVerified = false;
    }
    return profile;
  }
}
