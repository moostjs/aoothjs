/**
 * Resolves the OIDC profile claims to embed in an `id_token` for a given user +
 * granted scope (AUTH-SERVER.md §4.9). The authorization server already controls
 * the registered claims (`iss`/`aud`/`sub`/`iat`/`exp`/`nonce`) itself — this seam
 * supplies the **profile** claims that depend on the consumer's user shape
 * (`email`/`email_verified`/`name`/`picture`), which `@aooth/auth` cannot know.
 *
 * Pluggable like every other store/policy: the no-op default ({@link NoopOidcClaimsResolver},
 * `sub`-only tokens) ships, and a consumer subclasses it to read its own user
 * record. Bound in `@aooth/auth-moost` under `OIDC_CLAIMS_RESOLVER_TOKEN`.
 *
 * The map's keys are standard OIDC claim names; values MUST be JSON-safe. Honour
 * the granted `scope` — only emit `email`/`email_verified` under `email`, and
 * `name`/`picture`/etc. under `profile`, so a client receives only what it asked
 * for (and was allowed).
 */
export abstract class OidcClaimsResolver {
  /**
   * @param userId  the authenticated subject (the `id_token` `sub`).
   * @param scope   the granted scope, space-joined (e.g. `"openid email profile"`), or undefined.
   * @returns       a flat map of standard OIDC profile claims to merge into the `id_token`.
   */
  abstract resolveClaims(
    userId: string,
    scope: string | undefined,
  ): Record<string, unknown> | Promise<Record<string, unknown>>;
}

/** Default resolver: emits no profile claims, so the `id_token` carries only `sub` + the registered claims. */
export class NoopOidcClaimsResolver extends OidcClaimsResolver {
  resolveClaims(): Record<string, unknown> {
    return {};
  }
}

/** `true` when `scope` (space-joined) grants `claim` — `"email"`/`"profile"` etc. */
export function scopeGrants(scope: string | undefined, claim: string): boolean {
  if (!scope) return false;
  return scope.split(/\s+/u).includes(claim);
}
