import type { IssueOptions } from "../credential/auth-credential";

/**
 * What the authorization server mints for a completed grant — forwarded verbatim
 * into `AuthCredential.issue(userId, …)` at the token endpoint. Decided by the
 * {@link import("./client-policy").ClientRedirectPolicy} (per client / scope),
 * never by the client request, and recorded on the pending-authorization + the
 * issued auth-code so the grant's authority is fixed at `/authorize` time, not
 * `/token` time.
 *
 * Tier 1 (CLI / loopback) → a full-authority `cli-session` (`{ kind, ttl }`, no
 * `payload`). A scoped service token (Tier 2) additionally sets `payload` with
 * the consumer's attenuation root fields.
 */
export interface TokenPolicy {
  /** Semantic credential kind stamped on the token (e.g. `"cli-session"`). See `IssueOptions.kind`. */
  kind?: string;
  /** Per-mint access-token lifetime in ms (forwarded to `IssueOptions.ttl`). */
  ttl?: number;
  /**
   * Extra root payload merged into `issue()` — e.g. `@arbac.attenuate.*` fields
   * for a SCOPED token. Omit for a full-authority token. MUST be JSON-safe: it
   * is persisted on the pending-authorization + auth-code records.
   */
  payload?: Record<string, unknown>;
  /**
   * Opt-in refresh dimension (OAuth 2.1 `refresh_token` grant): when set, the
   * token endpoint mints a rotating refresh token alongside the access token
   * and redeems `grant_type=refresh_token` for the family. `ttl` is the
   * refresh-token (i.e. grant) lifetime in ms — defaults to
   * {@link DEFAULT_AUTHZ_REFRESH_TTL_MS} (30 days). Absent ⇒ today's behavior:
   * access token only, re-consent at expiry.
   *
   * Honored only for grants bound to a registered `client_id` (Tier-2 /
   * dynamic clients) — the family is stamped with `metadata.authzClientId` and
   * a refresh token redeems only for that client. A clientless (Tier-1
   * loopback) grant has nothing to bind to, so the flag is IGNORED there.
   */
  refresh?: { ttl?: number };
}

/**
 * Default refresh-token (grant) lifetime for {@link TokenPolicy.refresh} when
 * no `ttl` is given: 30 days. Deliberately independent of the session tier's
 * `AuthCredentialOptions.refresh.ttl` — an authz grant's lifetime is the
 * policy's decision, never inherited from browser-session posture.
 */
export const DEFAULT_AUTHZ_REFRESH_TTL_MS = 30 * 24 * 60 * 60_000;

/**
 * Flatten a {@link TokenPolicy} into the `AuthCredential.issue()` options a
 * token endpoint forwards. The refresh dimension applies only to client-bound
 * grants — the family is stamped with `metadata.authzClientId`, the binding
 * the `refresh_token` grant enforces — so a clientless (loopback) grant
 * ignores `policy.refresh`. `refresh: false` otherwise: an authz mint never
 * rides the instance-level session refresh config (no orphaned refresh row
 * for a policy that didn't opt in). Lives HERE, next to the policy type and
 * its default ttl, so every HTTP adapter applies the same semantics.
 */
export function tokenPolicyToIssueOptions(
  policy: TokenPolicy,
  clientId: string | undefined,
): IssueOptions {
  const withRefresh = policy.refresh !== undefined && clientId !== undefined;
  return {
    ...policy.payload,
    ...(policy.kind !== undefined && { kind: policy.kind }),
    ...(policy.ttl !== undefined && { ttl: policy.ttl }),
    refresh: withRefresh ? { ttl: policy.refresh?.ttl ?? DEFAULT_AUTHZ_REFRESH_TTL_MS } : false,
    ...(withRefresh && { metadata: { authzClientId: clientId } }),
  };
}
