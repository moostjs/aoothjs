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
}
