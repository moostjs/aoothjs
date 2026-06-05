/**
 * The read-time envelope a successful auth check always produces — the fixed
 * fields, before the credential's typed payload is merged in. See
 * {@link AuthContext}.
 */
export interface AuthContextBase {
  userId: string;
  method: "session" | "token";
  credentialId: string;
  /**
   * Stable id of the session (token family) that authenticated this request.
   * Survives refresh-token rotation (see {@link CredentialState.sessionId}).
   * Legacy tokens issued before sessionId existed fall back to the token
   * fingerprint, so a session is always identifiable. Lets a consumer match
   * "this device" against {@link SessionInfo} and pass `keepSessionId` to
   * `revokeOtherSessions`.
   */
  sessionId?: string;
  expiresAt: number;
}

/**
 * What a successful auth check produces: the {@link AuthContextBase} envelope
 * intersected with the credential's **typed payload** `TPayload` — the root
 * fields a consumer adds to their credential model (e.g. an
 * `@arbac.attenuate.*`-annotated field read by `@aooth/arbac-moost`). There is
 * no free-form `claims` container; per-token data is typed, validated root
 * fields that round-trip through the store and surface here by name.
 */
export type AuthContext<TPayload extends object = object> = AuthContextBase & TPayload;

/**
 * Display metadata for stateful credentials.
 * Extensible via TypeScript declaration merging:
 *   declare module '@aooth/auth' {
 *     interface CredentialMetadata { geoCountry?: string }
 *   }
 */
export interface CredentialMetadata {
  ip?: string;
  userAgent?: string;
  fingerprint?: string;
  label?: string;
  /**
   * Semantic credential kind — e.g. `"cli-session"` / `"pat"` — distinct from
   * the internal {@link CredentialState.kind} (`access`/`refresh`) discriminator.
   * Set from `IssueOptions.kind` at mint time and carried forward across
   * rotation with the rest of `metadata`, so the whole session family shares it.
   * Stored here (not as a top-level envelope column) so it round-trips through
   * every store with no schema change; surfaced as {@link SessionInfo.kind} and
   * the `listSessions({ kind })` filter. Absent ⇒ an ordinary interactive session.
   */
  credentialKind?: string;
}

/**
 * Persisted state of a credential — the fixed **envelope**. A consumer's
 * per-token payload is NOT a field here; it is carried as additional typed
 * root fields intersected via `CredentialState & TPayload` (the orchestrator,
 * stores, and atscript-db adapter are generic over that payload). Reserved
 * envelope keys (see {@link credentialPayloadOf}) must not be reused as
 * payload field names.
 */
export interface CredentialState {
  userId: string;
  issuedAt: number;
  expiresAt: number;
  metadata?: CredentialMetadata;
  /**
   * Discriminant between access and refresh credentials persisted in the same store.
   * Defaults to "access" when omitted.
   */
  kind?: "access" | "refresh";
  /** For rotated refresh tokens — id of the parent credential this one replaced */
  parentCredentialId?: string;
  /** Timestamp of rotation; used by sliding rotation grace period */
  rotatedAt?: number;
  /**
   * Stable id of the session (token family) this credential belongs to. Minted
   * once by `issue()` and copied forward onto every rotation (access + refresh),
   * so a single login = one `sessionId` for its whole lifetime. The keystone for
   * grouping access/refresh/rotations into one row in {@link SessionInfo} and for
   * per-session revoke. Opaque + random; never derived from token material.
   */
  sessionId?: string;
  /**
   * Last activity timestamp for the session. Only written when
   * `AuthCredential` is configured with `trackLastSeen`; otherwise undefined and
   * consumers fall back to `issuedAt`. See {@link SessionInfo.lastSeenAt}.
   */
  lastSeenAt?: number;
}

/**
 * One logical session — a token family collapsed into a single row. Returned by
 * `AuthCredential.listSessions`; the public surface the "active sessions" UI
 * reads (richer than {@link AuthContext}, additive). Stores only raw facts;
 * device/browser/os/location are derived at read time via {@link SessionEnricher}.
 */
export interface SessionInfo {
  /** Stable across rotation; see {@link CredentialState.sessionId}. */
  sessionId: string;
  userId: string;
  /** `issuedAt` of the session's origin credential. */
  createdAt: number;
  /** Newest activity time across the family; falls back to `createdAt` when untracked. */
  lastSeenAt?: number;
  /** Expiry of the session's live refresh token (or access token when no refresh). */
  expiresAt: number;
  /** Set by the caller (e.g. `SessionsController`) when this is the caller's own session. */
  current?: boolean;
  metadata?: CredentialMetadata;
  /**
   * Semantic credential kind of the family (`metadata.credentialKind`) — e.g.
   * `"cli-session"` / `"pat"`. Omitted for ordinary interactive sessions. Lets a
   * UI segment non-browser credentials into their own bucket; the matching
   * filter is `listSessions({ kind })`.
   */
  kind?: string;
}

/**
 * A {@link SessionInfo} enriched with derived, non-stored fields. Produced by a
 * consumer-supplied {@link SessionEnricher} at read time so aooth ships no
 * UA-parser or geo dependency and stores no derived data.
 */
export interface EnrichedSession extends SessionInfo {
  device?: string;
  browser?: string;
  os?: string;
  location?: string;
  geo?: { country?: string; city?: string };
}

/**
 * Read-time enrichment hook. Maps a raw {@link SessionInfo} to an
 * {@link EnrichedSession} (e.g. parse `metadata.userAgent`, GeoIP-lookup
 * `metadata.ip`). Plugged in via `listSessions(userId, { enrich })`.
 */
export type SessionEnricher = (s: SessionInfo) => EnrichedSession | Promise<EnrichedSession>;

/**
 * Result of issuing a credential or refreshing it.
 */
export interface IssueResult {
  accessToken: string;
  refreshToken?: string;
  accessExpiresAt: number;
  refreshExpiresAt?: number;
}

/**
 * Refresh token configuration.
 */
export interface RefreshConfig {
  /** Refresh token lifetime in milliseconds. */
  ttl: number;
  /**
   * Rotation strategy. Defaults to 'sliding'.
   *
   * - `'none'` — issue a new access token only; the refresh token stays in place.
   * - `'sliding'` — rotate the refresh token on every use and **slide** its
   *   expiry forward (`now + ttl`); a rolling session that lives as long as it
   *   keeps being used.
   * - `'always'` — rotate the refresh token on every use but keep a **fixed**
   *   session ceiling: each rotated token inherits the family's original
   *   `expiresAt`, so the session has an absolute maximum lifetime regardless of
   *   activity.
   *
   * Both `'sliding'` and `'always'` are **grace-tolerant** on stateful stores:
   * a benign concurrent refresh (multi-tab / parallel requests presenting the
   * just-rotated token) within {@link rotationGraceMs} re-issues a fresh pair
   * instead of being mistaken for token theft. Because the grace window is
   * tracked in the store (via {@link CredentialState.rotatedAt}), it is correct
   * across multiple app instances.
   *
   * Note: the grace window needs a stateful store (one with `listForUser`).
   * Stateless stores (JWT, Encapsulated) cannot mutate an issued token in place;
   * after the first rotation the old refresh becomes unusable, so on those
   * stores both `'sliding'` and `'always'` fall back to single-use semantics
   * with a process-local reuse signal (no cross-instance grace).
   */
  rotation?: "none" | "always" | "sliding";
  /** Grace period for sliding/always rotation, in milliseconds. Defaults to 30_000. */
  rotationGraceMs?: number;
  /**
   * Revocation scope when refresh-token reuse is detected (replay after grace,
   * or — on stateless stores — replay of a single-use token). Defaults to
   * `'session'`: revoke only the compromised token family
   * ({@link AuthCredential.revokeSession}), the OAuth-best-practice response.
   * `'user'` revokes every session for the user
   * ({@link AuthCredential.revokeAllForUser}) — more aggressive, opt-in. On
   * stateless stores that cannot enumerate sessions, `'session'` falls back to
   * the user-wide revocation epoch regardless.
   */
  reuseResponse?: "session" | "user";
  /** Theft detection hook — invoked when a previously-rotated refresh is reused. */
  onRotationReuse?: (state: CredentialState) => void;
}
