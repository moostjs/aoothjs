/**
 * What a successful auth check produces.
 * Generic over TClaims for typed custom claims.
 */
export interface AuthContext<TClaims extends object = object> {
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
  claims?: TClaims;
}

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
}

/**
 * Persisted state of a credential.
 */
export interface CredentialState<TClaims extends object = object> {
  userId: string;
  issuedAt: number;
  expiresAt: number;
  claims?: TClaims;
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
   * Note: 'sliding' grace-period replay tolerance only works against stateful
   * stores (e.g. {@link CredentialStoreMemory}). Stateless stores (JWT,
   * Encapsulated) cannot mutate an issued token in place; after the first
   * rotation the old refresh becomes unusable, so 'sliding' degrades to
   * 'always' semantics. Use 'always' explicitly for stateless deployments.
   */
  rotation?: "none" | "always" | "sliding";
  /** Grace period for sliding rotation, in milliseconds. Defaults to 30_000. */
  rotationGraceMs?: number;
  /** Theft detection hook — invoked when a previously-rotated refresh is reused. */
  onRotationReuse?: (state: CredentialState) => void;
}
