/**
 * What a successful auth check produces.
 * Generic over TClaims for typed custom claims.
 */
export interface AuthContext<TClaims extends object = object> {
  userId: string;
  method: "session" | "token";
  credentialId: string;
  expiresAt: number;
  claims?: TClaims;
}

/**
 * Display metadata for stateful credentials.
 * Extensible via TypeScript declaration merging:
 *   declare module '@aoothjs/auth' {
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
}

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
  /** Rotation strategy. Defaults to 'sliding'. */
  rotation?: "none" | "always" | "sliding";
  /** Grace period for sliding rotation, in milliseconds. Defaults to 30_000. */
  rotationGraceMs?: number;
  /** Theft detection hook — invoked when a previously-rotated refresh is reused. */
  onRotationReuse?: (state: CredentialState) => void;
}
