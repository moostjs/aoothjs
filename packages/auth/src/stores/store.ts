import type { CredentialState } from "../credential/types";

/**
 * Pluggable credential storage. Implementations: Memory, JWT, Encapsulated.
 * Same shape works for stateful and stateless stores. Stateless stores treat
 * the token as the state itself (sign/encrypt on persist, verify/decrypt on retrieve).
 *
 * The store is generic over the credential's typed **payload** `TPayload` — the
 * root fields a consumer adds to their credential model. Every state it handles
 * is `CredentialState & TPayload` (the envelope plus those flat root fields; no
 * `claims` container). `TPayload extends object` widens to arrays/classes, so
 * pass a plain object type (e.g. `{ scope: string; tier: number }`) whose
 * values survive a JSON round-trip on stateless stores.
 */
export interface CredentialStore<TPayload extends object = object> {
  /** Persist state, return token. For stateless stores, token IS the state. */
  persist(state: CredentialState & TPayload, ttl?: number): Promise<string>;
  /** Retrieve state from token. Returns null if expired/invalid/revoked. */
  retrieve(token: string): Promise<(CredentialState & TPayload) | null>;
  /** Retrieve + invalidate (single-use). For stateless: needs denylist. */
  consume(token: string): Promise<(CredentialState & TPayload) | null>;
  /**
   * Update state. The returned token MAY differ from the input — stateful
   * stores typically return the same token, while stateless stores re-issue
   * a new token (denylisting the old). Callers must use the returned value.
   */
  update(token: string, state: CredentialState & TPayload): Promise<string>;
  /** Revoke a single token. For stateless: requires denylist; otherwise throws. */
  revoke(token: string): Promise<void>;
  /**
   * Revoke all credentials for a user. Returns count revoked.
   * Stateless stores cannot enumerate individual tokens; they MAY implement
   * the cascade via a per-user revocation epoch (see `CredentialStoreJwt`)
   * and return a sentinel `1` to indicate "revocation took effect".
   */
  revokeAllForUser(userId: string): Promise<number>;
  /** List active credentials for a user (stateful only). */
  listForUser?(userId: string): Promise<Array<CredentialState & TPayload & { token: string }>>;
  /**
   * Optional last-activity stamp. Set `state.lastSeenAt = at` for the token if
   * it exists; no-op otherwise. Backs `AuthCredential`'s
   * `trackLastSeen: 'validate'` mode. Stateless stores omit it (the token is
   * immutable once issued).
   */
  touch?(token: string, at: number): Promise<void>;
  /**
   * Derive a stable, domain-separated 32-byte subkey from this store's
   * symmetric secret via HKDF-SHA256. Used so other subsystems (e.g. the
   * workflow-state encryption key) can reuse the auth secret WITHOUT the raw
   * secret ever leaving the store. Only implemented by stores backed by a
   * symmetric secret (JWT-HMAC, Encapsulated); stateful/asymmetric stores
   * omit it. `label` provides domain separation (different label → different key).
   */
  deriveSubkey?(label: string): Buffer;
}

/**
 * Denylist for stateless revocation. Stores revoked-but-not-yet-expired token IDs.
 * Auto-bounded by token TTLs.
 */
export interface DenylistStore {
  add(jti: string, expiresAt: number): Promise<void>;
  has(jti: string): Promise<boolean>;
  cleanup(): Promise<number>;
}
