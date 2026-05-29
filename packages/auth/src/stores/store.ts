import type { CredentialState } from "../credential/types";

/**
 * Pluggable credential storage. Implementations: Memory, JWT, Encapsulated.
 * Same shape works for stateful and stateless stores. Stateless stores treat
 * the token as the state itself (sign/encrypt on persist, verify/decrypt on retrieve).
 *
 * `TClaims` is constrained to `extends object`, which TypeScript widens to
 * include arrays, class instances, and `Function`. Pass a plain object type
 * (e.g. `{ role: string; tenant: string }`); using arrays/classes will type-
 * check but won't survive JSON-serialised stateless storage round-trips.
 */
export interface CredentialStore<TClaims extends object = object> {
  /** Persist state, return token. For stateless stores, token IS the state. */
  persist(state: CredentialState<TClaims>, ttl?: number): Promise<string>;
  /** Retrieve state from token. Returns null if expired/invalid/revoked. */
  retrieve(token: string): Promise<CredentialState<TClaims> | null>;
  /** Retrieve + invalidate (single-use). For stateless: needs denylist. */
  consume(token: string): Promise<CredentialState<TClaims> | null>;
  /**
   * Update state. The returned token MAY differ from the input — stateful
   * stores typically return the same token, while stateless stores re-issue
   * a new token (denylisting the old). Callers must use the returned value.
   */
  update(token: string, state: CredentialState<TClaims>): Promise<string>;
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
  listForUser?(userId: string): Promise<Array<CredentialState<TClaims> & { token: string }>>;
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
