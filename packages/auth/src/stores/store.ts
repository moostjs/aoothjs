import type { CredentialState } from "../credential/types";

/**
 * Pluggable credential storage. Implementations: Memory, JWT, Encapsulated.
 * Same shape works for stateful and stateless stores. Stateless stores treat
 * the token as the state itself (sign/encrypt on persist, verify/decrypt on retrieve).
 */
export interface CredentialStore<TClaims extends object = object> {
  /** Persist state, return token. For stateless stores, token IS the state. */
  persist(state: CredentialState<TClaims>, ttl?: number): Promise<string>;
  /** Retrieve state from token. Returns null if expired/invalid/revoked. */
  retrieve(token: string): Promise<CredentialState<TClaims> | null>;
  /** Retrieve + invalidate (single-use). For stateless: needs denylist. */
  consume(token: string): Promise<CredentialState<TClaims> | null>;
  /** Update state in-place. For stateless: re-issue token (consume + persist). */
  update(token: string, state: CredentialState<TClaims>): Promise<string>;
  /** Revoke a single token. For stateless: requires denylist; otherwise throws. */
  revoke(token: string): Promise<void>;
  /** Revoke all credentials for a user. Returns count revoked. */
  revokeAllForUser(userId: string): Promise<number>;
  /** List active credentials for a user (stateful only). */
  listForUser?(userId: string): Promise<Array<CredentialState<TClaims> & { token: string }>>;
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
