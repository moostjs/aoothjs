import { randomUUID } from "node:crypto";

import type { TokenPolicy } from "./token-policy";

/**
 * One in-flight authorization request, recorded at `GET /auth/authorize` and
 * read once at the login-workflow terminal that mints the auth code. Keyed by an
 * opaque `handle` that rides the login-wf ctx (and, across a "Continue with
 * Google" detour, the federated signed `state`) — so nothing secret leaves the
 * server.
 */
export interface PendingAuthorization {
  /** Opaque server-side handle (the only thing that rides the URL / wf state). */
  handle: string;
  /** Registered client id (Tier 2), absent for a public/loopback client. */
  clientId?: string;
  /** The client's validated `redirect_uri` — where the code is delivered. */
  redirectUri: string;
  /** PKCE S256 challenge (client-generated); verified against the verifier at `/token`. */
  codeChallenge: string;
  /** The client's `state`, echoed back on the redirect so the client can correlate. */
  clientState?: string;
  /** Requested scope (space-joined), informational for Tier 1. */
  scope?: string;
  /** What the grant will mint (fixed at authorize time). */
  tokenPolicy: TokenPolicy;
  createdAt: number;
  expiresAt: number;
}

/** Input to {@link PendingAuthorizationStore.create} — `handle`/timestamps are store-assigned. */
export interface NewPendingAuthorization {
  clientId?: string;
  redirectUri: string;
  codeChallenge: string;
  clientState?: string;
  scope?: string;
  tokenPolicy: TokenPolicy;
}

/**
 * Storage seam for in-flight authorizations (AUTH-SERVER.md §4.3). Short-lived
 * (≈ the login-session ceiling): created at `/authorize`, read+deleted at the
 * wf terminal. An in-memory impl ships for single-process apps + tests; a
 * multi-pod deployment provides a durable (e.g. Redis) impl under the same
 * {@link import("./authz-tokens").PENDING_AUTHORIZATION_STORE_TOKEN}.
 */
export abstract class PendingAuthorizationStore {
  /** Record a new pending authorization; returns its opaque `handle`. */
  abstract create(rec: NewPendingAuthorization): Promise<{ handle: string }>;
  /** Fetch by handle, or `null` when unknown/expired. */
  abstract get(handle: string): Promise<PendingAuthorization | null>;
  /** Drop a handle once consumed. Returns `true` when a row was removed. */
  abstract delete(handle: string): Promise<boolean>;
}

export interface PendingAuthorizationStoreMemoryOptions {
  /** Injectable clock for deterministic expiry. Defaults to `Date.now`. */
  clock?: () => number;
  /** How long a pending authorization stays valid. Default 15 min. */
  ttlMs?: number;
}

const DEFAULT_PENDING_TTL_MS = 15 * 60_000;

/**
 * In-memory {@link PendingAuthorizationStore} — the reference impl for a
 * single-process app + tests. `structuredClone` on read/write isolates callers.
 */
export class PendingAuthorizationStoreMemory extends PendingAuthorizationStore {
  private store = new Map<string, PendingAuthorization>();
  private clock: () => number;
  private ttlMs: number;

  constructor(opts?: PendingAuthorizationStoreMemoryOptions) {
    super();
    this.clock = opts?.clock ?? Date.now;
    this.ttlMs = opts?.ttlMs ?? DEFAULT_PENDING_TTL_MS;
  }

  async create(rec: NewPendingAuthorization): Promise<{ handle: string }> {
    const now = this.clock();
    const row: PendingAuthorization = {
      handle: randomUUID(),
      redirectUri: rec.redirectUri,
      codeChallenge: rec.codeChallenge,
      tokenPolicy: structuredClone(rec.tokenPolicy),
      createdAt: now,
      expiresAt: now + this.ttlMs,
      ...(rec.clientId !== undefined && { clientId: rec.clientId }),
      ...(rec.clientState !== undefined && { clientState: rec.clientState }),
      ...(rec.scope !== undefined && { scope: rec.scope }),
    };
    this.store.set(row.handle, structuredClone(row));
    return { handle: row.handle };
  }

  async get(handle: string): Promise<PendingAuthorization | null> {
    const row = this.store.get(handle);
    if (!row) return null;
    if (row.expiresAt <= this.clock()) {
      this.store.delete(handle);
      return null;
    }
    return structuredClone(row);
  }

  async delete(handle: string): Promise<boolean> {
    return this.store.delete(handle);
  }
}
