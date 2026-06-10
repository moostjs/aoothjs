import { randomUUID } from "node:crypto";

import { type Clock, defaultClock } from "../utils/clock";
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
  /** Granted scope (space-joined) — `requested ∩ allowed`; drives the `id_token` profile claims. */
  scope?: string;
  /** OIDC `nonce` from the authorize request — echoed into the `id_token` (Tier 2). */
  nonce?: string;
  /** Mint an `id_token` at `/token` (Tier 2). */
  idToken?: boolean;
  /** Mint an access token at `/token`. Omitted ⇒ minted (Tier-1 loopback). */
  accessToken?: boolean;
  /** The `id_token` `aud` (the registered `client_id`). */
  audience?: string;
  /** What the grant will mint (fixed at authorize time). */
  tokenPolicy: TokenPolicy;
  /**
   * High-entropy browser-binding secret (AUTH-SERVER.md §6). Set at
   * `/auth/authorize` and mirrored into the `aooth_authz` cookie; the
   * code-minting terminal accepts the handle ONLY when the request carries a
   * cookie that constant-time-matches this value — so the opaque handle can be
   * redeemed only by the browser that started the request, not one it was
   * phished into.
   */
  binding: string;
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
  nonce?: string;
  idToken?: boolean;
  accessToken?: boolean;
  audience?: string;
  tokenPolicy: TokenPolicy;
  /** Browser-binding secret (see {@link PendingAuthorization.binding}). */
  binding: string;
}

/**
 * Storage seam for in-flight authorizations (AUTH-SERVER.md §4.3). Short-lived
 * (≈ the login-session ceiling): created at `/authorize`, read+deleted at the
 * wf terminal. An in-memory impl ships for single-process apps + tests; a
 * multi-pod deployment provides a durable (e.g. Redis) impl under the same
 * `PENDING_AUTHORIZATION_STORE_TOKEN` (from `@aooth/auth-moost`).
 */
export abstract class PendingAuthorizationStore {
  /**
   * Record a new pending authorization; returns its opaque `handle` and the
   * row's `expiresAt` (epoch ms). The caller derives the `aooth_authz` binding
   * cookie's lifetime from `expiresAt`, so the cookie tracks the row's actual
   * TTL even when a store is configured with a non-default `ttlMs`.
   */
  abstract create(rec: NewPendingAuthorization): Promise<{ handle: string; expiresAt: number }>;
  /** Fetch by handle, or `null` when unknown/expired. */
  abstract get(handle: string): Promise<PendingAuthorization | null>;
  /** Drop a handle once consumed. Returns `true` when a row was removed. */
  abstract delete(handle: string): Promise<boolean>;
}

export interface PendingAuthorizationStoreMemoryOptions {
  /** Injectable clock for deterministic expiry. Defaults to {@link defaultClock}. */
  clock?: Clock;
  /** How long a pending authorization stays valid. Default 15 min. */
  ttlMs?: number;
}

/** Default pending-authorization lifetime (15 min). Shared by the memory + atscript-db stores. */
export const DEFAULT_PENDING_TTL_MS = 15 * 60_000;

/**
 * In-memory {@link PendingAuthorizationStore} — the reference impl for a
 * single-process app + tests. `structuredClone` on read/write isolates callers.
 */
export class PendingAuthorizationStoreMemory extends PendingAuthorizationStore {
  private store = new Map<string, PendingAuthorization>();
  private clock: Clock;
  private ttlMs: number;

  constructor(opts?: PendingAuthorizationStoreMemoryOptions) {
    super();
    this.clock = opts?.clock ?? defaultClock;
    this.ttlMs = opts?.ttlMs ?? DEFAULT_PENDING_TTL_MS;
  }

  async create(rec: NewPendingAuthorization): Promise<{ handle: string; expiresAt: number }> {
    const now = this.clock.now();
    const row: PendingAuthorization = {
      handle: randomUUID(),
      redirectUri: rec.redirectUri,
      codeChallenge: rec.codeChallenge,
      tokenPolicy: structuredClone(rec.tokenPolicy),
      binding: rec.binding,
      createdAt: now,
      expiresAt: now + this.ttlMs,
      ...(rec.clientId !== undefined && { clientId: rec.clientId }),
      ...(rec.clientState !== undefined && { clientState: rec.clientState }),
      ...(rec.scope !== undefined && { scope: rec.scope }),
      ...(rec.nonce !== undefined && { nonce: rec.nonce }),
      ...(rec.idToken !== undefined && { idToken: rec.idToken }),
      ...(rec.accessToken !== undefined && { accessToken: rec.accessToken }),
      ...(rec.audience !== undefined && { audience: rec.audience }),
    };
    this.store.set(row.handle, structuredClone(row));
    return { handle: row.handle, expiresAt: row.expiresAt };
  }

  async get(handle: string): Promise<PendingAuthorization | null> {
    const row = this.store.get(handle);
    if (!row) return null;
    if (row.expiresAt <= this.clock.now()) {
      this.store.delete(handle);
      return null;
    }
    return structuredClone(row);
  }

  async delete(handle: string): Promise<boolean> {
    return this.store.delete(handle);
  }
}
