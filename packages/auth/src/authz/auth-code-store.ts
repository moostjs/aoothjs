import { randomUUID } from "node:crypto";

import { type Clock, defaultClock } from "../utils/clock";
import type { TokenPolicy } from "./token-policy";

/**
 * A minted, single-use authorization code, bound to the user the login resolved
 * plus the PKCE challenge / redirect / token policy recorded at `/authorize`.
 * Consumed atomically at `POST /auth/token` — the token is minted there, off the
 * browser, so nothing long-lived ever rides a redirect URL.
 */
export interface AuthCode {
  /** Opaque single-use code (delivered to the client in the redirect query). */
  code: string;
  /** The user the login workflow authenticated. */
  userId: string;
  /** PKCE S256 challenge from the originating authorize request. */
  codeChallenge: string;
  /** The client's `redirect_uri` (bound; the code is meaningless elsewhere). */
  redirectUri: string;
  /** Registered client id (Tier 2), absent for a public/loopback client. */
  clientId?: string;
  /** Granted scope (space-joined) — drives the `id_token` profile claims. */
  scope?: string;
  /**
   * RFC 8707 `resource` indicator recorded at `/authorize`. The token endpoint
   * checks consistency (a `/token`-leg `resource` must match) — no audience
   * enforcement in v1 (OAUTH.md R4).
   */
  resource?: string;
  /** OIDC `nonce` from the authorize request — echoed into the `id_token` (Tier 2). */
  nonce?: string;
  /** Mint an `id_token` at `/token` (Tier 2). */
  idToken?: boolean;
  /** Mint an access token at `/token`. Omitted ⇒ minted (Tier-1 loopback). */
  accessToken?: boolean;
  /** The `id_token` `aud` (the registered `client_id`). */
  audience?: string;
  /** What `/token` mints when this code is redeemed. */
  tokenPolicy: TokenPolicy;
  expiresAt: number;
}

/** Input to {@link AuthCodeStore.mint} — `code`/`expiresAt` are store-assigned. */
export interface NewAuthCode {
  userId: string;
  codeChallenge: string;
  redirectUri: string;
  clientId?: string;
  scope?: string;
  resource?: string;
  nonce?: string;
  idToken?: boolean;
  accessToken?: boolean;
  audience?: string;
  tokenPolicy: TokenPolicy;
}

/**
 * Storage seam for issued authorization codes (AUTH-SERVER.md §4.3). Very
 * short-lived (≈ 30–60 s) and **single-use**: {@link consume} returns the row
 * AND invalidates it in one atomic step, so a concurrent double-redeem (or a
 * back-button replay) yields the code to exactly one caller. An in-memory impl
 * ships (atomic for free in single-threaded JS); a durable impl must implement
 * `consume` as an atomic check-and-delete (e.g. `withCas` / `@db.column.version`,
 * or a Redis `GETDEL`).
 */
export abstract class AuthCodeStore {
  /** Mint + store a single-use code; returns the opaque code string. */
  abstract mint(rec: NewAuthCode): Promise<{ code: string }>;
  /** Atomically claim + return the code's row, or `null` on miss / reuse / expiry. */
  abstract consume(code: string): Promise<AuthCode | null>;
}

export interface AuthCodeStoreMemoryOptions {
  /** Injectable clock for deterministic expiry. Defaults to {@link defaultClock}. */
  clock?: Clock;
  /** Code lifetime. Default 60 s. */
  ttlMs?: number;
}

/** Default auth-code lifetime (60 s). Shared by the memory + atscript-db stores. */
export const DEFAULT_CODE_TTL_MS = 60_000;

/**
 * In-memory {@link AuthCodeStore} — the reference impl. `consume` is atomic
 * because the `get` + `delete` run with no intervening `await`, so a second
 * concurrent `consume` of the same code always misses.
 */
export class AuthCodeStoreMemory extends AuthCodeStore {
  private store = new Map<string, AuthCode>();
  private clock: Clock;
  private ttlMs: number;

  constructor(opts?: AuthCodeStoreMemoryOptions) {
    super();
    this.clock = opts?.clock ?? defaultClock;
    this.ttlMs = opts?.ttlMs ?? DEFAULT_CODE_TTL_MS;
  }

  async mint(rec: NewAuthCode): Promise<{ code: string }> {
    const code = randomUUID();
    const row: AuthCode = {
      code,
      userId: rec.userId,
      codeChallenge: rec.codeChallenge,
      redirectUri: rec.redirectUri,
      tokenPolicy: structuredClone(rec.tokenPolicy),
      expiresAt: this.clock.now() + this.ttlMs,
      ...(rec.clientId !== undefined && { clientId: rec.clientId }),
      ...(rec.scope !== undefined && { scope: rec.scope }),
      ...(rec.resource !== undefined && { resource: rec.resource }),
      ...(rec.nonce !== undefined && { nonce: rec.nonce }),
      ...(rec.idToken !== undefined && { idToken: rec.idToken }),
      ...(rec.accessToken !== undefined && { accessToken: rec.accessToken }),
      ...(rec.audience !== undefined && { audience: rec.audience }),
    };
    this.store.set(code, structuredClone(row));
    return { code };
  }

  async consume(code: string): Promise<AuthCode | null> {
    const row = this.store.get(code);
    if (!row) return null;
    // Claim it FIRST (single-use) — a concurrent re-consume now misses, even if
    // this row turns out expired below.
    this.store.delete(code);
    if (row.expiresAt <= this.clock.now()) return null;
    return structuredClone(row);
  }
}
