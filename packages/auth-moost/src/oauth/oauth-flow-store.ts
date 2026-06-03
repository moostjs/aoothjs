import { type Clock, defaultClock } from "@aooth/auth";

/**
 * The server-side half of an in-flight OAuth authorization request — the
 * secret material that MUST NOT ride in the URL `state` (RFC IDP.md §3.6 /
 * §7). Minted by `OAuthController` at `/:provider/start`, keyed by the signed
 * state's anti-CSRF `random`, and consumed once by the `oauth-exchange`
 * workflow step at callback time.
 *
 * Keeping the PKCE `verifier` + OIDC `nonce` here (not in the signed `state`)
 * is the confidentiality requirement: a leaked / logged authorization URL must
 * not contain the verifier, or the PKCE binding is worthless.
 */
export interface OAuthFlowTransaction {
  /** Provider id the request was started for — re-checked against the verified state. */
  provider: string;
  /** PKCE code verifier — exchanged for tokens, then discarded. */
  verifier: string;
  /** OIDC nonce — asserted against the ID-token `nonce` claim during exchange. */
  nonce: string;
  /** Validated post-login app redirect (same-origin relative path). */
  redirect: string;
  /**
   * Initiating authenticated user id — set ONLY by `/:provider/link` (account
   * linking), so the `oauth-exchange` step links the verified identity to THIS
   * user rather than running the login-resolution branch. Absent for login.
   */
  userId?: string;
  /** Absolute expiry (ms epoch); a `take` past this returns `null`. */
  expiresAt: number;
}

/** Fields the caller supplies; `expiresAt` is stamped by the store from its clock + TTL. */
export type NewOAuthFlowTransaction = Omit<OAuthFlowTransaction, "expiresAt">;

/**
 * Storage seam for in-flight OAuth transactions (PKCE verifier + nonce + the
 * `/link` userId binding), keyed by the signed state's `random`. Single-use:
 * `take` removes the entry so a replayed callback cannot re-exchange.
 *
 * The bundled {@link OAuthFlowStoreMemory} is process-local — fine for a single
 * instance and for tests, but a multi-pod deployment MUST override with a
 * shared store (Redis/DB), or a callback that lands on a different pod than the
 * `/start` will 404 the transaction. Same operational posture as the workflow
 * state store's `HandleStateStrategy` override.
 */
export abstract class OAuthFlowStore {
  /** Persist a transaction under `random`, overwriting any prior entry for that key. */
  abstract put(random: string, txn: NewOAuthFlowTransaction): Promise<void>;
  /**
   * Atomically read + remove the transaction for `random`. Returns `null` when
   * absent or expired (single-use + lazy-expiry). Never returns an expired row.
   */
  abstract take(random: string): Promise<OAuthFlowTransaction | null>;
}

export interface OAuthFlowStoreMemoryOptions {
  /** Injectable clock for deterministic expiry tests. Default: real wall clock. */
  clock?: Clock;
  /**
   * Transaction lifetime in ms. Default `600_000` (10 min) — matches the
   * signed-state default TTL, so the two expire together.
   */
  ttlMs?: number;
}

/**
 * In-memory {@link OAuthFlowStore} — a `Map<random, txn>` with lazy + swept
 * expiry. Process-local; see the abstract class doc for the multi-pod caveat.
 */
export class OAuthFlowStoreMemory extends OAuthFlowStore {
  private readonly entries = new Map<string, OAuthFlowTransaction>();
  private readonly clock: Clock;
  private readonly ttlMs: number;

  constructor(opts: OAuthFlowStoreMemoryOptions = {}) {
    super();
    this.clock = opts.clock ?? defaultClock;
    this.ttlMs = opts.ttlMs ?? 600_000;
  }

  put(random: string, txn: NewOAuthFlowTransaction): Promise<void> {
    this.sweep();
    this.entries.set(random, { ...txn, expiresAt: this.clock.now() + this.ttlMs });
    return Promise.resolve();
  }

  take(random: string): Promise<OAuthFlowTransaction | null> {
    const txn = this.entries.get(random);
    // Single-use: drop the key on any hit (valid OR expired) so a replayed
    // callback can never re-exchange the same authorization request.
    if (txn) this.entries.delete(random);
    if (!txn || txn.expiresAt <= this.clock.now()) return Promise.resolve(null);
    return Promise.resolve(txn);
  }

  /** Drop expired rows so an abandoned-flow build-up can't grow unbounded. */
  private sweep(): void {
    const now = this.clock.now();
    for (const [k, v] of this.entries) {
      if (v.expiresAt <= now) this.entries.delete(k);
    }
  }
}
