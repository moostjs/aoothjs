import { createHash, randomUUID } from "node:crypto";
import { AuthError } from "../errors";
import type { CredentialStore, DenylistStore } from "../stores/store";
import { type Clock, defaultClock } from "../utils/clock";
import type {
  AuthContext,
  CredentialMetadata,
  CredentialState,
  EnrichedSession,
  IssueResult,
  RefreshConfig,
  SessionEnricher,
  SessionInfo,
} from "./types";

// Re-exported so existing import sites continue to compile.
export type { Clock } from "../utils/clock";

const DEFAULT_ACCESS_TTL = 60 * 60 * 1000; // 1 hour
const DEFAULT_ROTATION_GRACE_MS = 30_000;

/**
 * Stable, non-reversible fingerprint of a token used as `credentialId` in
 * {@link AuthContext}. Hashing avoids leaking a live bearer token whenever
 * downstream consumers log or persist `ctx.credentialId`.
 */
function fingerprint(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export interface AuthCredentialOptions<TClaims extends object = object> {
  /** Pluggable credential store (Memory, JWT, Encapsulated, ...). */
  store: CredentialStore<TClaims>;
  /** Default 'token' — distinguishes session-style from token-style use. */
  method?: "session" | "token";
  /** Access token TTL in milliseconds. Defaults to 1 hour. Must be > 0. */
  accessTtl?: number;
  /** If provided, refresh tokens are enabled. */
  refresh?: RefreshConfig;
  /**
   * Optional denylist consulted by `validate` keyed on the raw token.
   *
   * Note: stateless stores (JWT, Encapsulated) maintain their own denylist
   * keyed on `jti` for `revoke`/`update`/`consume`. Sharing a single
   * `DenylistStore` instance across both is safe (the keyspaces are disjoint:
   * raw tokens vs UUID jti) but conceptually they serve different purposes.
   */
  denylist?: DenylistStore;
  /** Maximum concurrent active access credentials per user. */
  maxConcurrent?: number;
  /** Behavior when limit reached: 'reject' (default) or 'evict-oldest'. */
  onLimit?: "reject" | "evict-oldest";
  /**
   * Track per-session activity time (`lastSeenAt`). Default `false` — no extra
   * writes; `listSessions` falls back to `createdAt`.
   * - `'refresh'` (cheap): stamp `lastSeenAt` on the newly-minted credentials
   *   during refresh — piggybacks the rotation write, no extra round-trip.
   * - `'validate'` (accurate, costly): `store.touch(token, now)` on every
   *   successful `validate()` — one write per authenticated request. Requires a
   *   store that implements `touch`; a no-op on stores that don't.
   */
  trackLastSeen?: "refresh" | "validate" | false;
  /** Optional clock for testability. */
  clock?: Clock;
}

export interface IssueOptions<TClaims extends object = object> {
  claims?: TClaims;
  metadata?: CredentialMetadata;
  /**
   * Pre-supply the session id. Omit to let `issue()` mint a random opaque one.
   * Both the access and refresh tokens of this login share it.
   */
  sessionId?: string;
}

/**
 * Orchestrates credential issuance, validation, refresh, and revocation
 * on top of a pluggable {@link CredentialStore}.
 *
 * Design notes:
 * - `credentialId` returned in {@link AuthContext} is a SHA-256 fingerprint of
 *   the access token, never the token itself. The fingerprint is stable
 *   per-token, safe to log/persist, and cannot be replayed against the API.
 *   M3 will switch to a `jti` claim for JWT/encapsulated stores.
 * - `kind: 'access' | 'refresh'` on {@link CredentialState} discriminates
 *   tokens stored side-by-side in the same store.
 * - `listForUser` and `maxConcurrent` consider only access-kind credentials,
 *   matching how callers typically display "active sessions".
 * - On detected refresh-reuse-after-grace, the orchestrator best-effort
 *   revokes ALL credentials for the affected user (access + refresh).
 *   This is OAuth-best-practice theft response; documented and intentional.
 */
export class AuthCredential<TClaims extends object = object> {
  private readonly store: CredentialStore<TClaims>;
  private readonly method: "session" | "token";
  private readonly accessTtl: number;
  private readonly refreshConfig?: RefreshConfig;
  private readonly denylist?: DenylistStore;
  private readonly maxConcurrent?: number;
  private readonly onLimit: "reject" | "evict-oldest";
  private readonly trackLastSeen: "refresh" | "validate" | false;
  private readonly clock: Clock;
  /**
   * Recently-consumed refresh tokens, keyed by the raw refresh token string.
   * Lets `'always'` rotation detect reuse: stateful stores forget the token
   * after `consume`, and stateless (JWT) stores hide it behind a denylist hit
   * on `retrieve`. Without this map the orchestrator can no longer distinguish
   * "fake token" from "previously valid token replayed". Pruned lazily on
   * access; bounded by refresh TTL.
   */
  private readonly consumedRefreshes = new Map<
    string,
    { userId: string; iat: number; exp: number }
  >();

  constructor(opts: AuthCredentialOptions<TClaims>) {
    this.store = opts.store;
    this.method = opts.method ?? "token";
    this.accessTtl = opts.accessTtl ?? DEFAULT_ACCESS_TTL;
    this.refreshConfig = opts.refresh;
    this.denylist = opts.denylist;
    this.maxConcurrent = opts.maxConcurrent;
    this.onLimit = opts.onLimit ?? "reject";
    this.trackLastSeen = opts.trackLastSeen ?? false;
    this.clock = opts.clock ?? defaultClock;

    // Catch the misconfiguration at boot rather than producing tokens that
    // fail validate() the moment they are issued.
    if (this.accessTtl <= 0) {
      throw new AuthError("INVALID_CONFIG", `accessTtl must be > 0 (got ${this.accessTtl})`);
    }
    if (this.refreshConfig && this.refreshConfig.ttl <= 0) {
      throw new AuthError(
        "INVALID_CONFIG",
        `refresh.ttl must be > 0 (got ${this.refreshConfig.ttl})`,
      );
    }
  }

  async issue(userId: string, options?: IssueOptions<TClaims>): Promise<IssueResult> {
    if (this.maxConcurrent !== undefined && this.store.listForUser) {
      await this.enforceConcurrencyLimit(userId);
    }

    const now = this.clock.now();
    // Mint the session id once and stamp it on BOTH the access and refresh
    // tokens (and, via the rotation copies below, every future rotation), so a
    // single login is one stable, opaque session for its whole lifetime.
    const sessionId = options?.sessionId ?? randomUUID();
    const accessState: CredentialState<TClaims> = {
      userId,
      issuedAt: now,
      expiresAt: now + this.accessTtl,
      kind: "access",
      claims: options?.claims,
      metadata: options?.metadata,
      sessionId,
    };
    const accessToken = await this.store.persist(accessState, this.accessTtl);

    let refreshToken: string | undefined;
    let refreshExpiresAt: number | undefined;
    if (this.refreshConfig) {
      const refreshState: CredentialState<TClaims> = {
        userId,
        issuedAt: now,
        expiresAt: now + this.refreshConfig.ttl,
        kind: "refresh",
        claims: options?.claims,
        metadata: options?.metadata,
        sessionId,
      };
      refreshToken = await this.store.persist(refreshState, this.refreshConfig.ttl);
      refreshExpiresAt = now + this.refreshConfig.ttl;
    }

    return {
      accessToken,
      refreshToken,
      accessExpiresAt: now + this.accessTtl,
      refreshExpiresAt,
    };
  }

  async validate(accessToken: string): Promise<AuthContext<TClaims> | null> {
    if (this.denylist && (await this.denylist.has(accessToken))) {
      return null;
    }
    const state = await this.store.retrieve(accessToken);
    if (!state) return null;
    if (state.expiresAt <= this.clock.now()) return null;
    if (state.kind === "refresh") return null;

    if (this.trackLastSeen === "validate" && this.store.touch) {
      // Best-effort activity stamp — one write per authenticated request.
      // Fire-and-forget would race the response; await keeps lastSeenAt
      // monotonic but adds a store round-trip (documented cost).
      await this.store.touch(accessToken, this.clock.now());
    }

    return {
      userId: state.userId,
      method: this.method,
      credentialId: fingerprint(accessToken),
      // Legacy tokens predating sessionId fall back to the token fingerprint —
      // the SAME fallback listSessions uses, so "this device" matching holds.
      sessionId: this.sessionIdOf(state.sessionId, accessToken),
      expiresAt: state.expiresAt,
      claims: state.claims,
    };
  }

  async refresh(refreshToken: string): Promise<IssueResult> {
    if (!this.refreshConfig) {
      throw new AuthError("INVALID_CONFIG", "Refresh not enabled");
    }
    const rotation = this.refreshConfig.rotation ?? "sliding";
    const now = this.clock.now();

    const oldState = await this.store.retrieve(refreshToken);
    if (!oldState) {
      // Stateful stores drop the consumed token; JWT stores hide it behind a
      // denylist hit on retrieve. The consumed-refreshes map preserves the
      // reuse signal across both so 'always' rotation can fire theft response.
      const consumed = this.lookupConsumedRefresh(refreshToken);
      if (consumed) {
        await this.fireRefreshReuseTheftResponse(consumed, refreshToken);
      }
      throw new AuthError("INVALID_TOKEN");
    }
    if (oldState.kind !== "refresh") {
      throw new AuthError("INVALID_TOKEN", "Token is not a refresh credential");
    }

    switch (rotation) {
      case "none":
        // Issue new access only; keep the refresh token in place.
        return await this.refreshNone(oldState, refreshToken, now);
      case "always": {
        // Single-use refresh: consume old, issue new pair.
        await this.store.consume(refreshToken);
        this.consumedRefreshes.set(refreshToken, {
          userId: oldState.userId,
          iat: oldState.issuedAt,
          exp: oldState.expiresAt,
        });
        return await this.issueRotatedPair(oldState, refreshToken, /* rotateOld */ false, now);
      }
      case "sliding":
        return await this.refreshSliding(oldState, refreshToken, now);
      default: {
        // Exhaustiveness guard — surfaces an explicit error if a new rotation
        // mode is added to RefreshConfig without updating this switch.
        const _exhaustive: never = rotation;
        throw new AuthError("INVALID_CONFIG", `Unknown rotation: ${String(_exhaustive)}`);
      }
    }
  }

  private async refreshNone(
    oldState: CredentialState<TClaims>,
    refreshToken: string,
    now: number,
  ): Promise<IssueResult> {
    const newAccess = await this.issueAccessFromRefresh(oldState, now);
    return {
      accessToken: newAccess.token,
      accessExpiresAt: newAccess.expiresAt,
      refreshToken,
      refreshExpiresAt: oldState.expiresAt,
    };
  }

  private async refreshSliding(
    oldState: CredentialState<TClaims>,
    refreshToken: string,
    now: number,
  ): Promise<IssueResult> {
    if (!this.refreshConfig) {
      throw new AuthError("INVALID_CONFIG", "Refresh not enabled");
    }
    const graceMs = this.refreshConfig.rotationGraceMs ?? DEFAULT_ROTATION_GRACE_MS;

    // First rotation: nothing to validate against the grace window yet.
    if (typeof oldState.rotatedAt !== "number") {
      return await this.issueRotatedPair(oldState, refreshToken, /* rotateOld */ true, now);
    }

    // Subsequent presentation of an already-rotated refresh.
    if (now - oldState.rotatedAt > graceMs) {
      // Reuse-after-grace: theft suspected.
      this.refreshConfig.onRotationReuse?.(oldState);
      // Best-effort theft response: revoke all credentials for this user.
      await this.store.revokeAllForUser(oldState.userId);
      throw new AuthError("REFRESH_REUSE_DETECTED", undefined, {
        userId: oldState.userId,
        rotatedAt: oldState.rotatedAt,
      });
    }

    // Within grace: replay-tolerant. Issue new tokens but don't re-rotate.
    return await this.issueRotatedPair(oldState, refreshToken, /* rotateOld */ false, now);
  }

  async revoke(token: string): Promise<void> {
    await this.store.revoke(token);
  }

  async revokeAllForUser(userId: string): Promise<number> {
    return await this.store.revokeAllForUser(userId);
  }

  async listForUser(userId: string): Promise<Array<AuthContext<TClaims>>> {
    if (!this.store.listForUser) return [];
    const all = await this.store.listForUser(userId);
    return all
      .filter((entry) => entry.kind !== "refresh")
      .map((entry) => ({
        userId: entry.userId,
        method: this.method,
        credentialId: fingerprint(entry.token),
        sessionId: this.sessionKeyOf(entry),
        expiresAt: entry.expiresAt,
        claims: entry.claims,
      }));
  }

  /**
   * The session id for a credential: its stored `sessionId`, or the token
   * fingerprint for legacy rows predating sessionId (so they surface as
   * singleton sessions). The ONE place this fallback rule lives — shared by
   * `validate()`, `listForUser()`, and the session-family methods so "this
   * device" matching stays consistent across all of them.
   */
  private sessionIdOf(sessionId: string | undefined, token: string): string {
    return sessionId ?? fingerprint(token);
  }

  /** Session-grouping key for a stored credential entry (token attached). */
  private sessionKeyOf(entry: CredentialState<TClaims> & { token: string }): string {
    return this.sessionIdOf(entry.sessionId, entry.token);
  }

  /**
   * List the user's active sessions, one row per token family (access +
   * refresh + every rotation collapsed by `sessionId`). Newest first by
   * `lastSeenAt` (or `createdAt` when activity isn't tracked). Returns `[]` for
   * stores that can't enumerate (stateless JWT/encapsulated). Pass `enrich` to
   * map each row through a {@link SessionEnricher} (device/location labels).
   */
  async listSessions(
    userId: string,
    opts?: { enrich?: SessionEnricher },
  ): Promise<SessionInfo[] | EnrichedSession[]> {
    if (!this.store.listForUser) return [];
    const all = await this.store.listForUser(userId);

    // Group every credential of the user into its session family.
    const families = new Map<string, Array<CredentialState<TClaims> & { token: string }>>();
    for (const entry of all) {
      const key = this.sessionKeyOf(entry);
      const bucket = families.get(key);
      if (bucket) bucket.push(entry);
      else families.set(key, [entry]);
    }

    const sessions: SessionInfo[] = [];
    for (const [sessionId, entries] of families) {
      let createdAt = Infinity;
      let lastSeenAt: number | undefined;
      let refreshExpiresAt: number | undefined;
      let accessExpiresAt: number | undefined;
      let metadata: CredentialMetadata | undefined;
      for (const e of entries) {
        if (e.issuedAt < createdAt) createdAt = e.issuedAt;
        if (
          typeof e.lastSeenAt === "number" &&
          (lastSeenAt === undefined || e.lastSeenAt > lastSeenAt)
        ) {
          lastSeenAt = e.lastSeenAt;
        }
        if (e.kind === "refresh") {
          if (refreshExpiresAt === undefined || e.expiresAt > refreshExpiresAt) {
            refreshExpiresAt = e.expiresAt;
          }
        } else if (accessExpiresAt === undefined || e.expiresAt > accessExpiresAt) {
          accessExpiresAt = e.expiresAt;
        }
        // First non-empty metadata wins — all family members carry the same
        // login-time metadata (copied forward on rotation).
        if (!metadata && e.metadata) metadata = e.metadata;
      }
      sessions.push({
        sessionId,
        userId,
        createdAt: createdAt === Infinity ? this.clock.now() : createdAt,
        // Refresh outlives access; prefer its expiry as the session's lifetime.
        expiresAt: refreshExpiresAt ?? accessExpiresAt ?? 0,
        ...(lastSeenAt !== undefined && { lastSeenAt }),
        ...(metadata && { metadata }),
      });
    }

    sessions.sort((a, b) => (b.lastSeenAt ?? b.createdAt) - (a.lastSeenAt ?? a.createdAt));

    if (!opts?.enrich) return sessions;
    const enrich = opts.enrich;
    // enrich may be sync or async — normalize so Promise.all is well-typed.
    return Promise.all(sessions.map((s) => Promise.resolve(enrich(s))));
  }

  /**
   * Revoke a single session — every token in its family (access + refresh +
   * rotations). No-op for stores that can't enumerate. Other sessions keep
   * validating.
   */
  async revokeSession(userId: string, sessionId: string): Promise<void> {
    if (!this.store.listForUser) return;
    const all = await this.store.listForUser(userId);
    await Promise.all(
      all
        .filter((entry) => this.sessionKeyOf(entry) === sessionId)
        .map((entry) => this.store.revoke(entry.token)),
    );
  }

  /**
   * Revoke every session for the user EXCEPT `keepSessionId` ("log out
   * everywhere else"). Returns the number of distinct sessions revoked. No-op
   * (returns 0) for stores that can't enumerate.
   */
  async revokeOtherSessions(userId: string, keepSessionId: string): Promise<number> {
    if (!this.store.listForUser) return 0;
    const all = await this.store.listForUser(userId);
    const toRevoke = all.filter((entry) => this.sessionKeyOf(entry) !== keepSessionId);
    await Promise.all(toRevoke.map((entry) => this.store.revoke(entry.token)));
    return new Set(toRevoke.map((entry) => this.sessionKeyOf(entry))).size;
  }

  /**
   * Derive a stable 32-byte key from this credential's underlying store secret,
   * domain-separated by `label`. Lets adjacent subsystems (e.g. workflow-state
   * encryption) reuse the auth secret without managing a second one. Throws if
   * the store has no reusable symmetric secret (stateful/asymmetric) — callers
   * should then require an explicit secret.
   */
  deriveStateKey(label = "wf-state"): Buffer {
    if (!this.store.deriveSubkey) {
      throw new AuthError(
        "INVALID_CONFIG",
        "credential store has no reusable secret; provide an explicit wfStateSecret",
      );
    }
    return this.store.deriveSubkey(label);
  }

  private async enforceConcurrencyLimit(userId: string): Promise<void> {
    if (!this.store.listForUser || this.maxConcurrent === undefined) return;
    const all = await this.store.listForUser(userId);
    const accessOnly = all.filter((entry) => entry.kind !== "refresh");
    if (accessOnly.length < this.maxConcurrent) return;

    if (this.onLimit === "reject") {
      throw new AuthError("MAX_CONCURRENT_REACHED", undefined, {
        userId,
        limit: this.maxConcurrent,
        active: accessOnly.length,
      });
    }
    // 'evict-oldest': revoke entries with the smallest issuedAt until under the cap.
    const sorted = accessOnly.toSorted((a, b) => a.issuedAt - b.issuedAt);
    const toEvict = accessOnly.length - this.maxConcurrent + 1;
    for (let i = 0; i < toEvict && i < sorted.length; i++) {
      await this.store.revoke(sorted[i].token);
    }
  }

  private async issueAccessFromRefresh(
    refreshState: CredentialState<TClaims>,
    now: number,
  ): Promise<{ token: string; expiresAt: number }> {
    const accessState: CredentialState<TClaims> = {
      userId: refreshState.userId,
      issuedAt: now,
      expiresAt: now + this.accessTtl,
      kind: "access",
      claims: refreshState.claims,
      metadata: refreshState.metadata,
      // Carry the session forward so every rotation stays in the same family.
      sessionId: refreshState.sessionId,
      ...(this.trackLastSeen === "refresh" && { lastSeenAt: now }),
    };
    const token = await this.store.persist(accessState, this.accessTtl);
    return { token, expiresAt: now + this.accessTtl };
  }

  private async issueRotatedPair(
    oldRefreshState: CredentialState<TClaims>,
    oldRefreshToken: string,
    rotateOld: boolean,
    now: number,
  ): Promise<IssueResult> {
    if (!this.refreshConfig) {
      throw new AuthError("INVALID_CONFIG", "Refresh not enabled");
    }
    const access = await this.issueAccessFromRefresh(oldRefreshState, now);

    const newRefreshState: CredentialState<TClaims> = {
      userId: oldRefreshState.userId,
      issuedAt: now,
      expiresAt: now + this.refreshConfig.ttl,
      kind: "refresh",
      claims: oldRefreshState.claims,
      metadata: oldRefreshState.metadata,
      parentCredentialId: oldRefreshToken,
      // Carry the session forward so every rotation stays in the same family.
      sessionId: oldRefreshState.sessionId,
      ...(this.trackLastSeen === "refresh" && { lastSeenAt: now }),
    };
    const newRefreshToken = await this.store.persist(newRefreshState, this.refreshConfig.ttl);

    if (rotateOld) {
      // Mark the old refresh as rotated; keep it valid until grace expires
      // (its expiresAt remains as originally set; sliding logic uses rotatedAt).
      const rotatedState: CredentialState<TClaims> = {
        ...oldRefreshState,
        rotatedAt: now,
      };
      await this.store.update(oldRefreshToken, rotatedState);
    }

    return {
      accessToken: access.token,
      accessExpiresAt: access.expiresAt,
      refreshToken: newRefreshToken,
      refreshExpiresAt: now + this.refreshConfig.ttl,
    };
  }

  private lookupConsumedRefresh(
    token: string,
  ): { userId: string; iat: number; exp: number } | null {
    const entry = this.consumedRefreshes.get(token);
    if (!entry) return null;
    if (entry.exp <= this.clock.now()) {
      this.consumedRefreshes.delete(token);
      return null;
    }
    return entry;
  }

  private async fireRefreshReuseTheftResponse(
    consumed: { userId: string; iat: number; exp: number },
    refreshToken: string,
  ): Promise<void> {
    this.refreshConfig?.onRotationReuse?.({
      userId: consumed.userId,
      issuedAt: consumed.iat,
      expiresAt: consumed.exp,
      kind: "refresh",
    });
    await this.store.revokeAllForUser(consumed.userId);
    this.consumedRefreshes.delete(refreshToken);
    throw new AuthError("REFRESH_REUSE_DETECTED", undefined, { userId: consumed.userId });
  }
}
