import { createHash, randomUUID } from "node:crypto";
import { AuthError } from "../errors";
import type { CredentialStore, DenylistStore } from "../stores/store";
import { type Clock, defaultClock } from "../utils/clock";
import { credentialPayloadOf } from "./payload";
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

/**
 * Merge a credential's typed payload under the fixed {@link CredentialState}
 * envelope, asserting the `CredentialState & TPayload` shape in ONE place. The
 * payload is spread first so an envelope field always wins a name clash. Every
 * issue / rotation state builder routes through here so the spread-order
 * invariant and the (irreducible, generic-spread) boundary cast live once.
 */
function stateWithPayload<TPayload extends object>(
  payload: object,
  envelope: CredentialState,
): CredentialState & TPayload {
  return { ...payload, ...envelope } as CredentialState & TPayload;
}

export interface AuthCredentialOptions<TPayload extends object = object> {
  /** Pluggable credential store (Memory, JWT, Encapsulated, ...). */
  store: CredentialStore<TPayload>;
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

/**
 * Options for {@link AuthCredential.issue}. The credential's typed payload
 * `TPayload` (the root fields a consumer added to their credential model — e.g.
 * `@arbac.attenuate.*`-annotated fields) is spread flat alongside the two
 * framework-level hints below. Reserved keys `metadata` and `sessionId` (and
 * the {@link CredentialState} envelope keys) must not be reused as payload
 * field names.
 */
export type IssueOptions<TPayload extends object = object> = TPayload & {
  metadata?: CredentialMetadata;
  /**
   * Pre-supply the session id. Omit to let `issue()` mint a random opaque one.
   * Both the access and refresh tokens of this login share it.
   */
  sessionId?: string;
};

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
 * - On detected refresh-reuse, the orchestrator best-effort revokes the
 *   compromised token family (the OAuth-best-practice theft response). Set
 *   `refresh.reuseResponse: 'user'` to escalate to revoking ALL of the user's
 *   sessions. See {@link RefreshConfig.reuseResponse}.
 */
export class AuthCredential<TPayload extends object = object> {
  private readonly store: CredentialStore<TPayload>;
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
    { userId: string; iat: number; exp: number; sessionId?: string }
  >();

  constructor(opts: AuthCredentialOptions<TPayload>) {
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

  async issue(userId: string, options?: IssueOptions<TPayload>): Promise<IssueResult> {
    if (this.maxConcurrent !== undefined && this.store.listForUser) {
      await this.enforceConcurrencyLimit(userId);
    }

    const now = this.clock.now();
    // Split the framework-level hints from the consumer's typed payload — the
    // remaining keys (`...payload`) are the credential's root fields and ride
    // flat on the persisted state (no `claims` container).
    const opts = options ?? ({} as IssueOptions<TPayload>);
    const { metadata, sessionId: providedSessionId, ...payload } = opts;
    // Mint the session id once and stamp it on BOTH the access and refresh
    // tokens (and, via the rotation copies below, every future rotation), so a
    // single login is one stable, opaque session for its whole lifetime.
    const sessionId = providedSessionId ?? randomUUID();
    const accessState = stateWithPayload<TPayload>(payload, {
      userId,
      issuedAt: now,
      expiresAt: now + this.accessTtl,
      kind: "access",
      metadata,
      sessionId,
    });
    const accessToken = await this.store.persist(accessState, this.accessTtl);

    let refreshToken: string | undefined;
    let refreshExpiresAt: number | undefined;
    if (this.refreshConfig) {
      const refreshState = stateWithPayload<TPayload>(payload, {
        userId,
        issuedAt: now,
        expiresAt: now + this.refreshConfig.ttl,
        kind: "refresh",
        metadata,
        sessionId,
      });
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

  async validate(accessToken: string): Promise<AuthContext<TPayload> | null> {
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

    // Surface the credential's typed payload fields by name (excludes envelope
    // internals like parentCredentialId); the base read-fields win any clash.
    return {
      ...credentialPayloadOf<TPayload>(state),
      userId: state.userId,
      method: this.method,
      credentialId: fingerprint(accessToken),
      // Legacy tokens predating sessionId fall back to the token fingerprint —
      // the SAME fallback listSessions uses, so "this device" matching holds.
      sessionId: this.sessionIdOf(state.sessionId, accessToken),
      expiresAt: state.expiresAt,
    } as AuthContext<TPayload>;
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
      case "always":
        return await this.refreshAlways(oldState, refreshToken, now);
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
    oldState: CredentialState & TPayload,
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

  /**
   * `sliding` rotation: rotate on every use and slide the refresh expiry
   * forward (rolling session). Grace-tolerant via the shared store-backed
   * window.
   */
  private async refreshSliding(
    oldState: CredentialState & TPayload,
    refreshToken: string,
    now: number,
  ): Promise<IssueResult> {
    return await this.rotateWithGrace(oldState, refreshToken, now, /* preserveExpiry */ false);
  }

  /**
   * `always` rotation: rotate on every use but keep a FIXED session ceiling —
   * each rotated token inherits the family's original `expiresAt` (no sliding).
   *
   * On a stateful store this reuses the same store-backed grace window as
   * `sliding` (so a benign concurrent refresh within grace is NOT mistaken for
   * theft, even across instances). On a stateless store the old token cannot be
   * kept valid (`update` re-issues), so it falls back to single-use semantics
   * with a process-local reuse signal — the only mechanism possible there.
   */
  private async refreshAlways(
    oldState: CredentialState & TPayload,
    refreshToken: string,
    now: number,
  ): Promise<IssueResult> {
    if (!this.store.listForUser) {
      // Stateless store: no in-place mutation → no store-backed grace. Consume
      // the old token and record the reuse signal in the process-local map so
      // a same-process replay still fires the theft response.
      await this.store.consume(refreshToken);
      this.consumedRefreshes.set(refreshToken, {
        userId: oldState.userId,
        iat: oldState.issuedAt,
        exp: oldState.expiresAt,
        ...(oldState.sessionId !== undefined && { sessionId: oldState.sessionId }),
      });
      return await this.issueRotatedPair(oldState, refreshToken, /* rotateOld */ false, now, true);
    }
    return await this.rotateWithGrace(oldState, refreshToken, now, /* preserveExpiry */ true);
  }

  /**
   * Shared rotation-with-grace mechanism for `sliding` and `always` on stateful
   * stores. Keeps the old refresh valid + stamps `rotatedAt` on first rotation;
   * within `rotationGraceMs` of that stamp it re-issues a fresh pair WITHOUT
   * re-rotating (replay-tolerant); beyond grace it treats the re-presentation
   * as theft. `preserveExpiry` selects fixed-ceiling (`always`) vs sliding
   * (`sliding`) expiry for the new refresh token.
   */
  private async rotateWithGrace(
    oldState: CredentialState & TPayload,
    refreshToken: string,
    now: number,
    preserveExpiry: boolean,
  ): Promise<IssueResult> {
    if (!this.refreshConfig) {
      throw new AuthError("INVALID_CONFIG", "Refresh not enabled");
    }
    const graceMs = this.refreshConfig.rotationGraceMs ?? DEFAULT_ROTATION_GRACE_MS;

    // First rotation: nothing to validate against the grace window yet.
    if (typeof oldState.rotatedAt !== "number") {
      return await this.issueRotatedPair(
        oldState,
        refreshToken,
        /* rotateOld */ true,
        now,
        preserveExpiry,
      );
    }

    // Subsequent presentation of an already-rotated refresh.
    if (now - oldState.rotatedAt > graceMs) {
      // Reuse-after-grace: theft suspected.
      await this.respondToRefreshReuse({
        userId: oldState.userId,
        sessionId: oldState.sessionId,
        issuedAt: oldState.issuedAt,
        expiresAt: oldState.expiresAt,
        rotatedAt: oldState.rotatedAt,
      });
    }

    // Within grace: replay-tolerant. Issue new tokens but don't re-rotate.
    return await this.issueRotatedPair(
      oldState,
      refreshToken,
      /* rotateOld */ false,
      now,
      preserveExpiry,
    );
  }

  async revoke(token: string): Promise<void> {
    await this.store.revoke(token);
  }

  async revokeAllForUser(userId: string): Promise<number> {
    return await this.store.revokeAllForUser(userId);
  }

  async listForUser(userId: string): Promise<Array<AuthContext<TPayload>>> {
    if (!this.store.listForUser) return [];
    const all = await this.store.listForUser(userId);
    return all
      .filter((entry) => entry.kind !== "refresh")
      .map(
        (entry) =>
          ({
            ...credentialPayloadOf<TPayload>(entry),
            userId: entry.userId,
            method: this.method,
            credentialId: fingerprint(entry.token),
            sessionId: this.sessionKeyOf(entry),
            expiresAt: entry.expiresAt,
          }) as AuthContext<TPayload>,
      );
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
  private sessionKeyOf(entry: CredentialState & TPayload & { token: string }): string {
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
    const families = new Map<string, Array<CredentialState & TPayload & { token: string }>>();
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
    // Single pass: compute each family key once (it hashes the token for legacy
    // rows), collecting the distinct revoked sessions for the count.
    const revokedSessions = new Set<string>();
    const revokes: Array<Promise<void>> = [];
    for (const entry of all) {
      const key = this.sessionKeyOf(entry);
      if (key === keepSessionId) continue;
      revokedSessions.add(key);
      revokes.push(this.store.revoke(entry.token));
    }
    await Promise.all(revokes);
    return revokedSessions.size;
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
    refreshState: CredentialState & TPayload,
    now: number,
  ): Promise<{ token: string; expiresAt: number }> {
    // Carry the credential's typed payload + session forward across rotation.
    const accessState = stateWithPayload<TPayload>(credentialPayloadOf<TPayload>(refreshState), {
      userId: refreshState.userId,
      issuedAt: now,
      expiresAt: now + this.accessTtl,
      kind: "access",
      metadata: refreshState.metadata,
      sessionId: refreshState.sessionId,
      ...(this.trackLastSeen === "refresh" && { lastSeenAt: now }),
    });
    const token = await this.store.persist(accessState, this.accessTtl);
    return { token, expiresAt: now + this.accessTtl };
  }

  /**
   * Issue a fresh access + refresh pair off an existing refresh credential.
   * `preserveExpiry` keeps the family's original refresh `expiresAt` (a fixed
   * session ceiling, used by `always`); otherwise the new refresh slides to
   * `now + ttl` (used by `sliding`). `rotateOld` stamps the old refresh as
   * rotated (keeping it valid through the grace window) instead of consuming it.
   */
  private async issueRotatedPair(
    oldRefreshState: CredentialState & TPayload,
    oldRefreshToken: string,
    rotateOld: boolean,
    now: number,
    preserveExpiry = false,
  ): Promise<IssueResult> {
    if (!this.refreshConfig) {
      throw new AuthError("INVALID_CONFIG", "Refresh not enabled");
    }
    const access = await this.issueAccessFromRefresh(oldRefreshState, now);

    // Fixed-ceiling (`always`) carries the family's original expiry forward;
    // sliding extends to now + ttl. Persist with the *remaining* lifetime so a
    // TTL-evicting store (Redis PX) never resurrects the token past its ceiling.
    const refreshExpiresAt = preserveExpiry
      ? oldRefreshState.expiresAt
      : now + this.refreshConfig.ttl;
    const refreshTtl = preserveExpiry
      ? Math.max(0, oldRefreshState.expiresAt - now)
      : this.refreshConfig.ttl;

    // Carry the credential's typed payload + session forward across rotation.
    const newRefreshState = stateWithPayload<TPayload>(
      credentialPayloadOf<TPayload>(oldRefreshState),
      {
        userId: oldRefreshState.userId,
        issuedAt: now,
        expiresAt: refreshExpiresAt,
        kind: "refresh",
        metadata: oldRefreshState.metadata,
        parentCredentialId: oldRefreshToken,
        sessionId: oldRefreshState.sessionId,
        ...(this.trackLastSeen === "refresh" && { lastSeenAt: now }),
      },
    );
    const newRefreshToken = await this.store.persist(newRefreshState, refreshTtl);

    if (rotateOld) {
      // Mark the old refresh as rotated; keep it valid until grace expires
      // (its expiresAt remains as originally set; grace logic uses rotatedAt).
      const rotatedState: CredentialState & TPayload = {
        ...oldRefreshState,
        rotatedAt: now,
      };
      await this.store.update(oldRefreshToken, rotatedState);
    }

    return {
      accessToken: access.token,
      accessExpiresAt: access.expiresAt,
      refreshToken: newRefreshToken,
      refreshExpiresAt,
    };
  }

  private lookupConsumedRefresh(
    token: string,
  ): { userId: string; iat: number; exp: number; sessionId?: string } | null {
    const entry = this.consumedRefreshes.get(token);
    if (!entry) return null;
    if (entry.exp <= this.clock.now()) {
      this.consumedRefreshes.delete(token);
      return null;
    }
    return entry;
  }

  private async fireRefreshReuseTheftResponse(
    consumed: { userId: string; iat: number; exp: number; sessionId?: string },
    refreshToken: string,
  ): Promise<void> {
    this.consumedRefreshes.delete(refreshToken);
    await this.respondToRefreshReuse({
      userId: consumed.userId,
      sessionId: consumed.sessionId,
      issuedAt: consumed.iat,
      expiresAt: consumed.exp,
    });
  }

  /**
   * Best-effort theft response for a detected refresh-token reuse. Fires the
   * `onRotationReuse` hook, then revokes per {@link RefreshConfig.reuseResponse}:
   * the compromised token family (`'session'`, default) or every session for
   * the user (`'user'`). Falls back to user-wide revocation when the session
   * can't be targeted (no `sessionId`, or a store that can't enumerate
   * sessions). Always throws `REFRESH_REUSE_DETECTED`.
   */
  private async respondToRefreshReuse(reuse: {
    userId: string;
    sessionId?: string;
    issuedAt: number;
    expiresAt: number;
    rotatedAt?: number;
  }): Promise<never> {
    this.refreshConfig?.onRotationReuse?.({
      userId: reuse.userId,
      issuedAt: reuse.issuedAt,
      expiresAt: reuse.expiresAt,
      kind: "refresh",
      ...(reuse.sessionId !== undefined && { sessionId: reuse.sessionId }),
      ...(reuse.rotatedAt !== undefined && { rotatedAt: reuse.rotatedAt }),
    });

    const scope = this.refreshConfig?.reuseResponse ?? "session";
    // `revokeSession` needs an enumerable store and a concrete sessionId;
    // without either, fall back to the user-wide cascade so theft never goes
    // un-revoked.
    if (scope === "session" && reuse.sessionId !== undefined && this.store.listForUser) {
      await this.revokeSession(reuse.userId, reuse.sessionId);
    } else {
      await this.store.revokeAllForUser(reuse.userId);
    }

    throw new AuthError("REFRESH_REUSE_DETECTED", undefined, {
      userId: reuse.userId,
      ...(reuse.sessionId !== undefined && { sessionId: reuse.sessionId }),
      ...(reuse.rotatedAt !== undefined && { rotatedAt: reuse.rotatedAt }),
    });
  }
}
