import { createHash } from "node:crypto";
import { AuthError } from "../errors";
import type { CredentialStore, DenylistStore } from "../stores/store";
import { type Clock, defaultClock } from "../utils/clock";
import type {
  AuthContext,
  CredentialMetadata,
  CredentialState,
  IssueResult,
  RefreshConfig,
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
  /** Access token TTL in milliseconds. Defaults to 1 hour. */
  accessTtl?: number;
  /** If provided, refresh tokens are enabled. */
  refresh?: RefreshConfig;
  /** Optional denylist (used during validate); stateful stores may ignore. */
  denylist?: DenylistStore;
  /** Maximum concurrent active access credentials per user. */
  maxConcurrent?: number;
  /** Behavior when limit reached: 'reject' (default) or 'evict-oldest'. */
  onLimit?: "reject" | "evict-oldest";
  /** Optional clock for testability. */
  clock?: Clock;
}

export interface IssueOptions<TClaims extends object = object> {
  claims?: TClaims;
  metadata?: CredentialMetadata;
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
  private readonly clock: Clock;

  constructor(opts: AuthCredentialOptions<TClaims>) {
    this.store = opts.store;
    this.method = opts.method ?? "token";
    this.accessTtl = opts.accessTtl ?? DEFAULT_ACCESS_TTL;
    this.refreshConfig = opts.refresh;
    this.denylist = opts.denylist;
    this.maxConcurrent = opts.maxConcurrent;
    this.onLimit = opts.onLimit ?? "reject";
    this.clock = opts.clock ?? defaultClock;
  }

  async issue(userId: string, options?: IssueOptions<TClaims>): Promise<IssueResult> {
    if (this.maxConcurrent !== undefined && this.store.listForUser) {
      await this.enforceConcurrencyLimit(userId);
    }

    const now = this.clock.now();
    const accessState: CredentialState<TClaims> = {
      userId,
      issuedAt: now,
      expiresAt: now + this.accessTtl,
      kind: "access",
      claims: options?.claims,
      metadata: options?.metadata,
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

    return {
      userId: state.userId,
      method: this.method,
      credentialId: fingerprint(accessToken),
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
        // Single-use refresh: consume old, issue new pair.
        await this.store.consume(refreshToken);
        return await this.issueRotatedPair(oldState, refreshToken, /* rotateOld */ false, now);
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
        expiresAt: entry.expiresAt,
        claims: entry.claims,
      }));
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
}
