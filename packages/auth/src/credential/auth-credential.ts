import {
  createCipheriv,
  createDecipheriv,
  createHash,
  hkdfSync,
  randomBytes,
  randomUUID,
} from "node:crypto";
import { AuthError } from "../errors";
import type { CredentialStore, DenylistStore } from "../stores/store";
import { type Clock, defaultClock } from "../utils/clock";
import { credentialPayloadOf } from "./payload";
import type {
  AuthContext,
  CredentialMetadata,
  CredentialState,
  CredentialSuccessorRef,
  EnrichedSession,
  IssueResult,
  RefreshConfig,
  RefreshResult,
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
 * Turn `ctx.credentialId` (already in place, so key order is kept) into a
 * lazily computed, memoized, still writable property.
 */
function lazyCredentialId(ctx: { credentialId: string }, token: string): void {
  let value: string | undefined;
  Object.defineProperty(ctx, "credentialId", {
    enumerable: true,
    configurable: true,
    get: () => (value ??= fingerprint(token)),
    set: (next: string) => {
      value = next;
    },
  });
}

/** Smallest map size an amortized expiry sweep runs at. */
const MIN_SWEEP_SIZE = 1024;

/** A store key that is the SHA-256 hex of a token (`tokens.hashAtRest`). */
const HASHED_KEY = /^[0-9a-f]{64}$/i;

/** The token shape the bundled stores minted before `hashAtRest` (`randomUUID`). */
const UUID_TOKEN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Prefix of a successor token encrypted at rest (`tokens.hashAtRest`). */
const SEALED_PREFIX = "enc1.";

/** AES-256-GCM key for the successor pair, derived from the presented (old) refresh token. */
function successorKey(oldRefreshToken: string): Buffer {
  return Buffer.from(hkdfSync("sha256", oldRefreshToken, "", "aooth-refresh-successor", 32));
}

function sealToken(key: Buffer, token: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const body = Buffer.concat([cipher.update(token, "utf8"), cipher.final()]);
  return `${SEALED_PREFIX}${iv.toString("base64url")}.${body.toString("base64url")}.${cipher
    .getAuthTag()
    .toString("base64url")}`;
}

/** Decrypt a sealed token; a plain (legacy) value passes through; `null` on a failed decrypt. */
function openToken(key: Buffer, value: string): string | null {
  if (!value.startsWith(SEALED_PREFIX)) return value;
  const [iv, body, tag] = value.slice(SEALED_PREFIX.length).split(".");
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64url"));
    decipher.setAuthTag(Buffer.from(tag, "base64url"));
    return Buffer.concat([
      decipher.update(Buffer.from(body, "base64url")),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    return null;
  }
}

/**
 * The opt-in `validateCache`: token → validated state for `ttlMs`, bounded
 * (oldest dropped first). `epoch` moves on every eviction so a validation
 * racing a revocation never re-caches the revoked token.
 */
class ValidateCache<S extends CredentialState> {
  private readonly entries = new Map<string, { state: S; until: number }>();
  epoch = 0;

  constructor(
    private readonly ttlMs: number,
    private readonly max: number,
  ) {}

  get(token: string, now: number): S | undefined {
    const entry = this.entries.get(token);
    if (!entry) return undefined;
    if (entry.until > now) return entry.state;
    this.entries.delete(token);
    return undefined;
  }

  set(token: string, state: S, now: number): void {
    this.entries.delete(token);
    if (this.entries.size >= this.max) {
      const oldest = this.entries.keys().next();
      if (!oldest.done) this.entries.delete(oldest.value);
    }
    this.entries.set(token, { state, until: now + this.ttlMs });
  }

  delete(token: string): void {
    this.epoch++;
    this.entries.delete(token);
  }

  deleteUser(userId: string): void {
    this.epoch++;
    for (const [token, entry] of this.entries) {
      if (entry.state.userId === userId) this.entries.delete(token);
    }
  }
}

/** A stored credential and the store key it was found under. */
interface Found<TPayload extends object> {
  key: string;
  state: CredentialState & TPayload;
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

/**
 * Match a session family's semantic kind against a `listSessions({ kind })`
 * filter. No filter ⇒ only ordinary interactive sessions (`"session"`), keeping
 * `cli-session` / `pat` credentials out of the default "active sessions" view.
 * A `"*"` value (a bare string or anywhere in the array) matches every kind.
 */
function matchesSessionKind(kind: string, filter?: string | string[]): boolean {
  if (filter === undefined) return kind === "session";
  const wanted = Array.isArray(filter) ? filter : [filter];
  return wanted.includes("*") || wanted.includes(kind);
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
  /**
   * OPT-IN process-local cache of validated access-token state (token →
   * state), reused by `validate()` for `ttlMs` instead of a store / denylist
   * round trip. Off by default. A hit still re-checks expiry and kind; this
   * instance's `revoke`, `revokeAllForUser`, `revokeSession`,
   * `revokeOtherSessions`, the concurrency eviction and refresh-reuse
   * responses evict their tokens at once. A revocation made elsewhere (another
   * process / instance, or a direct store / denylist write) is seen within
   * `ttlMs` — keep it short (seconds).
   *
   * @since 0.1.78
   */
  validateCache?: { ttlMs: number; max?: number };
  /**
   * How tokens are minted and stored. Both options need a store with
   * `persistAs` (memory, Redis, atscript-db — not the stateless JWT /
   * encapsulated stores, whose token IS the state).
   */
  tokens?: {
    /**
     * Store a SHA-256 of each token instead of the token itself, so a
     * database / backup / replica read yields no usable session, refresh token
     * or PAT. The successor pair kept on a rotated refresh row is encrypted
     * with a key derived from that refresh token (only its holder can read it
     * back during the grace window), and `parentCredentialId` holds the hash.
     * Tokens become 256-bit random strings unless `generate` is given.
     * - `true` — hash every token; rows written before are not found (a
     *   one-time sign-out of existing sessions).
     * - `'migrate'` — also look up the token itself when its hash is not
     *   found, so existing sessions keep working; a legacy refresh token is
     *   re-issued hashed on its next rotation. Switch to `true` once the
     *   longest refresh lifetime has passed.
     * Default `false`.
     */
    hashAtRest?: boolean | "migrate";
    /**
     * Token generator (e.g. to add a recognisable prefix). Must return at
     * least 128 bits of randomness — the stored SHA-256 is only as strong as
     * the token it hashes. Default: 256 random bits, base64url.
     */
    generate?: () => string;
    /**
     * `'migrate'` only: which presented tokens may be looked up as-is (rows
     * written before hashing). Default: the `randomUUID` shape the bundled
     * stores minted. Pass a predicate when earlier tokens came from a custom
     * `generate`. A 64-hex string (the shape of a stored hash) is never looked
     * up as-is, so a value read from the database cannot be replayed as a token.
     */
    isLegacyToken?: (token: string) => boolean;
  };
  /** Optional clock for testability. */
  clock?: Clock;
}

/**
 * Options for {@link AuthCredential.issue}. The credential's typed payload
 * `TPayload` (the root fields a consumer added to their credential model — e.g.
 * `@arbac.attenuate.*`-annotated fields) is spread flat alongside the
 * framework-level hints below. Reserved keys `metadata`, `sessionId`, `ttl`,
 * `expiresAt`, `kind`, `refresh` (and the {@link CredentialState} envelope keys)
 * must not be reused as payload field names.
 */
export type IssueOptions<TPayload extends object = object> = TPayload & {
  metadata?: CredentialMetadata;
  /**
   * Pre-supply the session id. Omit to let `issue()` mint a random opaque one.
   * Both the access and refresh tokens of this login share it.
   */
  sessionId?: string;
  /**
   * Per-mint access-token lifetime in **milliseconds**, overriding the
   * instance-level `accessTtl` for THIS credential only — so one `AuthCredential`
   * can mint, say, a 30-minute browser session AND a long-lived PAT/CLI token
   * without a second instance/posture. Must be `> 0`. Mutually exclusive with
   * {@link expiresAt}. The refresh token (if any) is unaffected — it keeps
   * `refresh.ttl`.
   */
  ttl?: number;
  /**
   * Absolute access-token expiry instant (ms since epoch), overriding both
   * `ttl` and the instance `accessTtl`. Mutually exclusive with {@link ttl}.
   * Use when the caller already holds the exact instant.
   */
  expiresAt?: number;
  /**
   * Semantic credential kind for THIS mint — e.g. `"cli-session"` / `"pat"`.
   * Distinct from the internal access/refresh discriminator
   * ({@link CredentialState.kind}): it is stored in `metadata.credentialKind`
   * and carried forward across rotation, so the whole session family is
   * labelled. Surfaced as {@link SessionInfo.kind} and consumed by the
   * `listSessions({ kind })` filter to keep non-browser credentials out of the
   * default "active sessions" view. Omit for an ordinary interactive session.
   */
  kind?: string;
  /**
   * Per-mint refresh-token control, overriding the instance-level
   * `AuthCredentialOptions.refresh` for THIS credential only:
   * - omitted — instance default: a refresh token is minted iff the instance
   *   `refresh` config exists (today's behavior).
   * - `false` — mint NO refresh token even when the instance config exists
   *   (e.g. the authz token endpoint suppressing the paired refresh for a
   *   policy that didn't opt in — no orphaned refresh row).
   * - `{ ttl?, graceMs? }` — mint a refresh token for this credential; `ttl`
   *   (ms) overrides the instance `refresh.ttl`. Works WITHOUT an instance
   *   config (then `ttl` is required). Per-mint families ALWAYS redeem with
   *   fixed-ceiling (`'always'`) rotation semantics — the family is stamped
   *   `metadata.refreshRotation: "always"` at mint, which `refresh()` honors
   *   over the instance rotation, so rotation never extends the family's
   *   lifetime even on an instance whose sessions rotate `'sliding'`.
   *   `graceMs` (ms, ≥ 0) fixes the family's rotation grace window the same
   *   mint-time-authority way (stamped `metadata.rotationGraceMs`, honored
   *   over the instance `rotationGraceMs`); `0` is strict single-use. Omit to
   *   inherit the instance window (or its 30 s default).
   */
  refresh?: false | { ttl?: number; graceMs?: number };
};

/** Options for {@link AuthCredential.refresh}. */
export interface RefreshCallOptions<TPayload extends object = object> {
  /**
   * Pre-rotation gate: invoked with the stored refresh credential AFTER it
   * resolved to a live refresh-kind row but BEFORE any rotation or state
   * change. Throwing aborts the refresh with nothing consumed or rotated —
   * the seam for caller-level binding checks (e.g. the OAuth token endpoint
   * verifying `metadata.authzClientId` against the presenting client).
   */
  guard?: (state: CredentialState & TPayload) => void | Promise<void>;
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
  /** Map size at which `consumedRefreshes` next sweeps its expired entries. */
  private consumedSweepAt = MIN_SWEEP_SIZE;
  /** Opt-in validated-state cache (`validateCache`), keyed by store key. */
  private readonly validated?: ValidateCache<CredentialState & TPayload>;
  private readonly hashAtRest: boolean | "migrate";
  private readonly generateToken?: () => string;
  private readonly isLegacyToken: (token: string) => boolean;

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
    this.hashAtRest = opts.tokens?.hashAtRest ?? false;
    this.generateToken = opts.tokens?.generate;
    this.isLegacyToken = opts.tokens?.isLegacyToken ?? ((token) => UUID_TOKEN.test(token));
    if ((this.hashAtRest || this.generateToken) && !this.store.persistAs) {
      throw new AuthError(
        "INVALID_CONFIG",
        "tokens.hashAtRest / tokens.generate need a store that implements persistAs (memory, Redis, atscript-db)",
      );
    }
    if (opts.validateCache) {
      if (!(opts.validateCache.ttlMs > 0)) {
        throw new AuthError(
          "INVALID_CONFIG",
          `validateCache.ttlMs must be > 0 (got ${opts.validateCache.ttlMs})`,
        );
      }
      this.validated = new ValidateCache(
        opts.validateCache.ttlMs,
        opts.validateCache.max ?? 10_000,
      );
    }

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
    // 0 is meaningful (strict single-use); only a negative window is nonsense.
    const graceMs = this.refreshConfig?.rotationGraceMs;
    if (graceMs !== undefined && graceMs < 0) {
      throw new AuthError(
        "INVALID_CONFIG",
        `refresh.rotationGraceMs must be >= 0 (got ${graceMs})`,
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
    const {
      metadata,
      sessionId: providedSessionId,
      ttl,
      expiresAt,
      kind,
      refresh,
      ...payload
    } = opts;

    // Resolve THIS mint's refresh-token lifetime (undefined ⇒ no refresh):
    // per-mint `refresh` wins over the instance config; a per-mint object
    // without `ttl` falls back to the instance `refresh.ttl`.
    let refreshTtl: number | undefined;
    if (refresh === undefined) {
      refreshTtl = this.refreshConfig?.ttl;
    } else if (refresh !== false) {
      refreshTtl = refresh.ttl ?? this.refreshConfig?.ttl;
      if (refreshTtl === undefined) {
        throw new AuthError(
          "INVALID_CONFIG",
          "issue: per-mint refresh needs a ttl when no instance refresh config exists",
        );
      }
      if (refreshTtl <= 0) {
        throw new AuthError("INVALID_CONFIG", `issue: refresh.ttl must be > 0 (got ${refreshTtl})`);
      }
      // 0 is meaningful (strict single-use); only a negative window is nonsense.
      if (refresh.graceMs !== undefined && refresh.graceMs < 0) {
        throw new AuthError(
          "INVALID_CONFIG",
          `issue: refresh.graceMs must be >= 0 (got ${refresh.graceMs})`,
        );
      }
    }

    // Fold the semantic `kind` into the persisted metadata bag — it rides every
    // store losslessly and is carried forward across rotation with the rest of
    // `metadata`, so the whole session family is labelled. This keeps the
    // envelope `kind` free for the internal access/refresh discriminator.
    // A per-mint refresh family additionally stamps its mint-time authority:
    // the per-mint access `ttl` (so refreshes never revert to the instance
    // `accessTtl`), fixed-ceiling `"always"` rotation (so an instance-level
    // 'sliding' config can never extend the family's lifetime), and — when
    // given — the family's own rotation grace window.
    const perMintRefresh = refresh !== undefined && refresh !== false;
    const stampAccessTtl = refreshTtl !== undefined && ttl !== undefined;
    const effectiveMetadata: CredentialMetadata | undefined =
      kind !== undefined || stampAccessTtl || perMintRefresh
        ? {
            ...metadata,
            ...(kind !== undefined && { credentialKind: kind }),
            ...(stampAccessTtl && { accessTtl: ttl }),
            ...(perMintRefresh && { refreshRotation: "always" as const }),
            ...(perMintRefresh &&
              refresh.graceMs !== undefined && { rotationGraceMs: refresh.graceMs }),
          }
        : metadata;

    // Resolve THIS mint's access-token expiry: an explicit `expiresAt` wins, else
    // a per-mint `ttl` override, else the instance `accessTtl`. Omitting both
    // reproduces the prior behavior exactly. The two overrides are exclusive.
    if (ttl !== undefined && expiresAt !== undefined) {
      throw new AuthError("INVALID_CONFIG", "issue: pass either `ttl` or `expiresAt`, not both");
    }
    if (ttl !== undefined && ttl <= 0) {
      throw new AuthError("INVALID_CONFIG", `issue: ttl must be > 0 (got ${ttl})`);
    }
    const accessExpiresAt = expiresAt ?? now + (ttl ?? this.accessTtl);
    // Persist with the remaining lifetime (`expiry - now`); the stores derive the
    // row/exp from `now + ttl`, so this keeps the stored expiry identical to the
    // resolved `accessExpiresAt`. A past `expiresAt` yields a non-positive ttl →
    // a born-expired credential (`validate()` rejects it), never a live token.
    const accessStoreTtl = accessExpiresAt - now;

    // Mint the session id once and stamp it on BOTH the access and refresh
    // tokens (and, via the rotation copies below, every future rotation), so a
    // single login is one stable, opaque session for its whole lifetime.
    const sessionId = providedSessionId ?? randomUUID();
    const accessState = stateWithPayload<TPayload>(payload, {
      userId,
      issuedAt: now,
      expiresAt: accessExpiresAt,
      kind: "access",
      metadata: effectiveMetadata,
      sessionId,
    });

    // The two persists stay SEQUENTIAL on purpose: stores are not required to
    // support concurrent writes on one connection (the sqlite adapter runs
    // each insert in a transaction on a single connection — overlapping them
    // nests transactions and throws).
    const accessToken = await this.put(accessState, accessStoreTtl);

    let refreshToken: string | undefined;
    let refreshExpiresAt: number | undefined;
    if (refreshTtl !== undefined) {
      const refreshState = stateWithPayload<TPayload>(payload, {
        userId,
        issuedAt: now,
        expiresAt: now + refreshTtl,
        kind: "refresh",
        metadata: effectiveMetadata,
        sessionId,
      });
      refreshToken = await this.put(refreshState, refreshTtl);
      refreshExpiresAt = now + refreshTtl;
    }

    return {
      accessToken,
      refreshToken,
      accessExpiresAt,
      refreshExpiresAt,
    };
  }

  async validate(accessToken: string): Promise<AuthContext<TPayload> | null> {
    let key = this.keyOf(accessToken);
    let state: (CredentialState & TPayload) | null | undefined = this.validated?.get(
      key,
      this.clock.now(),
    );
    // Only a state read by THIS call is handed to `touch`: a cached one may
    // predate a revocation made elsewhere, and a store writing it back whole
    // (Redis) would resurrect the token.
    let fresh = false;
    if (!state) {
      fresh = true;
      const epoch = this.validated?.epoch;
      const found = await this.retrieveUnlessDenied(accessToken, key);
      if (!found) return null;
      ({ key, state } = found);
      if (state.expiresAt <= this.clock.now()) return null;
      if (state.kind === "refresh") return null;
      // Not when a revocation ran while this one was reading.
      if (this.validated && this.validated.epoch === epoch) {
        this.validated.set(key, state, this.clock.now());
      }
    } else if (state.expiresAt <= this.clock.now()) {
      this.validated!.delete(key);
      return null;
    }

    if (this.trackLastSeen === "validate" && this.store.touch) {
      // Best-effort activity stamp — one write per authenticated request.
      // Fire-and-forget would race the response; await keeps lastSeenAt
      // monotonic but adds a store round-trip (documented cost). A state
      // just read is passed along so a store can skip re-reading it.
      await this.store.touch(key, this.clock.now(), fresh ? state : undefined);
    }

    // Surface the credential's typed payload fields by name (excludes envelope
    // internals like parentCredentialId); the base read-fields win any clash.
    // `credentialId` (a SHA-256 of the token) is computed on first read.
    const ctx = {
      ...credentialPayloadOf<TPayload>(state),
      userId: state.userId,
      method: this.method,
      credentialId: "",
      // Legacy tokens predating sessionId fall back to the token fingerprint —
      // the SAME fallback listSessions uses, so "this device" matching holds.
      sessionId: state.sessionId ?? this.fingerprintOfKey(key),
      expiresAt: state.expiresAt,
    } as AuthContext<TPayload>;
    // A hashed row key IS the fingerprint; otherwise compute it on first read.
    if (key !== accessToken) ctx.credentialId = key;
    else lazyCredentialId(ctx, accessToken);
    return ctx;
  }

  /**
   * The stored state of `accessToken` unless the orchestrator's denylist has
   * it — both looked up concurrently (one round trip on remote stores).
   */
  private async retrieveUnlessDenied(
    accessToken: string,
    key: string,
  ): Promise<Found<TPayload> | null> {
    const retrieving = this.find(accessToken, key);
    if (!this.denylist) return await retrieving;
    // Handled at once: a store failure settling while the denylist is still
    // awaited must not surface as an unhandled rejection.
    retrieving.catch(() => {});
    if (await this.denylist.has(accessToken)) return null;
    return await retrieving;
  }

  // ── Token ↔ store key (`tokens.hashAtRest`) ──

  /** The store key a token's row lives under: its SHA-256 when hashing, else the token. */
  private keyOf(token: string): string {
    return this.hashAtRest ? fingerprint(token) : token;
  }

  /** `credentialId` (the token's SHA-256) of a stored row, from its store key. */
  private fingerprintOfKey(key: string): string {
    return this.hashAtRest && HASHED_KEY.test(key) ? key : fingerprint(key);
  }

  /** Persist a new credential; returns the token the client will hold. */
  private async put(state: CredentialState & TPayload, ttl: number | undefined): Promise<string> {
    if (!this.hashAtRest && !this.generateToken) return await this.store.persist(state, ttl);
    const token = this.generateToken?.() ?? randomBytes(32).toString("base64url");
    await this.store.persistAs!(this.keyOf(token), state, ttl);
    return token;
  }

  /**
   * Look a token up: by its store key, and — under `hashAtRest: 'migrate'` —
   * by the token itself for a row written before hashing was enabled.
   */
  private async find(token: string, key = this.keyOf(token)): Promise<Found<TPayload> | null> {
    const state = await this.store.retrieve(key);
    if (state) return { key, state };
    if (!this.mayBeLegacyKey(token)) return null;
    const legacy = await this.store.retrieve(token);
    return legacy ? { key: token, state: legacy } : null;
  }

  /**
   * `'migrate'`: may `token` be a row written before hashing, stored under
   * the token itself? Never for a hash-shaped value — that is what a database
   * read yields, and accepting it would turn a leaked row key into a session.
   */
  private mayBeLegacyKey(token: string): boolean {
    return (
      this.hashAtRest === "migrate" &&
      !HASHED_KEY.test(token) &&
      !/\s/.test(token) &&
      this.isLegacyToken(token)
    );
  }

  async refresh(refreshToken: string, opts?: RefreshCallOptions<TPayload>): Promise<RefreshResult> {
    const now = this.clock.now();

    const found = await this.find(refreshToken);
    const oldState = found?.state;
    if (!found || !oldState) {
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

    // Caller-level gate (e.g. authz client binding) — before ANY rotation or
    // reuse response, so a rejected caller leaves the family untouched.
    await opts?.guard?.(oldState);

    // The family's mint-time stamp wins over the instance config (per-mint
    // families are stamped `"always"` — their ceiling must never slide).
    // Without either, only per-mint families can exist in the store, so the
    // no-config fallback is the same fixed-ceiling semantics — there is no
    // instance ttl to slide by anyway.
    const rotation =
      oldState.metadata?.refreshRotation ??
      (this.refreshConfig ? (this.refreshConfig.rotation ?? "sliding") : "always");

    switch (rotation) {
      case "none":
        // Issue new access only; keep the refresh token in place.
        return await this.refreshNone(oldState, refreshToken, now);
      case "always":
        return await this.refreshAlways(oldState, refreshToken, found.key, now);
      case "sliding":
        return await this.refreshSliding(oldState, refreshToken, found.key, now);
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
  ): Promise<RefreshResult> {
    const newAccess = await this.issueAccessFromRefresh(oldState, now);
    return {
      accessToken: newAccess.token,
      accessExpiresAt: newAccess.expiresAt,
      refreshToken,
      refreshExpiresAt: oldState.expiresAt,
      userId: oldState.userId,
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
    key: string,
    now: number,
  ): Promise<RefreshResult> {
    return await this.rotateWithGrace(oldState, refreshToken, key, now, /* preserveExpiry */ false);
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
    key: string,
    now: number,
  ): Promise<RefreshResult> {
    if (!this.store.listForUser) {
      // Stateless store: no in-place mutation → no store-backed grace. Consume
      // the old token and record the reuse signal in the process-local map so
      // a same-process replay still fires the theft response.
      await this.store.consume(key);
      this.sweepConsumedRefreshes();
      this.consumedRefreshes.set(refreshToken, {
        userId: oldState.userId,
        iat: oldState.issuedAt,
        exp: oldState.expiresAt,
        ...(oldState.sessionId !== undefined && { sessionId: oldState.sessionId }),
      });
      return await this.issueRotatedPair(
        oldState,
        refreshToken,
        key,
        /* rotateOld */ false,
        now,
        true,
      );
    }
    return await this.rotateWithGrace(oldState, refreshToken, key, now, /* preserveExpiry */ true);
  }

  /**
   * Shared rotation-with-grace mechanism for `sliding` and `always` on stateful
   * stores. The first rotation keeps the old refresh valid and stamps
   * `rotatedAt` + the {@link CredentialState.successor} pair on it; within the
   * grace window a re-presentation **re-delivers that same pair verbatim** —
   * idempotent, minting nothing, with no liveness side effects (no expiry
   * slide, no `lastSeenAt`) — so a captured stale token teaches an attacker
   * nothing beyond capturing the original rotation response, and a multi-tab
   * race converges on one successor. Beyond grace — or once the successor has
   * itself been rotated or revoked (superseded) — the re-presentation is
   * treated as theft. `preserveExpiry` selects fixed-ceiling (`always`) vs
   * sliding (`sliding`) expiry for the new refresh token; the family's
   * mint-time `metadata.rotationGraceMs` (when stamped) wins over the instance
   * window, and a window of `0` is strict single-use.
   */
  private async rotateWithGrace(
    oldState: CredentialState & TPayload,
    refreshToken: string,
    key: string,
    now: number,
    preserveExpiry: boolean,
  ): Promise<RefreshResult> {
    const graceMs =
      oldState.metadata?.rotationGraceMs ??
      this.refreshConfig?.rotationGraceMs ??
      DEFAULT_ROTATION_GRACE_MS;

    // First rotation: nothing to validate against the grace window yet.
    if (typeof oldState.rotatedAt !== "number") {
      return await this.issueRotatedPair(
        oldState,
        refreshToken,
        key,
        /* rotateOld */ true,
        now,
        preserveExpiry,
      );
    }

    // Both theft paths below (out-of-window, and superseded successor) respond
    // to the same reuse of the same rotated token — one envelope, two guards.
    const reuse = {
      userId: oldState.userId,
      sessionId: oldState.sessionId,
      issuedAt: oldState.issuedAt,
      expiresAt: oldState.expiresAt,
      rotatedAt: oldState.rotatedAt,
    };

    // Re-presentation of an already-rotated refresh. Outside the window — or
    // under a strict `0` window — it is indistinguishable from an attacker
    // replay: theft suspected.
    if (graceMs <= 0 || now - oldState.rotatedAt > graceMs) {
      return await this.respondToRefreshReuse(reuse);
    }

    // Within grace — but only while the family is still parked on the
    // successor this rotation minted. A missing or itself-rotated successor
    // means the client already moved on (or the row predates successor
    // tracking): the presented token is superseded and dead regardless of the
    // window, so a re-presentation can only be a replay.
    // An encrypted (hashAtRest) pair opens only with the presented token.
    const successor =
      oldState.successor === undefined
        ? undefined
        : this.openSuccessor(oldState.successor, refreshToken);
    const successorState =
      successor === undefined ? null : ((await this.find(successor.refreshToken))?.state ?? null);
    if (
      successor === undefined ||
      successorState === null ||
      typeof successorState.rotatedAt === "number"
    ) {
      return await this.respondToRefreshReuse(reuse);
    }

    // Grace hit: idempotent re-delivery of the successor pair. A re-delivery
    // is not user activity — nothing is minted, no state changes, the sliding
    // window does not extend and `lastSeenAt` is not stamped.
    this.refreshConfig?.onRotationGraceHit?.({
      userId: oldState.userId,
      issuedAt: oldState.issuedAt,
      expiresAt: oldState.expiresAt,
      kind: "refresh",
      rotatedAt: oldState.rotatedAt,
      ...(oldState.sessionId !== undefined && { sessionId: oldState.sessionId }),
    });
    return {
      accessToken: successor.accessToken,
      accessExpiresAt: successor.accessExpiresAt,
      refreshToken: successor.refreshToken,
      refreshExpiresAt: successor.refreshExpiresAt,
      userId: oldState.userId,
    };
  }

  // The validate cache is evicted before AND after the store write: a
  // validation that starts while the write is in flight can still read the
  // old state, and must neither stay cached nor be cached after it.
  async revoke(token: string): Promise<void> {
    await this.revokeKey(this.keyOf(token));
    // A row written before hashing was enabled lives under the token itself.
    if (this.mayBeLegacyKey(token)) await this.revokeKey(token);
  }

  /** Revoke the row stored under `key` (a store key, as `listForUser` returns it). */
  private async revokeKey(key: string): Promise<void> {
    this.validated?.delete(key);
    try {
      await this.store.revoke(key);
    } finally {
      this.validated?.delete(key);
    }
  }

  async revokeAllForUser(userId: string): Promise<number> {
    this.validated?.deleteUser(userId);
    try {
      return await this.store.revokeAllForUser(userId);
    } finally {
      this.validated?.deleteUser(userId);
    }
  }

  async listForUser(userId: string): Promise<Array<AuthContext<TPayload>>> {
    if (!this.store.listForUser) return [];
    const all = await this.store.listForUser(userId);
    return all
      .filter((entry) => entry.kind !== "refresh")
      .map((entry) => ({
        ...credentialPayloadOf<TPayload>(entry),
        userId: entry.userId,
        method: this.method,
        credentialId: this.fingerprintOfKey(entry.token),
        sessionId: this.sessionKeyOf(entry),
        expiresAt: entry.expiresAt,
      }));
  }

  /**
   * Session-grouping key for a stored credential entry (its store key
   * attached): its stored `sessionId`, or the token fingerprint for legacy
   * rows predating sessionId (so they surface as singleton sessions) — the
   * same fallback `validate()` applies, so "this device" matching holds.
   */
  private sessionKeyOf(entry: CredentialState & TPayload & { token: string }): string {
    return entry.sessionId ?? this.fingerprintOfKey(entry.token);
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
    opts?: { enrich?: SessionEnricher; kind?: string | string[] },
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
      // Semantic kind of the family (stamped at mint, carried in `metadata`).
      // Filter HERE, against the raw rows — the SessionInfo deliberately drops
      // payload/attenuation, so kind can't be recovered downstream. Absent ⇒
      // an ordinary interactive session.
      const credentialKind = metadata?.credentialKind;
      if (!matchesSessionKind(credentialKind ?? "session", opts?.kind)) continue;
      sessions.push({
        sessionId,
        userId,
        createdAt: createdAt === Infinity ? this.clock.now() : createdAt,
        // Refresh outlives access; prefer its expiry as the session's lifetime.
        expiresAt: refreshExpiresAt ?? accessExpiresAt ?? 0,
        ...(lastSeenAt !== undefined && { lastSeenAt }),
        ...(metadata && { metadata }),
        ...(credentialKind !== undefined && { kind: credentialKind }),
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
        .map((entry) => this.revokeKey(entry.token)),
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
      revokes.push(this.revokeKey(entry.token));
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
      await this.revokeKey(sorted[i].token);
    }
  }

  private async issueAccessFromRefresh(
    refreshState: CredentialState & TPayload,
    now: number,
  ): Promise<{ token: string; expiresAt: number }> {
    // A family stamped with a per-mint access ttl (metadata.accessTtl) keeps
    // it across every refresh — the authority fixed at mint time, never the
    // instance default.
    const accessTtl = refreshState.metadata?.accessTtl ?? this.accessTtl;
    // Carry the credential's typed payload + session forward across rotation.
    const accessState = stateWithPayload<TPayload>(credentialPayloadOf<TPayload>(refreshState), {
      userId: refreshState.userId,
      issuedAt: now,
      expiresAt: now + accessTtl,
      kind: "access",
      metadata: refreshState.metadata,
      sessionId: refreshState.sessionId,
      ...(this.trackLastSeen === "refresh" && { lastSeenAt: now }),
    });
    const token = await this.put(accessState, accessTtl);
    return { token, expiresAt: now + accessTtl };
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
    oldKey: string,
    rotateOld: boolean,
    now: number,
    preserveExpiry = false,
  ): Promise<RefreshResult> {
    // Sliding needs an instance ttl to slide by; fixed-ceiling (`always` — and
    // every no-instance-config redemption) derives everything from the family.
    const slidingTtl = this.refreshConfig?.ttl;
    if (!preserveExpiry && slidingTtl === undefined) {
      throw new AuthError("INVALID_CONFIG", "Refresh not enabled");
    }

    // Fixed-ceiling (`always`) carries the family's original expiry forward;
    // sliding extends to now + ttl. Persist with the *remaining* lifetime so a
    // TTL-evicting store (Redis PX) never resurrects the token past its ceiling.
    const refreshExpiresAt = preserveExpiry ? oldRefreshState.expiresAt : now + slidingTtl!;
    const refreshTtl = preserveExpiry ? Math.max(0, oldRefreshState.expiresAt - now) : slidingTtl!;

    // Carry the credential's typed payload + session forward across rotation.
    const newRefreshState = stateWithPayload<TPayload>(
      credentialPayloadOf<TPayload>(oldRefreshState),
      {
        userId: oldRefreshState.userId,
        issuedAt: now,
        expiresAt: refreshExpiresAt,
        kind: "refresh",
        metadata: oldRefreshState.metadata,
        // Never the raw token at rest under `hashAtRest`.
        parentCredentialId: this.hashAtRest ? fingerprint(oldRefreshToken) : oldRefreshToken,
        sessionId: oldRefreshState.sessionId,
        ...(this.trackLastSeen === "refresh" && { lastSeenAt: now }),
      },
    );
    // SEQUENTIAL like issue(): stores need not support concurrent writes on
    // one connection (see the note there). The old-row rotation stamp comes
    // last so the new refresh is durable before the old enters grace.
    const access = await this.issueAccessFromRefresh(oldRefreshState, now);
    const newRefreshToken = await this.put(newRefreshState, refreshTtl);

    if (rotateOld) {
      // Mark the old refresh as rotated and pin the successor pair on it; it
      // stays valid until grace expires (its expiresAt remains as originally
      // set; grace logic uses rotatedAt) and a within-grace re-presentation
      // re-delivers EXACTLY this pair — grace hits mint nothing.
      const rotatedState: CredentialState & TPayload = {
        ...oldRefreshState,
        rotatedAt: now,
        successor: this.sealSuccessor(
          {
            accessToken: access.token,
            accessExpiresAt: access.expiresAt,
            refreshToken: newRefreshToken,
            refreshExpiresAt,
          },
          oldRefreshToken,
        ),
      };
      await this.store.update(oldKey, rotatedState);
    }

    return {
      accessToken: access.token,
      accessExpiresAt: access.expiresAt,
      refreshToken: newRefreshToken,
      refreshExpiresAt,
      userId: oldRefreshState.userId,
    };
  }

  /**
   * Under `hashAtRest` the successor pair is stored encrypted with a key
   * derived from the old refresh token — only a holder of that token (the
   * grace-window re-presentation) can read the pair back.
   */
  private sealSuccessor(
    successor: CredentialSuccessorRef,
    oldRefreshToken: string,
  ): CredentialSuccessorRef {
    if (!this.hashAtRest) return successor;
    const key = successorKey(oldRefreshToken);
    return {
      ...successor,
      accessToken: sealToken(key, successor.accessToken),
      refreshToken: sealToken(key, successor.refreshToken),
    };
  }

  /** Inverse of {@link sealSuccessor}; `undefined` when the pair cannot be opened. */
  private openSuccessor(
    successor: CredentialSuccessorRef,
    presentedToken: string,
  ): CredentialSuccessorRef | undefined {
    const sealed =
      successor.accessToken.startsWith(SEALED_PREFIX) ||
      successor.refreshToken.startsWith(SEALED_PREFIX);
    if (!sealed) return successor;
    const key = successorKey(presentedToken);
    const accessToken = openToken(key, successor.accessToken);
    const refreshToken = openToken(key, successor.refreshToken);
    if (accessToken === null || refreshToken === null) return undefined;
    return { ...successor, accessToken, refreshToken };
  }

  /** Amortized sweep of expired `consumedRefreshes` entries (each size doubling). */
  private sweepConsumedRefreshes(): void {
    if (this.consumedRefreshes.size < this.consumedSweepAt) return;
    const now = this.clock.now();
    for (const [token, entry] of this.consumedRefreshes) {
      if (entry.exp <= now) this.consumedRefreshes.delete(token);
    }
    this.consumedSweepAt = Math.max(MIN_SWEEP_SIZE, this.consumedRefreshes.size * 2);
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
      await this.revokeAllForUser(reuse.userId);
    }

    throw new AuthError("REFRESH_REUSE_DETECTED", undefined, {
      userId: reuse.userId,
      ...(reuse.sessionId !== undefined && { sessionId: reuse.sessionId }),
      ...(reuse.rotatedAt !== undefined && { rotatedAt: reuse.rotatedAt }),
    });
  }
}
