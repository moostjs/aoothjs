import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";

import { UserAuthError } from "./errors";
import { verifyTotpCode } from "./mfa/totp";
import { PasswordHasher } from "./password/hasher";
import { normalizePolicies, PasswordPolicy } from "./password/policy";
import type {
  DeepPartial,
  LockStatus,
  LockoutConfig,
  LoginResult,
  MfaData,
  MfaMethod,
  MfaMethodInfo,
  PasswordConfig,
  PasswordData,
  PolicyCheckResult,
  TotpConfig,
  TransferablePolicy,
  TrustedDeviceRecord,
  UserCredentials,
  UserServiceConfig,
} from "./types";
import { UserStore } from "./store/user-store";
import { maskMfaValue } from "./utils";

interface ResolvedConfig {
  password: Required<Omit<PasswordConfig, "policies">> & { policies: PasswordPolicy[] };
  lockout: Required<LockoutConfig>;
  clock: () => number;
  deviceTrust?: { secret: string };
}

function resolveConfig(config?: UserServiceConfig): ResolvedConfig {
  return {
    password: {
      pepper: config?.password?.pepper ?? "",
      historyLength: config?.password?.historyLength ?? 0,
      scryptN: config?.password?.scryptN ?? 16384,
      scryptR: config?.password?.scryptR ?? 8,
      scryptP: config?.password?.scryptP ?? 1,
      keyLength: config?.password?.keyLength ?? 64,
      policies: normalizePolicies(config?.password?.policies),
      maxAgeMs: config?.password?.maxAgeMs ?? 0,
    },
    lockout: {
      threshold: config?.lockout?.threshold ?? 0,
      duration: config?.lockout?.duration ?? 0,
    },
    clock: config?.clock ?? Date.now,
    ...(config?.deviceTrust && { deviceTrust: config.deviceTrust }),
  };
}

// ---- device-trust helpers ----
// Token format: `<raw 32-byte hex>.<hmac-sha256(userId|raw|ip-or-empty)>`.
// The HMAC ties the token to the user (and optionally the IP); the persisted
// record enforces expiry + IP binding on top.
const DEVICE_TRUST_TOKEN_BYTES = 32;
const DEVICE_TRUST_SEPARATOR = ".";
// Recognition ledger cap — beyond this, least-recently-verified records
// (smallest `expiresAt`) are evicted on `addSeenDevice`.
const SEEN_DEVICES_DEFAULT_CAP = 5;

function signDeviceTrust(secret: string, payload: string): string {
  return createHmac("sha256", secret).update(payload).digest("hex");
}

// Domain-separated HMAC payloads — kept adjacent so it stays obvious the two
// token kinds can never be interchangeable (trust skips MFA; seen only
// suppresses the new-sign-in notification).
function trustedDevicePayload(userId: string, raw: string, ip?: string): string {
  return `${userId}|${raw}|${ip ?? ""}`;
}

function seenDevicePayload(userId: string, raw: string): string {
  return `seen|${userId}|${raw}`;
}

function parseDeviceTrustToken(token: string): { raw: string; sig: string } | undefined {
  const sepIdx = token.lastIndexOf(DEVICE_TRUST_SEPARATOR);
  if (sepIdx <= 0) return undefined;
  return { raw: token.slice(0, sepIdx), sig: token.slice(sepIdx + 1) };
}

function deviceTrustSafeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/**
 * Orchestrates user credentials over a pluggable {@link UserStore}.
 *
 * Identity model: the stable surrogate **`id`** is the token subject. `getUser`
 * and every mutation/admin method are keyed by `id` (the value carried in the
 * session and returned by `useAuth().getUserId()`); only `login` (and other
 * handle-driven entry points) take a `username`/`email` login handle, resolved
 * via `UserStore.findByHandle`.
 */
export class UserService<T extends object = object> {
  protected readonly config: ResolvedConfig;
  protected readonly hasher: PasswordHasher;

  constructor(
    protected readonly store: UserStore<T>,
    config?: UserServiceConfig,
  ) {
    this.config = resolveConfig(config);
    this.hasher = new PasswordHasher(this.config.password);
  }

  /**
   * Creates a user with `account.active: false`. The invite workflow relies
   * on this default (see `InviteWorkflow.acceptInvite` — pending invitees stay
   * inactive until they accept). For setup scripts / seeders / tests that
   * don't go through invite, follow up with `activateAccount(id)` or `login()`
   * will throw `UserAuthError("INACTIVE")` — which the login workflow
   * deliberately re-maps to `"Invalid credentials"` to avoid account
   * enumeration, so the failure is silent client-side.
   *
   * A stable `id` is minted here (server-managed surrogate, also the token
   * subject) and returned on the record, so callers can `auth.issue(user.id)`
   * without a re-read. Pass `id` via `extras` to override it.
   *
   * @param extras Optional partial user fields merged AFTER the base
   *   `UserCredentials` shape, so callers can populate consumer-specific
   *   required fields (e.g. `tenantId`) without subclassing the store.
   *   Because the merge is shallow and extras win, overlapping top-level
   *   keys (`id`, `email`, `account`, `mfa`, ...) replace the defaults
   *   entirely — pass nested objects with all required sub-fields if you
   *   intend to override them.
   */
  async createUser(
    username: string,
    password?: string,
    extras?: Partial<T>,
  ): Promise<UserCredentials & T> {
    const pw = password ?? this.hasher.generatePassword();
    const hash = await this.hasher.hash(pw);

    const base: UserCredentials = {
      id: randomUUID(),
      username,
      password: {
        hash,
        history: [],
        lastChanged: this.config.clock(),
        isInitial: !password,
      },
      account: {
        active: false,
        locked: false,
        lockReason: "",
        lockEnds: 0,
        failedLoginAttempts: 0,
        lastLogin: 0,
      },
      mfa: {
        methods: [],
        defaultMethod: "",
        autoSend: false,
      },
    };

    const userData = { ...base, ...extras } as UserCredentials & T;
    await this.store.create(userData);
    return userData;
  }

  /** Read by the stable `id` (the token subject). */
  async getUser(id: string): Promise<UserCredentials & T> {
    const user = await this.store.findById(id);
    if (!user) throw new UserAuthError("NOT_FOUND");
    return user;
  }

  /**
   * Deterministic handle resolver — `username` exact, then `email` exact.
   * Returns `null` when nothing matches. Maps a login/recovery handle to a row;
   * `login` uses the same resolution.
   */
  async findByHandle(handle: string): Promise<(UserCredentials & T) | null> {
    return this.store.findByHandle(handle);
  }

  /**
   * Permissive lookup — `id`, then `username`, then `email` (ordered, first
   * match). For internal / admin / recovery callers that may hold either an id
   * or a handle. NOT for the login path (use {@link login}/{@link findByHandle}).
   */
  async findByIdentifier(value: string): Promise<(UserCredentials & T) | null> {
    return this.store.findByIdentifier(value);
  }

  async login(
    handle: string,
    password: string,
    lockoutOverride?: Partial<LockoutConfig>,
  ): Promise<LoginResult<T>> {
    const user = await this.store.findByHandle(handle);
    if (!user) throw new UserAuthError("NOT_FOUND");

    if (!user.account.active) {
      throw new UserAuthError("INACTIVE");
    }

    await this.ensureNotLockedOrThrow(user.id, user.account);

    const valid = await this.hasher.verify(password, user.password.hash);

    if (valid) {
      const now = this.config.clock();
      await this.store.update(user.id, {
        set: {
          account: { lastLogin: now, failedLoginAttempts: 0 },
        } as DeepPartial<UserCredentials>,
      });

      // Patch in-memory instead of re-reading from store
      user.account.lastLogin = now;
      user.account.failedLoginAttempts = 0;
      const mfaRequired = this.hasConfirmedMfaMethods(user.mfa);
      return { user, mfaRequired };
    }

    return this.incrementAndMaybeLock(
      user.id,
      user.account,
      "INVALID_CREDENTIALS",
      lockoutOverride,
    );
  }

  async verifyPassword(id: string, password: string): Promise<boolean> {
    const user = await this.store.findById(id);
    if (!user) throw new UserAuthError("NOT_FOUND");
    return this.hasher.verify(password, user.password.hash);
  }

  async changePassword(
    id: string,
    currentPassword: string,
    newPassword: string,
    repeatPassword?: string,
  ): Promise<void> {
    if (repeatPassword !== undefined && newPassword !== repeatPassword) {
      throw new UserAuthError("PASSWORDS_MISMATCH");
    }

    const user = await this.getUser(id);

    const valid = await this.hasher.verify(currentPassword, user.password.hash);
    if (!valid) throw new UserAuthError("INVALID_CREDENTIALS");

    await this.applyPasswordChange(id, user, newPassword);
  }

  async setPassword(id: string, newPassword: string): Promise<void> {
    const user = await this.getUser(id);
    await this.applyPasswordChange(id, user, newPassword);
  }

  /**
   * Hard-delete the user row by `id`. Returns nothing on success. Throws
   * `UserAuthError("NOT_FOUND")` when no row matches. Used by the invite
   * workflow's `auth/invite/cancel` to revoke a pending invitation.
   */
  async deleteUser(id: string): Promise<void> {
    const removed = await this.store.delete(id);
    if (!removed) throw new UserAuthError("NOT_FOUND");
  }

  /**
   * Deep-merge `patch` into the user record (top-level fields are shallow-
   * merged; `account` / `mfa` / `password` are merged per their
   * `@db.patch.strategy 'merge'` declaration). Returns the patched record.
   * Used by the invite workflow's `applyProfile` default fallback.
   */
  async update(id: string, patch: Partial<UserCredentials & T>): Promise<UserCredentials & T> {
    const found = await this.store.update(id, {
      set: patch as DeepPartial<UserCredentials>,
    });
    if (!found) throw new UserAuthError("NOT_FOUND");
    return this.getUser(id);
  }

  async activateAccount(id: string): Promise<void> {
    const found = await this.store.update(id, {
      set: { account: { active: true } } as DeepPartial<UserCredentials>,
    });
    if (!found) throw new UserAuthError("NOT_FOUND");
  }

  async deactivateAccount(id: string): Promise<void> {
    const found = await this.store.update(id, {
      set: { account: { active: false } } as DeepPartial<UserCredentials>,
    });
    if (!found) throw new UserAuthError("NOT_FOUND");
  }

  async lockAccount(id: string, reason: string, duration?: number): Promise<void> {
    const lockEnds = duration ? this.config.clock() + duration : 0;
    const found = await this.store.update(id, {
      set: {
        account: { locked: true, lockReason: reason, lockEnds },
      } as DeepPartial<UserCredentials>,
    });
    if (!found) throw new UserAuthError("NOT_FOUND");
  }

  async unlockAccount(id: string): Promise<void> {
    const found = await this.store.update(id, {
      set: {
        account: { locked: false, lockReason: "", lockEnds: 0, failedLoginAttempts: 0 },
      } as DeepPartial<UserCredentials>,
    });
    if (!found) throw new UserAuthError("NOT_FOUND");
  }

  getLockStatus(account: UserCredentials["account"]): LockStatus {
    if (!account.locked) {
      return { locked: false, expired: false, reason: "", lockEnds: 0 };
    }
    const expired = account.lockEnds > 0 && account.lockEnds < this.config.clock();
    return {
      locked: true,
      expired,
      reason: account.lockReason,
      lockEnds: account.lockEnds,
    };
  }

  /**
   * Returns `true` when the user's password is older than
   * `config.password.maxAgeMs`. Returns `false` when:
   * - `maxAgeMs` is unset or `0` (expiry disabled)
   * - `password.lastChanged` is `0` / falsy (no recorded change — never
   *   expire a user whose timestamp wasn't captured, since that would
   *   force-loop on every login)
   *
   * Consulted by `@aooth/auth-moost` `LoginWorkflow`'s `credentials`
   * step to set `ctx.isPasswordExpired` when `guards.passwordExpiry`
   * is true (the default).
   */
  isPasswordExpired(user: UserCredentials & T, now: number = this.config.clock()): boolean {
    const maxAgeMs = this.config.password.maxAgeMs;
    const lastChanged = user.password.lastChanged;
    if (!maxAgeMs || !lastChanged) return false;
    return now - lastChanged > maxAgeMs;
  }

  async checkPolicies(password: string, passwordData?: PasswordData): Promise<PolicyCheckResult> {
    const result: PolicyCheckResult = { passed: true, policies: [], errors: [] };
    for (const policy of this.config.password.policies) {
      const passed = await policy.evaluate(password, {
        passwordData,
        passwordConfig: this.config.password,
      });
      result.passed = result.passed && passed;
      result.policies.push({ description: policy.description, passed });
      if (!passed) result.errors.push(policy.errorMessage);
    }
    return result;
  }

  getTransferablePolicies(): TransferablePolicy[] {
    return this.config.password.policies
      .filter((p) => p.transferable)
      .map((p) => ({
        // `serialized` is the pre-baked `(v) => (fn)(v, ...args)` text built
        // by `definePasswordPolicy`. `.filter(transferable)` above guarantees
        // it's present; the `!` reflects that contract.
        rule: p.serialized as string,
        description: p.description,
        errorMessage: p.errorMessage,
      }));
  }

  async addMfaMethod(id: string, method: MfaMethod): Promise<void> {
    await this.store.withCas(id, (user) => {
      const methods = [...user.mfa.methods.filter((m) => m.name !== method.name), method];
      return { set: { mfa: { methods } } as DeepPartial<UserCredentials> };
    });
  }

  async confirmMfaMethod(id: string, name: string): Promise<void> {
    await this.store.withCas(id, (user) => {
      let found = false;
      const methods = user.mfa.methods.map((m) => {
        if (m.name === name) {
          found = true;
          return { ...m, confirmed: true };
        }
        return m;
      });
      if (!found) throw new UserAuthError("MFA_NOT_CONFIGURED");
      return { set: { mfa: { methods } } as DeepPartial<UserCredentials> };
    });
  }

  async removeMfaMethod(id: string, name: string): Promise<void> {
    const user = await this.getUser(id);
    const methods = user.mfa.methods.filter((m) => m.name !== name);
    const update: DeepPartial<UserCredentials> = { mfa: { methods } };
    if (user.mfa.defaultMethod === name) {
      update.mfa!.defaultMethod = "";
    }
    await this.store.update(id, { set: update });
  }

  async setDefaultMfaMethod(id: string, name: string): Promise<void> {
    const user = await this.getUser(id);
    if (name && !user.mfa.methods.some((m) => m.name === name)) {
      throw new UserAuthError("MFA_NOT_CONFIGURED");
    }
    await this.store.update(id, {
      set: { mfa: { defaultMethod: name, autoSend: false } } as DeepPartial<UserCredentials>,
    });
  }

  async setMfaAutoSend(id: string, value: boolean): Promise<void> {
    const found = await this.store.update(id, {
      set: { mfa: { autoSend: value } } as DeepPartial<UserCredentials>,
    });
    if (!found) throw new UserAuthError("NOT_FOUND");
  }

  getAvailableMfaMethods(mfa: MfaData): MfaMethodInfo[] {
    return mfa.methods
      .filter((m) => m.confirmed)
      .map((m) => ({
        name: m.name,
        isDefault: mfa.defaultMethod === m.name,
        masked: maskMfaValue(m),
      }));
  }

  /**
   * Verify a TOTP code against the user's confirmed `totp` MFA method.
   * Failures bump the same `failedLoginAttempts` counter as `login` so an
   * attacker who knows the password but not the TOTP gets `lockout.threshold`
   * total tries across BOTH factors, not `2 * threshold`.
   */
  async verifyMfa(
    id: string,
    code: string,
    config?: TotpConfig,
    lockoutOverride?: Partial<LockoutConfig>,
  ): Promise<void> {
    const user = await this.getUser(id);

    if (!user.account.active) {
      throw new UserAuthError("INACTIVE");
    }

    await this.ensureNotLockedOrThrow(id, user.account);

    const totp = user.mfa.methods.find((m) => m.name === "totp" && m.confirmed);
    if (!totp) throw new UserAuthError("MFA_NOT_CONFIGURED");

    const matchedCounter = verifyTotpCode(totp.value, code, config);
    // Replay guard: a code whose HOTP counter is `<= lastUsedWindow` was already
    // consumed in this or an earlier window. Fall through to the same wrong-code
    // path so we don't leak "replay" vs "wrong" to an attacker.
    const isReplay =
      matchedCounter !== null &&
      totp.lastUsedWindow !== undefined &&
      matchedCounter <= totp.lastUsedWindow;
    if (matchedCounter !== null && !isReplay) {
      // Re-check replay inside the CAS mutator against the FRESH snapshot so two
      // concurrent same-window logins resolve to exactly one winner: the loser
      // re-reads, sees the winner's `lastUsedWindow`, returns `null` (no-op),
      // and falls through to the wrong-code path. Without this re-check the
      // outer `isReplay` is bypassed by a race between `getUser` and `withCas`.
      let replayDuringCas = false;
      await this.store.withCas(id, (current) => {
        const currentTotp = current.mfa.methods.find((m) => m.name === "totp" && m.confirmed);
        if (
          currentTotp?.lastUsedWindow !== undefined &&
          matchedCounter <= currentTotp.lastUsedWindow
        ) {
          replayDuringCas = true;
          return null;
        }
        const methods = current.mfa.methods.map((m) =>
          m.name === "totp" && m.confirmed ? { ...m, lastUsedWindow: matchedCounter } : m,
        );
        const set: DeepPartial<UserCredentials> = {
          mfa: { methods } as DeepPartial<MfaData>,
        };
        if (current.account.failedLoginAttempts > 0) {
          set.account = { failedLoginAttempts: 0 };
        }
        return { set };
      });
      if (!replayDuringCas) return;
    }

    await this.incrementAndMaybeLock(id, user.account, "MFA_INVALID", lockoutOverride);
  }

  /**
   * Verify a TOTP code against an UNCONFIRMED `totp` MFA method during initial
   * enrollment. Differs from `verifyMfa`:
   *   - Looks up unconfirmed (not confirmed) — confirmed totp uses verifyMfa.
   *   - Throws MFA_INVALID on bad code; no failed-login counter bump (this is
   *     pre-activation; lockout doesn't apply).
   *   - No replay/lastUsedWindow tracking — confirmMfaMethod gates further use.
   *
   * Throws: NOT_FOUND if user missing; MFA_NOT_CONFIGURED if no unconfirmed
   * totp method; MFA_INVALID on wrong code.
   */
  async verifyTotpSetupCode(id: string, code: string, config?: TotpConfig): Promise<void> {
    const user = await this.getUser(id);
    const totp = user.mfa.methods.find((m) => m.name === "totp" && !m.confirmed);
    if (!totp) throw new UserAuthError("MFA_NOT_CONFIGURED");
    const matched = verifyTotpCode(totp.value, code, config);
    if (matched === null) throw new UserAuthError("MFA_INVALID");
  }

  getPasswordHasher(): PasswordHasher {
    return this.hasher;
  }

  getConfig(): Readonly<ResolvedConfig> {
    return this.config;
  }

  // ---- trusted devices ----
  /**
   * Mint a freshly-signed trust record (does NOT persist — pair with
   * `addTrustedDevice`). Throws when `deviceTrust.secret` is unset.
   */
  issueTrustedDevice(
    userId: string,
    opts: { ip?: string; ttlMs: number; name?: string },
  ): TrustedDeviceRecord {
    const secret = this.requireDeviceTrustSecret();
    const raw = randomBytes(DEVICE_TRUST_TOKEN_BYTES).toString("hex");
    const sig = signDeviceTrust(secret, trustedDevicePayload(userId, raw, opts.ip));
    const now = this.config.clock();
    return {
      token: `${raw}${DEVICE_TRUST_SEPARATOR}${sig}`,
      ...(opts.ip !== undefined && { ip: opts.ip }),
      issuedAt: now,
      expiresAt: now + opts.ttlMs,
      ...(opts.name !== undefined && { name: opts.name }),
    };
  }

  /**
   * Append a trust record to the user's `trustedDevices` list. Read-modify-
   * write — the array shape is preserved end-to-end so DB adapters with a
   * merge strategy replace the whole array.
   */
  async addTrustedDevice(id: string, record: TrustedDeviceRecord): Promise<void> {
    await this.store.withCas(id, (user) => {
      const next = [...(user.trustedDevices ?? []), record];
      return { set: { trustedDevices: next } as DeepPartial<UserCredentials> };
    });
  }

  /**
   * Returns true when the supplied token (a) signs against the user+ip with
   * the configured secret, AND (b) matches a persisted record that is still
   * within its expiry window and whose bound IP (if any) matches.
   */
  async verifyTrustedDevice(userId: string, token: string, ip?: string): Promise<boolean> {
    const secret = this.requireDeviceTrustSecret();
    const parsed = parseDeviceTrustToken(token);
    if (!parsed) return false;
    const expectedSig = signDeviceTrust(secret, trustedDevicePayload(userId, parsed.raw, ip));
    if (!deviceTrustSafeEqual(parsed.sig, expectedSig)) return false;

    const user = await this.store.findById(userId);
    if (!user) return false;
    const list = user.trustedDevices ?? [];
    const now = this.config.clock();
    const found = list.find((r) => r.token === token && r.expiresAt > now);
    if (!found) return false;
    if (found.ip !== undefined && found.ip !== ip) return false;
    return true;
  }

  /**
   * Remove a specific trust record from the user. No-op when the record is
   * absent — mirrors the legacy `DeviceTrustStore.revoke` semantics.
   */
  async revokeTrustedDevice(id: string, token: string): Promise<void> {
    const user = await this.store.findById(id);
    if (!user) return;
    const list = user.trustedDevices ?? [];
    const next = list.filter((r) => r.token !== token);
    if (next.length === list.length) return;
    await this.store.update(id, {
      set: { trustedDevices: next } as DeepPartial<UserCredentials>,
    });
  }

  async listTrustedDevices(id: string): Promise<TrustedDeviceRecord[]> {
    const user = await this.getUser(id);
    return user.trustedDevices ?? [];
  }

  private requireDeviceTrustSecret(): string {
    const secret = this.config.deviceTrust?.secret;
    if (!secret) {
      throw new Error("UserService: deviceTrust.secret is required to use trusted-device APIs");
    }
    return secret;
  }

  // ---- seen devices (recognition ledger) ----
  // Same token format and signing secret as trust; domain separation lives in
  // `seenDevicePayload` vs `trustedDevicePayload` above.

  /**
   * Mint a freshly-signed recognition record (does NOT persist — pair with
   * `addSeenDevice`). No IP binding — recognition is pure noise control.
   * Throws when `deviceTrust.secret` is unset.
   */
  issueSeenDevice(userId: string, opts: { ttlMs: number; name?: string }): TrustedDeviceRecord {
    const secret = this.requireDeviceTrustSecret();
    const raw = randomBytes(DEVICE_TRUST_TOKEN_BYTES).toString("hex");
    const sig = signDeviceTrust(secret, seenDevicePayload(userId, raw));
    const now = this.config.clock();
    return {
      token: `${raw}${DEVICE_TRUST_SEPARATOR}${sig}`,
      issuedAt: now,
      expiresAt: now + opts.ttlMs,
      ...(opts.name !== undefined && { name: opts.name }),
    };
  }

  /**
   * Append a recognition record to the user's `seenDevices` ledger and enforce
   * the cap (default 5): expired records are dropped first, then the
   * least-recently-verified records (smallest `expiresAt` — verification
   * slides it, so it doubles as the LRU key) are evicted until at cap.
   * Read-modify-write under CAS — the array shape is preserved end-to-end so
   * DB adapters with a merge strategy replace the whole array.
   */
  async addSeenDevice(
    id: string,
    record: TrustedDeviceRecord,
    opts?: { cap?: number },
  ): Promise<void> {
    const cap = opts?.cap ?? SEEN_DEVICES_DEFAULT_CAP;
    await this.store.withCas(id, (user) => {
      let next = [...(user.seenDevices ?? []), record];
      if (next.length > cap) {
        const now = this.config.clock();
        next = next.filter((r) => r.expiresAt > now);
        if (next.length > cap) {
          // `next` is already a fresh copy — sort in place, keep the cap newest.
          next.sort((a, b) => a.expiresAt - b.expiresAt);
          next = next.slice(next.length - cap);
        }
      }
      return { set: { seenDevices: next } as DeepPartial<UserCredentials> };
    });
  }

  /**
   * Returns true when the supplied token signs against the user with the
   * configured secret (recognition domain) AND matches a persisted
   * `seenDevices` record still within its expiry window. On a valid hit with
   * `opts.slideTtlMs` set, the record's `expiresAt` is slid to
   * `clock() + slideTtlMs` under CAS — the LRU bump. Never throws on a bad
   * token (only on a missing secret, mirroring `verifyTrustedDevice`).
   */
  async verifySeenDevice(
    userId: string,
    token: string,
    opts?: { slideTtlMs?: number },
  ): Promise<boolean> {
    const secret = this.requireDeviceTrustSecret();
    const parsed = parseDeviceTrustToken(token);
    if (!parsed) return false;
    const expectedSig = signDeviceTrust(secret, seenDevicePayload(userId, parsed.raw));
    if (!deviceTrustSafeEqual(parsed.sig, expectedSig)) return false;

    const user = await this.store.findById(userId);
    if (!user) return false;
    const now = this.config.clock();
    const found = (user.seenDevices ?? []).find((r) => r.token === token && r.expiresAt > now);
    if (!found) return false;

    const slideTtlMs = opts?.slideTtlMs;
    if (slideTtlMs !== undefined) {
      await this.store.withCas(userId, (current) => {
        const list = current.seenDevices ?? [];
        const idx = list.findIndex((r) => r.token === token);
        if (idx === -1) return null;
        const next = [...list];
        next[idx] = { ...next[idx], expiresAt: this.config.clock() + slideTtlMs };
        return { set: { seenDevices: next } as DeepPartial<UserCredentials> };
      });
    }
    return true;
  }

  async listSeenDevices(id: string): Promise<TrustedDeviceRecord[]> {
    const user = await this.getUser(id);
    return user.seenDevices ?? [];
  }

  /**
   * Clear the whole recognition ledger. No-op safe when the ledger is absent
   * or already empty.
   */
  async revokeSeenDevices(id: string): Promise<void> {
    const user = await this.store.findById(id);
    if (!user || (user.seenDevices ?? []).length === 0) return;
    await this.store.update(id, {
      set: { seenDevices: [] } as DeepPartial<UserCredentials>,
    });
  }

  /**
   * True when `deviceTrust.secret` is configured — lets the workflow layer
   * skip device recognition entirely (degrade gracefully) instead of throwing.
   */
  hasDeviceTrustSecret(): boolean {
    return !!this.config.deviceTrust?.secret;
  }

  // ---- private helpers ----

  private async applyPasswordChange(
    id: string,
    user: UserCredentials & T,
    newPassword: string,
  ): Promise<void> {
    const policyResult = await this.checkPolicies(newPassword, user.password);
    if (!policyResult.passed) {
      throw new UserAuthError("POLICY_VIOLATION", policyResult.errors.join("; "), {
        policies: policyResult.policies,
      });
    }

    // Check against current password + history in parallel
    const hashesToCheck = [user.password.hash, ...user.password.history].filter(Boolean);
    if (hashesToCheck.length > 0) {
      const results = await Promise.all(
        hashesToCheck.map((h) => this.hasher.verify(newPassword, h)),
      );
      if (results.some(Boolean)) {
        throw new UserAuthError("PASSWORD_IN_HISTORY");
      }
    }

    const newHash = await this.hasher.hash(newPassword);
    const limit = this.config.password.historyLength;
    const newHistory =
      limit > 0
        ? [user.password.hash, ...user.password.history].filter(Boolean).slice(0, limit)
        : [];

    await this.store.update(id, {
      set: {
        password: {
          hash: newHash,
          history: newHistory,
          lastChanged: this.config.clock(),
          isInitial: false,
        },
      } as DeepPartial<UserCredentials>,
    });
  }

  private hasConfirmedMfaMethods(mfa: MfaData): boolean {
    return mfa.methods.some((m) => m.confirmed);
  }

  /**
   * If `account.locked`: auto-unlock when the lock has expired (mutating
   * `account` in place), or throw `LOCKED` otherwise.
   */
  private async ensureNotLockedOrThrow(
    id: string,
    account: UserCredentials["account"],
  ): Promise<void> {
    const lockStatus = this.getLockStatus(account);
    if (!lockStatus.locked) return;
    if (lockStatus.expired) {
      await this.store.update(id, {
        set: {
          account: { locked: false, lockReason: "", lockEnds: 0 },
        } as DeepPartial<UserCredentials>,
      });
      account.locked = false;
      account.lockEnds = 0;
      account.lockReason = "";
      return;
    }
    throw new UserAuthError("LOCKED", undefined, {
      reason: account.lockReason,
      lockEnds: account.lockEnds,
    });
  }

  /**
   * Bump `failedLoginAttempts`, locking the account when threshold is hit,
   * and always throw `errorCode` (with `details.lockEnds` when the lockout
   * just tripped). Used by both `login` and `verifyMfa` so the two factors
   * share one counter.
   *
   * `lockoutOverride` lets a caller (e.g. a workflow policy resolver) force a
   * different posture for THIS lock — notably `{ duration: 0 }` to make the
   * lock permanent (admin-/recovery-lift only) instead of timed. Unset fields
   * fall back to `this.config.lockout`.
   */
  private async incrementAndMaybeLock(
    id: string,
    account: UserCredentials["account"],
    errorCode: "INVALID_CREDENTIALS" | "MFA_INVALID",
    lockoutOverride?: Partial<LockoutConfig>,
  ): Promise<never> {
    const newAttempts = account.failedLoginAttempts + 1;
    const { threshold, duration } = { ...this.config.lockout, ...lockoutOverride };
    const shouldLock = threshold > 0 && newAttempts >= threshold;

    if (shouldLock) {
      const lockEnds = duration ? this.config.clock() + duration : 0;
      await this.store.update(id, {
        inc: { "account.failedLoginAttempts": 1 },
        set: {
          account: { locked: true, lockReason: "Too many login attempts", lockEnds },
        } as DeepPartial<UserCredentials>,
      });
      throw new UserAuthError(errorCode, undefined, { lockEnds });
    }

    await this.store.update(id, {
      inc: { "account.failedLoginAttempts": 1 },
    });
    throw new UserAuthError(errorCode);
  }
}
