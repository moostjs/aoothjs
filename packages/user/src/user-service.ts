import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

import { UserAuthError } from "./errors";
import { generateBackupCodePlaintext } from "./mfa/backup-codes";
import { hashMfaCode, verifyMfaCode } from "./mfa/codes";
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

function signDeviceTrust(secret: string, payload: string): string {
  return createHmac("sha256", secret).update(payload).digest("hex");
}

function deviceTrustSafeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

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
   * don't go through invite, follow up with `activateAccount(username)` or
   * `login()` will throw `UserAuthError("INACTIVE")` — which the login
   * workflow deliberately re-maps to `"Invalid credentials"` to avoid account
   * enumeration, so the failure is silent client-side.
   *
   * @param extras Optional partial user fields merged AFTER the base
   *   `UserCredentials` shape, so callers can populate consumer-specific
   *   required fields (e.g. `tenantId`) without subclassing the store.
   *   Because the merge is shallow and extras win, overlapping top-level
   *   keys (`id`, `account`, `mfa`, ...) replace the defaults entirely —
   *   pass nested objects with all required sub-fields if you intend to
   *   override them.
   */
  async createUser(
    username: string,
    password?: string,
    extras?: Partial<T>,
  ): Promise<UserCredentials & T> {
    const pw = password ?? this.hasher.generatePassword();
    const hash = await this.hasher.hash(pw);

    // Omit `id` from the base record so the underlying store/DB default
    // (e.g. atscript-db's `@db.default.uuid`) decides. Callers that want a
    // specific id pass it via `extras`.
    const base: Omit<UserCredentials, "id"> = {
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

  async getUser(username: string): Promise<UserCredentials & T> {
    const user = await this.store.findByUsername(username);
    if (!user) throw new UserAuthError("NOT_FOUND");
    return user;
  }

  async login(username: string, password: string): Promise<LoginResult<T>> {
    const user = await this.store.findByUsername(username);
    if (!user) throw new UserAuthError("NOT_FOUND");

    if (!user.account.active) {
      throw new UserAuthError("INACTIVE");
    }

    await this.ensureNotLockedOrThrow(username, user.account);

    const valid = await this.hasher.verify(password, user.password.hash);

    if (valid) {
      const now = this.config.clock();
      await this.store.update(username, {
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

    return this.incrementAndMaybeLock(username, user.account, "INVALID_CREDENTIALS");
  }

  async verifyPassword(username: string, password: string): Promise<boolean> {
    const user = await this.store.findByUsername(username);
    if (!user) throw new UserAuthError("NOT_FOUND");
    return this.hasher.verify(password, user.password.hash);
  }

  async changePassword(
    username: string,
    currentPassword: string,
    newPassword: string,
    repeatPassword?: string,
  ): Promise<void> {
    if (repeatPassword !== undefined && newPassword !== repeatPassword) {
      throw new UserAuthError("PASSWORDS_MISMATCH");
    }

    const user = await this.getUser(username);

    const valid = await this.hasher.verify(currentPassword, user.password.hash);
    if (!valid) throw new UserAuthError("INVALID_CREDENTIALS");

    await this.applyPasswordChange(username, user, newPassword);
  }

  async setPassword(username: string, newPassword: string): Promise<void> {
    const user = await this.getUser(username);
    await this.applyPasswordChange(username, user, newPassword);
  }

  /**
   * Hard-delete the user row. Returns nothing on success. Throws
   * `UserAuthError("NOT_FOUND")` when no row matches `username`. Used by the
   * invite workflow's `auth.cancelInvite` to revoke a pending invitation.
   */
  async deleteUser(username: string): Promise<void> {
    const removed = await this.store.delete(username);
    if (!removed) throw new UserAuthError("NOT_FOUND");
  }

  /**
   * Deep-merge `patch` into the user record (top-level fields are shallow-
   * merged; `account` / `mfa` / `password` are merged per their
   * `@db.patch.strategy 'merge'` declaration). Returns the patched record.
   * Used by the invite workflow's `applyProfile` default fallback.
   */
  async update(
    username: string,
    patch: Partial<UserCredentials & T>,
  ): Promise<UserCredentials & T> {
    const found = await this.store.update(username, {
      set: patch as DeepPartial<UserCredentials>,
    });
    if (!found) throw new UserAuthError("NOT_FOUND");
    return this.getUser(username);
  }

  async activateAccount(username: string): Promise<void> {
    const found = await this.store.update(username, {
      set: { account: { active: true } } as DeepPartial<UserCredentials>,
    });
    if (!found) throw new UserAuthError("NOT_FOUND");
  }

  async deactivateAccount(username: string): Promise<void> {
    const found = await this.store.update(username, {
      set: { account: { active: false } } as DeepPartial<UserCredentials>,
    });
    if (!found) throw new UserAuthError("NOT_FOUND");
  }

  async lockAccount(username: string, reason: string, duration?: number): Promise<void> {
    const lockEnds = duration ? this.config.clock() + duration : 0;
    const found = await this.store.update(username, {
      set: {
        account: { locked: true, lockReason: reason, lockEnds },
      } as DeepPartial<UserCredentials>,
    });
    if (!found) throw new UserAuthError("NOT_FOUND");
  }

  async unlockAccount(username: string): Promise<void> {
    const found = await this.store.update(username, {
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
        rule: p.rule as string,
        description: p.description,
        errorMessage: p.errorMessage,
      }));
  }

  async addMfaMethod(username: string, method: MfaMethod): Promise<void> {
    await this.store.withCas(username, (user) => {
      const methods = [...user.mfa.methods.filter((m) => m.name !== method.name), method];
      return { set: { mfa: { methods } } as DeepPartial<UserCredentials> };
    });
  }

  async confirmMfaMethod(username: string, name: string): Promise<void> {
    await this.store.withCas(username, (user) => {
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

  async removeMfaMethod(username: string, name: string): Promise<void> {
    const user = await this.getUser(username);
    const methods = user.mfa.methods.filter((m) => m.name !== name);
    const update: DeepPartial<UserCredentials> = { mfa: { methods } };
    if (user.mfa.defaultMethod === name) {
      update.mfa!.defaultMethod = "";
    }
    await this.store.update(username, { set: update });
  }

  async setDefaultMfaMethod(username: string, name: string): Promise<void> {
    const user = await this.getUser(username);
    if (name && !user.mfa.methods.some((m) => m.name === name)) {
      throw new UserAuthError("MFA_NOT_CONFIGURED");
    }
    await this.store.update(username, {
      set: { mfa: { defaultMethod: name, autoSend: false } } as DeepPartial<UserCredentials>,
    });
  }

  async setMfaAutoSend(username: string, value: boolean): Promise<void> {
    const found = await this.store.update(username, {
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
   * Generate `count` plaintext backup codes (default 10), persist their
   * hashes (replacing any existing batch), and return the plaintext codes
   * once for the caller to deliver to the user. Plaintext is never
   * recoverable after this call returns.
   *
   * Throws `UserAuthError("NOT_FOUND")` if the user does not exist.
   */
  async generateBackupCodes(username: string, count = 10): Promise<string[]> {
    const codes = generateBackupCodePlaintext(count);
    const hashes = codes.map(hashMfaCode);
    const found = await this.store.update(username, {
      set: { backupCodes: hashes } as DeepPartial<UserCredentials>,
    });
    if (!found) throw new UserAuthError("NOT_FOUND");
    return codes;
  }

  /**
   * Consume a backup code: returns `true` and removes the matching hash
   * from storage if `code` matches a stored backup code; returns `false`
   * if no match (without modifying storage). Single-use is enforced by
   * optimistic-concurrency CAS on the version column — concurrent consumes
   * of the same code race fairly and only one wins; the loser re-reads,
   * finds the hash already removed, and returns `false`.
   *
   * Throws `UserAuthError("NOT_FOUND")` if the user does not exist.
   * Throws `UserAuthError("CAS_EXHAUSTED")` if retries are saturated.
   */
  async consumeBackupCode(username: string, code: string): Promise<boolean> {
    let consumed = false;
    await this.store.withCas(username, (user) => {
      const hashes = user.backupCodes ?? [];
      const idx = hashes.findIndex((h) => verifyMfaCode(code, h));
      if (idx < 0) {
        // Reset across retries: previous attempt may have set true before CAS miss;
        // if the competing writer consumed this code, we now correctly report false.
        consumed = false;
        return null;
      }
      consumed = true;
      const remaining = hashes.filter((_, i) => i !== idx);
      return { set: { backupCodes: remaining } as DeepPartial<UserCredentials> };
    });
    return consumed;
  }

  /**
   * Verify a TOTP code against the user's confirmed `totp` MFA method.
   * Failures bump the same `failedLoginAttempts` counter as `login` so an
   * attacker who knows the password but not the TOTP gets `lockout.threshold`
   * total tries across BOTH factors, not `2 * threshold`.
   */
  async verifyMfa(username: string, code: string, config?: TotpConfig): Promise<void> {
    const user = await this.getUser(username);

    if (!user.account.active) {
      throw new UserAuthError("INACTIVE");
    }

    await this.ensureNotLockedOrThrow(username, user.account);

    const totp = user.mfa.methods.find((m) => m.name === "totp" && m.confirmed);
    if (!totp) throw new UserAuthError("MFA_NOT_CONFIGURED");

    if (verifyTotpCode(totp.value, code, config)) {
      if (user.account.failedLoginAttempts > 0) {
        await this.store.update(username, {
          set: {
            account: { failedLoginAttempts: 0 },
          } as DeepPartial<UserCredentials>,
        });
      }
      return;
    }

    await this.incrementAndMaybeLock(username, user.account, "MFA_INVALID");
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
    const sig = signDeviceTrust(secret, `${userId}|${raw}|${opts.ip ?? ""}`);
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
  async addTrustedDevice(username: string, record: TrustedDeviceRecord): Promise<void> {
    await this.store.withCas(username, (user) => {
      const next = [...(user.trustedDevices ?? []), record];
      return { set: { trustedDevices: next } as DeepPartial<UserCredentials> };
    });
  }

  /**
   * Returns true when the supplied token (a) signs against the user+ip with
   * the configured secret, AND (b) matches a persisted record that is still
   * within its expiry window and whose bound IP (if any) matches.
   */
  async verifyTrustedDevice(username: string, token: string, ip?: string): Promise<boolean> {
    const secret = this.requireDeviceTrustSecret();
    const sepIdx = token.lastIndexOf(DEVICE_TRUST_SEPARATOR);
    if (sepIdx <= 0) return false;
    const raw = token.slice(0, sepIdx);
    const sig = token.slice(sepIdx + 1);
    const expectedSig = signDeviceTrust(secret, `${username}|${raw}|${ip ?? ""}`);
    if (!deviceTrustSafeEqual(sig, expectedSig)) return false;

    const user = await this.store.findByUsername(username);
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
  async revokeTrustedDevice(username: string, token: string): Promise<void> {
    const user = await this.store.findByUsername(username);
    if (!user) return;
    const list = user.trustedDevices ?? [];
    const next = list.filter((r) => r.token !== token);
    if (next.length === list.length) return;
    await this.store.update(username, {
      set: { trustedDevices: next } as DeepPartial<UserCredentials>,
    });
  }

  async listTrustedDevices(username: string): Promise<TrustedDeviceRecord[]> {
    const user = await this.getUser(username);
    return user.trustedDevices ?? [];
  }

  private requireDeviceTrustSecret(): string {
    const secret = this.config.deviceTrust?.secret;
    if (!secret) {
      throw new Error("UserService: deviceTrust.secret is required to use trusted-device APIs");
    }
    return secret;
  }

  // ---- private helpers ----

  private async applyPasswordChange(
    username: string,
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

    await this.store.update(username, {
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
    username: string,
    account: UserCredentials["account"],
  ): Promise<void> {
    const lockStatus = this.getLockStatus(account);
    if (!lockStatus.locked) return;
    if (lockStatus.expired) {
      await this.store.update(username, {
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
   */
  private async incrementAndMaybeLock(
    username: string,
    account: UserCredentials["account"],
    errorCode: "INVALID_CREDENTIALS" | "MFA_INVALID",
  ): Promise<never> {
    const newAttempts = account.failedLoginAttempts + 1;
    const { threshold, duration } = this.config.lockout;
    const shouldLock = threshold > 0 && newAttempts >= threshold;

    if (shouldLock) {
      const lockEnds = duration ? this.config.clock() + duration : 0;
      await this.store.update(username, {
        inc: { "account.failedLoginAttempts": 1 },
        set: {
          account: { locked: true, lockReason: "Too many login attempts", lockEnds },
        } as DeepPartial<UserCredentials>,
      });
      throw new UserAuthError(errorCode, undefined, { lockEnds });
    }

    await this.store.update(username, {
      inc: { "account.failedLoginAttempts": 1 },
    });
    throw new UserAuthError(errorCode);
  }
}
