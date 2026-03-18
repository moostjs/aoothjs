import { UserAuthError } from "./errors";
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
  TransferablePolicy,
  UserCredentials,
  UserServiceConfig,
} from "./types";
import { UserStore } from "./store/user-store";
import { maskMfaValue } from "./utils";

interface ResolvedConfig {
  password: Required<Omit<PasswordConfig, "policies">> & { policies: PasswordPolicy[] };
  lockout: Required<LockoutConfig>;
  clock: () => number;
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
  };
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

  async createUser(username: string, password?: string): Promise<UserCredentials & T> {
    const pw = password ?? this.hasher.generatePassword();
    const hash = await this.hasher.hash(pw);

    const userData: UserCredentials = {
      id: "",
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

    await this.store.create(userData as UserCredentials & T);
    return userData as UserCredentials & T;
  }

  async getUser(username: string): Promise<UserCredentials & T> {
    const user = await this.store.findByUsername(username);
    if (!user) throw new UserAuthError("NOT_FOUND");
    return user;
  }

  async login(username: string, password: string): Promise<LoginResult<T>> {
    const user = await this.store.findByUsername(username);
    if (!user) throw new UserAuthError("NOT_FOUND");

    // Check active status
    if (!user.account.active) {
      throw new UserAuthError("INACTIVE");
    }

    // Check and potentially auto-unlock expired lock
    const lockStatus = this.getLockStatus(user.account);
    if (lockStatus.locked) {
      if (lockStatus.expired) {
        await this.store.update(username, {
          set: {
            account: { locked: false, lockReason: "", lockEnds: 0 },
          } as DeepPartial<UserCredentials>,
        });
      } else {
        throw new UserAuthError("LOCKED", undefined, {
          reason: user.account.lockReason,
          lockEnds: user.account.lockEnds,
        });
      }
    }

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

    // Failed login — combine inc + lock into single update when possible
    const newAttempts = user.account.failedLoginAttempts + 1;
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
    } else {
      await this.store.update(username, {
        inc: { "account.failedLoginAttempts": 1 },
      });
    }

    throw new UserAuthError("INVALID_CREDENTIALS");
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
    const user = await this.getUser(username);
    const methods = [...user.mfa.methods.filter((m) => m.name !== method.name), method];
    await this.store.update(username, {
      set: { mfa: { methods } } as DeepPartial<UserCredentials>,
    });
  }

  async confirmMfaMethod(username: string, name: string): Promise<void> {
    const user = await this.getUser(username);
    let found = false;
    const methods = user.mfa.methods.map((m) => {
      if (m.name === name) {
        found = true;
        return { ...m, confirmed: true };
      }
      return m;
    });
    if (!found) throw new UserAuthError("MFA_NOT_CONFIGURED");
    await this.store.update(username, {
      set: { mfa: { methods } } as DeepPartial<UserCredentials>,
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

  getPasswordHasher(): PasswordHasher {
    return this.hasher;
  }

  getConfig(): Readonly<ResolvedConfig> {
    return this.config;
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
}
