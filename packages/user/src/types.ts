export interface UserCredentials {
  id: string;
  username: string;
  /**
   * Server-managed optimistic-concurrency counter. Bumped by `UserStore.update`
   * on every successful write; checked against `UserStoreUpdate.expectedVersion`
   * for CAS. Callers MUST NOT write it directly — atscript-db rejects direct
   * writes with `DbError("VERSION_COLUMN_WRITE")`. Optional in TS so pre-OCC
   * fixtures keep compiling; the store seeds `0` on insert.
   */
  version?: number;
  password: PasswordData;
  account: AccountData;
  mfa: MfaData;
  /**
   * Hashed backup codes (SHA-256, hex-encoded). Generated via
   * `UserService.generateBackupCodes`. Undefined when the user has not
   * enrolled backup codes; an empty array means all codes were consumed.
   */
  backupCodes?: string[];
  /**
   * Persisted device-trust records ("remember this device, skip MFA next
   * time"). Managed by `UserService.{issue,add,verify,revoke,list}TrustedDevice`.
   * Absent when the user has never opted in.
   */
  trustedDevices?: TrustedDeviceRecord[];
}

export interface TrustedDeviceRecord {
  /** `<raw>.<sig>` — what we hand back to the consumer and what they round-trip. */
  token: string;
  /** Bound IP — set when `deviceTrust.bindsTo === 'cookie+ip'`. */
  ip?: string;
  issuedAt: number;
  expiresAt: number;
  /** Optional human-readable label (e.g. user-agent summary). */
  name?: string;
}

export interface PasswordData {
  /** Self-describing scrypt hash: $scrypt$N=...,r=...,p=...,l=...$salt$hash */
  hash: string;
  /** Previous password hashes (self-describing strings) */
  history: string[];
  lastChanged: number;
  /** True when password was system-generated and user hasn't set their own */
  isInitial: boolean;
}

export interface AccountData {
  active: boolean;
  locked: boolean;
  lockReason: string;
  /** 0 = permanent lock, >0 = timestamp (ms) when lock expires */
  lockEnds: number;
  failedLoginAttempts: number;
  lastLogin: number;
  /**
   * True while the user record exists from an admin-issued invite but the
   * invitee has not yet accepted (set password + activate). Used by
   * `InviteWorkflow` to gate the accept tail, reject duplicate invites, and
   * power `auth/invite/resend` / `auth/invite/cancel`. Absent / `false` once
   * the invite has been accepted.
   */
  pendingInvitation?: boolean;
}

export interface MfaData {
  /** Registered MFA methods */
  methods: MfaMethod[];
  /** Name of the default MFA method */
  defaultMethod: string;
  /** Auto-send MFA challenge on login */
  autoSend: boolean;
}

export interface MfaMethod {
  /** Method name: 'email', 'sms', 'totp' */
  name: string;
  /** Whether this method has been verified/confirmed */
  confirmed: boolean;
  /** The method's value: email address, phone number, or TOTP secret */
  value: string;
  /**
   * Last HOTP counter accepted for this method (TOTP only). Server-managed
   * replay guard — `verifyMfa` rejects any code whose matched counter is
   * `<= lastUsedWindow`. Never written from user-facing input.
   */
  lastUsedWindow?: number;
}

// ---- Configuration ----

export interface UserServiceConfig {
  password?: PasswordConfig;
  lockout?: LockoutConfig;
  /** Injectable clock for testability. Defaults to Date.now */
  clock?: () => number;
  /**
   * Device-trust config. Required (with a non-empty `secret`) when any
   * `issueTrustedDevice` / `verifyTrustedDevice` API is called; the methods
   * throw clearly when invoked without it.
   */
  deviceTrust?: {
    /** HMAC-SHA256 signing secret for trust-device tokens. */
    secret: string;
  };
}

export interface PasswordConfig {
  /** Pepper string prepended to password before hashing */
  pepper?: string;
  /** Number of historical hashes to retain (0 = disabled) */
  historyLength?: number;
  /** scrypt cost parameter N (default 16384) */
  scryptN?: number;
  /** scrypt block size r (default 8) */
  scryptR?: number;
  /** scrypt parallelism p (default 1) */
  scryptP?: number;
  /** Hash output length in bytes (default 64) */
  keyLength?: number;
  /** Password policy rules */
  policies?: (PasswordPolicyDef | PasswordPolicyInstance)[];
}

export interface LockoutConfig {
  /** Lock after this many failed attempts (0 = disabled) */
  threshold?: number;
  /** Lock duration in ms (0 = permanent) */
  duration?: number;
}

// ---- Password Policy ----

export interface PasswordPolicyDef {
  /**
   * Backend evaluator. Function only — executed directly with no sandbox.
   * String rules were removed: `@prostojs/ftring`'s sandbox does NOT block
   * prototype-chain escapes (`constructor.constructor("return process")()`,
   * `__proto__.x = ...`), so accepting strings was an RCE vector. Authors
   * use `definePasswordPolicy({ rule, args })` to get both this fn AND the
   * serialized form for free.
   */
  rule: PasswordPolicyEvalFn;
  /**
   * Pre-baked function-literal text shipped to clients for cross-tier
   * validation via `getTransferablePolicies()`. Authored as
   * `(v) => (${ruleSource})(v, ${args.map(JSON.stringify).join(', ')})` by
   * `definePasswordPolicy`. Absent → the policy is backend-only (frontend
   * skips it; server-side check remains authoritative).
   */
  serialized?: string;
  description?: string;
  errorMessage?: string;
}

export type PasswordPolicyEvalFn = (
  password: string,
  context?: PasswordPolicyContext,
) => boolean | Promise<boolean>;

export interface PasswordPolicyContext {
  passwordData?: PasswordData;
  passwordConfig?: PasswordConfig;
}

/** Interface satisfied by the PasswordPolicy class (avoids circular import) */
export interface PasswordPolicyInstance extends PasswordPolicyDef {
  evaluate(password: string, context?: PasswordPolicyContext): boolean | Promise<boolean>;
  transferable: boolean;
}

// ---- Store ----

export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export interface UserStoreUpdate {
  /** Partial object with fields to set (deep-merged) */
  set?: DeepPartial<UserCredentials>;
  /** Dot-paths to atomically increment: e.g. {'account.failedLoginAttempts': 1} */
  inc?: Record<string, number>;
  /**
   * Optimistic concurrency control: when supplied, the store applies the
   * update iff the row's current `version` equals this value. On mismatch
   * the store returns `false` (same shape as "not found") and does NOT
   * mutate. Service callers treat both states as "stale read, retry".
   */
  expectedVersion?: number;
}

// ---- Error ----

export type UserAuthErrorType =
  | "NOT_FOUND"
  | "ALREADY_EXISTS"
  | "LOCKED"
  | "INACTIVE"
  | "INVALID_CREDENTIALS"
  | "POLICY_VIOLATION"
  | "PASSWORDS_MISMATCH"
  | "PASSWORD_IN_HISTORY"
  | "MFA_REQUIRED"
  | "MFA_INVALID"
  | "MFA_NOT_CONFIGURED"
  | "CAS_EXHAUSTED";

// ---- Service results ----

export interface LoginResult<T extends object = object> {
  user: UserCredentials & T;
  /** Whether MFA verification is required before granting full access */
  mfaRequired: boolean;
}

export interface LockStatus {
  locked: boolean;
  /** True when lock has a non-zero lockEnds that is in the past */
  expired: boolean;
  reason: string;
  lockEnds: number;
}

export interface PolicyCheckResult {
  passed: boolean;
  policies: { description: string; passed: boolean }[];
  errors: string[];
}

export interface TransferablePolicy {
  rule: string;
  description?: string;
  errorMessage?: string;
}

export interface MfaMethodInfo {
  name: string;
  isDefault: boolean;
  masked: string;
}

// ---- TOTP ----

export interface TotpConfig {
  /** Time step in seconds (default 30) */
  period?: number;
  /** Number of digits in the code (default 6) */
  digits?: number;
  /** Verification window — number of steps to check on each side (default 1) */
  window?: number;
  /** Injectable clock for testability */
  clock?: () => number;
}
