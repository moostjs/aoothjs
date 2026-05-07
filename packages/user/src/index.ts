// Types
export type {
  UserCredentials,
  PasswordData,
  AccountData,
  MfaData,
  MfaMethod,
  UserServiceConfig,
  PasswordConfig,
  LockoutConfig,
  PasswordPolicyDef,
  PasswordPolicyEvalFn,
  PasswordPolicyContext,
  PasswordPolicyInstance,
  UserStoreUpdate,
  DeepPartial,
  UserAuthErrorType,
  LoginResult,
  LockStatus,
  PolicyCheckResult,
  TransferablePolicy,
  MfaMethodInfo,
  TotpConfig,
} from "./types";

// Error
export { UserAuthError } from "./errors";

// Service
export { UserService } from "./user-service";

// Store
export { UserStore } from "./store/user-store";
export { UserStoreMemory } from "./store/memory";

// Password
export { PasswordHasher } from "./password/hasher";
export { PasswordPolicy, normalizePolicies } from "./password/policy";
export {
  ppHasMinLength,
  ppHasUpperCase,
  ppHasLowerCase,
  ppHasNumber,
  ppHasSpecialChar,
  ppMaxRepeatedChars,
} from "./password/policies";

// MFA — TOTP + code helpers + backup codes
export {
  generateTotpSecret,
  generateTotpUri,
  generateTotpCode,
  verifyTotpCode,
  generateMfaCode,
} from "./mfa/totp";
export { hashMfaCode, verifyMfaCode } from "./mfa/codes";
export { generateBackupCodePlaintext } from "./mfa/backup-codes";

// Utilities
export { maskEmail, maskPhone, maskMfaValue, setAtPath } from "./utils";
