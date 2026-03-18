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

// TOTP
export {
  generateTotpSecret,
  generateTotpUri,
  generateTotpCode,
  verifyTotpCode,
  generateMfaCode,
} from "./mfa/totp";

// Utilities
export { maskEmail, maskPhone, maskMfaValue, setAtPath } from "./utils";
