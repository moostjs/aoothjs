import type { UserAuthErrorType } from "./types";

const defaultMessages: Record<UserAuthErrorType, string> = {
  NOT_FOUND: "User not found",
  ALREADY_EXISTS: "User already exists",
  LOCKED: "Account is locked",
  INACTIVE: "Account is not active",
  INVALID_CREDENTIALS: "Invalid credentials",
  POLICY_VIOLATION: "Password does not meet policy requirements",
  PASSWORDS_MISMATCH: "Passwords do not match",
  PASSWORD_IN_HISTORY: "Password was recently used",
  MFA_REQUIRED: "Multi-factor authentication is required",
  MFA_INVALID: "Invalid MFA code",
  MFA_NOT_CONFIGURED: "MFA method is not configured",
  CAS_EXHAUSTED: "Update conflict — please retry",
};

export class UserAuthError extends Error {
  override readonly name = "UserAuthError";

  constructor(
    public readonly type: UserAuthErrorType,
    message?: string,
    public readonly details?: Record<string, unknown>,
  ) {
    super(message ?? defaultMessages[type]);
  }
}
