import type { UserAuthErrorType } from "./types";

/**
 * The default English message of each `UserAuthError` type — the error's
 * `type` is its message code.
 *
 * `@aooth/auth-moost` registers it with moost's `registerMessages`, so a moost
 * translator (`setTranslator`) translates a `UserAuthError` by its type and the
 * texts reach the `$i18n` the server sends with form schemas and `/meta`.
 */
export const USER_AUTH_ERROR_MESSAGES: Readonly<Record<UserAuthErrorType, string>> = Object.freeze({
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
});

export class UserAuthError extends Error {
  override readonly name = "UserAuthError";

  constructor(
    public readonly type: UserAuthErrorType,
    message?: string,
    public readonly details?: Record<string, unknown>,
  ) {
    super(message ?? USER_AUTH_ERROR_MESSAGES[type]);
  }
}
