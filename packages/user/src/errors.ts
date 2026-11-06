import type { UserAuthErrorType } from "./types";

/**
 * The message code of each `UserAuthError` type — the id its text is
 * registered and translated by, and the `code` of the HTTP error made from it.
 * Message codes share one process-wide id space with every other library, so
 * types with a generic name get an `AOOTH_USER_` code; `NOT_FOUND` and
 * `INVALID_CREDENTIALS` are shared on purpose and keep neutral texts.
 */
export const USER_AUTH_ERROR_CODES = Object.freeze({
  NOT_FOUND: "NOT_FOUND",
  ALREADY_EXISTS: "AOOTH_USER_ALREADY_EXISTS",
  LOCKED: "AOOTH_USER_LOCKED",
  INACTIVE: "AOOTH_USER_INACTIVE",
  INVALID_CREDENTIALS: "INVALID_CREDENTIALS",
  POLICY_VIOLATION: "AOOTH_USER_POLICY_VIOLATION",
  PASSWORDS_MISMATCH: "PASSWORDS_MISMATCH",
  PASSWORD_IN_HISTORY: "PASSWORD_IN_HISTORY",
  MFA_REQUIRED: "MFA_REQUIRED",
  MFA_INVALID: "MFA_INVALID",
  MFA_NOT_CONFIGURED: "MFA_NOT_CONFIGURED",
  CAS_EXHAUSTED: "AOOTH_USER_CAS_EXHAUSTED",
} as const satisfies Record<UserAuthErrorType, string>);

/** A message code of a `UserAuthError` — see {@link USER_AUTH_ERROR_CODES}. */
export type UserAuthErrorCode = (typeof USER_AUTH_ERROR_CODES)[UserAuthErrorType];

/**
 * The default English message of each `UserAuthError`, by its message code
 * ({@link USER_AUTH_ERROR_CODES}).
 *
 * `@aooth/auth-moost` registers it with moost's `registerMessages`, so a moost
 * translator (`setTranslator`) translates a `UserAuthError` by its code and the
 * texts reach the `$i18n` the server sends with form schemas and `/meta`.
 */
export const USER_AUTH_ERROR_MESSAGES: Readonly<Record<UserAuthErrorCode, string>> = Object.freeze({
  /** Shared on purpose — the same neutral text as other libraries' `NOT_FOUND`. */
  NOT_FOUND: "Not found",
  AOOTH_USER_ALREADY_EXISTS: "User already exists",
  AOOTH_USER_LOCKED: "Account is locked",
  AOOTH_USER_INACTIVE: "Account is not active",
  /** Shared on purpose — also the sign-in workflow's code, with the same text. */
  INVALID_CREDENTIALS: "Invalid credentials",
  AOOTH_USER_POLICY_VIOLATION: "Password does not meet policy requirements",
  PASSWORDS_MISMATCH: "Passwords do not match",
  PASSWORD_IN_HISTORY: "Password was recently used",
  MFA_REQUIRED: "Multi-factor authentication is required",
  MFA_INVALID: "Invalid MFA code",
  MFA_NOT_CONFIGURED: "MFA method is not configured",
  AOOTH_USER_CAS_EXHAUSTED: "Update conflict — please retry",
});

export class UserAuthError extends Error {
  override readonly name = "UserAuthError";

  /** The message code — the id the error's text is translated by ({@link USER_AUTH_ERROR_CODES}). */
  readonly code: UserAuthErrorCode;

  constructor(
    public readonly type: UserAuthErrorType,
    message?: string,
    public readonly details?: Record<string, unknown>,
  ) {
    const code = USER_AUTH_ERROR_CODES[type];
    super(message ?? USER_AUTH_ERROR_MESSAGES[code]);
    this.code = code;
  }
}
