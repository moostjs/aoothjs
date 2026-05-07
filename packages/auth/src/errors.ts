export type AuthErrorType =
  | "INVALID_TOKEN"
  | "TOKEN_EXPIRED"
  | "TOKEN_REVOKED"
  | "REFRESH_REUSE_DETECTED"
  | "STATELESS_OPERATION_UNSUPPORTED"
  | "MAX_CONCURRENT_REACHED"
  | "INVALID_CONFIG";

const defaultMessages: Record<AuthErrorType, string> = {
  INVALID_TOKEN: "Invalid token",
  TOKEN_EXPIRED: "Token has expired",
  TOKEN_REVOKED: "Token has been revoked",
  REFRESH_REUSE_DETECTED: "Refresh token reuse detected",
  STATELESS_OPERATION_UNSUPPORTED: "Operation is not supported by stateless credential store",
  MAX_CONCURRENT_REACHED: "Maximum concurrent credentials reached for user",
  INVALID_CONFIG: "Invalid auth configuration",
};

export class AuthError extends Error {
  override readonly name = "AuthError";

  constructor(
    public readonly type: AuthErrorType,
    message?: string,
    public readonly details?: Record<string, unknown>,
  ) {
    super(message ?? defaultMessages[type]);
  }
}
