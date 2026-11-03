import { UserAuthError, type UserAuthErrorType } from "@aooth/user";
import { HttpError } from "@wooksjs/event-http";
import { defineErrorInterceptor, type TInterceptorDef, TInterceptorPriority } from "moost";

/** The body of an `HttpError` made by {@link userAuthErrorToHttp}. */
export interface UserAuthErrorBody {
  message: string;
  /** The `UserAuthError` type (`"PASSWORD_IN_HISTORY"`, `"NOT_FOUND"`, …). */
  code: UserAuthErrorType;
  /** `POLICY_VIOLATION`: `{ policies: [{ description, passed }] }` — every policy and its result. */
  params?: Record<string, unknown>;
  /** The form field the error belongs to (password errors only). */
  field?: "currentPassword" | "newPassword" | "confirmPassword";
}

const STATUS: Record<UserAuthErrorType, 400 | 403 | 404 | 409 | 422> = {
  NOT_FOUND: 404,
  ALREADY_EXISTS: 409,
  CAS_EXHAUSTED: 409,
  // Not 401: an authed fetch client answers 401 with a token refresh and a
  // retry, which would re-submit the wrong password or code.
  INVALID_CREDENTIALS: 400,
  MFA_INVALID: 400,
  MFA_NOT_CONFIGURED: 400,
  PASSWORDS_MISMATCH: 400,
  PASSWORD_IN_HISTORY: 400,
  POLICY_VIOLATION: 422,
  INACTIVE: 403,
  LOCKED: 403,
  MFA_REQUIRED: 403,
};

const FIELD: Partial<Record<UserAuthErrorType, UserAuthErrorBody["field"]>> = {
  INVALID_CREDENTIALS: "currentPassword",
  POLICY_VIOLATION: "newPassword",
  PASSWORD_IN_HISTORY: "newPassword",
  PASSWORDS_MISMATCH: "confirmPassword",
};

/** The password-form field an error belongs to (shared with the bundled password forms). */
export function userAuthErrorField(type: UserAuthErrorType): UserAuthErrorBody["field"] {
  return FIELD[type];
}

/**
 * Map a `UserAuthError` (thrown by `UserService`) to an `HttpError` whose body
 * carries `code` (the error type), the message and — for password errors —
 * the form `field` it belongs to (named as in the bundled password forms):
 *
 * | type | status | field |
 * |---|---|---|
 * | `NOT_FOUND` | 404 | |
 * | `ALREADY_EXISTS`, `CAS_EXHAUSTED` | 409 | |
 * | `INVALID_CREDENTIALS` | 400 | `currentPassword` |
 * | `PASSWORD_IN_HISTORY` | 400 | `newPassword` |
 * | `POLICY_VIOLATION` (+ `params.policies`) | 422 | `newPassword` |
 * | `PASSWORDS_MISMATCH` | 400 | `confirmPassword` |
 * | `MFA_INVALID`, `MFA_NOT_CONFIGURED` | 400 | |
 * | `INACTIVE`, `LOCKED`, `MFA_REQUIRED` | 403 | |
 *
 * For routes such as an admin "set password" endpoint. Do not use it on a
 * sign-in endpoint: distinct answers for unknown, inactive and locked accounts
 * let a caller enumerate accounts (the bundled login workflow answers them
 * uniformly).
 */
export function userAuthErrorToHttp(err: UserAuthError): HttpError<UserAuthErrorBody> {
  const field = userAuthErrorField(err.type);
  const policies = err.type === "POLICY_VIOLATION" ? err.details?.policies : undefined;
  return new HttpError(STATUS[err.type], {
    message: err.message,
    code: err.type,
    ...(policies !== undefined && { params: { policies } }),
    ...(field && { field }),
  });
}

/**
 * Error interceptor answering every `UserAuthError` a handler throws with
 * {@link userAuthErrorToHttp}; other errors pass through. Attach it per
 * controller (or per handler) where `UserService` errors should become 4xx
 * instead of 500 — typically admin and self-service routes:
 *
 * ```ts
 * @Controller("admin/users")
 * @Intercept(userAuthErrorInterceptor)
 * export class AdminUsersController {}
 * ```
 *
 * Don't install it globally: a custom sign-in or recovery handler calling
 * `login()` / `verifyMfa()` would then answer unknown, inactive and locked
 * accounts with distinct 404 / 403 codes — account enumeration, defeating
 * `lockoutDisclosure: 'uniform'`.
 */
export const userAuthErrorInterceptor: TInterceptorDef = defineErrorInterceptor((error, reply) => {
  if (error instanceof UserAuthError) reply(userAuthErrorToHttp(error));
}, TInterceptorPriority.CATCH_ERROR);
