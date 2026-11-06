import {
  PASSWORD_POLICY_MESSAGES,
  type TransferablePolicy,
  UserAuthError,
  USER_AUTH_ERROR_MESSAGES,
  type UserAuthErrorCode,
  type UserAuthErrorType,
} from "@aooth/user";
import { HttpError } from "@wooksjs/event-http";
import {
  defineErrorInterceptor,
  registerMessages,
  type TInterceptorDef,
  TInterceptorPriority,
} from "moost";

import { translateCode } from "./workflow/auth-messages";

registerMessages(PASSWORD_POLICY_MESSAGES);
registerMessages(USER_AUTH_ERROR_MESSAGES);

/** The body of an `HttpError` made by {@link userAuthErrorToHttp}. */
export interface UserAuthErrorBody {
  message: string;
  /** The `UserAuthError`'s message code (`"PASSWORD_IN_HISTORY"`, `"AOOTH_USER_LOCKED"`, …) — see `USER_AUTH_ERROR_CODES`. */
  code: UserAuthErrorCode;
  /**
   * `POLICY_VIOLATION`: `{ policies: [{ description, passed, errorMessage, code?, params? }] }`
   * — every policy and its result (`code` / `params`: the built-in policies' `PP_*` codes).
   */
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
 * carries `code` (the error's message code, `err.code`), the message and — for
 * password errors — the form `field` it belongs to (named as in the bundled
 * password forms):
 *
 * | type | code | status | field |
 * |---|---|---|---|
 * | `NOT_FOUND` | `NOT_FOUND` | 404 | |
 * | `ALREADY_EXISTS`, `CAS_EXHAUSTED` | `AOOTH_USER_ALREADY_EXISTS`, `AOOTH_USER_CAS_EXHAUSTED` | 409 | |
 * | `INVALID_CREDENTIALS` | `INVALID_CREDENTIALS` | 400 | `currentPassword` |
 * | `PASSWORD_IN_HISTORY` | `PASSWORD_IN_HISTORY` | 400 | `newPassword` |
 * | `POLICY_VIOLATION` (+ `params.policies`) | `AOOTH_USER_POLICY_VIOLATION` | 422 | `newPassword` |
 * | `PASSWORDS_MISMATCH` | `PASSWORDS_MISMATCH` | 400 | `confirmPassword` |
 * | `MFA_INVALID`, `MFA_NOT_CONFIGURED` | same as type | 400 | |
 * | `INACTIVE`, `LOCKED`, `MFA_REQUIRED` | `AOOTH_USER_INACTIVE`, `AOOTH_USER_LOCKED`, `MFA_REQUIRED` | 403 | |
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
    message: userAuthErrorText(err),
    code: err.code,
    ...(policies !== undefined && { params: { policies } }),
    ...(field && { field }),
  });
}

/** A password policy's texts, as `checkPolicies` / `getTransferablePolicies` give them. */
type PolicyTexts = Omit<TransferablePolicy, "rule">;

/**
 * A policy's texts in the request's locale (moost translator): `errorMessage`
 * by its `code`, `description` by `${code}_DESCRIPTION` — by the text itself
 * when the policy has no code. Unchanged without a translation.
 */
export function translatePolicyTexts<T extends PolicyTexts>(policy: T): T {
  const { code, params, description, errorMessage } = policy;
  const out = { ...policy };
  if (description) {
    out.description = translateCode(
      code ? `${code}_DESCRIPTION` : description,
      params,
      description,
    );
  }
  if (errorMessage) out.errorMessage = translatePolicyError(policy);
  return out;
}

/** A policy's `errorMessage` in the request's locale, by its `code` (or the text itself). */
function translatePolicyError({ code, params, errorMessage }: PolicyTexts): string | undefined {
  return errorMessage && translateCode(code ?? errorMessage, params, errorMessage);
}

/**
 * A `UserAuthError`'s text in the request's locale: a `POLICY_VIOLATION` lists
 * its failed policies' translated `errorMessage`s (`; `-joined, like the
 * English message) when at least one of them has a translation; otherwise —
 * and for any other type — the error is translated by its code (`err.code`),
 * its own message the fallback.
 */
export function userAuthErrorText(err: UserAuthError): string {
  const policies = err.type === "POLICY_VIOLATION" ? err.details?.policies : undefined;
  const failed = Array.isArray(policies)
    ? (policies as Array<PolicyTexts & { passed?: boolean }>).filter((p) => p?.passed === false)
    : [];
  // Only when some failure actually gets translated: otherwise (no translator,
  // or a hand-thrown error whose details lack texts) the error's own message.
  if (failed.length > 0 && failed.every((p) => typeof p.errorMessage === "string")) {
    const texts = failed.map((p) => translatePolicyError(p) as string);
    if (texts.some((text, i) => text !== failed[i].errorMessage)) return texts.join("; ");
  }
  return translateCode(err.code, undefined, err.message);
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
