import { HttpError } from "@wooksjs/event-http";
import { formatMessage, registerMessages } from "moost";

/**
 * Code-keyed English templates of the `HttpError`s auth-moost raises outside
 * the auth workflow (guard, controllers, `useAuth()`, the workflow trigger).
 * Each error body carries the `code` and its `params`;
 * `MoostHttp` translates it by code with the moost translator
 * (`translateErrorBody`). Registered with `registerMessages` on import.
 *
 * The workflow's own texts are in `AOOTH_MESSAGES`; the rate limiter's 429
 * (`RATE_LIMITED`) template is `RATE_LIMIT_MESSAGES` from `@aooth/auth`.
 */
export const AOOTH_HTTP_MESSAGES = {
  /** 401 — the guard found no credential on a protected route. */
  AOOTH_AUTH_REQUIRED: "Unauthorized",
  /** 401 — the guard's credential is invalid, expired or revoked. */
  AOOTH_CREDENTIAL_INVALID: "Invalid credential",
  /** 401 — `useAuth().getUserId()` and `AuthController` routes without a signed-in user. */
  AOOTH_NOT_AUTHENTICATED: "Not authenticated",
  /** 401 — "log out other sessions" without a current session. */
  NO_CURRENT_SESSION: "No current session to keep",
  /** 401 — `POST /auth/refresh` without a refresh token. */
  MISSING_REFRESH_TOKEN: "Missing refresh token",
  /** 401 — `POST /auth/refresh` with an unknown, expired or reused refresh token. */
  INVALID_REFRESH_TOKEN: "Invalid refresh token",
  /** 400 — `DELETE /auth/sessions` without `?others=true`. */
  LOGOUT_OTHERS_REQUIRED: "Pass ?others=true to log out other sessions",
  /** 404 — `GET /auth/invite/post-redemption` for an unknown or still pending invite. */
  INVITE_NOT_FOUND: "Invite not found",
  /** 400 — `GET /auth/invite/post-redemption` without `uid`. */
  AOOTH_MISSING_UID: "Missing uid query parameter",
  /** 404 — unlinking an identity the user does not have. */
  LINKED_IDENTITY_NOT_FOUND: "Linked identity not found",
  /** 409 — unlinking the user's only sign-in method. */
  LAST_SIGN_IN_METHOD:
    "Cannot remove your only sign-in method. Set a password first, or link another provider.",
  /** 404 — unlinking an identity of an unconfigured provider. Params: `provider`. */
  AOOTH_UNKNOWN_PROVIDER: "Unknown provider '{provider}'",
  /** 429 — the one-time codes of this account or address failed too often; answered to every code send and check until the window passes. */
  AOOTH_CODE_LIMIT_REACHED: "Too many code attempts. Try again later.",
  /** 403 — the workflow trigger refused a workflow outside its allow list. Params: `workflow`. */
  AOOTH_WORKFLOW_NOT_ALLOWED: "Workflow '{workflow}' is not allowed",
} as const;

registerMessages(AOOTH_HTTP_MESSAGES);

/** A code of {@link AOOTH_HTTP_MESSAGES}. */
export type AoothHttpMessageCode = keyof typeof AOOTH_HTTP_MESSAGES;

/** An `HttpError` with `code`, `params` and the code's English text. */
export function aoothHttpError(
  status: 400 | 401 | 403 | 404 | 409 | 429,
  code: AoothHttpMessageCode,
  params?: Record<string, string | number>,
): HttpError {
  return codedHttpError(status, code, formatMessage(AOOTH_HTTP_MESSAGES[code], params), params);
}

/**
 * An `HttpError` whose body carries the message `code` and `params` next to
 * its text, so `MoostHttp` can translate it by code.
 */
export function codedHttpError(
  status: 400 | 401 | 403 | 404 | 409 | 410 | 429,
  code: string,
  message: string,
  params?: Readonly<Record<string, unknown>>,
): HttpError {
  return new HttpError(status, { message, code, ...(params && { params }) });
}
