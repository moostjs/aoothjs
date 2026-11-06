import { HttpError } from "@moostjs/event-http";
import { formatMessage, registerMessages } from "moost";

/**
 * Code-keyed English templates of the `HttpError`s arbac-moost raises. Each
 * error body carries the `code` and its `params`; `MoostHttp` translates it
 * by code with the moost translator (`translateErrorBody`). Registered with
 * `registerMessages` on import.
 *
 * Not coded: the 404 a row outside the caller's scope answers — it is the
 * same answer as a missing row on purpose.
 */
export const ARBAC_MESSAGES = {
  /** 403 — the authorize interceptor denied the handler. Params: `resource`, `action`. */
  ARBAC_INSUFFICIENT_PRIVILEGES:
    'Insufficient privileges for action "{action}" on resource "{resource}"',
  /** 403 — `useArbac().evaluateOrThrow()` denied. Params: `resource`, `action`. */
  ARBAC_FORBIDDEN: "Forbidden: {resource}/{action}",
  /** 401 — the authorize interceptor could not evaluate the caller (e.g. unknown user). */
  ARBAC_NOT_AUTHORIZED: "Not authorized",
  /** 403 — a query control the role's `controls` gate denies. Params: `control`. */
  ARBAC_CONTROL_NOT_ALLOWED: 'Control "{control}" is not allowed for your role',
  /** 403 — a value outside the role's `controls` whitelist. Params: `control`, `value`. */
  ARBAC_CONTROL_VALUE_NOT_ALLOWED: 'Control "{control}={value}" is not allowed for your role',
  /** 403 — a write through a relation no scope lists in `nestedWrites`. Params: `relation`. */
  ARBAC_NESTED_WRITE_NOT_ALLOWED: 'Nested writes through "{relation}" are not allowed',
  /** 403 — a written row fails the scope `check` (WITH CHECK). */
  ARBAC_ROW_OUT_OF_SCOPE: "Row outside your write scope",
  /** 403 — a foreign key the write sets points at a row outside the caller's read scope. Params: `fields`. */
  ARBAC_REFERENCE_OUT_OF_SCOPE: 'Referenced row "{fields}" is outside your scope',
  /** 400 — the query string does not parse. Params: `error` (the parser's text). */
  ARBAC_INVALID_QUERY_STRING: "Invalid query string: {error}",
} as const;

registerMessages(ARBAC_MESSAGES);

/** A code of {@link ARBAC_MESSAGES}. */
export type ArbacMessageCode = keyof typeof ARBAC_MESSAGES;

/** An `HttpError` with `code`, `params` and the code's English text. */
export function arbacHttpError(
  status: 400 | 401 | 403,
  code: ArbacMessageCode,
  params?: Record<string, string>,
): HttpError {
  return new HttpError(status, {
    message: formatMessage(ARBAC_MESSAGES[code], params),
    code,
    ...(params && { params }),
  });
}
