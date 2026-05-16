/**
 * Internal helpers for the three auth workflows.
 *
 * Co-locates two patterns the @atscript/moost-wf reference docs tell consumers
 * to copy into their own projects (`httpInputRequired` + `validateFormInput`)
 * with auth-specific glue for cookie + finished-response building.
 */
import type { IssueResult } from "@aoothjs/auth";
import { UserAuthError } from "@aoothjs/user";
import { extractPassContext, serializeFormSchema } from "@atscript/moost-wf";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { HttpError } from "@moostjs/event-http";
import { outletHttp } from "@moostjs/event-wf";
import { current } from "@wooksjs/event-core";
import { useRequest } from "@wooksjs/event-http";
import type { WfFinishedResponse } from "@wooksjs/event-wf";

import type { MoostAuthConfig } from "../auth.config";
import { cookieAttrs } from "../auth.cookies";

/**
 * Special error keys:
 *   - `__form` — top-level form-wide error (e.g. "Invalid credentials").
 *   - everything else — keyed by field path.
 */
export function httpInputRequired(
  type: TAtscriptAnnotatedType,
  wfContext: object,
  errors?: Record<string, string>,
): ReturnType<typeof outletHttp> {
  const context: Record<string, unknown> = {
    ...extractPassContext(type, wfContext as Record<string, unknown>),
  };
  if (errors) context.errors = errors;
  return outletHttp(serializeFormSchema(type), context);
}

/**
 * Returns `null` when valid, or a flat `field → message` map. Top-level errors
 * land on `__form`. `partial: 'deep'` validates only the fields the caller
 * supplied (action-with-data submits).
 */
export function validateFormInput(
  type: TAtscriptAnnotatedType,
  input: unknown,
  opts: { partial?: "deep" } = {},
): Record<string, string> | null {
  const validator = type.validator({
    unknownProps: "strip",
    ...(opts.partial === "deep" && { partial: "deep" }),
  });
  try {
    validator.validate(input);
    return null;
  } catch (err) {
    if (
      err !== null &&
      typeof err === "object" &&
      "errors" in err &&
      Array.isArray((err as { errors: unknown }).errors)
    ) {
      const out: Record<string, string> = {};
      for (const e of (err as { errors: Array<{ path: string; message: string }> }).errors) {
        out[e.path || "__form"] = e.message;
      }
      return out;
    }
    throw err;
  }
}

/**
 * Build the `cookies` map for `useWfFinished({ cookies })`. The outlet
 * trigger's HTTP layer turns the entries into `Set-Cookie` headers, mirroring
 * what `writeAuthCookies()` does for the REST controller.
 */
export function buildFinishedCookies(
  config: MoostAuthConfig,
  issue: IssueResult,
): WfFinishedResponse["cookies"] {
  if (!config.enableCookie) return undefined;
  const cookies: NonNullable<WfFinishedResponse["cookies"]> = {
    [config.cookie.name]: { value: issue.accessToken, options: cookieAttrs(config.cookie) },
  };
  if (issue.refreshToken) {
    cookies[config.refreshCookie.name] = {
      value: issue.refreshToken,
      options: cookieAttrs(config.refreshCookie),
    };
  }
  return cookies;
}

/**
 * Translate password-mutation errors from `UserService.setPassword` /
 * `createUser` into the matching HTTP status. Mirrors `translatePasswordError`
 * in `auth.controller.ts`; kept here so workflow steps don't import from the
 * controller module. All `UserAuthError` shapes from a set-password call are
 * client-side (policy / history / mismatch), so they collapse to 400.
 */
export function translatePasswordSetError(err: unknown): never {
  if (err instanceof UserAuthError) throw new HttpError(400, err.message);
  throw err;
}

/**
 * Asserts `ctx.username` is populated. Workflow steps reach for `ctx.username`
 * after `credentials`/`init` has set it; losing it indicates a workflow-state
 * bug, not a client error. Throws `HttpError(500)` on miss; otherwise narrows
 * the field to `string` for the caller via `asserts`.
 */
export function requireUsername<T extends { username?: string }>(
  ctx: T,
): asserts ctx is T & { username: string } {
  if (!ctx.username) throw new HttpError(500, "Workflow state corrupted: missing username");
}

/** Mint a numeric pincode of the requested length using Math.random — fine for OTPs. */
export function generatePincode(length: number): string {
  let out = "";
  for (let i = 0; i < length; i++) out += Math.floor(Math.random() * 10).toString();
  return out;
}

/** Workflow context shape expected by `mintPin` + `verifyPin`. */
export interface PinCtx {
  pin?: string;
  pinExpire?: number;
}

/**
 * Mint a pincode + its expiry onto `ctx.pin` / `ctx.pinExpire`. Returns the
 * code so the caller can hand it to the delivery transport.
 */
export function mintPin(ctx: PinCtx, length: number, ttlMs: number): string {
  const code = generatePincode(length);
  ctx.pin = code;
  ctx.pinExpire = Date.now() + ttlMs;
  return code;
}

/**
 * Verify a submitted pincode against `ctx.pin`. Returns a `{ code: '…' }`
 * error map on expired/invalid, or `null` on success. Callers wrap with
 * `httpInputRequired(PincodeForm, ctx, …)` to render.
 */
export function verifyPin(ctx: PinCtx, submitted: string | undefined): { code: string } | null {
  if (!ctx.pin || !ctx.pinExpire || Date.now() > ctx.pinExpire) return { code: "Code expired" };
  if (submitted !== ctx.pin) return { code: "Invalid code" };
  return null;
}

/**
 * Resolve the client IP from the active HTTP request, swallowing the case
 * where there is no HTTP context (unit tests that hand-roll the wf runtime).
 */
export function resolveClientIp(): string | undefined {
  try {
    const req = useRequest(current());
    const ip = (req as unknown as { getIp?: () => string | undefined }).getIp?.();
    return ip || undefined;
  } catch {
    return undefined;
  }
}
