/**
 * Cookie helpers shared between the REST controller and the workflow steps.
 * Factoring them out keeps wire behaviour identical and prevents subtle drift
 * (e.g. `sameSite` casing) from creeping into one path only.
 *
 * Composables read the active event context via `current()`; workflow steps
 * run as children of the HTTP event context (the `eventContext` passed to
 * `MoostWf.start/resume`), so `useResponse()` / `useCookies()` resolve
 * through the parent chain.
 */
import type { IssueResult } from "@aoothjs/auth";
import { current } from "@wooksjs/event-core";
import { type TCookieAttributesInput, useResponse } from "@wooksjs/event-http";

import type { MoostAuthConfig } from "./auth.config";
import type { AuthLoginResponse } from "./auth.dto";

/**
 * `sameSite` is upper-cased because wooks accepts `'Lax' | 'Strict' | 'None'`
 * while {@link MoostAuthConfig} stores lower-case for ergonomics.
 */
export function cookieAttrs(
  c: MoostAuthConfig["cookie"],
  extra?: TCookieAttributesInput,
): TCookieAttributesInput {
  return {
    httpOnly: c.httpOnly,
    secure: c.secure,
    sameSite: (c.sameSite.charAt(0).toUpperCase() + c.sameSite.slice(1)) as
      | "Lax"
      | "Strict"
      | "None",
    path: c.path,
    domain: c.domain,
    ...extra,
  };
}

export function writeAuthCookies(config: MoostAuthConfig, issue: IssueResult): void {
  if (!config.enableCookie) return;
  const response = useResponse(current());
  response.setCookie(config.cookie.name, issue.accessToken, cookieAttrs(config.cookie));
  if (issue.refreshToken) {
    response.setCookie(
      config.refreshCookie.name,
      issue.refreshToken,
      cookieAttrs(config.refreshCookie),
    );
  }
}

export function clearAuthCookies(config: MoostAuthConfig): void {
  if (!config.enableCookie) return;
  const response = useResponse(current());
  response.setCookie(config.cookie.name, "", cookieAttrs(config.cookie, { maxAge: 0 }));
  response.setCookie(
    config.refreshCookie.name,
    "",
    cookieAttrs(config.refreshCookie, { maxAge: 0 }),
  );
}

/**
 * With `enableBearer === false` the response shape still carries `userId` +
 * `accessExpiresAt` so clients can schedule a silent refresh, but the tokens
 * themselves travel only via the cookies set by {@link writeAuthCookies}.
 */
export function buildLoginResponse(
  config: MoostAuthConfig,
  userId: string,
  issue: IssueResult,
): AuthLoginResponse {
  return {
    userId,
    accessExpiresAt: issue.accessExpiresAt,
    ...(issue.refreshExpiresAt !== undefined && { refreshExpiresAt: issue.refreshExpiresAt }),
    ...(config.enableBearer && {
      accessToken: issue.accessToken,
      ...(issue.refreshToken && { refreshToken: issue.refreshToken }),
    }),
  };
}
