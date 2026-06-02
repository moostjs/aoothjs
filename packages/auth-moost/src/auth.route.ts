import { Injectable } from "moost";

/**
 * Normalize a router path into a value usable as a cookie `Path` attribute:
 * a single leading slash, no doubled slashes, and no trailing slash (except
 * for the bare root `/`).
 */
export function normalizeCookiePath(path: string): string {
  const withLead = path.startsWith("/") ? path : `/${path}`;
  const collapsed = withLead.replaceAll(/\/{2,}/g, "/");
  return collapsed.length > 1 && collapsed.endsWith("/") ? collapsed.slice(0, -1) : collapsed;
}

/**
 * Singleton sink for the refresh cookie's resolved `Path`.
 *
 * Written once at application boot by `AuthController`'s `@MoostInit` hook, which
 * reads the controller's REAL mounted refresh route from Moost's post-bind route
 * table via `@HandlerPaths('refresh')` — correct under any mount prefix (e.g.
 * `api/auth` → `/api/auth/refresh`), including a subclassed controller, since the
 * hook runs on the registered instance. `authGuardInterceptor` reads `path` to
 * scope the refresh cookie to that route.
 *
 * `path` stays `undefined` when the consumer set `refreshCookie.path` explicitly,
 * `AuthController` isn't registered, or the refresh route can't be uniquely
 * resolved — in every such case the guard keeps the configured default.
 *
 * A DI singleton (not a module global) so each Moost app gets its own holder —
 * no cross-app/test bleed.
 */
@Injectable() // SINGLETON
export class RefreshCookiePathHolder {
  path?: string;
}
