/** Resolved cookie attributes. Same shape is used for both access + refresh. */
export interface ResolvedAuthCookieConfig {
  name: string;
  secure: boolean;
  sameSite: "lax" | "strict" | "none";
  httpOnly: boolean;
  path: string;
  domain?: string;
}

export interface AuthOptions {
  cookie?: Partial<ResolvedAuthCookieConfig>;
  /**
   * Refresh-cookie attribute overrides. Defaults to `name='aooth_refresh'`,
   * `path='/auth/refresh'`; inherits `secure/sameSite/httpOnly/domain` from
   * the access cookie unless overridden here.
   */
  refreshCookie?: Partial<ResolvedAuthCookieConfig>;
  /** Read the session token from a cookie. Default: `true`. */
  enableCookie?: boolean;
  /** Read the session token from `Authorization: Bearer ...`. Default: `true`. */
  enableBearer?: boolean;
}

/**
 * Fully-resolved options carried by `authGuardInterceptor(opts)` through the
 * HTTP event slot. `useAuth().options` returns this shape so consumers can type
 * variables without re-resolving defaults.
 */
export interface ResolvedAuthOptions {
  cookie: ResolvedAuthCookieConfig;
  /**
   * Narrow `path: '/auth/refresh'` ensures the refresh token only travels to
   * the refresh endpoint. Transport attrs (`secure/sameSite/httpOnly/domain`)
   * are inherited from {@link cookie} unless overridden.
   */
  refreshCookie: ResolvedAuthCookieConfig;
  enableCookie: boolean;
  enableBearer: boolean;
}

/**
 * Resolve `AuthOptions` to its `ResolvedAuthOptions` form, applying the same
 * defaults the legacy `MoostAuthConfig` constructor did. Pure — call once per
 * `authGuardInterceptor` factory invocation; the resolved value is stashed in
 * a wook slot for the event chain.
 */
export function resolveAuthOptions(opts: AuthOptions = {}): ResolvedAuthOptions {
  const cookie: ResolvedAuthCookieConfig = {
    name: "aooth_session",
    secure: true,
    sameSite: "lax",
    httpOnly: true,
    path: "/",
    ...opts.cookie,
  };
  const refreshCookie: ResolvedAuthCookieConfig = {
    name: "aooth_refresh",
    secure: cookie.secure,
    sameSite: cookie.sameSite,
    httpOnly: cookie.httpOnly,
    ...(cookie.domain !== undefined && { domain: cookie.domain }),
    path: "/auth/refresh",
    ...opts.refreshCookie,
  };
  return {
    cookie,
    refreshCookie,
    enableCookie: opts.enableCookie ?? true,
    enableBearer: opts.enableBearer ?? true,
  };
}
