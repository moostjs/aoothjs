/** Resolved cookie attributes. Same shape is used for both access + refresh. */
export interface ResolvedAuthCookieConfig {
  name: string;
  secure: boolean;
  sameSite: "lax" | "strict" | "none";
  httpOnly: boolean;
  path: string;
  domain?: string;
  /**
   * Keep the cookie across browser restarts: `Max-Age` follows the token it
   * carries (access / refresh expiry) and is renewed on every rotation.
   * Default `false` — a session cookie (gone when the browser closes). Not
   * inherited by the refresh cookie: set it on `refreshCookie` for a
   * "stay signed in" device (the access cookie can stay session-only — a
   * missing one is silently refreshed).
   */
  persistent: boolean;
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
  /**
   * Return `accessToken` / `refreshToken` in JSON bodies (login finish,
   * `POST /auth/refresh`). Default: `!enableCookie` — a cookie app keeps token
   * material out of reach of page scripts, so an XSS cannot read a fresh
   * refresh token from `/auth/refresh`. Set `true` for token clients (CLI,
   * mobile) that share the cookie deployment; accepting `Authorization: Bearer`
   * on requests is controlled separately by {@link enableBearer}.
   */
  exposeTokensInBody?: boolean;
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
  exposeTokensInBody: boolean;
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
    persistent: false,
    ...opts.cookie,
  };
  const refreshCookie: ResolvedAuthCookieConfig = {
    name: "aooth_refresh",
    secure: cookie.secure,
    sameSite: cookie.sameSite,
    httpOnly: cookie.httpOnly,
    ...(cookie.domain !== undefined && { domain: cookie.domain }),
    path: "/auth/refresh",
    persistent: false,
    ...opts.refreshCookie,
  };
  const enableCookie = opts.enableCookie ?? true;
  return {
    cookie,
    refreshCookie,
    enableCookie,
    enableBearer: opts.enableBearer ?? true,
    exposeTokensInBody: opts.exposeTokensInBody ?? !enableCookie,
  };
}
