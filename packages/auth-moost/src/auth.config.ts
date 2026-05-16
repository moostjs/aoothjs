import { Injectable } from "moost";

/** Resolved cookie attributes. Same shape is used for both access + refresh. */
export interface ResolvedAuthCookieConfig {
  name: string;
  secure: boolean;
  sameSite: "lax" | "strict" | "none";
  httpOnly: boolean;
  path: string;
  domain?: string;
}

export interface MoostAuthConfigOptions {
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
 * DI singleton carrying the resolved auth-guard transport configuration.
 * Constructed by the consumer (typically inside the Moost provide registry)
 * with the desired overrides; defaults are baked at construction time.
 */
@Injectable()
export class MoostAuthConfig {
  cookie: ResolvedAuthCookieConfig;
  /**
   * Narrow `path: '/auth/refresh'` ensures the refresh token only travels to
   * the refresh endpoint. Transport attrs (`secure/sameSite/httpOnly/domain`)
   * are inherited from {@link cookie} unless overridden.
   */
  refreshCookie: ResolvedAuthCookieConfig;
  enableCookie: boolean;
  enableBearer: boolean;

  constructor(opts: MoostAuthConfigOptions = {}) {
    this.cookie = {
      name: "aooth_session",
      secure: true,
      sameSite: "lax",
      httpOnly: true,
      path: "/",
      ...opts.cookie,
    };
    this.refreshCookie = {
      name: "aooth_refresh",
      secure: this.cookie.secure,
      sameSite: this.cookie.sameSite,
      httpOnly: this.cookie.httpOnly,
      domain: this.cookie.domain,
      path: "/auth/refresh",
      ...opts.refreshCookie,
    };
    this.enableCookie = opts.enableCookie ?? true;
    this.enableBearer = opts.enableBearer ?? true;
  }
}
