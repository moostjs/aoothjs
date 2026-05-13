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

/**
 * DI singleton carrying the resolved auth-guard transport configuration.
 * Populated once at boot by `setupAuthMoost()` via {@link configure}.
 */
@Injectable()
export class MoostAuthConfig {
  cookie: ResolvedAuthCookieConfig = {
    name: "aooth_session",
    secure: true,
    sameSite: "lax",
    httpOnly: true,
    path: "/",
  };
  /**
   * Narrow `path: '/auth/refresh'` ensures the refresh token only travels to
   * the refresh endpoint. Transport attrs (`secure/sameSite/httpOnly/domain`)
   * are inherited from {@link cookie} in {@link configure} unless overridden.
   */
  refreshCookie: ResolvedAuthCookieConfig = {
    name: "aooth_refresh",
    secure: true,
    sameSite: "lax",
    httpOnly: true,
    path: "/auth/refresh",
  };
  enableCookie = true;
  enableBearer = true;
  /** When `false`, `setupAuthMoost` skips registering `AuthController`. */
  endpoints = true;

  configure(config: {
    cookie?: Partial<ResolvedAuthCookieConfig>;
    refreshCookie?: Partial<ResolvedAuthCookieConfig>;
    enableCookie?: boolean;
    enableBearer?: boolean;
    endpoints?: boolean;
  }): void {
    if (config.cookie) {
      this.cookie = { ...this.cookie, ...config.cookie };
    }
    this.refreshCookie = {
      ...this.refreshCookie,
      secure: this.cookie.secure,
      sameSite: this.cookie.sameSite,
      httpOnly: this.cookie.httpOnly,
      domain: this.cookie.domain,
      ...config.refreshCookie,
    };
    if (typeof config.enableCookie === "boolean") {
      this.enableCookie = config.enableCookie;
    }
    if (typeof config.enableBearer === "boolean") {
      this.enableBearer = config.enableBearer;
    }
    if (typeof config.endpoints === "boolean") {
      this.endpoints = config.endpoints;
    }
  }
}
