import { Injectable } from "moost";

/** Resolved cookie attributes read by `authGuardInterceptor`. */
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
  enableCookie = true;
  enableBearer = true;

  configure(config: {
    cookie?: Partial<ResolvedAuthCookieConfig>;
    enableCookie?: boolean;
    enableBearer?: boolean;
  }): void {
    if (config.cookie) {
      this.cookie = { ...this.cookie, ...config.cookie };
    }
    if (typeof config.enableCookie === "boolean") {
      this.enableCookie = config.enableCookie;
    }
    if (typeof config.enableBearer === "boolean") {
      this.enableBearer = config.enableBearer;
    }
  }
}
