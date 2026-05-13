import { AuthCredential } from "@aoothjs/auth";
import { UserService } from "@aoothjs/user";
import { createProvideRegistry, type Moost } from "moost";

import { MoostAuthConfig, type ResolvedAuthCookieConfig } from "./auth.config";
import { AuthController } from "./auth.controller";
import { authGuardInterceptor } from "./auth.guard";

export interface SetupAuthMoostOptions<TClaims extends object = object> {
  /** The `AuthCredential` instance issuing/validating tokens for this app. */
  authCredential: AuthCredential<TClaims>;
  /**
   * `UserService` used by login + password-change endpoints. Required when
   * `endpoints` is `true` (the default); a missing `userService` then throws
   * at setup time.
   */
  userService?: UserService;
  /** Cookie attributes used when reading the session cookie. */
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
   * When `true` (default), auto-registers `AuthController` (login, logout,
   * refresh, status, password). Set `false` to opt out — e.g. to roll a
   * subclassed controller with custom user-id mapping or a different prefix.
   */
  endpoints?: boolean;
}

/**
 * One-call configuration for `@aoothjs/auth-moost`.
 *
 * - Registers DI singletons: `AuthCredential`, `MoostAuthConfig`, and
 *   `UserService` (when provided).
 * - Auto-registers `AuthController` when `endpoints` is true (default).
 * - Applies `authGuardInterceptor` globally so every handler is protected by
 *   default; opt out per controller/method with `@Public()`.
 *
 * Call once per Moost instance — `applyGlobalInterceptors` appends, so a
 * second call would register the guard twice.
 *
 * Throws when `endpoints !== false` and no `userService` is provided, because
 * `/auth/login` and `/auth/password` cannot function without one.
 */
export function setupAuthMoost<TClaims extends object = object>(
  moost: Moost,
  opts: SetupAuthMoostOptions<TClaims>,
): void {
  const config = new MoostAuthConfig();
  config.configure({
    cookie: opts.cookie,
    refreshCookie: opts.refreshCookie,
    enableCookie: opts.enableCookie,
    enableBearer: opts.enableBearer,
    endpoints: opts.endpoints,
  });

  if (config.endpoints && !opts.userService) {
    throw new Error(
      "setupAuthMoost: `userService` is required when `endpoints` is enabled. " +
        "Pass a `UserService` instance, or set `endpoints: false` to skip the " +
        "auto-registered controller.",
    );
  }

  const providers: Parameters<typeof createProvideRegistry> = [
    [AuthCredential, () => opts.authCredential],
    [MoostAuthConfig, () => config],
  ];
  if (opts.userService) {
    const users = opts.userService;
    providers.push([UserService, () => users]);
  }
  moost.setProvideRegistry(createProvideRegistry(...providers));

  moost.applyGlobalInterceptors(authGuardInterceptor);

  if (config.endpoints) {
    moost.registerControllers(AuthController);
  }
}
