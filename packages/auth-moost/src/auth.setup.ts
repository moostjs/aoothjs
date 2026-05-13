import { AuthCredential } from "@aoothjs/auth";
import { createProvideRegistry, type Moost } from "moost";

import { authGuardInterceptor } from "./auth.guard";
import { MoostAuthConfig, type ResolvedAuthCookieConfig } from "./auth.config";

export interface SetupAuthMoostOptions<TClaims extends object = object> {
  /** The `AuthCredential` instance issuing/validating tokens for this app. */
  authCredential: AuthCredential<TClaims>;
  /** Cookie attributes used when reading the session cookie. */
  cookie?: Partial<ResolvedAuthCookieConfig>;
  /** Read the session token from a cookie. Default: `true`. */
  enableCookie?: boolean;
  /** Read the session token from `Authorization: Bearer ...`. Default: `true`. */
  enableBearer?: boolean;
}

/**
 * One-call configuration for `@aoothjs/auth-moost`.
 *
 * - Registers `opts.authCredential` as the `AuthCredential` DI singleton.
 * - Registers a `MoostAuthConfig` singleton with the resolved transport defaults.
 * - Applies `authGuardInterceptor` globally so every handler is protected by
 *   default; opt out per controller/method with `@Public()`.
 *
 * Call once per Moost instance — `applyGlobalInterceptors` appends, so a
 * second call would register the guard twice.
 */
export function setupAuthMoost<TClaims extends object = object>(
  moost: Moost,
  opts: SetupAuthMoostOptions<TClaims>,
): void {
  const config = new MoostAuthConfig();
  config.configure({
    cookie: opts.cookie,
    enableCookie: opts.enableCookie,
    enableBearer: opts.enableBearer,
  });

  moost.setProvideRegistry(
    createProvideRegistry(
      [AuthCredential, () => opts.authCredential],
      [MoostAuthConfig, () => config],
    ),
  );

  moost.applyGlobalInterceptors(authGuardInterceptor);
}
