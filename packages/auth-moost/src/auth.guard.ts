import { AuthCredential } from "@aoothjs/auth";
import { current } from "@wooksjs/event-core";
import { HttpError, useAuthorization, useCookies } from "@wooksjs/event-http";
import { defineBeforeInterceptor, TInterceptorPriority, useControllerContext } from "moost";

import { MoostAuthConfig } from "./auth.config";
import { setAuthContext } from "./auth.composables";
import type { TAuthMeta } from "./auth.mate";

/**
 * `GUARD`-priority interceptor that authenticates incoming requests.
 *
 * Token extraction precedence: `Authorization: Bearer ...` wins over cookie
 * when both transports are enabled. On `@Public()` routes a missing or
 * invalid token leaves AuthContext as `null` and the handler runs anyway;
 * on protected routes it throws `HttpError(401)`.
 *
 * Never auto-refreshes — refresh is a separate REST endpoint.
 */
export const authGuardInterceptor = defineBeforeInterceptor(async () => {
  const ctx = current();
  const cc = useControllerContext(ctx);

  const cMeta = cc.getControllerMeta<TAuthMeta>();
  const mMeta = cc.getMethodMeta<TAuthMeta>();
  const isPublic = mMeta?.authPublic ?? cMeta?.authPublic ?? false;

  const [credential, config] = await Promise.all([
    cc.instantiate(AuthCredential),
    cc.instantiate(MoostAuthConfig),
  ]);

  let token: string | undefined;
  if (config.enableBearer) {
    const auth = useAuthorization(ctx);
    if (auth.is("bearer")) token = auth.credentials() ?? undefined;
  }
  if (!token && config.enableCookie) {
    token = useCookies(ctx).getCookie(config.cookie.name) ?? undefined;
  }

  if (!token) {
    if (isPublic) {
      setAuthContext(ctx, null);
      return;
    }
    throw new HttpError(401, "Unauthorized");
  }

  const authContext = await credential.validate(token);
  if (!authContext) {
    if (isPublic) {
      setAuthContext(ctx, null);
      return;
    }
    throw new HttpError(401, "Invalid credential");
  }

  setAuthContext(ctx, authContext);
}, TInterceptorPriority.GUARD);
