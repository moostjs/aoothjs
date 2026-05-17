import { AuthCredential } from "@aoothjs/auth";
import { current, eventTypeKey } from "@wooksjs/event-core";
import { HttpError } from "@wooksjs/event-http";
import {
  defineBeforeInterceptor,
  Intercept,
  type TInterceptorDef,
  TInterceptorPriority,
  useControllerContext,
} from "moost";

import { type AuthOptions, resolveAuthOptions } from "./auth.config";
import { authOptionsKey, setAuthContext, useAuth } from "./auth.composables";
import type { TAuthMeta } from "./auth.mate";

/**
 * `GUARD`-priority interceptor factory that authenticates incoming requests.
 *
 * Returns a configured `TInterceptorDef`. Each invocation captures its own
 * resolved options and stashes them onto the HTTP event context's
 * `authOptionsKey` slot so `useAuth()` (and the workflows that depend on it)
 * can read the same transport config.
 *
 * Token extraction precedence: `Authorization: Bearer ...` wins over cookie
 * when both transports are enabled. On `@Public()` routes a missing or
 * invalid token leaves AuthContext as `null` and the handler runs anyway;
 * on protected routes it throws `HttpError(401)`.
 *
 * Never auto-refreshes — refresh is a separate REST endpoint.
 *
 * No-ops on non-HTTP event contexts (workflow steps, CLI, WS messages). The
 * guard reads tokens from HTTP headers/cookies; nothing to read elsewhere.
 * Authorization for workflow steps is the step's own responsibility (e.g.
 * an admin-only invite endpoint protects its outlet HTTP route, not the
 * step handler).
 */
export function authGuardInterceptor(opts?: AuthOptions): TInterceptorDef {
  const resolved = resolveAuthOptions(opts);
  return defineBeforeInterceptor(async () => {
    const ctx = current();
    if (ctx.get(eventTypeKey) !== "http") return;
    // Stash resolved options into the event slot BEFORE doing anything that
    // might call `useAuth()` (including ours below). Child events started via
    // `start({ eventContext: current() })` inherit this slot through the
    // parent-context chain.
    ctx.set(authOptionsKey, resolved);

    const cc = useControllerContext(ctx);
    const cMeta = cc.getControllerMeta<TAuthMeta>();
    const mMeta = cc.getMethodMeta<TAuthMeta>();
    const isPublic = mMeta?.authPublic ?? cMeta?.authPublic ?? false;

    // Extract the token BEFORE instantiating AuthCredential — public routes
    // with no token (e.g. health checks) avoid the DI lookup entirely.
    const token = useAuth().extractToken();

    if (!token) {
      if (isPublic) {
        setAuthContext(ctx, null);
        return;
      }
      throw new HttpError(401, "Unauthorized");
    }

    const credential = await cc.instantiate(AuthCredential);
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
}

/**
 * Decorator-factory sugar for attaching `authGuardInterceptor(opts)` to a
 * specific controller or method instead of globally. Equivalent to
 * `@Intercept(authGuardInterceptor(opts))`.
 */
export function AuthGuarded(opts?: AuthOptions): ClassDecorator & MethodDecorator {
  return Intercept(authGuardInterceptor(opts));
}
