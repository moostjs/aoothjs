import { AuthCredential } from "@aoothjs/auth";
import { current, eventTypeKey } from "@wooksjs/event-core";
import { HttpError } from "@wooksjs/event-http";
import { defineBeforeInterceptor, TInterceptorPriority, useControllerContext } from "moost";

import { MoostAuthConfig } from "./auth.config";
import { setAuthContext } from "./auth.composables";
import type { TAuthMeta } from "./auth.mate";
import { extractAccessToken } from "./auth.token";

/**
 * `GUARD`-priority interceptor that authenticates incoming requests.
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
export const authGuardInterceptor = defineBeforeInterceptor(async () => {
  const ctx = current();
  if (ctx.get(eventTypeKey) !== "http") return;
  const cc = useControllerContext(ctx);

  const cMeta = cc.getControllerMeta<TAuthMeta>();
  const mMeta = cc.getMethodMeta<TAuthMeta>();
  const isPublic = mMeta?.authPublic ?? cMeta?.authPublic ?? false;

  const [credential, config] = await Promise.all([
    cc.instantiate(AuthCredential),
    cc.instantiate(MoostAuthConfig),
  ]);

  const token = extractAccessToken(ctx, config);

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
