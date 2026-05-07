import { current } from "@wooksjs/event-core";
import { HttpError } from "@wooksjs/event-http";
import {
  defineBeforeInterceptor,
  Intercept,
  Resolve,
  TInterceptorPriority,
  useLogger,
} from "moost";

import { useArbac } from "./arbac.composables";
import { getArbacMate } from "./arbac.mate";

/**
 * Interceptor that enforces authorization checks based on ARBAC rules.
 *
 * Runs at `GUARD` priority. Skips evaluation when no resource/action is
 * resolved or when the handler/controller is marked `@ArbacPublic()`.
 * Throws `HttpError(403)` on deny, `HttpError(401)` on unexpected errors.
 * On allow, stores the resolved `scopes` in the event context so they can
 * be read via `@ArbacScopes()` / `@CurrentArbacScopes()`.
 */
export const arbacAuthorizeInterceptor = defineBeforeInterceptor(async () => {
  const ctx = current();
  const logger = useLogger("arbac", ctx);

  const { setScopes, evaluate, resource, action, isPublic } = useArbac(ctx);

  if (!action || !resource || isPublic) {
    return;
  }

  try {
    const { allowed, scopes, userId } = await evaluate({ resource, action });
    logger.debug(`[${userId}] ${allowed ? "Authorized" : "Blocked"} "${resource}" : "${action}"`);
    if (!allowed) {
      throw new HttpError(
        403,
        `Insufficient privileges for action "${action}" on resource "${resource}"`,
      );
    }
    setScopes(scopes);
  } catch (error) {
    if (error instanceof HttpError) {
      throw error;
    }
    logger.warn(String(error));
    throw new HttpError(401, "Authorization error");
  }
}, TInterceptorPriority.GUARD);

/**
 * Decorator that applies the `arbacAuthorizeInterceptor` to enforce ARBAC.
 */
export const ArbacAuthorize = () => Intercept(arbacAuthorizeInterceptor);

/**
 * Resolves the evaluated ARBAC scopes for the current event. Use as a
 * parameter or property decorator.
 */
export const ArbacScopes = () => Resolve(() => useArbac().getScopes());

/**
 * Alias for `ArbacScopes` that reads more naturally on a parameter.
 *
 * ```ts
 * handler(@CurrentArbacScopes() scopes?: MyScope[]) {}
 * ```
 */
export const CurrentArbacScopes = ArbacScopes;

/**
 * Decorator to specify a resource id for ARBAC evaluation. Apply to a
 * controller class or a handler method.
 */
export const ArbacResource = (name: string) => getArbacMate().decorate("arbacResourceId", name);

/**
 * Decorator to specify an action id for ARBAC evaluation. Typically applied
 * at the method level.
 */
export const ArbacAction = (name: string) => getArbacMate().decorate("arbacActionId", name);

/**
 * Marks a handler or controller as publicly accessible, bypassing
 * authorization checks.
 */
export const ArbacPublic = () => getArbacMate().decorate("arbacPublic", true);
