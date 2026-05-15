import { current } from "@wooksjs/event-core";
import type { TAuthGuardDef, TAuthTransportDeclaration } from "@moostjs/event-http";
import { Authenticate, HttpError } from "@moostjs/event-http";
import type { Moost } from "moost";
import { defineBeforeInterceptor, Resolve, TInterceptorPriority, useLogger } from "moost";

import { useArbac } from "./arbac.composables";
import { getArbacMate } from "./arbac.mate";

/**
 * ARBAC checks authorization, not authentication, so the transport
 * declaration is empty — pair with an upstream auth guard (e.g. JWT
 * bearer) that publishes the principal.
 *
 * Runs for every event kind (HTTP, WF, CLI, WS). `@ArbacPublic()` is the
 * only bypass — apply it to controllers/handlers that should remain
 * reachable without an evaluated rule (e.g. login/recovery workflows,
 * health probes).
 */
export const arbacAuthorizeInterceptor: TAuthGuardDef = Object.assign(
  defineBeforeInterceptor(async () => {
    const ctx = current();
    const { setScopes, evaluate, resource, action, isPublic } = useArbac(ctx);

    if (!action || !resource || isPublic) {
      return;
    }

    const logger = useLogger("arbac", ctx);
    try {
      const { allowed, scopes, userId } = await evaluate();
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
  }, TInterceptorPriority.GUARD),
  { __authTransports: {} as TAuthTransportDeclaration },
);

/** Wrapped via `Authenticate` so `@moostjs/swagger` picks up the auth-guard metadata. */
export const ArbacAuthorize = () => Authenticate(arbacAuthorizeInterceptor);

/** Gate every route globally; pair with `@ArbacPublic()` for opt-out. */
export function applyArbacGuardGlobally(app: Moost): void {
  app.applyGlobalInterceptors(arbacAuthorizeInterceptor);
}

/**
 * Resolves the evaluated ARBAC scopes for the current event. Use as a
 * parameter or property decorator.
 */
export const ArbacScopes = () => Resolve(() => useArbac().getScopes());

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
