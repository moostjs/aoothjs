import { current } from "@wooksjs/event-core";
import type { EventContext } from "@wooksjs/event-core";
import type { TAuthGuardDef } from "@moostjs/event-http";
import { Authenticate, HttpError } from "@moostjs/event-http";
import {
  defineBeforeInterceptor,
  TInterceptorPriority,
  useControllerContext,
  useLogger,
} from "moost";

import { useArbac } from "./arbac.composables";
import { insufficientPrivileges } from "./arbac.evaluate";
import { ARBAC_DELEGATED_AUTH, getArbacMate } from "./arbac.mate";
import type { ArbacDelegatedAuth } from "./arbac.mate";

/**
 * ARBAC checks authorization, not authentication, so the transport
 * declaration is empty — pair with an upstream auth guard (e.g. JWT
 * bearer) that publishes the principal.
 *
 * Runs for every event kind (HTTP, WF, CLI, WS). The `arbacPublic` mate
 * flag (written by auth-moost's combined `@Public()`) is the only bypass —
 * apply it to controllers/handlers that should remain reachable without an
 * evaluated rule (e.g. login/recovery workflows, health probes).
 */
export const arbacAuthorizeInterceptor: TAuthGuardDef = Object.assign(
  defineBeforeInterceptor(async () => {
    const ctx = current();
    const { setScopes, evaluate, resource, action, isPublic } = useArbac(ctx);

    if (!action || !resource || isPublic) {
      return;
    }
    // A moost-db handler that delegates its authorization to the controller's
    // ARBAC `prepareRequest` (no grant of its own) — it authorizes there.
    if (delegatesToArbacPrepareRequest(ctx)) return;

    const logger = useLogger("arbac", ctx);
    try {
      const { allowed, scopes, userId } = await evaluate();
      logger.debug(`[${userId}] ${allowed ? "Authorized" : "Blocked"} "${resource}" : "${action}"`);
      if (!allowed) throw insufficientPrivileges(resource, action);
      setScopes(scopes);
    } catch (error) {
      if (error instanceof HttpError) {
        throw error;
      }
      logger.warn(String(error));
      const originalMessage = error instanceof Error ? error.message : String(error);
      throw new HttpError(401, originalMessage);
    }
  }, TInterceptorPriority.GUARD),
  { __authTransports: {} },
);

function delegatesToArbacPrepareRequest(ctx: EventContext): boolean {
  const cc = useControllerContext(ctx);
  const controller = cc.getController() as Partial<ArbacDelegatedAuth> | undefined;
  const method = cc.getMethod();
  const check = controller?.[ARBAC_DELEGATED_AUTH];
  return (
    typeof method === "string" && typeof check === "function" && check.call(controller, method)
  );
}

/** Wrapped via `Authenticate` so `@moostjs/swagger` picks up the auth-guard metadata. */
export const ArbacAuthorize = () => Authenticate(arbacAuthorizeInterceptor);

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
