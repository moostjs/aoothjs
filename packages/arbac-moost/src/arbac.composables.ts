import { HttpError } from "@moostjs/event-http";
import type { EventContext } from "@wooksjs/event-core";
import { current, key } from "@wooksjs/event-core";
import { getConstructor, useControllerContext } from "moost";

import type { TArbacMeta } from "./arbac.mate";
import { MoostArbac } from "./moost-arbac";
import { ArbacUserProvider, ArbacUserProviderToken } from "./user.provider";

/**
 * Writable slot holding the evaluated scopes for the current event.
 *
 * Module-level `key()` per the `@wooksjs/event-core` slot system. The
 * authorize interceptor calls `setScopes(...)` after a successful evaluate;
 * downstream `@ArbacScopes()` resolvers read it back from the same event context.
 */
const arbacScopesKey = key<unknown[] | undefined>("arbac.scopes");

interface ArbacBindings {
  getScopes: <TScope extends object>() => TScope[] | undefined;
  setScopes: <TScope extends object>(scope: TScope[] | undefined) => void;
  evaluate: <TScope extends object>(opts?: {
    resource?: string;
    action?: string;
  }) => Promise<{ allowed: boolean; scopes?: TScope[]; userId: string }>;
  /**
   * Throw-on-deny variant of {@link evaluate}. Returns the same shape on
   * `allowed: true`; throws `HttpError(403)` otherwise.
   *
   * Use this in handlers/steps that want a hard short-circuit on deny.
   * Use {@link evaluate} when you need to inspect `allowed` (e.g. to merge
   * with another policy, to filter UI metadata, or to fall through to a
   * different authorization path).
   */
  evaluateOrThrow: <TScope extends object>(opts?: {
    resource?: string;
    action?: string;
  }) => Promise<{ allowed: true; scopes?: TScope[]; userId: string }>;
  resource: string;
  action: string;
  isPublic: boolean;
}

/**
 * Composable for ARBAC utilities within Moost handlers and interceptors.
 *
 * Exposes scope read/write, lazy `evaluate`, and the resolved
 * resource/action/public flags derived from the current controller +
 * method metadata.
 *
 * Intentionally NOT a `defineWook`-cached composable: WF events created via
 * `WfTriggerProvider.handle()` are passed the originating HTTP `EventContext`
 * as their `parent`. A `defineWook` cache slot would traverse that parent
 * chain and return the HTTP request's first-resolution tuple (resource +
 * action + isPublic from the @Public-marked `/auth/trigger` route) for every
 * downstream WF step — silently bypassing class-level `@ArbacResource` on the
 * workflow controller. Re-resolving per call is cheap (two `mate.read` cache
 * hits) and avoids that cross-context leak.
 *
 * Read/write scope state goes through `arbacScopesKey` directly so it still
 * lives on the per-event slot (set inside the WF event ctx, read by handlers
 * running inside the same event).
 */
export const useArbac = (ctx?: EventContext): ArbacBindings => {
  const _ctx = ctx ?? current();
  return _useArbacFactory(_ctx);
};

const _useArbacFactory = (ctx: EventContext): ArbacBindings => {
  const cc = useControllerContext(ctx);

  const getScopes = <TScope extends object>(): TScope[] | undefined =>
    ctx.has(arbacScopesKey) ? (ctx.get(arbacScopesKey) as TScope[] | undefined) : undefined;

  const setScopes = <TScope extends object>(scope: TScope[] | undefined): void => {
    ctx.set(arbacScopesKey, scope);
  };

  const cMeta = cc.getControllerMeta<TArbacMeta>();
  const mMeta = cc.getMethodMeta<TArbacMeta>();

  // Strict-by-default per ACT-04: undecorated controllers fall back to the
  // class name as resource and the method name as action, so a globally
  // wired `arbacAuthorizeInterceptor` denies access unless the user holds a
  // matching grant (or the controller/method is `@Public()`).
  const resource =
    mMeta?.arbacResourceId ||
    cMeta?.arbacResourceId ||
    cMeta?.id ||
    getConstructor(cc.getController()).name;
  // Action resolution. Class-level `@ArbacAction` is honoured so a workflow
  // consumer can pin a single action id for every step event (e.g.
  // `@ArbacResource('auth') @ArbacAction('admin.invite')` on the workflow
  // class evaluates every step against `auth/admin.invite`).
  const action =
    mMeta?.arbacActionId ||
    // atscript_db_action is set by @atscript/moost-db on method metadata; TArbacMeta does not
    // include it because arbac-moost doesn't depend on atscript-db — side-channel read only.
    (mMeta as { atscript_db_action?: { name?: string } } | undefined)?.atscript_db_action?.name ||
    cMeta?.arbacActionId ||
    mMeta?.id ||
    (cc.getMethod() ?? "");
  const isPublic = mMeta?.arbacPublic || cMeta?.arbacPublic || false;

  const evaluate = async <TScope extends object>(opts?: {
    resource?: string;
    action?: string;
  }): Promise<{ allowed: boolean; scopes?: TScope[]; userId: string }> => {
    const effectiveResource = opts?.resource || resource;
    const effectiveAction = opts?.action || action;
    if (!effectiveResource) {
      throw new Error(
        "useArbac().evaluate(): `resource` is required — could not be resolved from controller/method metadata. Pass it explicitly.",
      );
    }
    if (!effectiveAction) {
      throw new Error(
        "useArbac().evaluate(): `action` is required — could not be resolved from controller/method metadata. Pass it explicitly.",
      );
    }
    const [user, arbac] = (await Promise.all([
      cc.instantiate(ArbacUserProviderToken),
      cc.instantiate(MoostArbac),
    ])) as [ArbacUserProvider, MoostArbac<object, TScope>];
    const userId = await user.getUserId();
    const result = await arbac.evaluate(
      { resource: effectiveResource, action: effectiveAction },
      {
        id: userId,
        roles: await user.getRoles(userId),
        attrs: (id: string) => user.getAttrs(id),
      },
    );
    return { ...result, userId };
  };

  const evaluateOrThrow = async <TScope extends object>(opts?: {
    resource?: string;
    action?: string;
  }): Promise<{ allowed: true; scopes?: TScope[]; userId: string }> => {
    const result = await evaluate<TScope>(opts);
    if (!result.allowed) {
      const r = opts?.resource || resource;
      const a = opts?.action || action;
      throw new HttpError(403, `Forbidden: ${r}/${a}`);
    }
    return { ...result, allowed: true };
  };

  return {
    getScopes,
    setScopes,
    evaluate,
    evaluateOrThrow,
    resource,
    action,
    isPublic,
  };
};
