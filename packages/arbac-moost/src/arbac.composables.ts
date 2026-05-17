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
 * Per-event memoization of {@link useArbac} bindings.
 *
 * Keyed on the `EventContext` object itself (NOT a wook slot). This is the
 * critical distinction vs. `defineWook`: a `defineWook` cache slot lives in
 * the slot-id space and `ctx.get(slot)` traverses the parent chain — so a WF
 * event created via `WfTriggerProvider.handle()` (whose `parent` is the
 * originating HTTP `EventContext`) would resolve the HTTP request's bindings
 * (resource + action + isPublic from `/auth/trigger`) and silently bypass the
 * workflow controller's `@ArbacResource`. A WeakMap keyed on the child `ctx`
 * object never sees the parent's bindings because the child and parent are
 * distinct object identities. See `arbac.decorator.spec.ts` "evaluates arbac
 * on non-HTTP event kinds" for the regression test that gated the de-cache.
 *
 * `setControllerContext` is invoked exactly once per event dispatch in moost
 * (`defineMoostEventHandler` and the controller-binding startup path), so the
 * `(controller, method)` tuple feeding `resource`/`action`/`isPublic` is
 * stable for the lifetime of one `ctx` — making the cached bindings safe to
 * re-hand-out for every `useArbac()` call within the same event.
 */
const bindingsCache = new WeakMap<EventContext, ArbacBindings>();

/**
 * Composable for ARBAC utilities within Moost handlers and interceptors.
 *
 * Exposes scope read/write, lazy `evaluate`, and the resolved
 * resource/action/public flags derived from the current controller +
 * method metadata.
 *
 * Bindings are memoized per `EventContext` via a WeakMap keyed on the ctx
 * object itself — see {@link bindingsCache} for the rationale and the
 * parent-chain leak this side-steps. Read/write scope state still goes
 * through `arbacScopesKey` directly so it lives on the per-event slot.
 */
export const useArbac = (ctx?: EventContext): ArbacBindings => {
  const _ctx = ctx ?? current();
  let bindings = bindingsCache.get(_ctx);
  if (bindings) return bindings;
  bindings = _useArbacFactory(_ctx);
  bindingsCache.set(_ctx, bindings);
  return bindings;
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
