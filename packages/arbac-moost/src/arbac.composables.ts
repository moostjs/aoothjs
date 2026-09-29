import { HttpError } from "@moostjs/event-http";
import type { EventContext } from "@wooksjs/event-core";
import { current, key } from "@wooksjs/event-core";
import { useControllerContext } from "moost";

import { arbacIdsFromMeta, evaluateArbac } from "./arbac.evaluate";
import type { TArbacMeta } from "./arbac.mate";
import type { VisibilityTableSource } from "./db/visibility";

/**
 * Writable slot holding the evaluated scopes for the current event.
 *
 * Module-level `key()` per the `@wooksjs/event-core` slot system. The
 * authorize interceptor calls `setScopes(...)` after a successful evaluate;
 * downstream `@ArbacScopes()` resolvers read it back from the same event context.
 */
const arbacScopesKey = key<unknown[] | undefined>("arbac.scopes");

/**
 * The scopes cached for the current event (`undefined` before the authorize
 * interceptor / `setScopes` ran). A direct slot read — no controller
 * metadata resolution — for per-field hot paths like `hasField`; use
 * {@link useArbac} for `evaluate` / `setScopes`.
 *
 * `TScope` is a caller-side type witness (see `evaluate` below).
 */
// oxlint-disable-next-line typescript/no-unnecessary-type-parameters
export function getArbacScopes<TScope extends object>(ctx?: EventContext): TScope[] | undefined {
  const c = ctx ?? current();
  return c.has(arbacScopesKey) ? (c.get(arbacScopesKey) as TScope[] | undefined) : undefined;
}

/** Options of `useArbac().evaluate()` / `evaluateOrThrow()`. */
export interface ArbacEvaluateOptions {
  /** Resource to evaluate; defaults to the current handler's. */
  resource?: string;
  /** Action to evaluate; defaults to the current handler's. */
  action?: string;
  /**
   * The atscript-db readable whose schema a credential-attenuation
   * conjunction uses to subtract nested exclusions exactly — pass the
   * related table when evaluating a grant on it (e.g. a `$with` target).
   * Defaults to the current controller's `readable`.
   *
   * @since 0.1.72
   */
  table?: VisibilityTableSource;
}

interface ArbacBindings {
  getScopes: <TScope extends object>() => TScope[] | undefined;
  setScopes: <TScope extends object>(scope: TScope[] | undefined) => void;
  evaluate: <TScope extends object>(
    opts?: ArbacEvaluateOptions,
  ) => Promise<{
    allowed: boolean;
    scopes?: TScope[];
    userId: string;
  }>;
  /**
   * Throw-on-deny variant of {@link evaluate}. Returns the same shape on
   * `allowed: true`; throws `HttpError(403)` otherwise.
   *
   * Use this in handlers/steps that want a hard short-circuit on deny.
   * Use {@link evaluate} when you need to inspect `allowed` (e.g. to merge
   * with another policy, to filter UI metadata, or to fall through to a
   * different authorization path).
   */
  evaluateOrThrow: <TScope extends object>(
    opts?: ArbacEvaluateOptions,
  ) => Promise<{ allowed: true; scopes?: TScope[]; userId: string }>;
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
 * Resource/action/isPublic are recomputed on every call because WF events
 * dispatch multiple step handlers under one `EventContext` — each step
 * mutates the controller-context method via `setControllerContext`, so any
 * per-ctx memo would lock in the first dispatched method's metadata (e.g.
 * the `@Public()` WF_FLOW body) and incorrectly bypass ARBAC on the gated
 * step handlers. Scope read/write goes through `arbacScopesKey` directly
 * so it still lives on the per-event slot.
 */
export const useArbac = (_ctx?: EventContext): ArbacBindings => {
  const ctx = _ctx ?? current();
  const cc = useControllerContext(ctx);

  const getScopes = <TScope extends object>(): TScope[] | undefined => getArbacScopes<TScope>(ctx);

  const setScopes = <TScope extends object>(scope: TScope[] | undefined): void => {
    ctx.set(arbacScopesKey, scope);
  };

  const cMeta = cc.getControllerMeta<TArbacMeta>();
  const mMeta = cc.getMethodMeta<TArbacMeta>();

  // Strict-by-default per ACT-04: undecorated controllers fall back to the
  // class name as resource and the method name as action, so a globally
  // wired `arbacAuthorizeInterceptor` denies access unless the user holds a
  // matching grant (or the controller/method is `@Public()`). Class-level
  // `@ArbacAction` is honoured so a workflow consumer can pin a single action
  // id for every step event (e.g. `@ArbacResource('auth')
  // @ArbacAction('admin.invite')` on the workflow class).
  const { resource, action } = arbacIdsFromMeta(
    cMeta,
    mMeta,
    cc.getController(),
    cc.getMethod() ?? "",
  );
  const isPublic = mMeta?.arbacPublic || cMeta?.arbacPublic || false;

  // TScope is a deliberate caller-side type witness: it appears only in the
  // return type so callers (`arbac.evaluate<ArbacDbScope>()`) name the scope
  // shape they expect without having to cast `.scopes` at every use site.
  // oxlint-disable-next-line typescript/no-unnecessary-type-parameters
  const evaluate = async <TScope extends object>(
    opts?: ArbacEvaluateOptions,
  ): Promise<{ allowed: boolean; scopes?: TScope[]; userId: string }> => {
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
    return evaluateArbac<TScope>(ctx, {
      resource: effectiveResource,
      action: effectiveAction,
      table: opts?.table,
    });
  };

  // See `evaluate` above for the type-witness rationale.
  // oxlint-disable-next-line typescript/no-unnecessary-type-parameters
  const evaluateOrThrow = async <TScope extends object>(
    opts?: ArbacEvaluateOptions,
  ): Promise<{ allowed: true; scopes?: TScope[]; userId: string }> => {
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
