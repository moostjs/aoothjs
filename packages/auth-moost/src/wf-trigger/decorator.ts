import {
  defineAfterInterceptor,
  getMoostMate,
  Intercept,
  TInterceptorPriority,
  useControllerContext,
} from "moost";

import { WfTriggerProvider, type WfTriggerOpts } from "./provider";

export type { WfTriggerOpts };

/** Method metadata written by `@WfTrigger(opts)`: the route's trigger options. */
interface TWfTriggerMeta {
  wfTrigger?: WfTriggerOpts;
}

/**
 * The ONE trigger interceptor every `@WfTrigger` attaches. moost dedupes
 * interceptors by handler reference, so a subclass override decorated again
 * keeps a single trigger; the options ride on the method's metadata, where
 * the override's own value replaces the inherited one.
 */
const wfTriggerInterceptor = defineAfterInterceptor(async (response, reply) => {
  if ((await response) !== undefined) return;
  const cc = useControllerContext();
  const opts = cc.getMethodMeta<TWfTriggerMeta>()?.wfTrigger ?? {};
  const provider = await cc.instantiate(WfTriggerProvider);
  reply(await provider.handle(opts));
}, TInterceptorPriority.INTERCEPTOR);

/**
 * Method decorator that turns a handler into a workflow trigger.
 *
 * The handler may have an empty body — the interceptor's after-phase invokes
 * `WfTriggerProvider.handle()` when the handler returns `undefined`. Subclasses
 * that need to short-circuit (e.g. emit a custom error response) just return a
 * non-undefined value from the overridden handler and the trigger is skipped.
 *
 * `opts` also takes the workflow-trigger hooks (`around`, `beforePersist`,
 * `renderEnvelope`, `restoreOnError`, `maxRestores` — see `WfTriggerHooks`);
 * each one set here replaces the provider's `triggerHooks()` hook of the
 * same name for this route.
 *
 * Under `@Inherit()`, re-decorating an overridden handler REPLACES the base
 * route's options as a whole (e.g. a narrower `allow` is the only list
 * checked) — the trigger still runs once per request. An override without
 * its own `@WfTrigger` keeps the base options.
 *
 * The single `useControllerContext().instantiate(...)` call is the one
 * documented escape hatch: interceptors are functions, not classes, so there's
 * no ctor to inject into. Every class still uses constructor injection.
 */
export const WfTrigger = (opts: WfTriggerOpts = {}): MethodDecorator => {
  const intercept = Intercept(wfTriggerInterceptor);
  return (target, key, descriptor) => {
    // moost dedupes interceptors only across inheritance levels, so a method
    // decorated twice attaches the trigger once: only when its OWN metadata
    // has no options yet (the top decorator's options win).
    let first = false;
    getMoostMate<TWfTriggerMeta, TWfTriggerMeta>().decorate((meta: TWfTriggerMeta) => {
      first = meta.wfTrigger === undefined;
      meta.wfTrigger = opts;
      return meta;
    })(target, key, descriptor);
    if (first) intercept(target, key, descriptor);
  };
};
