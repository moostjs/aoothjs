import {
  defineAfterInterceptor,
  Intercept,
  TInterceptorPriority,
  useControllerContext,
} from "moost";

import { WfTriggerProvider, type WfTriggerOpts } from "./provider";

export type { WfTriggerOpts };

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
 * The single `useControllerContext().instantiate(...)` call is the one
 * documented escape hatch: interceptors are functions, not classes, so there's
 * no ctor to inject into. Every class still uses constructor injection.
 */
export const WfTrigger = (opts: WfTriggerOpts = {}) =>
  Intercept(
    defineAfterInterceptor(async (response, reply) => {
      if ((await response) !== undefined) return;
      const provider = await useControllerContext().instantiate(WfTriggerProvider);
      reply(await provider.handle(opts));
    }, TInterceptorPriority.INTERCEPTOR),
  );
