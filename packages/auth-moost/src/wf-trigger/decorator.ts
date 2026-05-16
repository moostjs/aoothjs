import type { WfOutletTokenConfig } from "@moostjs/event-wf";
import {
  defineAfterInterceptor,
  Intercept,
  TInterceptorPriority,
  useControllerContext,
} from "moost";

import { WfTriggerProvider } from "./provider";

export interface WfTriggerOpts {
  /** Whitelist of workflow ids the trigger may start/resume. Defaults to the provider's setting. */
  allow?: string[];
  /** Per-endpoint token wire override. Defaults to the provider's wire (`{read:['body','query','cookie'], write:'body', name:'wfs'}`). */
  token?: WfOutletTokenConfig;
}

/**
 * Method decorator that turns a handler into a workflow trigger.
 *
 * The handler may have an empty body — the interceptor's after-phase invokes
 * `WfTriggerProvider.handle()` when the handler returns `undefined`. Subclasses
 * that need to short-circuit (e.g. emit a custom error response) just return a
 * non-undefined value from the overridden handler and the trigger is skipped.
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
