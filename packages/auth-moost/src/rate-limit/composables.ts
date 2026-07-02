import type { RateLimitDecision } from "@aooth/auth";
import type { EventContext } from "@wooksjs/event-core";
import { current, key } from "@wooksjs/event-core";

/**
 * Internal: the decision for this event, written by `rateLimitInterceptors`.
 * Its presence also serves as the "already evaluated" marker that prevents
 * double counting when the interceptor pair is registered more than once
 * (global + `@Intercept`) — moost runs `before` hooks sequentially, so a
 * duplicate instance always observes the first one's write.
 */
export const rateLimitDecisionKey = key<RateLimitDecision>("aooth.rateLimit.decision");

export interface RateLimitBindings {
  /**
   * The decision the interceptor computed for this event, or `null` when the
   * route has no rules (or the interceptors are not installed).
   */
  decision: RateLimitDecision | null;
}

/**
 * Read the current event's rate-limit state. A plain function (not a cached
 * wook) — it's a single slot read, and workflow child events inherit the
 * HTTP parent's slot transparently.
 */
export function useRateLimit(ctx: EventContext = current()): RateLimitBindings {
  return {
    decision: ctx.has(rateLimitDecisionKey) ? ctx.get(rateLimitDecisionKey) : null,
  };
}
