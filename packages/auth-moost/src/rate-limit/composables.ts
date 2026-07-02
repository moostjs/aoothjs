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

/**
 * Internal: named rate-limit subjects for this event — subject kind
 * (`'user'`, `'tenant'`, …) → resolved caller identity, written via
 * {@link setRateLimitSubject} and read by the post-guard rate-limit phase.
 */
export const rateLimitSubjectsKey = key<Record<string, string>>("aooth.rateLimit.subjects");

/**
 * Supply the rate-limit subject for a named key strategy — the seam for
 * custom IAMs / tenant resolvers. Call from GUARD-priority (or earlier)
 * code; the value is used VERBATIM as the counter subject (include your own
 * prefix, e.g. `iam:<sub>`) and always wins over the built-in `user` /
 * `session` derivations. Full contract: docs `/moost/rate-limit`.
 */
export function setRateLimitSubject(
  kind: string,
  subject: string,
  ctx: EventContext = current(),
): void {
  const subjects = ctx.has(rateLimitSubjectsKey) ? ctx.get(rateLimitSubjectsKey) : {};
  subjects[kind] = subject;
  ctx.set(rateLimitSubjectsKey, subjects);
}

/** Read a named rate-limit subject set for this event (or `undefined`). */
export function getRateLimitSubject(
  kind: string,
  ctx: EventContext = current(),
): string | undefined {
  return ctx.has(rateLimitSubjectsKey) ? ctx.get(rateLimitSubjectsKey)[kind] : undefined;
}

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
