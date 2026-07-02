import type { RateLimitRule } from "@aooth/auth";
import type { Mate, TMateParamMeta, TMoostMetadata } from "moost";
import { getMoostMate } from "moost";

/**
 * Caller-identity strategy for a rate-limited route (RL.spec.md §5.3):
 *  - `'ip'` — client IP (the public-endpoint mode; honors `trustProxy`).
 *    Evaluated PRE-guard — floods rejected before credential work.
 *  - any other string — a NAMED SUBJECT, looked up in the per-event
 *    subjects slot (see `setRateLimitSubject`) and evaluated POST-guard so
 *    GUARD-priority writers have run. When the slot is empty, `'user'` and
 *    `'session'` (per login/device) derive from the auth context; anything
 *    unresolved falls back to the IP budget. `'auto'` is an alias of
 *    `'user'`. Apps supply their own kinds (`'tenant'`, `'apiKey'`, …) via
 *    `setRateLimitSubject`.
 *  - custom function — runs inside the event context PRE-guard; must be
 *    self-sufficient (it cannot read what GUARD-priority code sets).
 */
export type RateLimitKeyStrategy =
  | "ip"
  | "user"
  | "auto"
  | "session"
  // (string & {}) keeps literal autocomplete while accepting any subject kind
  | (string & {})
  | (() => string | Promise<string>);

/** Trailing options object accepted by `@RateLimit(...rules, opts)`. */
export interface RateLimitDecoratorOptions {
  /** Overrides the interceptor-level default key strategy for this route. */
  key?: RateLimitKeyStrategy;
  /** Default 429 message template for rules without an inline `| message`. */
  message?: string;
  /**
   * Bucket id — handlers sharing an id share counters. Default scope is
   * `<ControllerClass>.<methodName>` (per-handler isolation).
   */
  id?: string;
}

/**
 * Rate-limit metadata written by `@RateLimit()` and read by
 * `rateLimitInterceptors`. Merged into `TMoostMetadata` so other moost-aware
 * tooling sees it.
 */
export interface TRateLimitMeta {
  /** Rules normalized at decoration time — bad grammar fails at boot. */
  rateLimitRules?: RateLimitRule[];
  rateLimitOptions?: RateLimitDecoratorOptions;
  /** `@RateLimit(false)` — opt this route out of interceptor-level default rules. */
  rateLimitDisabled?: boolean;
}

declare module "moost" {
  interface TMoostMetadata extends TRateLimitMeta {}
}

type RateLimitMate = Mate<
  TMoostMetadata & { params: TMateParamMeta[] },
  TMoostMetadata & { params: TMateParamMeta[] }
>;

export function getRateLimitMate(): RateLimitMate {
  return getMoostMate<TRateLimitMeta, TRateLimitMeta>() as RateLimitMate;
}
