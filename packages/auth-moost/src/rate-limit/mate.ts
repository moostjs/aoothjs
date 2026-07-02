import type { RateLimitRule } from "@aooth/auth";
import type { Mate, TMateParamMeta, TMoostMetadata } from "moost";
import { getMoostMate } from "moost";

/**
 * Caller-identity strategy for a rate-limited route (RL.spec.md §5.3):
 *  - `'ip'` — client IP (the public-endpoint mode; honors `trustProxy`)
 *  - `'user'` / `'auto'` — authenticated user id, falling back to IP for
 *    anonymous callers (both spellings share one behavior; `'auto'` reads
 *    better on mixed public/authed routes)
 *  - custom function — runs inside the event context, so any composable is
 *    usable (tenant id, API key, `userId + ip`, …)
 */
export type RateLimitKeyStrategy = "ip" | "user" | "auto" | (() => string | Promise<string>);

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
