import { parseRateLimitRule, type RateLimitRuleInput } from "@aooth/auth";
import { Intercept } from "moost";

import { rateLimitInterceptors, type RateLimitInterceptorOptions } from "./interceptor";
import { getRateLimitMate, type RateLimitDecoratorOptions } from "./mate";

/**
 * Declares rate-limit rules for a controller method (or every method of a
 * controller, when applied at class level — method-level metadata replaces
 * class-level). Metadata-only: enforcement happens in the globally registered
 * `rateLimitInterceptors(...)` (RL.spec.md §5) or a per-controller
 * {@link RateLimited}.
 *
 * ```ts
 * RateLimit('6/5m | Too many login attempts, please wait {{delta}}')
 * RateLimit('1/1s', '30/1m')          // stacked windows, one budget each
 * RateLimit('100/1h', { key: 'user' }) // per-user budget on an authed route
 * RateLimit(false)                     // opt out of interceptor-level default rules
 * ```
 *
 * Rules are parsed eagerly, so a bad rule string throws at decoration
 * (boot) time, not per request.
 */
export function RateLimit(disabled: false): ClassDecorator & MethodDecorator;
export function RateLimit(
  ...rulesAndOpts: [RateLimitRuleInput, ...Array<RateLimitRuleInput | RateLimitDecoratorOptions>]
): ClassDecorator & MethodDecorator;
export function RateLimit(
  ...args: [false] | Array<RateLimitRuleInput | RateLimitDecoratorOptions>
): ClassDecorator & MethodDecorator {
  const mate = getRateLimitMate();
  if (args.length === 1 && args[0] === false) {
    return mate.decorate("rateLimitDisabled", true);
  }

  const inputs = [...args] as Array<RateLimitRuleInput | RateLimitDecoratorOptions>;
  let options: RateLimitDecoratorOptions | undefined;
  const last = inputs[inputs.length - 1];
  // An object rule always carries `limit`; a trailing object without it is the options bag.
  if (typeof last === "object" && last !== null && !("limit" in last)) {
    options = inputs.pop() as RateLimitDecoratorOptions;
  }
  if (inputs.length === 0) {
    throw new Error("@RateLimit requires at least one rule (or the literal `false` to opt out)");
  }
  const rules = (inputs as RateLimitRuleInput[]).map((r) => parseRateLimitRule(r));

  return mate.decorate((meta) => {
    meta.rateLimitRules = rules;
    if (options) meta.rateLimitOptions = options;
    return meta;
  });
}

/**
 * Decorator-factory sugar for attaching the `rateLimitInterceptors(opts)`
 * PAIR to a specific controller or method instead of globally — the
 * `AuthGuarded` counterpart. Attaching the pair (not one phase) matters:
 * dropping the pre-guard def loses flood protection for ip-keyed routes,
 * dropping the post-guard def silently disables `key: 'user'` routes.
 */
export function RateLimited(opts?: RateLimitInterceptorOptions): ClassDecorator & MethodDecorator {
  const [pre, post] = rateLimitInterceptors(opts);
  const interceptPre = Intercept(pre);
  const interceptPost = Intercept(post);
  return ((target, key, descriptor) => {
    interceptPre(target, key, descriptor);
    interceptPost(target, key, descriptor);
  }) as ClassDecorator & MethodDecorator;
}
