import {
  parseRateLimitRule,
  RateLimiter,
  type RateLimitRule,
  type RateLimitRuleInput,
} from "@aooth/auth";
import type { EventContext } from "@wooksjs/event-core";
import { current, eventTypeKey } from "@wooksjs/event-core";
import { HttpError, useRequest, useResponse } from "@wooksjs/event-http";
import {
  defineBeforeInterceptor,
  type TInterceptorDef,
  TInterceptorPriority,
  useControllerContext,
} from "moost";

import { useAuth } from "../auth.composables";
import { getRateLimitSubject, rateLimitDecisionKey } from "./composables";
import type { RateLimitKeyStrategy, TRateLimitMeta } from "./mate";

export interface RateLimitInterceptorOptions {
  /**
   * The shared limiter (wire your `RateLimitStoreRedis` here). When omitted,
   * a memory-store `RateLimiter` is created ONCE per factory call — stable
   * across requests, but single-process and private to this interceptor
   * pair. Pass an explicit limiter for anything beyond zero-config dev.
   */
  limiter?: RateLimiter;
  /**
   * App-wide default rules applied to EVERY http route without its own
   * `@RateLimit(...)` metadata. Opt out per-route with `@RateLimit(false)`.
   */
  rules?: RateLimitRuleInput[];
  /** Default key strategy for routes whose `@RateLimit` doesn't set one. Default: `'ip'`. */
  key?: RateLimitKeyStrategy;
  /** Trust `x-forwarded-for` for the client IP (behind a proxy). Default: `false`. */
  trustProxy?: boolean;
  /** Emit draft `RateLimit-*` headers on every response of a limited route. Default: `true`. */
  headers?: boolean;
  /** App-wide default 429 message template. */
  message?: string;
}

/**
 * Everything about a route that is static across requests, resolved from
 * metadata once on the first hit and memoized per controller class + method.
 * `null` = the route opted out or has no rules — nothing to enforce.
 */
interface RouteConfig {
  rules: RateLimitRule[];
  /** `'auto'` is normalized to `'user'` here — one comparison downstream. */
  keyStrategy: Exclude<RateLimitKeyStrategy, "auto">;
  /** True for any NAMED subject keying — the route belongs to the post-guard phase. */
  postGuardKeyed: boolean;
  scope: string;
  defaultMessage?: string;
  /** Precomputed `RateLimit-Policy` value — constant per route. */
  policyHeader: string;
}

/**
 * Global interceptor PAIR enforcing `@RateLimit` metadata (RL.spec.md §5.2)
 * — register with spread:
 *
 * ```ts
 * app.applyGlobalInterceptors(
 *   authGuardInterceptor({ ... }),
 *   ...rateLimitInterceptors({ limiter, trustProxy: true }),
 * )
 * ```
 *
 * Two phases, because the primary target is public endpoints and
 * `authGuardInterceptor` is NOT free there — with any `Authorization`
 * header present it runs full credential validation before tolerating the
 * failure on `@Public()` routes:
 *
 *  - `BEFORE_GUARD` phase owns routes whose effective key strategy is
 *    `'ip'` or a custom resolver — floods are rejected before any
 *    token/credential work.
 *  - `AFTER_GUARD` phase owns `'user'` / `'auto'` keyed routes — those need
 *    the auth context `useAuth()` reads, and by definition target
 *    authenticated traffic where the guard must run anyway.
 *
 * Ownership is static per route (from metadata/options), so exactly one
 * phase evaluates each event; the decision event-slot additionally guards
 * against double counting when the pair is also attached per-controller
 * (see {@link RateLimited}).
 *
 * On rejection: draft `RateLimit-*` headers + `Retry-After` are written to
 * the accumulated response (they survive the throw — wooks renders the error
 * onto the same `HttpResponse`), then `HttpError(429, message)` is thrown.
 */
export function rateLimitInterceptors(opts?: RateLimitInterceptorOptions): TInterceptorDef[] {
  // Parse eagerly — invalid default rules fail at registration, not per request.
  const defaultRules = opts?.rules?.map((r) => parseRateLimitRule(r));
  // Stable fallback created once per factory call (RL.spec.md §5.2) — never
  // per event, which would silently give every request a fresh empty budget.
  const limiter = opts?.limiter ?? new RateLimiter();
  const emitHeaders = opts?.headers ?? true;
  const ipOpts = { trustProxy: opts?.trustProxy ?? false };

  // Route metadata is static, so the resolved config is memoized per
  // controller class + method — after the first hit each request pays one
  // WeakMap + Map lookup instead of two Mate metadata walks per phase.
  const routeConfigs = new WeakMap<object, Map<string, RouteConfig | null>>();

  const resolveRouteConfig = (cc: ReturnType<typeof useControllerContext>): RouteConfig | null => {
    const ctor = cc.getController().constructor;
    const method = String(cc.getMethod());
    let byMethod = routeConfigs.get(ctor);
    if (!byMethod) {
      byMethod = new Map();
      routeConfigs.set(ctor, byMethod);
    }
    const cached = byMethod.get(method);
    if (cached !== undefined) return cached;

    const cMeta = cc.getControllerMeta<TRateLimitMeta>();
    const mMeta = cc.getMethodMeta<TRateLimitMeta>();
    let config: RouteConfig | null = null;
    const disabled = mMeta?.rateLimitDisabled ?? cMeta?.rateLimitDisabled ?? false;
    // Method-level rules replace class-level; class-level covers methods
    // without their own; interceptor defaults cover undecorated routes.
    const rules = mMeta?.rateLimitRules ?? cMeta?.rateLimitRules ?? defaultRules;
    if (!disabled && rules && rules.length > 0) {
      const metaOpts = mMeta?.rateLimitOptions ?? cMeta?.rateLimitOptions;
      const rawKey = metaOpts?.key ?? opts?.key ?? "ip";
      const keyStrategy = rawKey === "auto" ? "user" : rawKey;
      config = {
        rules,
        keyStrategy,
        postGuardKeyed: typeof keyStrategy === "string" && keyStrategy !== "ip",
        scope: metaOpts?.id ?? `${ctor.name}.${method}`,
        ...((metaOpts?.message ?? opts?.message) !== undefined && {
          defaultMessage: metaOpts?.message ?? opts?.message,
        }),
        policyHeader: rules
          .map((p) => `${p.limit};w=${Math.max(1, Math.round(p.window / 1000))}`)
          .join(", "),
      };
    }
    byMethod.set(method, config);
    return config;
  };

  const evaluate = async (phase: "pre" | "post"): Promise<void> => {
    const ctx = current();
    if (ctx.get(eventTypeKey) !== "http") return;
    if (ctx.has(rateLimitDecisionKey)) return; // another registration already evaluated

    const config = resolveRouteConfig(useControllerContext(ctx));
    if (!config) return;
    if (config.postGuardKeyed !== (phase === "post")) return; // the other phase owns this route

    const subject = await resolveSubject(config.keyStrategy, ipOpts, ctx);
    const decision = await limiter.check(config.scope, subject, config.rules, {
      ...(config.defaultMessage !== undefined && { defaultMessage: config.defaultMessage }),
    });
    ctx.set(rateLimitDecisionKey, decision);

    const response = useResponse(ctx);
    if (emitHeaders) {
      response.setHeader("ratelimit-limit", String(decision.limit));
      response.setHeader("ratelimit-remaining", String(decision.remaining));
      response.setHeader("ratelimit-reset", String(Math.ceil(decision.resetAfterMs / 1000)));
      response.setHeader("ratelimit-policy", config.policyHeader);
    }

    if (!decision.allowed) {
      response.setHeader("retry-after", String(Math.ceil(decision.resetAfterMs / 1000)));
      throw new HttpError(429, decision.message ?? "Too many requests");
    }
  };

  return [
    defineBeforeInterceptor(() => evaluate("pre"), TInterceptorPriority.BEFORE_GUARD),
    defineBeforeInterceptor(() => evaluate("post"), TInterceptorPriority.AFTER_GUARD),
  ];
}

async function resolveSubject(
  strategy: Exclude<RateLimitKeyStrategy, "auto">,
  ipOpts: { trustProxy: boolean },
  ctx: EventContext,
): Promise<string> {
  if (typeof strategy === "function") return await strategy();
  if (strategy !== "ip") {
    // Named subject — the slot (written via `setRateLimitSubject` by a
    // custom IAM / tenant resolver at GUARD priority) is read FIRST, so an
    // explicit write always wins over the built-in derivations below,
    // regardless of guard registration order.
    const subject = getRateLimitSubject(strategy, ctx);
    if (subject !== undefined) return subject;
    // Built-in kinds derive lazily from the auth context — only routes
    // actually keyed by them pay this read.
    const auth =
      strategy === "user" || strategy === "session" ? useAuth(ctx).getAuthContext() : null;
    if (strategy === "user" && auth?.userId !== undefined) return `u:${auth.userId}`;
    if (strategy === "session" && auth?.sessionId !== undefined) return `s:${auth.sessionId}`;
    // Nobody populated the subject (anonymous caller on `'user'`, or a
    // misconfigured custom kind) — fall back to the per-IP budget rather
    // than lumping everyone into one bucket.
  }
  return `ip:${useRequest(ctx).getIp(ipOpts)}`;
}
