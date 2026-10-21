import {
  parseRateLimitRule,
  pickGoverning,
  type RateLimitDecision,
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
import { getRateLimitSubject, rateLimitDecisionKey, rateLimitPhasesKey } from "./composables";
import type { RateLimitKeyStrategy, TRateLimitMeta, TRateLimitPolicy } from "./mate";

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
 * One policy of a route (one `@RateLimit(...)` declaration, or the
 * interceptor-level defaults), static across requests.
 */
interface PolicyConfig {
  rules: RateLimitRule[];
  /** `'auto'` is normalized to `'user'` here — one comparison downstream. */
  keyStrategy: Exclude<RateLimitKeyStrategy, "auto">;
  scope: string;
  defaultMessage?: string;
  /** Precomputed `RateLimit-Policy` entry — constant per policy. */
  policyHeader: string;
}

/**
 * Everything about a route that is static across requests, resolved from
 * metadata once on the first hit and memoized per controller class + method.
 * `null` = the route opted out or has no rules — nothing to enforce.
 */
interface RouteConfig {
  /** Policies owned by the pre-guard phase (`'ip'` / custom-function keys). */
  pre: PolicyConfig[];
  /** Policies owned by the post-guard phase (NAMED subject keys — need the auth context). */
  post: PolicyConfig[];
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
 * Ownership is static per policy (from metadata/options): a route whose
 * stacked policies mix both kinds is evaluated by both phases, each checking
 * its own policies. A per-event phase marker guards against double counting
 * when the pair is also attached per-controller (see {@link RateLimited}).
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
    // Method-level policies replace class-level; class-level covers methods
    // without their own; interceptor defaults cover undecorated routes.
    const declared: TRateLimitPolicy[] | undefined =
      mMeta?.rateLimitPolicies ??
      cMeta?.rateLimitPolicies ??
      (defaultRules && defaultRules.length > 0 ? [{ rules: defaultRules }] : undefined);
    if (!disabled && declared && declared.length > 0) {
      const baseScope = `${ctor.name}.${method}`;
      const route: RouteConfig = { pre: [], post: [] };
      for (const [i, policy] of declared.entries()) {
        const rawKey = policy.options?.key ?? opts?.key ?? "ip";
        const keyStrategy = rawKey === "auto" ? "user" : rawKey;
        const message = policy.options?.message ?? opts?.message;
        const postGuardKeyed = typeof keyStrategy === "string" && keyStrategy !== "ip";
        route[postGuardKeyed ? "post" : "pre"].push({
          rules: policy.rules,
          keyStrategy,
          // Each stacked policy gets its own bucket unless it names one.
          scope: policy.options?.id ?? (i === 0 ? baseScope : `${baseScope}#${i}`),
          ...(message !== undefined && { defaultMessage: message }),
          policyHeader: policy.rules
            .map((p) => `${p.limit};w=${Math.max(1, Math.round(p.window / 1000))}`)
            .join(", "),
        });
      }
      config = route;
    }
    byMethod.set(method, config);
    return config;
  };

  const evaluate = async (phase: "pre" | "post"): Promise<void> => {
    const ctx = current();
    if (ctx.get(eventTypeKey) !== "http") return;
    // Another registration of the pair already evaluated this phase.
    const done = ctx.has(rateLimitPhasesKey) ? ctx.get(rateLimitPhasesKey) : [];
    if (done.includes(phase)) return;

    const config = resolveRouteConfig(useControllerContext(ctx));
    if (!config) return;
    const owned = config[phase];
    if (owned.length === 0) return; // the other phase owns this route
    ctx.set(rateLimitPhasesKey, [...done, phase]);

    // Every owned policy is checked (each counts its own hit) before deciding.
    const decisions: RateLimitDecision[] = [];
    const headers: string[] = [];
    for (const policy of owned) {
      const subject = await resolveSubject(policy.keyStrategy, ipOpts, ctx);
      if (subject == null) continue; // the key function skipped this request
      decisions.push(
        await limiter.check(policy.scope, subject, policy.rules, {
          ...(policy.defaultMessage !== undefined && { defaultMessage: policy.defaultMessage }),
        }),
      );
      headers.push(policy.policyHeader);
    }
    if (ctx.has(rateLimitDecisionKey)) decisions.unshift(ctx.get(rateLimitDecisionKey));
    if (decisions.length === 0) return;
    const decision = pickGoverning(decisions, (d) => !d.allowed);
    ctx.set(rateLimitDecisionKey, decision);

    const response = useResponse(ctx);
    if (emitHeaders) {
      const prior = response.getHeader("ratelimit-policy");
      if (typeof prior === "string" && prior) headers.unshift(prior);
      response.setHeader("ratelimit-limit", String(decision.limit));
      response.setHeader("ratelimit-remaining", String(decision.remaining));
      response.setHeader("ratelimit-reset", String(Math.ceil(decision.resetAfterMs / 1000)));
      response.setHeader("ratelimit-policy", headers.join(", "));
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
): Promise<string | null | undefined> {
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
