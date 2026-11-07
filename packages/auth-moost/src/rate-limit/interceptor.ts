import {
  parseRateLimitRule,
  pickGoverning,
  RATE_LIMIT_MESSAGES,
  type RateLimitDecision,
  RateLimiter,
  type RateLimitRule,
  type RateLimitRuleInput,
} from "@aooth/auth";
import type { EventContext } from "@wooksjs/event-core";
import { current, eventTypeKey, tryGetCurrent } from "@wooksjs/event-core";
import { useRequest, useResponse } from "@wooksjs/event-http";
import {
  defineBeforeInterceptor,
  formatMessage,
  registerMessages,
  type TInterceptorDef,
  TInterceptorPriority,
  useControllerContext,
} from "moost";

import { readPresentedRefreshToken, useAuth } from "../auth.composables";
import {
  getRateLimitSubject,
  rateLimitDecisionKey,
  rateLimitPhasesKey,
  type RateLimitRuntime,
  rateLimitRuntimeKey,
} from "./composables";
import { tokenSubject } from "./subjects";
import { type BundledRateLimit, declaredRateLimitIds, isDeclaredRateLimitId } from "./registry";
import type { RateLimitKeyStrategy, TRateLimitMeta, TRateLimitPolicy } from "./mate";
import { codedHttpError } from "../http-messages";

registerMessages(RATE_LIMIT_MESSAGES);

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
  /**
   * @deprecated Set `trustProxy` (and `proxyHeaders`) on the HTTP app instead;
   * removed in 0.3. Still honoured, with a one-time warning: `true` trusts
   * exactly one proxy hop, read from the header family the app's
   * `proxyHeaders` names. Without it, the client IP is the one the HTTP app
   * resolves (`useRequest().getIp()`).
   */
  trustProxy?: boolean;
  /** Emit draft `RateLimit-*` headers on every response of a limited route. Default: `true`. */
  headers?: boolean;
  /**
   * Re-tune declared policies without redeclaring their routes, by policy id
   * (the `id` a `@RateLimit` names, or a bundled id such as `aooth.refresh` /
   * `aooth.send`): new rules replace the declared ones — the key strategy, id
   * and message stay — and `false` switches the policy off. E.g.
   * `{ "aooth.refresh": "300/5m", "aooth.refresh-token": false }`. Parsed at
   * registration, like `rules`; an id no policy declared throws.
   */
  policies?: Record<string, RateLimitRuleInput | RateLimitRuleInput[] | false>;
  /**
   * App-wide default 429 message template (placeholders `{{limit}}`,
   * `{{window}}`, `{{delta}}` humanized; `{limit}`, `{window}`, `{retryAfter}`
   * in seconds). Under a moost translator the body is translated by its
   * `RATE_LIMITED` code, which replaces this English text.
   */
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
 *   ...rateLimitInterceptors({ limiter }),
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
 * onto the same `HttpResponse`), then an `HttpError(429)` is thrown whose body
 * carries the rendered `message`, `code: "RATE_LIMITED"` and
 * `params: { policy, limit, window, retryAfter }` (seconds) — translate by code.
 */
export function rateLimitInterceptors(opts?: RateLimitInterceptorOptions): TInterceptorDef[] {
  // Parse eagerly — invalid default rules fail at registration, not per request.
  const defaultRules = opts?.rules?.map((r) => parseRateLimitRule(r));
  const overrides = new Map<string, RateLimitRule[] | false>();
  for (const [id, value] of Object.entries(opts?.policies ?? {})) {
    if (!isDeclaredRateLimitId(id)) {
      throw new Error(
        `rateLimitInterceptors: unknown policy id "${id}" in policies — known ids: ${declaredRateLimitIds().join(", ")}. Give a @RateLimit an { id } to re-tune it here (declare it before configuring).`,
      );
    }
    const rules = value === false ? false : Array.isArray(value) ? value : [value];
    if (rules !== false && rules.length === 0) {
      throw new Error(
        `rateLimitInterceptors: policies["${id}"] has no rules — pass false to switch it off`,
      );
    }
    overrides.set(id, rules && rules.map((r) => parseRateLimitRule(r)));
  }
  // Stable fallback created once per factory call (RL.spec.md §5.2) — never
  // per event, which would silently give every request a fresh empty budget.
  const limiter = opts?.limiter ?? new RateLimiter();
  const emitHeaders = opts?.headers ?? true;
  const trustProxy = opts?.trustProxy ?? false;
  if (opts?.trustProxy !== undefined) warnTrustProxyDeprecated();

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
        // Each stacked policy gets its own bucket unless it names one.
        const scope = policy.options?.id ?? (i === 0 ? baseScope : `${baseScope}#${i}`);
        const rules = effectiveRules(overrides, scope, policy.rules);
        if (!rules) continue;
        const rawKey = policy.options?.key ?? opts?.key ?? "ip";
        const keyStrategy = rawKey === "auto" ? "user" : rawKey;
        const message = policy.options?.message ?? opts?.message;
        const postGuardKeyed = typeof keyStrategy === "string" && keyStrategy !== "ip";
        route[postGuardKeyed ? "post" : "pre"].push({
          rules,
          keyStrategy,
          scope,
          ...(message !== undefined && { defaultMessage: message }),
          policyHeader: policyHeader(rules),
        });
      }
      config = route;
    }
    byMethod.set(method, config);
    return config;
  };

  const runtime: RateLimitRuntime = { limiter, overrides, trustProxy, emitHeaders };

  const evaluate = async (phase: "pre" | "post"): Promise<void> => {
    const ctx = current();
    if (ctx.get(eventTypeKey) !== "http") return;
    // Policies enforced from inside a handler (the auth workflow's sends) use
    // the same limiter and overrides — see `enforceRateLimit`.
    if (!ctx.has(rateLimitRuntimeKey)) ctx.set(rateLimitRuntimeKey, runtime);
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
      const subject = await resolveSubject(policy.keyStrategy, ctx);
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

    answerDecision(decision, headers, emitHeaders, ctx);
  };

  return [
    defineBeforeInterceptor(() => evaluate("pre"), TInterceptorPriority.BEFORE_GUARD),
    defineBeforeInterceptor(() => evaluate("post"), TInterceptorPriority.AFTER_GUARD),
  ];
}

async function resolveSubject(
  strategy: Exclude<RateLimitKeyStrategy, "auto">,
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
    if (strategy === "refresh-token") {
      // The presented refresh token — never the raw bearer secret, which would
      // otherwise sit in the counter store's keys. No token: skip the policy
      // (the refresh handler answers 401), rather than share an IP budget.
      const token = await readPresentedRefreshToken(ctx);
      return token === undefined ? null : tokenSubject(token);
    }
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
  return `ip:${requestClientIp(ctx)}`;
}

let warnedTrustProxy = false;

/** Warn once per process (at registration — no event yet) that the limiter's own `trustProxy` is deprecated. */
function warnTrustProxyDeprecated(): void {
  if (warnedTrustProxy) return;
  warnedTrustProxy = true;
  console.warn(
    "[aooth] rateLimitInterceptors({ trustProxy }) is deprecated — still honoured (one hop, " +
      "using the app's proxyHeaders); removed in 0.3. Set `trustProxy` on the HTTP app instead.",
  );
}

/**
 * Internal: the client IP of the current HTTP event — the single source of
 * every client IP aooth keys on (rate limits, one-time-code failure buckets,
 * session metadata, device binding). The IP the HTTP app resolves
 * (`useRequest().getIp()`, governed by the app's `trustProxy` /
 * `proxyHeaders`); with the deprecated `rateLimitInterceptors({ trustProxy:
 * true })` installed, wooks' one-hop resolution (`getIp({ trustProxy: true })`,
 * which reads the app's `proxyHeaders` family). `""` outside an HTTP event.
 */
export function requestClientIp(ctx: EventContext | undefined = tryGetCurrent()): string {
  if (!ctx) return "";
  try {
    const req = useRequest(ctx);
    const oneHop = ctx.has(rateLimitRuntimeKey) && ctx.get(rateLimitRuntimeKey).trustProxy;
    return oneHop ? req.getIp({ trustProxy: true }) : req.getIp();
  } catch {
    return "";
  }
}

/**
 * Write the decision's `RateLimit-*` headers (with `emitHeaders`) and, when it
 * rejects, `Retry-After` and the coded 429.
 */
function answerDecision(
  decision: RateLimitDecision,
  policyHeaders: string[],
  emitHeaders: boolean,
  ctx: EventContext,
): void {
  const response = useResponse(ctx);
  if (emitHeaders) {
    const prior = response.getHeader("ratelimit-policy");
    if (typeof prior === "string" && prior) policyHeaders.unshift(prior);
    response.setHeader("ratelimit-limit", String(decision.limit));
    response.setHeader("ratelimit-remaining", String(decision.remaining));
    response.setHeader("ratelimit-reset", String(Math.ceil(decision.resetAfterMs / 1000)));
    response.setHeader("ratelimit-policy", policyHeaders.join(", "));
  }
  if (!decision.allowed) {
    response.setHeader("retry-after", String(Math.ceil(decision.resetAfterMs / 1000)));
    throw codedHttpError(
      429,
      decision.code ?? "RATE_LIMITED",
      decision.message ?? formatMessage(RATE_LIMIT_MESSAGES.RATE_LIMITED, decision.params),
      decision.params,
    );
  }
}

/**
 * Internal: check a bundled policy from inside a handler — per client IP
 * unless `key` names another subject (e.g. `user:<id>`), with the limiter and
 * `policies` overrides of the installed `rateLimitInterceptors` (none
 * installed → nothing is enforced, like any `@RateLimit`). Over the limit it
 * throws the same coded 429 as the interceptors. Used by the auth workflow
 * for code and link sends (`aooth.send`, `aooth.send-user`).
 */
export async function enforceRateLimit(
  policy: BundledRateLimit,
  key?: string,
  ctx: EventContext | undefined = tryGetCurrent(),
): Promise<void> {
  if (!ctx?.has(rateLimitRuntimeKey)) return;
  const runtime = ctx.get(rateLimitRuntimeKey);
  const rules = effectiveRules(runtime.overrides, policy.id, policy.rules);
  if (!rules) return;
  const decision = await runtime.limiter.check(
    policy.id,
    key ?? `ip:${requestClientIp(ctx)}`,
    rules,
  );
  answerDecision(decision, [policyHeader(rules)], runtime.emitHeaders, ctx);
}

/** The rules of policy `id` after `policies` overrides — `false` when switched off. */
function effectiveRules(
  overrides: ReadonlyMap<string, RateLimitRule[] | false>,
  id: string,
  declared: RateLimitRule[],
): RateLimitRule[] | false {
  return overrides.get(id) ?? declared;
}

/** The draft `RateLimit-Policy` value of `rules` (`<limit>;w=<seconds>`, comma-joined). */
function policyHeader(rules: RateLimitRule[]): string {
  return rules.map((p) => `${p.limit};w=${Math.max(1, Math.round(p.window / 1000))}`).join(", ");
}
