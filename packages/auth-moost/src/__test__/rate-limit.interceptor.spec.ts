import type { Clock, RateLimitDecision, RateLimitStore } from "@aooth/auth";
import { RateLimiter, RateLimitStoreMemory } from "@aooth/auth";
import { current } from "@wooksjs/event-core";
import {
  createHttpApp,
  HttpError,
  useRequest,
  useResponse,
  type WooksHttp,
} from "@wooksjs/event-http";
import type { TInterceptorDef } from "moost";
import { getMoostMate } from "moost";
import { describe, expect, it, vi } from "vite-plus/test";
import { Wooks } from "wooks";

import { Public } from "../auth.decorator";
import "../auth.controller"; // declares the bundled policy ids
import { setRateLimitSubject, useRateLimit } from "../rate-limit/composables";
import { RateLimit, RateLimited } from "../rate-limit/decorator";
import { rateLimitInterceptors, requestClientIp } from "../rate-limit/interceptor";
import {
  Controller,
  prepareTestApp,
  type PreparedTestApp,
  TestHandler,
  withHandlerContext,
} from "./test-utils";

function fakeClock(start = 1_000_000_800_000): Clock & { advance(ms: number): void } {
  let t = start;
  return {
    now: () => t,
    advance(ms: number) {
      t += ms;
    },
  };
}

@Controller("rl")
class RlController {
  @TestHandler()
  @Public()
  @RateLimit("2/1m")
  publicRoute() {
    return "ok";
  }

  @TestHandler()
  @Public()
  @RateLimit("1/1m | Slow down, wait {{delta}} ({{limit}}/{{window}})", "10/1h")
  messaged() {
    return "ok";
  }

  @TestHandler()
  @RateLimit("2/1m", { key: "user" })
  userKeyed() {
    return "ok";
  }

  @TestHandler()
  @Public()
  @RateLimit("1/1m", { key: "tenant" })
  tenantKeyed() {
    return "ok";
  }

  @TestHandler()
  @RateLimit("1/1m", { key: "session" })
  sessionKeyed() {
    return "ok";
  }

  @TestHandler()
  @Public()
  @RateLimit("2/1m", { key: "refresh-token" })
  refreshKeyed() {
    return "ok";
  }

  @TestHandler()
  @Public()
  plain() {
    return "ok";
  }

  @TestHandler()
  @Public()
  @RateLimit(false)
  optedOut() {
    return "ok";
  }

  @TestHandler()
  @Public()
  @RateLimit("1/1m", { id: "shared-bucket" })
  sharedA() {
    return "ok";
  }

  @TestHandler()
  @Public()
  @RateLimit("1/1m", { id: "shared-bucket" })
  sharedB() {
    return "ok";
  }
}

@RateLimit("1/1m")
@Controller("rl-class")
class ClassLevelController {
  @TestHandler()
  @Public()
  inherited() {
    return "ok";
  }

  @TestHandler()
  @Public()
  @RateLimit("5/1m")
  overridden() {
    return "ok";
  }
}

// A4: stacked decorators are independent policies (each its own key + bucket).
let skipFor: string | null = null;
@Controller("rl-stacked")
class StackedController {
  @TestHandler()
  @Public()
  @RateLimit("2/1m")
  @RateLimit("1/1m", { key: () => "global" })
  stacked() {
    return "ok";
  }

  @TestHandler()
  @Public()
  @RateLimit("1/1m", { key: () => (skipFor === "me" ? null : "k") })
  skippable() {
    return "ok";
  }
}

/** A memory rate-limit store that records every key it is hit with. */
function recordingStore(): { keys: string[]; store: RateLimitStore } {
  const keys: string[] = [];
  const memory = new RateLimitStoreMemory();
  const store: RateLimitStore = {
    hit: (key, ttl) => (keys.push(key), memory.hit(key, ttl)),
    get: (key) => memory.get(key),
  };
  return { keys, store };
}

/**
 * An HTTP app behind one reverse proxy (`trustProxy: 1`): the client IP is the
 * right-most `x-forwarded-for` entry, the one that proxy wrote.
 */
const behindOneProxy = createHttpApp({ trustProxy: 1 }, new Wooks());

/** Seed `app`'s settings (`trustProxy`, `proxyHeaders`) into the test event, as the app does. */
function applyHttpApp(app: WooksHttp, ctx: ReturnType<typeof current>): void {
  (app as unknown as { applyAppConfig(c: typeof ctx): void }).applyAppConfig(ctx);
}

interface RunResult {
  thrown?: HttpError;
  headers: Record<string, string | string[] | number>;
  decision: RateLimitDecision | null;
  /** How many times the credential layer was asked to validate a token. */
  validateCalls: number;
}

/**
 * Runs the full before-chain for one request in interceptor-priority order:
 * pre (BEFORE_GUARD) → auth guard (GUARD) → post (AFTER_GUARD), mirroring
 * moost's ascending-priority dispatch.
 */
async function runChain(
  app: PreparedTestApp,
  pair: TInterceptorDef[],
  controllerName: string,
  method: string,
  httpOpts: {
    headers?: Record<string, string>;
    cookies?: string;
    rawBody?: string;
    /** The HTTP app the request arrives on (its `trustProxy` / `proxyHeaders`). */
    app?: WooksHttp;
  } = {},
  /** Simulated custom GUARD-priority interceptors (e.g. an external IAM). */
  guards: { beforeAuthGuard?: () => void; afterAuthGuard?: () => void } = {},
): Promise<RunResult> {
  const validate = app.auth.validate.bind(app.auth);
  let validateCalls = 0;
  app.auth.validate = (token: string) => {
    validateCalls++;
    return validate(token);
  };
  try {
    return await withHandlerContext(app, controllerName, method, httpOpts, async () => {
      const ctx = current();
      // A test context has no socket peer (wooks 0.8: unknown peer → no IP,
      // nothing trusted); give it the proxy's address, as a real socket has.
      Object.defineProperty(useRequest(ctx).raw.socket, "remoteAddress", { value: "10.0.0.1" });
      if (httpOpts.app) applyHttpApp(httpOpts.app, ctx);
      let thrown: HttpError | undefined;
      const noop = (): void => undefined;
      try {
        await pair[0].before?.(noop);
        guards.beforeAuthGuard?.();
        await app.guard.before?.(noop);
        guards.afterAuthGuard?.();
        await pair[1].before?.(noop);
      } catch (err) {
        thrown = err as HttpError;
      }
      return {
        thrown,
        headers: useResponse(ctx).headers(),
        decision: useRateLimit(ctx).decision,
        validateCalls,
      };
    });
  } finally {
    app.auth.validate = validate;
  }
}

/** A JSON body presenting `token` as `refreshToken`, from client `ip` (behind one proxy). */
function refreshBody(token: string, ip: string) {
  return {
    headers: { "content-type": "application/json", "x-forwarded-for": ip },
    rawBody: JSON.stringify({ refreshToken: token }),
    app: behindOneProxy,
  };
}

describe("rateLimitInterceptors", () => {
  it("allows under the limit and emits draft RateLimit-* headers on success", async () => {
    const app = await prepareTestApp([RlController]);
    const pair = rateLimitInterceptors({ limiter: new RateLimiter({ clock: fakeClock() }) });

    const first = await runChain(app, pair, "RlController", "publicRoute");
    expect(first.thrown).toBeUndefined();
    expect(first.headers["ratelimit-limit"]).toBe("2");
    expect(first.headers["ratelimit-remaining"]).toBe("1");
    expect(first.headers["ratelimit-reset"]).toBe("60");
    expect(first.headers["ratelimit-policy"]).toBe("2;w=60");
    expect(first.decision?.allowed).toBe(true);
  });

  it("throws HttpError(429) with Retry-After once the limit is exceeded", async () => {
    const clock = fakeClock();
    const app = await prepareTestApp([RlController]);
    const pair = rateLimitInterceptors({ limiter: new RateLimiter({ clock }) });

    await runChain(app, pair, "RlController", "publicRoute");
    await runChain(app, pair, "RlController", "publicRoute");
    clock.advance(15_000);
    const rejected = await runChain(app, pair, "RlController", "publicRoute");
    expect(rejected.thrown).toBeInstanceOf(HttpError);
    expect(rejected.thrown?.body.statusCode).toBe(429);
    expect(rejected.headers["ratelimit-remaining"]).toBe("0");
    expect(rejected.headers["retry-after"]).toBe("45");
    expect(rejected.decision?.allowed).toBe(false);
  });

  it("the 429 body carries code RATE_LIMITED and params { policy, limit, window, retryAfter } (seconds)", async () => {
    const clock = fakeClock();
    const app = await prepareTestApp([RlController]);
    const pair = rateLimitInterceptors({ limiter: new RateLimiter({ clock }) });

    await runChain(app, pair, "RlController", "publicRoute");
    await runChain(app, pair, "RlController", "publicRoute");
    clock.advance(15_000);
    const rejected = await runChain(app, pair, "RlController", "publicRoute");
    expect(rejected.thrown?.body).toMatchObject({
      statusCode: 429,
      code: "RATE_LIMITED",
      params: { policy: "RlController.publicRoute", limit: 2, window: 60, retryAfter: 45 },
      message: "Too many requests. Retry after 45 s.",
    });
    // `retryAfter` is the Retry-After header's value.
    expect(rejected.headers["retry-after"]).toBe(String(rejected.thrown?.body.params?.retryAfter));
  });

  it("renders the violated rule's inline message with humanized placeholders", async () => {
    const app = await prepareTestApp([RlController]);
    const pair = rateLimitInterceptors({ limiter: new RateLimiter({ clock: fakeClock() }) });

    await runChain(app, pair, "RlController", "messaged");
    const rejected = await runChain(app, pair, "RlController", "messaged");
    expect(rejected.thrown?.message).toBe("Slow down, wait 1 minute (1/1 minute)");
    // Both stacked rules appear in the policy header.
    expect(rejected.headers["ratelimit-policy"]).toBe("1;w=60, 10;w=3600");
  });

  it("evaluates ip-keyed routes PRE-guard — a garbage bearer flood never reaches credential validation", async () => {
    const app = await prepareTestApp([RlController]);
    const pair = rateLimitInterceptors({ limiter: new RateLimiter({ clock: fakeClock() }) });
    const headers = { authorization: "Bearer garbage" };

    // Two admitted requests DO reach the guard (public route tolerates the
    // bogus token, but validation runs).
    const first = await runChain(app, pair, "RlController", "publicRoute", { headers });
    expect(first.validateCalls).toBe(1);
    await runChain(app, pair, "RlController", "publicRoute", { headers });

    // The third is 429'd by the pre-guard phase — zero credential work.
    const rejected = await runChain(app, pair, "RlController", "publicRoute", { headers });
    expect(rejected.thrown?.body.statusCode).toBe(429);
    expect(rejected.validateCalls).toBe(0);
  });

  it("evaluates user-keyed routes POST-guard with per-user budgets across IPs", async () => {
    const app = await prepareTestApp([RlController]);
    const pair = rateLimitInterceptors({ limiter: new RateLimiter({ clock: fakeClock() }) });
    const { accessToken: alice } = await app.auth.issue("alice");
    const { accessToken: bob } = await app.auth.issue("bob");
    const from = (token: string, ip: string) => ({
      headers: { authorization: `Bearer ${token}`, "x-forwarded-for": ip },
      app: behindOneProxy,
    });

    // Same user from two different IPs → one shared budget (2/1m).
    await runChain(app, pair, "RlController", "userKeyed", from(alice, "1.1.1.1"));
    await runChain(app, pair, "RlController", "userKeyed", from(alice, "2.2.2.2"));
    const rejected = await runChain(app, pair, "RlController", "userKeyed", from(alice, "3.3.3.3"));
    expect(rejected.thrown?.body.statusCode).toBe(429);

    // Different user, same IP as alice's last request → own budget.
    const other = await runChain(app, pair, "RlController", "userKeyed", from(bob, "3.3.3.3"));
    expect(other.thrown).toBeUndefined();
    expect(other.decision?.allowed).toBe(true);
  });

  it("separates ip buckets only when the HTTP app trusts the proxy", async () => {
    const app = await prepareTestApp([RlController]);
    const clock = fakeClock();

    // No `trustProxy` on the HTTP app (default) — x-forwarded-for is ignored,
    // both callers share the socket-address bucket.
    const untrusted = rateLimitInterceptors({ limiter: new RateLimiter({ clock }) });
    await runChain(app, untrusted, "RlController", "sharedA", {
      headers: { "x-forwarded-for": "1.1.1.1" },
    });
    const sameBucket = await runChain(app, untrusted, "RlController", "sharedA", {
      headers: { "x-forwarded-for": "2.2.2.2" },
    });
    expect(sameBucket.thrown?.body.statusCode).toBe(429);
    // A policy with an explicit `id` names its bucket in the 429 params.
    expect(sameBucket.thrown?.body.params?.policy).toBe("shared-bucket");

    // The HTTP app trusts one proxy — distinct forwarded IPs get distinct budgets.
    const trusted = rateLimitInterceptors({ limiter: new RateLimiter({ clock }) });
    await runChain(app, trusted, "RlController", "sharedB", {
      headers: { "x-forwarded-for": "1.1.1.1" },
      app: behindOneProxy,
    });
    const otherBucket = await runChain(app, trusted, "RlController", "sharedB", {
      headers: { "x-forwarded-for": "2.2.2.2" },
      app: behindOneProxy,
    });
    expect(otherBucket.thrown).toBeUndefined();

    // Only the right-most entry (the one the trusted proxy wrote) counts: a
    // forged left-most entry buys no fresh budget.
    await runChain(app, trusted, "RlController", "sharedB", {
      headers: { "x-forwarded-for": "9.9.9.9, 3.3.3.3" },
      app: behindOneProxy,
    });
    const forged = await runChain(app, trusted, "RlController", "sharedB", {
      headers: { "x-forwarded-for": "8.8.8.8, 3.3.3.3" },
      app: behindOneProxy,
    });
    expect(forged.thrown?.body.statusCode).toBe(429);
  });

  it("applies interceptor-level default rules to undecorated routes; @RateLimit(false) opts out", async () => {
    const app = await prepareTestApp([RlController]);
    const pair = rateLimitInterceptors({
      limiter: new RateLimiter({ clock: fakeClock() }),
      rules: ["1/1m"],
    });

    await runChain(app, pair, "RlController", "plain");
    const rejected = await runChain(app, pair, "RlController", "plain");
    expect(rejected.thrown?.body.statusCode).toBe(429);

    // Opted-out route: unlimited, no headers, no decision.
    for (let i = 0; i < 3; i++) {
      const r = await runChain(app, pair, "RlController", "optedOut");
      expect(r.thrown).toBeUndefined();
      expect(r.headers["ratelimit-limit"]).toBeUndefined();
      expect(r.decision).toBeNull();
    }
  });

  it("class-level rules cover undecorated methods; method-level rules replace them", async () => {
    const app = await prepareTestApp([ClassLevelController]);
    const pair = rateLimitInterceptors({ limiter: new RateLimiter({ clock: fakeClock() }) });

    await runChain(app, pair, "ClassLevelController", "inherited");
    const rejected = await runChain(app, pair, "ClassLevelController", "inherited");
    expect(rejected.thrown?.body.statusCode).toBe(429); // class-level 1/1m

    const overridden = await runChain(app, pair, "ClassLevelController", "overridden");
    expect(overridden.thrown).toBeUndefined();
    expect(overridden.headers["ratelimit-limit"]).toBe("5"); // method-level 5/1m
  });

  it("shares one budget between routes declaring the same bucket id", async () => {
    const app = await prepareTestApp([RlController]);
    const pair = rateLimitInterceptors({ limiter: new RateLimiter({ clock: fakeClock() }) });

    await runChain(app, pair, "RlController", "sharedA");
    const rejected = await runChain(app, pair, "RlController", "sharedB");
    expect(rejected.thrown?.body.statusCode).toBe(429);
  });

  it("never double-counts one event when the pair is registered twice (global + @Intercept)", async () => {
    const app = await prepareTestApp([RlController]);
    const pair = rateLimitInterceptors({ limiter: new RateLimiter({ clock: fakeClock() }) });
    const doubled = [pair[0], pair[0], pair[1], pair[1]];

    const decision = await withHandlerContext(app, "RlController", "publicRoute", {}, async () => {
      for (const def of doubled) await def.before?.(() => undefined);
      return useRateLimit(current()).decision;
    });
    // One event, one hit: remaining 1 of 2 — a double count would report 0.
    expect(decision?.remaining).toBe(1);
  });

  it("RateLimited() attaches BOTH phases via @Intercept (the AuthGuarded counterpart)", () => {
    @RateLimited({ limiter: new RateLimiter({ clock: fakeClock() }) })
    @Controller("rl-sugar")
    class SugarController {}
    const meta = getMoostMate().read(SugarController);
    // Dropping either phase silently disables one keying mode — pin the pair.
    expect(meta?.interceptors?.length).toBe(2);
  });

  it("A4: a second @RateLimit adds an independent policy instead of overwriting the first", async () => {
    const app = await prepareTestApp([StackedController]);
    const pair = rateLimitInterceptors({ limiter: new RateLimiter({ clock: fakeClock() }) });
    const hit = (ip: string) =>
      runChain(app, pair, "StackedController", "stacked", {
        headers: { "x-forwarded-for": ip },
        app: behindOneProxy,
      });
    // The global 1/1m policy (one bucket for everyone) rejects the second caller…
    expect((await hit("1.1.1.1")).thrown).toBeUndefined();
    const second = await hit("2.2.2.2");
    expect(second.thrown?.body.statusCode).toBe(429);
    // …and the per-IP 2/1m policy is still enforced too.
    expect(second.headers["ratelimit-policy"]).toBe("2;w=60, 1;w=60");
  });

  it("A4: a key function returning null skips the policy (nothing is counted)", async () => {
    const app = await prepareTestApp([StackedController]);
    const pair = rateLimitInterceptors({ limiter: new RateLimiter({ clock: fakeClock() }) });
    skipFor = "me";
    try {
      for (let i = 0; i < 3; i++) {
        const r = await runChain(app, pair, "StackedController", "skippable");
        expect(r.thrown).toBeUndefined();
        expect(r.decision).toBeNull();
      }
    } finally {
      skipFor = null;
    }
    expect((await runChain(app, pair, "StackedController", "skippable")).thrown).toBeUndefined();
    const over = await runChain(app, pair, "StackedController", "skippable");
    expect(over.thrown?.body.statusCode).toBe(429);
  });

  it("supports a custom key function running inside the event context", async () => {
    const app = await prepareTestApp([RlController]);
    let tenant = "t1";
    const pair = rateLimitInterceptors({
      limiter: new RateLimiter({ clock: fakeClock() }),
      key: () => `tenant:${tenant}`,
      rules: ["1/1m"],
    });

    await runChain(app, pair, "RlController", "plain");
    const rejected = await runChain(app, pair, "RlController", "plain");
    expect(rejected.thrown?.body.statusCode).toBe(429);

    tenant = "t2"; // new subject → fresh budget
    const fresh = await runChain(app, pair, "RlController", "plain");
    expect(fresh.thrown).toBeUndefined();
  });

  it("a custom IAM guard's 'user' subject wins over aooth's derivation, in either GUARD order", async () => {
    const app = await prepareTestApp([RlController]);
    const pair = rateLimitInterceptors({ limiter: new RateLimiter({ clock: fakeClock() }) });
    const { accessToken: alice } = await app.auth.issue("alice");
    const { accessToken: bob } = await app.auth.issue("bob");

    const run = (token: string, iamSub: string, order: "beforeAuthGuard" | "afterAuthGuard") =>
      runChain(
        app,
        pair,
        "RlController",
        "userKeyed",
        { headers: { authorization: `Bearer ${token}` } },
        { [order]: () => setRateLimitSubject("user", `iam:${iamSub}`) },
      );

    // Two different aooth users behind ONE IAM subject → one shared 2/1m
    // budget (proves the slot beats the built-in `u:<userId>` derivation).
    expect((await run(alice, "sub-1", "beforeAuthGuard")).thrown).toBeUndefined();
    expect((await run(bob, "sub-1", "beforeAuthGuard")).thrown).toBeUndefined();
    // The IAM guard registered AFTER aooth's guard still owns the subject —
    // the slot is read FIRST by the resolver, so ordering is irrelevant.
    const rejected = await run(bob, "sub-1", "afterAuthGuard");
    expect(rejected.thrown?.body.statusCode).toBe(429);

    // A fresh IAM subject gets a fresh budget, even for an exhausted token.
    expect((await run(alice, "sub-2", "beforeAuthGuard")).thrown).toBeUndefined();
  });

  it("custom subject kinds ('tenant') budget post-guard by the supplied value, with IP fallback when unset", async () => {
    const app = await prepareTestApp([RlController]);
    const pair = rateLimitInterceptors({ limiter: new RateLimiter({ clock: fakeClock() }) });
    const hit = (ip: string, tenant?: string) =>
      runChain(
        app,
        pair,
        "RlController",
        "tenantKeyed",
        { headers: { "x-forwarded-for": ip }, app: behindOneProxy },
        tenant ? { beforeAuthGuard: () => setRateLimitSubject("tenant", `t:${tenant}`) } : {},
      );

    // Same tenant from different IPs → one shared 1/1m budget.
    await hit("1.1.1.1", "acme");
    expect((await hit("2.2.2.2", "acme")).thrown?.body.statusCode).toBe(429);
    // Another tenant → own budget.
    expect((await hit("2.2.2.2", "globex")).thrown).toBeUndefined();

    // Nobody populated the kind → degrade to per-IP budgets, never one global bucket.
    await hit("3.3.3.3");
    expect((await hit("4.4.4.4")).thrown).toBeUndefined();
    expect((await hit("4.4.4.4")).thrown?.body.statusCode).toBe(429);
  });

  it("named subject kinds are owned by the POST-guard phase (never evaluated pre-guard)", async () => {
    const app = await prepareTestApp([RlController]);
    const pair = rateLimitInterceptors({ limiter: new RateLimiter({ clock: fakeClock() }) });

    const decision = await withHandlerContext(app, "RlController", "tenantKeyed", {}, async () => {
      await pair[0].before?.(() => undefined); // pre-guard phase only
      return useRateLimit(current()).decision;
    });
    expect(decision).toBeNull();
  });

  it("'session' keying gives each login of the same user its own budget", async () => {
    const app = await prepareTestApp([RlController]);
    const pair = rateLimitInterceptors({ limiter: new RateLimiter({ clock: fakeClock() }) });
    const { accessToken: login1 } = await app.auth.issue("alice");
    const { accessToken: login2 } = await app.auth.issue("alice");
    const bearer = (token: string) => ({ headers: { authorization: `Bearer ${token}` } });

    await runChain(app, pair, "RlController", "sessionKeyed", bearer(login1));
    // Same session again → 1/1m exhausted.
    const rejected = await runChain(app, pair, "RlController", "sessionKeyed", bearer(login1));
    expect(rejected.thrown?.body.statusCode).toBe(429);
    // Same USER, different login/device → untouched budget.
    const other = await runChain(app, pair, "RlController", "sessionKeyed", bearer(login2));
    expect(other.thrown).toBeUndefined();
  });

  it("suppresses RateLimit-* headers with headers:false but still throws 429", async () => {
    const app = await prepareTestApp([RlController]);
    const pair = rateLimitInterceptors({
      limiter: new RateLimiter({ clock: fakeClock() }),
      headers: false,
    });

    await runChain(app, pair, "RlController", "publicRoute");
    await runChain(app, pair, "RlController", "publicRoute");
    const rejected = await runChain(app, pair, "RlController", "publicRoute");
    expect(rejected.thrown?.body.statusCode).toBe(429);
    expect(rejected.headers["ratelimit-limit"]).toBeUndefined();
    // Retry-After is part of the 429 contract itself, not the headers option.
    expect(rejected.headers["retry-after"]).toBe("60");
  });
  it("'refresh-token' keys on the presented refresh token — body or cookie, any IP — stored hashed", async () => {
    // WHY: one refresh token's budget must follow the token (not the caller's
    // IP), and the bearer secret must never become a counter-store key.
    const { keys, store } = recordingStore();
    const app = await prepareTestApp([RlController]);
    const pair = rateLimitInterceptors({ limiter: new RateLimiter({ store }) });

    expect(
      (
        await runChain(
          app,
          pair,
          "RlController",
          "refreshKeyed",
          refreshBody("rt-secret", "1.1.1.1"),
        )
      ).thrown,
    ).toBeUndefined();
    expect(
      (
        await runChain(
          app,
          pair,
          "RlController",
          "refreshKeyed",
          refreshBody("rt-secret", "2.2.2.2"),
        )
      ).thrown,
    ).toBeUndefined();
    // Third presentation from yet another IP — and via the cookie — shares the budget.
    const viaCookie = await runChain(app, pair, "RlController", "refreshKeyed", {
      cookies: "aooth_refresh=rt-secret",
      headers: { "x-forwarded-for": "3.3.3.3" },
      rawBody: "",
      app: behindOneProxy,
    });
    expect(viaCookie.thrown?.body.statusCode).toBe(429);
    // Another token: its own budget.
    expect(
      (
        await runChain(
          app,
          pair,
          "RlController",
          "refreshKeyed",
          refreshBody("rt-other", "1.1.1.1"),
        )
      ).thrown,
    ).toBeUndefined();

    expect(keys.length).toBeGreaterThan(0);
    expect(keys.some((k) => k.includes("rt-secret") || k.includes("rt-other"))).toBe(false);
  });

  it("'refresh-token' skips the policy when the request presents no refresh token", async () => {
    const app = await prepareTestApp([RlController]);
    const pair = rateLimitInterceptors({ limiter: new RateLimiter({ clock: fakeClock() }) });
    for (let i = 0; i < 3; i++) {
      const res = await runChain(app, pair, "RlController", "refreshKeyed", {
        headers: { "content-type": "application/json" },
        rawBody: "{}",
      });
      expect(res.thrown).toBeUndefined();
      expect(res.decision).toBeNull();
    }
    // An unparsable body is no token either — not an error from the limiter.
    const garbled = await runChain(app, pair, "RlController", "refreshKeyed", {
      headers: { "content-type": "application/json" },
      rawBody: "{not json",
    });
    expect(garbled.thrown).toBeUndefined();
  });

  it("policies re-tunes a declared policy by id (rules replaced, key + id kept) or switches it off", async () => {
    // WHY: apps must be able to change bundled limits (e.g. /auth/refresh)
    // without subclassing the controller that declares them.
    const app = await prepareTestApp([RlController]);
    const pair = rateLimitInterceptors({
      limiter: new RateLimiter({ clock: fakeClock() }),
      policies: { "shared-bucket": ["3/1m"] },
    });
    for (let i = 0; i < 3; i++) {
      expect((await runChain(app, pair, "RlController", "sharedA")).thrown).toBeUndefined();
    }
    const rejected = await runChain(app, pair, "RlController", "sharedB");
    expect(rejected.thrown?.body).toMatchObject({ params: { policy: "shared-bucket", limit: 3 } });
    expect(rejected.headers["ratelimit-policy"]).toBe("3;w=60");

    const off = rateLimitInterceptors({
      limiter: new RateLimiter({ clock: fakeClock() }),
      policies: { "shared-bucket": false },
    });
    for (let i = 0; i < 4; i++) {
      const res = await runChain(app, off, "RlController", "sharedA");
      expect(res.thrown).toBeUndefined();
      expect(res.decision).toBeNull();
    }
  });

  it("policies rejects an empty rule list at registration", () => {
    expect(() => rateLimitInterceptors({ policies: { "shared-bucket": [] } })).toThrow(
      /pass false/,
    );
    expect(() => rateLimitInterceptors({ policies: { "shared-bucket": "nonsense" } })).toThrow();
  });

  it("policies refuses an unknown policy id at configuration time (L3)", () => {
    // WHY: a typo ("aooth.refesh") silently left the bundled limit in force.
    expect(() => rateLimitInterceptors({ policies: { "aooth.refesh": "1/1m" } })).toThrow(
      /unknown policy id "aooth\.refesh"/,
    );
    // Declared ids — the bundled ones and any @RateLimit({ id }) — are accepted.
    expect(() =>
      rateLimitInterceptors({
        policies: { "aooth.refresh": "1/1m", "aooth.send": false, "shared-bucket": "2/1m" },
      }),
    ).not.toThrow();
  });

  it("'refresh-token' counts lenient base64url spellings of one token as that token (L1)", async () => {
    // WHY: `tok=`, `tok `, `tok\n`, a `+/` spelling or `tok!` decode to the
    // same bytes; each was its own bucket.
    const app = await prepareTestApp([RlController]);
    const pair = rateLimitInterceptors({ limiter: new RateLimiter({ clock: fakeClock() }) });
    const token = "abc-def_ghij";
    const hit = (t: string) =>
      runChain(app, pair, "RlController", "refreshKeyed", {
        headers: { "content-type": "application/json" },
        rawBody: JSON.stringify({ refreshToken: t }),
      });
    expect((await hit(token)).thrown).toBeUndefined();
    expect((await hit(`${token}=`)).thrown).toBeUndefined();
    const third = await hit("abc+def/ghij!");
    expect(third.thrown?.body.statusCode).toBe(429);
  });

  it("keys on the IP the HTTP app resolves — under proxyHeaders 'forwarded' a spoofed X-Forwarded-For buys no fresh budget", async () => {
    // WHY: the limiter's key and the app's client IP must be one value; a
    // client-chosen X-Forwarded-For must never pick its own bucket.
    const { keys, store } = recordingStore();
    const app = await prepareTestApp([RlController]);
    const pair = rateLimitInterceptors({ limiter: new RateLimiter({ store }) });
    const viaForwarded = createHttpApp({ trustProxy: 1, proxyHeaders: "forwarded" }, new Wooks());
    const hit = (spoofed: string) =>
      runChain(app, pair, "RlController", "sharedA", {
        headers: { forwarded: "for=203.0.113.9", "x-forwarded-for": spoofed },
        app: viaForwarded,
      });
    expect((await hit("1.1.1.1")).thrown).toBeUndefined();
    expect((await hit("2.2.2.2")).thrown?.body.statusCode).toBe(429);
    expect(keys.length).toBeGreaterThan(0);
    for (const key of keys) {
      expect(key).toContain("ip%3A203.0.113.9");
      expect(key).not.toMatch(/1\.1\.1\.1|2\.2\.2\.2/);
    }
    // The one-time-code failure buckets read the same value.
    const seen = await withHandlerContext(
      app,
      "RlController",
      "plain",
      { headers: { forwarded: "for=203.0.113.9", "x-forwarded-for": "1.1.1.1" } },
      async () => {
        applyHttpApp(viaForwarded, current());
        return requestClientIp();
      },
    );
    expect(seen).toBe("203.0.113.9");
  });

  it("the deprecated trustProxy option warns once and is still honoured — one hop", async () => {
    // WHY: apps that set it behind a proxy (no trustProxy on the HTTP app)
    // must keep per-client buckets after upgrading, not share the proxy's IP.
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const pair = rateLimitInterceptors({
        limiter: new RateLimiter({ clock: fakeClock() }),
        trustProxy: true,
      });
      rateLimitInterceptors({ trustProxy: false });
      const notices = warn.mock.calls.filter((c) =>
        String(c[0]).includes("rateLimitInterceptors({ trustProxy })"),
      );
      expect(notices).toHaveLength(1);
      expect(String(notices[0][0])).toMatch(/still honoured.*removed in 0\.3.*HTTP app/s);

      const app = await prepareTestApp([RlController]);
      const hit = (xff: string) =>
        runChain(app, pair, "RlController", "sharedA", { headers: { "x-forwarded-for": xff } });
      // Distinct forwarded clients → distinct buckets (no app-level trust needed).
      expect((await hit("1.1.1.1")).thrown).toBeUndefined();
      expect((await hit("2.2.2.2")).thrown).toBeUndefined();
      // One hop: only the right-most entry counts — a forged left-most one buys nothing.
      expect((await hit("9.9.9.9, 3.3.3.3")).thrown).toBeUndefined();
      expect((await hit("8.8.8.8, 3.3.3.3")).thrown?.body.statusCode).toBe(429);
    } finally {
      warn.mockRestore();
    }
  });

  it("the deprecated trustProxy reads the app's proxyHeaders family — a spoofed X-Forwarded-For is ignored", async () => {
    const { keys, store } = recordingStore();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const pair = rateLimitInterceptors({ limiter: new RateLimiter({ store }), trustProxy: true });
    warn.mockRestore();
    const app = await prepareTestApp([RlController]);
    const forwardedOnly = createHttpApp({ proxyHeaders: "forwarded" }, new Wooks());
    const hit = (spoofed: string) =>
      runChain(app, pair, "RlController", "sharedA", {
        headers: { forwarded: "for=203.0.113.9", "x-forwarded-for": spoofed },
        app: forwardedOnly,
      });
    expect((await hit("1.1.1.1")).thrown).toBeUndefined();
    expect((await hit("2.2.2.2")).thrown?.body.statusCode).toBe(429);
    for (const key of keys) expect(key).toContain("ip%3A203.0.113.9");
  });

  it("without the option the limiter keys on the app's getIp()", async () => {
    const app = await prepareTestApp([RlController]);
    const pair = rateLimitInterceptors({ limiter: new RateLimiter({ clock: fakeClock() }) });
    const seen = await withHandlerContext(
      app,
      "RlController",
      "sharedA",
      { headers: { "x-forwarded-for": "1.1.1.1" } },
      async () => {
        Object.defineProperty(useRequest().raw.socket, "remoteAddress", { value: "10.0.0.1" });
        await pair[0].before?.(() => undefined);
        return requestClientIp();
      },
    );
    // No trust anywhere: the socket peer, x-forwarded-for unread.
    expect(seen).toBe("10.0.0.1");
  });
});
