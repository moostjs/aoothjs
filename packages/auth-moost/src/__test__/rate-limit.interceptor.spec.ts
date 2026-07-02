import type { Clock, RateLimitDecision } from "@aooth/auth";
import { RateLimiter } from "@aooth/auth";
import { current } from "@wooksjs/event-core";
import { HttpError, useResponse } from "@wooksjs/event-http";
import type { TInterceptorDef } from "moost";
import { getMoostMate } from "moost";
import { describe, expect, it } from "vite-plus/test";

import { Public } from "../auth.decorator";
import { useRateLimit } from "../rate-limit/composables";
import { RateLimit, RateLimited } from "../rate-limit/decorator";
import { rateLimitInterceptors } from "../rate-limit/interceptor";
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
  httpOpts: { headers?: Record<string, string> } = {},
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
      let thrown: HttpError | undefined;
      const noop = (): void => undefined;
      try {
        await pair[0].before?.(noop);
        await app.guard.before?.(noop);
        await pair[1].before?.(noop);
      } catch (err) {
        thrown = err as HttpError;
      }
      return {
        thrown,
        headers: useResponse(ctx).headers() as RunResult["headers"],
        decision: useRateLimit(ctx).decision,
        validateCalls,
      };
    });
  } finally {
    app.auth.validate = validate;
  }
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
    const pair = rateLimitInterceptors({
      limiter: new RateLimiter({ clock: fakeClock() }),
      trustProxy: true,
    });
    const { accessToken: alice } = await app.auth.issue("alice");
    const { accessToken: bob } = await app.auth.issue("bob");
    const from = (token: string, ip: string) => ({
      headers: { authorization: `Bearer ${token}`, "x-forwarded-for": ip },
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

  it("separates ip buckets only when trustProxy is enabled", async () => {
    const app = await prepareTestApp([RlController]);
    const clock = fakeClock();

    // trustProxy: false (default) — x-forwarded-for is ignored, both callers
    // share the socket-address bucket.
    const untrusted = rateLimitInterceptors({ limiter: new RateLimiter({ clock }) });
    await runChain(app, untrusted, "RlController", "sharedA", {
      headers: { "x-forwarded-for": "1.1.1.1" },
    });
    const sameBucket = await runChain(app, untrusted, "RlController", "sharedA", {
      headers: { "x-forwarded-for": "2.2.2.2" },
    });
    expect(sameBucket.thrown?.body.statusCode).toBe(429);

    // trustProxy: true — distinct forwarded IPs get distinct budgets.
    const trusted = rateLimitInterceptors({
      limiter: new RateLimiter({ clock }),
      trustProxy: true,
    });
    await runChain(app, trusted, "RlController", "sharedB", {
      headers: { "x-forwarded-for": "1.1.1.1" },
    });
    const otherBucket = await runChain(app, trusted, "RlController", "sharedB", {
      headers: { "x-forwarded-for": "2.2.2.2" },
    });
    expect(otherBucket.thrown).toBeUndefined();
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
});
