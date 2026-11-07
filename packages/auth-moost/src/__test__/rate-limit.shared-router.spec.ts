import { RateLimiter, RateLimitStoreMemory, type RateLimitStore } from "@aooth/auth";
import { Get, MoostHttp } from "@moostjs/event-http";
import { HttpError } from "@wooksjs/event-http";
import { clearGlobalWooks, Controller, Moost } from "moost";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";

import { RateLimit, RateLimited } from "../rate-limit/decorator";
import { rateLimitInterceptors } from "../rate-limit/interceptor";
import { requestVia } from "./test-harness";

/** A limiter whose store counts every hit (one hit = one `check` of a one-rule policy). */
function countingLimiter(): { limiter: RateLimiter; hits: () => number } {
  const memory = new RateLimitStoreMemory();
  let hits = 0;
  const store: RateLimitStore = {
    hit: (key, ttl) => (hits++, memory.hit(key, ttl)),
    get: (key) => memory.get(key),
  };
  return { limiter: new RateLimiter({ store }), hits: () => hits };
}

beforeEach(() => {
  clearGlobalWooks();
  // moost warns that both apps route through one Wooks — expected here.
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
  vi.spyOn(console, "error").mockImplementation(() => undefined);
});
afterEach(() => {
  clearGlobalWooks();
  vi.restoreAllMocks();
});

describe("H1: two Moost apps sharing the global router", () => {
  it("answers 429 at limit+1 through both apps' chains, counting each request once", async () => {
    const { limiter, hits } = countingLimiter();

    @Controller("shared")
    class FirstController {
      @Get("ping")
      @RateLimit("2/1m", { id: "shared-ping" })
      ping() {
        return "first";
      }
    }
    @Controller("shared")
    class SecondController {
      @Get("ping")
      @RateLimit("2/1m", { id: "shared-ping" })
      ping() {
        return "second";
      }
    }

    const request = await bootShared(limiter, [FirstController, SecondController]);
    expect((await request("/shared/ping")).status).toBe(200);
    expect((await request("/shared/ping")).status).toBe(200);
    // Third request: the first app's limiter rejects, wooks moves on to the
    // second app's chain — which must reject again, not run its handler.
    const over = await request("/shared/ping");
    expect(over.status).toBe(429);
    expect(over.body).toMatchObject({ code: "RATE_LIMITED" });
    // The headers of the first answer survive the second chain's re-throw.
    expect(over.response?.headers.get("retry-after")).toBeTruthy();
    expect(over.response?.headers.get("ratelimit-limit")).toBe("2");
    expect(over.response?.headers.get("ratelimit-remaining")).toBe("0");
    expect(hits()).toBe(3);
    // And it stays rejected.
    expect((await request("/shared/ping")).status).toBe(429);
    expect(hits()).toBe(4);
  });
});

/**
 * Boots one Moost app per controller on the global router (the first app's adapter
 * serves). One limiter for every app, or one per app (matched by index).
 */
async function bootShared(
  limiters: RateLimiter | RateLimiter[],
  controllers: Array<new () => object>,
) {
  let http!: MoostHttp;
  for (const [i, controller] of controllers.entries()) {
    const limiter = Array.isArray(limiters) ? limiters[i] : limiters;
    const app = new Moost();
    const adapter = app.adapter(new MoostHttp());
    http ??= adapter;
    app.applyGlobalInterceptors(...rateLimitInterceptors({ limiter }));
    app.registerControllers(controller);
    await app.init();
  }
  return requestVia(http);
}

describe("H1: policies are checked once per event, per policy", () => {
  it("the second app's stricter policy is enforced after the first allowed and threw non-429", async () => {
    const { limiter } = countingLimiter();

    @Controller("shared")
    class LooseController {
      @Get("ping")
      @RateLimit("100/1m")
      ping(): string {
        throw new HttpError(404, "not here");
      }
    }
    @Controller("shared")
    class StrictController {
      @Get("ping")
      @RateLimit("1/1m")
      ping() {
        return "strict";
      }
    }
    const request = await bootShared(limiter, [LooseController, StrictController]);
    expect((await request("/shared/ping")).status).toBe(200);
    const over = await request("/shared/ping");
    expect(over.status).toBe(429);
    expect(over.body).toMatchObject({ code: "RATE_LIMITED" });
  });

  it("a second app's route that opts out is not handed the first app's 429", async () => {
    @Controller("shared")
    class LimitedController {
      @Get("ping")
      @RateLimit("1/1m")
      ping(): string {
        throw new HttpError(404, "not here");
      }
    }
    @Controller("shared")
    class OptedOutController {
      @Get("ping")
      @RateLimit(false)
      ping() {
        return "opted out";
      }
    }
    @Controller("shared")
    class UnlimitedController {
      @Get("ping")
      ping() {
        return "unlimited";
      }
    }
    for (const second of [OptedOutController, UnlimitedController]) {
      clearGlobalWooks();
      const request = await bootShared(countingLimiter().limiter, [LimitedController, second]);
      expect((await request("/shared/ping")).status).toBe(200);
      // The first app rejects; the second serves a route that has no policy.
      expect((await request("/shared/ping")).status).toBe(200);
    }
  });
});

describe("H1: the once-per-event record is per limiter", () => {
  it("another app's limiter runs its own check after the first allowed and threw non-429", async () => {
    const first = countingLimiter();
    const second = countingLimiter();

    // Same scope id in both apps; each app's limiter holds its own budget.
    @Controller("shared")
    class LooseController {
      @Get("ping")
      @RateLimit("100/1m", { id: "shared-ping" })
      ping(): string {
        throw new HttpError(404, "not here");
      }
    }
    @Controller("shared")
    class StrictController {
      @Get("ping")
      @RateLimit("1/1m", { id: "shared-ping" })
      ping() {
        return "strict";
      }
    }
    const request = await bootShared(
      [first.limiter, second.limiter],
      [LooseController, StrictController],
    );

    // Request 1: the first app allows and throws; the second app checks (its own
    // hit) and serves.
    expect((await request("/shared/ping")).status).toBe(200);
    expect(first.hits()).toBe(1);
    expect(second.hits()).toBe(1);

    // Request 2: the first app allows (its limit is far off) and throws; the
    // second app must not reuse that "allowed" — its own limiter rejects, and
    // each limiter counted this request exactly once.
    const over = await request("/shared/ping");
    expect(over.status).toBe(429);
    expect(over.body).toMatchObject({ code: "RATE_LIMITED" });
    expect(first.hits()).toBe(2);
    expect(second.hits()).toBe(2);
  });
});

describe("one app, global + per-controller registration", () => {
  it("counts each request once", async () => {
    const { limiter, hits } = countingLimiter();

    @RateLimited({ limiter, rules: ["2/1m"] })
    @Controller("once")
    class OnceController {
      @Get("ping")
      ping() {
        return "ok";
      }
    }

    const app = new Moost();
    const http = app.adapter(new MoostHttp());
    app.applyGlobalInterceptors(...rateLimitInterceptors({ limiter, rules: ["2/1m"] }));
    app.registerControllers(OnceController);
    await app.init();

    const request = requestVia(http);
    expect((await request("/once/ping")).status).toBe(200);
    expect((await request("/once/ping")).status).toBe(200);
    expect(hits()).toBe(2);
    expect((await request("/once/ping")).status).toBe(429);
    expect(hits()).toBe(3);
  });
});
