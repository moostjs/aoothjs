import { describe, expect, it } from "vite-plus/test";

import { fakeClock } from "../../__test__/fake-clock";
import { RateLimiter } from "../../rate-limit/rate-limiter";
import { RateLimitStoreRedis } from "../index";
import { MockRedis } from "./mock-redis";

describe("RateLimitStoreRedis", () => {
  it("INCRs under the prefix and PEXPIREs (ms) only on the first hit", async () => {
    const redis = new MockRedis();
    const store = new RateLimitStoreRedis({ redis });

    expect(await store.hit("k", 5000)).toBe(1);
    expect(await store.hit("k", 5000)).toBe(2);

    expect(redis.opsOf("incr").map((o) => o.args[0])).toEqual(["aooth:rl:k", "aooth:rl:k"]);
    // TTL is garbage collection only — set once, in MILLISECONDS (pexpire).
    expect(redis.opsOf("pexpire")).toEqual([{ cmd: "pexpire", args: ["aooth:rl:k", 5000] }]);
  });

  it("respects a custom prefix and reset() deletes the counter", async () => {
    const redis = new MockRedis();
    const store = new RateLimitStoreRedis({ redis, prefix: "app:rl" });

    await store.hit("k", 1000);
    await store.reset("k");
    expect(redis.opsOf("del")).toEqual([{ cmd: "del", args: ["app:rl:k"] }]);
    expect(await store.hit("k", 1000)).toBe(1);
  });

  it("backs a full RateLimiter run — window rollover via key alignment, not TTL", async () => {
    // MockRedis never enforces TTLs, which proves the limiter's correctness
    // comes from window-aligned key names alone (RL.spec.md §4.2).
    const clock = fakeClock();
    const limiter = new RateLimiter({
      store: new RateLimitStoreRedis({ redis: new MockRedis() }),
      clock,
    });

    expect((await limiter.check("login", "ip:1.2.3.4", ["2/1m"])).allowed).toBe(true);
    expect((await limiter.check("login", "ip:1.2.3.4", ["2/1m"])).allowed).toBe(true);
    const rejected = await limiter.check("login", "ip:1.2.3.4", ["2/1m"]);
    expect(rejected.allowed).toBe(false);
    expect(rejected.retryAfterMs).toBe(60_000);

    clock.advance(60_000);
    const fresh = await limiter.check("login", "ip:1.2.3.4", ["2/1m"]);
    expect(fresh.allowed).toBe(true);
    expect(fresh.remaining).toBe(1);
  });
});
