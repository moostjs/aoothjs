import { describe, expect, it } from "vite-plus/test";

import { fakeClock } from "../__test__/fake-clock";
import { RateLimiter } from "./rate-limiter";
import { RateLimitStoreMemory } from "./store";

describe("RateLimiter", () => {
  it("allows up to the limit, then rejects with retryAfter until the window resets", async () => {
    const clock = fakeClock();
    const limiter = new RateLimiter({ clock });

    for (let i = 1; i <= 3; i++) {
      const d = await limiter.check("route", "ip:1.2.3.4", ["3/1m"]);
      expect(d.allowed).toBe(true);
      expect(d.limit).toBe(3);
      expect(d.remaining).toBe(3 - i);
    }

    clock.advance(10_000);
    const rejected = await limiter.check("route", "ip:1.2.3.4", ["3/1m"]);
    expect(rejected.allowed).toBe(false);
    expect(rejected.remaining).toBe(0);
    expect(rejected.retryAfterMs).toBe(50_000); // 60s window, 10s in
    expect(rejected.resetAt).toBe(clock.now() + 50_000);

    // Window rollover: a new window-aligned key, counting restarts.
    clock.advance(50_000);
    const fresh = await limiter.check("route", "ip:1.2.3.4", ["3/1m"]);
    expect(fresh.allowed).toBe(true);
    expect(fresh.remaining).toBe(2);
  });

  it("isolates subjects and scopes into separate buckets", async () => {
    const limiter = new RateLimiter({ clock: fakeClock() });
    await limiter.check("login", "ip:a", ["1/1m"]);
    // Different subject, same scope — own budget.
    expect((await limiter.check("login", "ip:b", ["1/1m"])).allowed).toBe(true);
    // Same subject, different scope — own budget.
    expect((await limiter.check("reset", "ip:a", ["1/1m"])).allowed).toBe(true);
    // Same subject + scope — budget exhausted.
    expect((await limiter.check("login", "ip:a", ["1/1m"])).allowed).toBe(false);
  });

  it("URI-encodes scope/subject so ':'-bearing components cannot collide", async () => {
    const limiter = new RateLimiter({ clock: fakeClock() });
    // Crafted so naive `<scope>:<subject>` concatenation would be identical.
    await limiter.check("a:b", "c", ["1/1m"]);
    const other = await limiter.check("a", "b:c", ["1/1m"]);
    expect(other.allowed).toBe(true);
  });

  it("evaluates multiple rules; the governing violated rule is the slowest-resetting one", async () => {
    const clock = fakeClock();
    const limiter = new RateLimiter({ clock });
    const rules = ["1/1s", "3/1m"];

    expect((await limiter.check("r", "s", rules)).allowed).toBe(true);
    // Second hit within the same second violates 1/1s but not 3/1m.
    const shortViolation = await limiter.check("r", "s", rules);
    expect(shortViolation.allowed).toBe(false);
    expect(shortViolation.limit).toBe(1);
    expect(shortViolation.retryAfterMs).toBeLessThanOrEqual(1000);
    expect(shortViolation.policies).toHaveLength(2);

    // Burn through the long rule too (each rejected hit still counts).
    clock.advance(1100);
    await limiter.check("r", "s", rules); // 3rd hit
    clock.advance(1100);
    await limiter.check("r", "s", rules); // 4th hit: violates 3/1m only
    clock.advance(1100);
    await limiter.check("r", "s", rules); // 5th hit: fresh 1s window, violates 3/1m only
    const bothViolated = await limiter.check("r", "s", rules); // 6th, same second: violates BOTH
    expect(bothViolated.allowed).toBe(false);
    // Governing = the rule that frees capacity LAST (the 1m one).
    expect(bothViolated.limit).toBe(3);
    expect(bothViolated.retryAfterMs).toBeGreaterThan(1000);
  });

  it("renders the violated rule's inline message, falling back to defaultMessage then the built-in", async () => {
    const clock = fakeClock();
    const limiter = new RateLimiter({ clock });

    await limiter.check("r", "s", ["1/1m | Wait {{delta}} ({{limit}}/{{window}})"]);
    clock.advance(30_000);
    const inline = await limiter.check("r", "s", ["1/1m | Wait {{delta}} ({{limit}}/{{window}})"]);
    expect(inline.message).toBe("Wait 30 seconds (1/1 minute)");

    // Clock is 30s into the current 1m window here, so delta = 30s.
    await limiter.check("r2", "s", ["1/1m"]);
    const viaDefault = await limiter.check("r2", "s", ["1/1m"], {
      defaultMessage: "Custom: {{delta}}",
    });
    expect(viaDefault.message).toBe("Custom: 30 seconds");

    await limiter.check("r3", "s", ["1/1m"]);
    const builtIn = await limiter.check("r3", "s", ["1/1m"]);
    expect(builtIn.message).toBe("Too many requests. Please try again in 30 seconds.");
  });

  it("reports the lowest-remaining rule as governing when allowed", async () => {
    const limiter = new RateLimiter({ clock: fakeClock() });
    const d = await limiter.check("r", "s", ["2/1s", "100/1h"]);
    expect(d.allowed).toBe(true);
    // 2/1s has remaining 1; 100/1h has remaining 99 — the tighter one governs headers.
    expect(d.limit).toBe(2);
    expect(d.remaining).toBe(1);
  });

  it("throws on an empty rule set — a configured limiter with nothing to enforce is a bug", async () => {
    const limiter = new RateLimiter({ clock: fakeClock() });
    await expect(limiter.check("r", "s", [])).rejects.toThrow(/at least one rule/);
  });

  it("shares one store across limiter calls and respects an injected store", async () => {
    const clock = fakeClock();
    const store = new RateLimitStoreMemory({ clock });
    const limiter = new RateLimiter({ store, clock });
    await limiter.check("r", "s", ["1/1m"]);
    const second = new RateLimiter({ store, clock });
    expect((await second.check("r", "s", ["1/1m"])).allowed).toBe(false);
  });
});

describe("RateLimitStoreMemory", () => {
  it("expires counters by ttl and supports reset + cleanup", async () => {
    const clock = fakeClock();
    const store = new RateLimitStoreMemory({ clock });
    expect(await store.hit("k", 1000)).toBe(1);
    expect(await store.hit("k", 1000)).toBe(2);

    clock.advance(1001);
    expect(await store.hit("k", 1000)).toBe(1); // lazy eviction on access

    await store.reset("k");
    expect(await store.hit("k", 1000)).toBe(1);

    await store.hit("dead", 10);
    clock.advance(11);
    // "dead" (ttl 10) expired; "k" (fresh 1000ms ttl) survives the sweep.
    expect(await store.cleanup()).toBe(1);
  });
});
