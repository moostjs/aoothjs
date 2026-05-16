/**
 * Unit tests for the in-memory `WorkflowRateLimitStore` shipped as the default
 * for the recovery (and future invite) rate-limit cap. Exercises the store
 * directly — no workflow scaffolding — so we can pin down its behavioural
 * contract independent of caller wiring.
 *
 * Behavioural contract (per `WF_RECOVERY.md` §"Rate limiting"):
 *   - Counts every `consume` call against the key.
 *   - `allowed` flips false once `live.length >= maxCount` inside the window.
 *   - Sliding window: older hits drop off as time moves past `windowMs`.
 *   - Stored timestamps are bounded by `maxCount` so a sustained denied
 *     attacker cannot grow the array without bound.
 */
import { describe, expect, it } from "vite-plus/test";

import { WorkflowRateLimitStoreMemory } from "../rate-limit/index";

describe("WorkflowRateLimitStoreMemory", () => {
  it("allows up to maxCount calls in the window, denies the next one", async () => {
    const store = new WorkflowRateLimitStoreMemory();
    const r1 = await store.consume("alice", 60_000, 2);
    expect(r1.allowed).toBe(true);
    expect(r1.remaining).toBe(1);
    const r2 = await store.consume("alice", 60_000, 2);
    expect(r2.allowed).toBe(true);
    expect(r2.remaining).toBe(0);
    const r3 = await store.consume("alice", 60_000, 2);
    expect(r3.allowed).toBe(false);
    expect(r3.remaining).toBe(0);
  });

  it("keys are isolated — alice's hits don't deny bob", async () => {
    const store = new WorkflowRateLimitStoreMemory();
    await store.consume("alice", 60_000, 1);
    const denied = await store.consume("alice", 60_000, 1);
    expect(denied.allowed).toBe(false);
    const bob = await store.consume("bob", 60_000, 1);
    expect(bob.allowed).toBe(true);
  });

  it("sliding window: hits older than windowMs drop off → allowance restored", async () => {
    const store = new WorkflowRateLimitStoreMemory();
    // Use a small window so we can wait past it within a test.
    await store.consume("alice", 50, 1);
    const denied = await store.consume("alice", 50, 1);
    expect(denied.allowed).toBe(false);
    await new Promise((r) => setTimeout(r, 80));
    const allowedAgain = await store.consume("alice", 50, 1);
    expect(allowedAgain.allowed).toBe(true);
  });

  it("bounded-array guarantee: denied calls do NOT grow the stored hit list past maxCount", async () => {
    const store = new WorkflowRateLimitStoreMemory();
    // Cap = 3 — fill the window then hammer with denied calls.
    await store.consume("alice", 60_000, 3);
    await store.consume("alice", 60_000, 3);
    await store.consume("alice", 60_000, 3);
    for (let i = 0; i < 50; i++) {
      const r = await store.consume("alice", 60_000, 3);
      expect(r.allowed).toBe(false);
    }
    // Peek at the internal hit list via a synthetic call: a `remaining` of
    // `maxCount - live.length` should always be `0` here (never negative,
    // never positive). If the array grew, `remaining` would be negative.
    const tail = await store.consume("alice", 60_000, 3);
    expect(tail.allowed).toBe(false);
    expect(tail.remaining).toBe(0);
  });

  it("resetAt reports when the oldest live hit ages out (`oldest + windowMs`)", async () => {
    const store = new WorkflowRateLimitStoreMemory();
    const before = Date.now();
    await store.consume("alice", 60_000, 2);
    const r2 = await store.consume("alice", 60_000, 2);
    // resetAt is anchored on the OLDEST hit (not the latest) so callers can
    // surface a precise countdown to the window roll-off.
    expect(r2.resetAt).toBeGreaterThanOrEqual(before + 60_000);
    expect(r2.resetAt).toBeLessThanOrEqual(Date.now() + 60_000 + 50);
  });

  it("changing maxCount mid-flight is honoured per-call (no cached cap)", async () => {
    const store = new WorkflowRateLimitStoreMemory();
    // First config: cap=1 → second call denied.
    await store.consume("alice", 60_000, 1);
    const denied = await store.consume("alice", 60_000, 1);
    expect(denied.allowed).toBe(false);
    // Same key — caller bumps the cap to 5 → allowed again.
    const allowed = await store.consume("alice", 60_000, 5);
    expect(allowed.allowed).toBe(true);
  });
});
