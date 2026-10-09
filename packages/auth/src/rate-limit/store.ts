import { type Clock, defaultClock } from "../utils/clock";

/**
 * Storage contract for the fixed-window limiter (RL.spec.md §4.3).
 *
 * The limiter embeds the window start in the key, so a new window is a new
 * key and correctness never depends on the TTL — the TTL only garbage-collects
 * dead counters.
 */
export interface RateLimitStore {
  /**
   * Atomically increment `key`, setting `ttlMs` expiry when the key is
   * created; returns the new count.
   */
  hit(key: string, ttlMs: number): Promise<number>;
  /** Optional: drop a counter (tests / admin unblock). */
  reset?(key: string): Promise<void>;
}

/**
 * In-memory `RateLimitStore` — the zero-config default (single process only).
 * Lazy-evicts expired counters on access, and sweeps expired counters itself
 * as the map grows (amortized, each time it doubles); `cleanup()` sweeps the
 * whole map on demand (same pattern as `DenylistStoreMemory`).
 */
export class RateLimitStoreMemory implements RateLimitStore {
  private readonly entries = new Map<string, { count: number; expiresAt: number }>();
  private readonly clock: Clock;
  /** Map size at which `hit` next sweeps expired counters (amortized; doubles). */
  private sweepAt = MIN_SWEEP_SIZE;

  constructor(opts?: { clock?: Clock }) {
    this.clock = opts?.clock ?? defaultClock;
  }

  async hit(key: string, ttlMs: number): Promise<number> {
    const now = this.clock.now();
    const entry = this.entries.get(key);
    if (!entry || entry.expiresAt <= now) {
      // Window keys embed their start, so dead counters are never hit again:
      // sweep them as the map grows (amortized O(1) per hit).
      if (!entry && this.entries.size >= this.sweepAt) {
        this.sweep(now);
        this.sweepAt = Math.max(MIN_SWEEP_SIZE, this.entries.size * 2);
      }
      this.entries.set(key, { count: 1, expiresAt: now + ttlMs });
      return 1;
    }
    entry.count += 1;
    return entry.count;
  }

  async reset(key: string): Promise<void> {
    this.entries.delete(key);
  }

  /** Drop every counter — test-harness reset between cases. */
  clear(): void {
    this.entries.clear();
  }

  async cleanup(): Promise<number> {
    return this.sweep(this.clock.now());
  }

  private sweep(now: number): number {
    let removed = 0;
    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= now) {
        this.entries.delete(key);
        removed++;
      }
    }
    return removed;
  }
}

/** Smallest map size an amortized expiry sweep runs at. */
const MIN_SWEEP_SIZE = 1024;
