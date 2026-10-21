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
  /**
   * Optional: read `key`'s current count without incrementing it (`0` when
   * missing or expired). Required by `RateLimiter.peek()`.
   */
  get?(key: string): Promise<number>;
  /** Optional: reset `key`'s expiry to `ttlMs` from now (a sliding window); no-op when missing. */
  expire?(key: string, ttlMs: number): Promise<void>;
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
  private readonly maxEntries: number;
  private readonly evictLast?: (key: string) => boolean;
  /** Map size at which `hit` next sweeps expired counters (amortized; doubles). */
  private sweepAt = MIN_SWEEP_SIZE;
  /**
   * Lower bound of every entry's `expiresAt` (exact after a sweep): while
   * `now` is below it nothing can have expired, so a sweep is skipped.
   */
  private minExpiry = Infinity;

  /**
   * - `maxEntries` caps the live counters kept (default: unbounded). At the
   *   cap a new key first sweeps expired counters, then evicts the oldest one.
   * - `evictLast` marks keys to keep while others can go: at the cap the
   *   oldest key it does NOT match is evicted first (the oldest matching one
   *   only when every key matches) — e.g. active lock markers that a flood of
   *   fresh counters must not push out.
   */
  constructor(opts?: { clock?: Clock; maxEntries?: number; evictLast?: (key: string) => boolean }) {
    this.clock = opts?.clock ?? defaultClock;
    this.maxEntries = opts?.maxEntries ?? Infinity;
    this.evictLast = opts?.evictLast;
  }

  async hit(key: string, ttlMs: number): Promise<number> {
    const now = this.clock.now();
    const entry = this.entries.get(key);
    if (!entry || entry.expiresAt <= now) {
      if (!entry && this.entries.size >= this.maxEntries) {
        if (now >= this.minExpiry) this.sweep(now);
        while (this.entries.size >= this.maxEntries) this.evictOne();
      } else if (!entry && this.entries.size >= this.sweepAt) {
        // Window keys embed their start, so dead counters are never hit again:
        // sweep them as the map grows (amortized O(1) per hit).
        if (now >= this.minExpiry) this.sweep(now);
        this.sweepAt = Math.max(MIN_SWEEP_SIZE, this.entries.size * 2);
      }
      const expiresAt = now + ttlMs;
      if (expiresAt < this.minExpiry) this.minExpiry = expiresAt;
      this.entries.delete(key);
      this.entries.set(key, { count: 1, expiresAt });
      return 1;
    }
    entry.count += 1;
    return entry.count;
  }

  /** Drop the oldest key (Map keeps insertion order), sparing `evictLast` keys while it can. */
  private evictOne(): void {
    let victim: string | undefined;
    for (const key of this.entries.keys()) {
      if (!this.evictLast?.(key)) {
        victim = key;
        break;
      }
      victim ??= key;
    }
    if (victim !== undefined) this.entries.delete(victim);
  }

  async get(key: string): Promise<number> {
    const entry = this.entries.get(key);
    return entry && entry.expiresAt > this.clock.now() ? entry.count : 0;
  }

  async expire(key: string, ttlMs: number): Promise<void> {
    const entry = this.entries.get(key);
    const now = this.clock.now();
    if (!entry || entry.expiresAt <= now) return;
    entry.expiresAt = now + ttlMs;
    if (entry.expiresAt < this.minExpiry) this.minExpiry = entry.expiresAt;
    // Re-insert: the most recently touched counter is evicted last.
    this.entries.delete(key);
    this.entries.set(key, entry);
  }

  async reset(key: string): Promise<void> {
    this.entries.delete(key);
  }

  /** Drop every counter — test-harness reset between cases. */
  clear(): void {
    this.entries.clear();
    this.minExpiry = Infinity;
  }

  async cleanup(): Promise<number> {
    return this.sweep(this.clock.now());
  }

  private sweep(now: number): number {
    let removed = 0;
    let min = Infinity;
    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= now) {
        this.entries.delete(key);
        removed++;
      } else if (entry.expiresAt < min) {
        min = entry.expiresAt;
      }
    }
    this.minExpiry = min;
    return removed;
  }
}

/** Smallest map size an amortized expiry sweep runs at. */
const MIN_SWEEP_SIZE = 1024;
