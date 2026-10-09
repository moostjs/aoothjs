import { type Clock, defaultClock } from "../utils/clock";
import type { DenylistStore } from "./store";

// Re-exported so existing import sites continue to compile.
export type { Clock } from "../utils/clock";

/**
 * In-memory denylist for stateless revocation.
 *
 * Stores a map from JTI (or any opaque identifier) to absolute expiry timestamp.
 * `has` returns false for entries whose TTL has elapsed and lazily removes them;
 * `add` sweeps expired entries as the map grows (amortized, each time it
 * doubles). `cleanup` performs a sweep on demand and returns the number of
 * entries removed.
 */
export class DenylistStoreMemory implements DenylistStore {
  private readonly entries = new Map<string, number>();
  private readonly clock: Clock;
  /** Map size at which `add` next sweeps expired entries (amortized; doubles). */
  private sweepAt = MIN_SWEEP_SIZE;

  constructor(opts?: { clock?: Clock }) {
    this.clock = opts?.clock ?? defaultClock;
  }

  async add(jti: string, expiresAt: number): Promise<void> {
    if (this.entries.size >= this.sweepAt && !this.entries.has(jti)) {
      this.sweep(this.clock.now());
      this.sweepAt = Math.max(MIN_SWEEP_SIZE, this.entries.size * 2);
    }
    this.entries.set(jti, expiresAt);
  }

  async has(jti: string): Promise<boolean> {
    const expiresAt = this.entries.get(jti);
    if (expiresAt === undefined) return false;
    if (expiresAt <= this.clock.now()) {
      this.entries.delete(jti);
      return false;
    }
    return true;
  }

  async cleanup(): Promise<number> {
    return this.sweep(this.clock.now());
  }

  private sweep(now: number): number {
    let removed = 0;
    for (const [jti, expiresAt] of this.entries) {
      if (expiresAt <= now) {
        this.entries.delete(jti);
        removed++;
      }
    }
    return removed;
  }
}

/** Smallest map size an amortized expiry sweep runs at. */
const MIN_SWEEP_SIZE = 1024;
