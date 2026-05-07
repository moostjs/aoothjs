import { type Clock, defaultClock } from "../utils/clock";
import type { DenylistStore } from "./store";

// Re-exported so existing import sites continue to compile.
export type { Clock } from "../utils/clock";

/**
 * In-memory denylist for stateless revocation.
 *
 * Stores a map from JTI (or any opaque identifier) to absolute expiry timestamp.
 * `has` returns false for entries whose TTL has elapsed and lazily removes them.
 * `cleanup` performs a sweep across the map and returns the number of entries
 * removed, useful for periodic compaction in long-lived processes.
 */
export class DenylistStoreMemory implements DenylistStore {
  private readonly entries = new Map<string, number>();
  private readonly clock: Clock;

  constructor(opts?: { clock?: Clock }) {
    this.clock = opts?.clock ?? defaultClock;
  }

  async add(jti: string, expiresAt: number): Promise<void> {
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
    const now = this.clock.now();
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
