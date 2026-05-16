/**
 * Workflow-shared rate limiter.
 *
 * Phase 4 of the OOP-reshape dropped rate-limiting from the auth workflow
 * surface entirely — consumers who want a cap wire it themselves at the
 * trigger / HTTP layer. This interface + the in-memory default ship for that
 * use-case. The `key` parameter is consumer-defined (typically the inbound
 * email for recovery, the admin's `userId` for invite); the store treats it
 * opaquely.
 *
 * The in-memory default ships per-process; consumers running multiple
 * instances replace it with a Redis-backed implementation so counts are
 * shared across replicas.
 */
export interface WorkflowRateLimitConsumeResult {
  /** True when the request fits inside the window; false when the cap was hit. */
  allowed: boolean;
  /** Remaining headroom after this call (`max - count`); 0 when the cap was hit. */
  remaining: number;
  /** Unix-ms timestamp at which the oldest hit in the window expires. */
  resetAt: number;
}

export interface WorkflowRateLimitStore {
  /**
   * Record a hit against `key` and report whether it stayed under `maxCount`
   * within the rolling `windowMs` window. Always counts the call — callers
   * that need to peek without spending a hit should layer their own gate.
   */
  consume(key: string, windowMs: number, maxCount: number): Promise<WorkflowRateLimitConsumeResult>;
}

/**
 * In-memory `WorkflowRateLimitStore` keyed by `key`. Each entry holds the list
 * of hit-timestamps inside the window; expired timestamps are dropped lazily on
 * each `consume` so memory stays bounded by the active key set.
 *
 * Single-process only — multi-instance deployments must swap in a Redis-backed
 * store so the cap actually limits across replicas.
 */
export class WorkflowRateLimitStoreMemory implements WorkflowRateLimitStore {
  private readonly hits = new Map<string, number[]>();

  async consume(
    key: string,
    windowMs: number,
    maxCount: number,
  ): Promise<WorkflowRateLimitConsumeResult> {
    const now = Date.now();
    const cutoff = now - windowMs;
    const existing = this.hits.get(key) ?? [];
    const live = existing.filter((t) => t > cutoff);
    // Cap stored timestamps at `maxCount`. Beyond that the result (denied) does
    // not depend on the new timestamp, and pushing unconditionally would let a
    // sustained attacker grow the array without bound within the window.
    const allowed = live.length < maxCount;
    if (allowed) live.push(now);
    this.hits.set(key, live);
    const oldest = live[0] ?? now;
    return {
      allowed,
      remaining: maxCount - live.length,
      resetAt: oldest + windowMs,
    };
  }
}
