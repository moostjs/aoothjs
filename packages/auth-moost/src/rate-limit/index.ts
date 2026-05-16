/**
 * Workflow-shared rate limiter.
 *
 * Used by `RecoveryWorkflow.request` to cap recovery requests per email and
 * (eventually) by `InviteWorkflow` to cap admin-side invite sends. The `key`
 * parameter is workflow-defined — for recovery it is the inbound email, for
 * invite it is the admin's `userId` — the store treats it opaquely.
 *
 * The in-memory default ships per-process; consumers running multiple
 * instances register a Redis-backed implementation via the
 * `WORKFLOW_RATE_LIMIT_STORE_TOKEN` DI token to keep counts shared.
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
