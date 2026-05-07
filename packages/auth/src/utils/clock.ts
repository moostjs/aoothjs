/**
 * Minimal time abstraction shared across stores and orchestrators.
 *
 * Defaults to wall-clock; tests inject a fake clock to deterministically
 * advance time. Kept tiny (single `now()` method) so any timing primitive
 * — Date, performance.now-ish, monotonic, etc. — can be plugged in.
 */
export interface Clock {
  now(): number;
}

export const defaultClock: Clock = { now: () => Date.now() };
