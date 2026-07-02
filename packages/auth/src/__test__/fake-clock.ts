import type { Clock } from "../utils/clock";

/**
 * Deterministic test clock. The default start is divisible by 1h (thus 1m/1s),
 * so fixed-window math (`floor(now / window) * window`) aligns exactly and
 * specs can assert reset/retry deltas without boundary fuzz.
 */
export function fakeClock(start = 1_000_000_800_000): Clock & { advance(ms: number): void } {
  let t = start;
  return {
    now: () => t,
    advance(ms: number) {
      t += ms;
    },
  };
}
