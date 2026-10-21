import { type Clock, defaultClock } from "../utils/clock";
import {
  DEFAULT_RATE_LIMIT_MESSAGE,
  parseRateLimitRule,
  type RateLimitRule,
  type RateLimitRuleInput,
  renderRateLimitMessage,
} from "./rules";
import { type RateLimitStore, RateLimitStoreMemory } from "./store";

export interface RateLimiterOptions {
  /** Counter storage. Default: a fresh `RateLimitStoreMemory` (single process only). */
  store?: RateLimitStore;
  /** Injectable time source for deterministic tests. */
  clock?: Clock;
}

/** The outcome of one `check()` — everything a transport needs for headers + 429. */
export interface RateLimitDecision {
  allowed: boolean;
  /** Limit of the governing rule (the violated one, else the lowest-remaining one). */
  limit: number;
  remaining: number;
  /** ms epoch when the governing window resets. */
  resetAt: number;
  /**
   * ms until the governing window resets, measured with the limiter's own
   * clock — transports derive the `RateLimit-Reset` header from this instead
   * of re-subtracting `Date.now()` (which would drift under injected clocks).
   */
  resetAfterMs: number;
  /** Present when `!allowed`: ms until the governing window frees capacity. */
  retryAfterMs?: number;
  /** Present when `!allowed`: rendered from the violated rule's message template. */
  message?: string;
  /** Every evaluated rule (for the `RateLimit-Policy` header). */
  policies: RateLimitRule[];
}

/**
 * Fixed-window rate limiter with window-aligned keys (RL.spec.md §4.2).
 *
 * For each rule the current window starts at `floor(now / window) * window`;
 * the counter key embeds that start, so a new window is automatically a new
 * key and one atomic store increment decides. All rules are hit on every
 * check (rejected requests count too — they cannot extend a fixed window).
 */
/**
 * The item that governs a combined decision: among the rejected ones (when
 * any), the one whose window frees capacity LAST — the request only becomes
 * allowed once every one passes, so a shorter hint would invite
 * guaranteed-rejected retries; otherwise the one with the least remaining
 * budget. Used across the rules of one check and across stacked policies.
 */
export function pickGoverning<T extends { resetAt: number; remaining: number }>(
  items: readonly T[],
  rejected: (item: T) => boolean,
): T {
  const failing = items.filter(rejected);
  if (failing.length > 0) return failing.reduce((a, b) => (b.resetAt > a.resetAt ? b : a));
  return items.reduce((a, b) => (b.remaining < a.remaining ? b : a));
}

export class RateLimiter {
  private readonly store: RateLimitStore;
  private readonly clock: Clock;

  constructor(opts?: RateLimiterOptions) {
    this.store = opts?.store ?? new RateLimitStoreMemory({ clock: opts?.clock });
    this.clock = opts?.clock ?? defaultClock;
  }

  /**
   * Evaluate `rules` for `scope` (handler/bucket id) + `subject` (caller
   * identity). Store keys are `<scope>:<subject>:<ruleIndex>:<windowStart>`
   * with scope/subject each URI-encoded — raw components would collide
   * (IPv6 addresses, route paths, and custom subjects all contain `:`).
   *
   * When several rules are violated at once, the governing rule is the one
   * whose window frees capacity LAST — the request only becomes allowed once
   * every rule passes, so a shorter hint would invite guaranteed-rejected
   * retries.
   */
  async check(
    scope: string,
    subject: string,
    rules: RateLimitRuleInput[],
    opts?: { defaultMessage?: string },
  ): Promise<RateLimitDecision> {
    return this.evaluate(scope, subject, rules, opts, (key, rule) =>
      this.store.hit(key, rule.window * 2),
    );
  }

  /**
   * Read the budget `check()` would see — without spending it. `remaining`
   * is what is left in each window; `allowed` says whether a `check()` made
   * now would pass. Use it for a "N left today" status line. Requires a store
   * with `get()` (both bundled stores have it).
   */
  async peek(
    scope: string,
    subject: string,
    rules: RateLimitRuleInput[],
    opts?: { defaultMessage?: string },
  ): Promise<RateLimitDecision> {
    if (!this.store.get) {
      throw new Error("RateLimiter.peek: the rate-limit store does not implement get()");
    }
    const get = this.store.get.bind(this.store);
    // A peek "spends" one hypothetical request: violated when nothing is left.
    return this.evaluate(scope, subject, rules, opts, async (key) => (await get(key)) + 1, 1);
  }

  private async evaluate(
    scope: string,
    subject: string,
    rules: RateLimitRuleInput[],
    opts: { defaultMessage?: string } | undefined,
    count: (key: string, rule: RateLimitRule) => Promise<number>,
    /** Added back to `remaining` — a peek counts one hypothetical request it never spends. */
    offset = 0,
  ): Promise<RateLimitDecision> {
    if (rules.length === 0) {
      throw new Error("RateLimiter: at least one rule is required");
    }
    const parsed = rules.map((r) => parseRateLimitRule(r));
    const now = this.clock.now();
    const keyBase = `${encodeURIComponent(scope)}:${encodeURIComponent(subject)}`;

    const evaluated = await Promise.all(
      parsed.map(async (rule, i) => {
        const windowStart = Math.floor(now / rule.window) * rule.window;
        const key = `${keyBase}:${i}:${windowStart}`;
        const n = await count(key, rule);
        return {
          rule,
          remaining: Math.max(0, rule.limit - n + offset),
          resetAt: windowStart + rule.window,
          violated: n > rule.limit,
        };
      }),
    );

    const governing = pickGoverning(evaluated, (e) => e.violated);
    const rejected = governing.violated;
    const resetAfterMs = governing.resetAt - now;
    return {
      allowed: !rejected,
      limit: governing.rule.limit,
      remaining: governing.remaining,
      resetAt: governing.resetAt,
      resetAfterMs,
      policies: parsed,
      ...(rejected && {
        retryAfterMs: resetAfterMs,
        message: renderRateLimitMessage(
          governing.rule.message ?? opts?.defaultMessage ?? DEFAULT_RATE_LIMIT_MESSAGE,
          governing.rule,
          resetAfterMs,
        ),
      }),
    };
  }
}
