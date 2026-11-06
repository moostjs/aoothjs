import { parseRateLimitRule, type RateLimitRule } from "@aooth/auth";

/**
 * Policy ids that `rateLimitInterceptors({ policies })` accepts: every
 * `@RateLimit({ id })` registers its id when it decorates, and aooth's own
 * handler-enforced policies register below. Process-wide.
 */
const declared = new Set<string>();

/** Internal: record a policy id as re-tunable through `policies`. */
export function declareRateLimitId(id: string): void {
  declared.add(id);
}

/** Internal: whether `id` was declared (see {@link declareRateLimitId}). */
export function isDeclaredRateLimitId(id: string): boolean {
  return declared.has(id);
}

/** Internal: every declared id, sorted. */
export function declaredRateLimitIds(): string[] {
  return [...declared].toSorted();
}

/** A policy aooth enforces from inside a handler (see `enforceRateLimit`). */
export interface BundledRateLimit {
  id: string;
  rules: RateLimitRule[];
}

/** Declare a bundled handler-enforced policy: its id and parsed rule. */
function bundledRateLimit(id: string, rule: string): BundledRateLimit {
  declareRateLimitId(id);
  return { id, rules: [parseRateLimitRule(rule)] };
}

/**
 * The bundled per-IP limit on anonymous sends — recovery codes, magic links
 * and signup codes (each request that could send, whether or not it does).
 * Re-tune or switch off with `rateLimitInterceptors({ policies: { "aooth.send": … } })`.
 */
export const SEND_RATE_LIMIT = bundledRateLimit("aooth.send", "20/15m");

/**
 * The bundled per-account limit on code sends after a first factor — the
 * email/SMS second factor, MFA enrolment and channel checks, the proof code of
 * a federated account link. Keyed by the account, not the IP. Re-tune or
 * switch off with `rateLimitInterceptors({ policies: { "aooth.send-user": … } })`.
 */
export const SEND_USER_RATE_LIMIT = bundledRateLimit("aooth.send-user", "10/1h");
