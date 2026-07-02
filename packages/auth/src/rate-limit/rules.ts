/**
 * Rate-limit rule model + the compact string grammar (RL.spec.md §4.1).
 *
 * Input rules and normalized rules are distinct types: inputs accept the
 * ergonomic forms (`'6/5m | message'`, `{ limit, window: '5m' }`),
 * `parseRateLimitRule` normalizes everything to ms. Parsing happens eagerly
 * (decoration/config time), so a bad rule string fails at boot, not per
 * request.
 */

/** Normalized rule — `window` always in ms. */
export interface RateLimitRule {
  /** Max hits per window. */
  limit: number;
  /** Window length, ms. */
  window: number;
  /** 429 message template for THIS rule (see {@link renderRateLimitMessage}). */
  message?: string;
}

/**
 * What decorators / options accept:
 *  - `'<limit>/<window>'`            — `'6/5m'`
 *  - `'<limit> per <window>'`        — `'6 per 5m'`
 *  - either form + `' | <message>'`  — `'6/5m | Wait {{delta}}'`
 *  - `{ limit, window, message? }`   — `window` in ms or `'5m'` form
 */
export type RateLimitRuleInput =
  | string
  | { limit: number; window: number | string; message?: string };

export const DEFAULT_RATE_LIMIT_MESSAGE = "Too many requests. Please try again in {{delta}}.";

const DURATION_UNITS: Record<string, number> = {
  ms: 1,
  s: 1000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
};

/** `'5m'` / `'90s'` / `'500ms'` / `'1h'` / `'2d'` → ms. Throws on anything else. */
export function parseDurationMs(input: string): number {
  const m = /^(\d+)(ms|s|m|h|d)$/.exec(input.trim());
  if (!m) {
    throw new Error(
      `Invalid rate-limit window "${input}" — expected "<int><unit>" with unit ms|s|m|h|d (e.g. "5m")`,
    );
  }
  return Number(m[1]) * DURATION_UNITS[m[2]];
}

/**
 * Humanize a ms duration for `{{window}}` / `{{delta}}` placeholders:
 * `"5 minutes"`, `"4 minutes 32 seconds"`, `"1 hour"`. Sub-second values
 * round UP to `"1 second"` — a retry hint of "0 seconds" reads as broken.
 * At most the two largest units are shown.
 */
export function formatDurationMs(ms: number): string {
  const totalSeconds = Math.max(1, Math.ceil(ms / 1000));
  const units: Array<[string, number]> = [
    ["day", 86_400],
    ["hour", 3600],
    ["minute", 60],
    ["second", 1],
  ];
  const parts: string[] = [];
  let rest = totalSeconds;
  for (const [name, size] of units) {
    if (parts.length === 2) break;
    const n = Math.floor(rest / size);
    if (n === 0) continue;
    rest -= n * size;
    parts.push(`${n} ${name}${n === 1 ? "" : "s"}`);
  }
  return parts.join(" ");
}

function parseRuleString(input: string): RateLimitRule {
  // Message is everything after the first `|` (the grammar's only `|`).
  const pipe = input.indexOf("|");
  const message = pipe >= 0 ? input.slice(pipe + 1).trim() : undefined;
  const head = (pipe >= 0 ? input.slice(0, pipe) : input).trim();
  const m = /^(\d+)\s*(?:\/|\s+per\s+)\s*(\d+(?:ms|s|m|h|d))$/i.exec(head);
  if (!m) {
    throw new Error(
      `Invalid rate-limit rule "${input}" — expected "<limit>/<window>" or "<limit> per <window>" (e.g. "6/5m", "30 per 1m"), optionally followed by " | <message>"`,
    );
  }
  return {
    limit: Number(m[1]),
    window: parseDurationMs(m[2]),
    ...(message !== undefined && message !== "" && { message }),
  };
}

function assertValidRule(rule: RateLimitRule): void {
  if (!Number.isInteger(rule.limit) || rule.limit <= 0) {
    throw new Error(
      `Invalid rate-limit rule: limit must be a positive integer (got ${rule.limit})`,
    );
  }
  if (!Number.isFinite(rule.window) || rule.window <= 0) {
    throw new Error(
      `Invalid rate-limit rule: window must be a positive ms value (got ${rule.window})`,
    );
  }
}

/** Normalize any {@link RateLimitRuleInput}. Throws on invalid grammar or non-positive values. */
export function parseRateLimitRule(input: RateLimitRuleInput): RateLimitRule {
  if (typeof input !== "string" && typeof input.window === "number") {
    // Already-normalized fast path — `RateLimiter.check()` runs on every
    // request, so rules parsed eagerly at decoration/registration time must
    // not be re-allocated here (validation is two number checks).
    assertValidRule(input as RateLimitRule);
    return input as RateLimitRule;
  }
  const rule =
    typeof input === "string"
      ? parseRuleString(input)
      : {
          limit: input.limit,
          window: parseDurationMs(input.window as string),
          ...(input.message !== undefined && { message: input.message }),
        };
  assertValidRule(rule);
  return rule;
}

/**
 * Render a 429 message template. Placeholders: `{{limit}}` (alias `{{max}}`),
 * `{{window}}` and `{{delta}}` — both humanized via {@link formatDurationMs}.
 */
export function renderRateLimitMessage(
  template: string,
  rule: RateLimitRule,
  retryAfterMs: number,
): string {
  return template
    .replaceAll("{{limit}}", String(rule.limit))
    .replaceAll("{{max}}", String(rule.limit))
    .replaceAll("{{window}}", formatDurationMs(rule.window))
    .replaceAll("{{delta}}", formatDurationMs(retryAfterMs));
}
