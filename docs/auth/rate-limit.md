# Rate Limiting (Core)

`RateLimiter` is the framework-agnostic counting engine behind HTTP rate limiting: you give it a **scope** (which bucket), a **subject** (who is calling), and one or more **rules** (`'6/5m'`), and it answers with a full `RateLimitDecision` — allowed or not, remaining budget, when the window resets, and a rendered human message. It has no HTTP knowledge; the Moost layer ([`@RateLimit` & interceptors](../moost/rate-limit)) sits on top of it.

```ts
import { RateLimiter } from "@aooth/auth";

const limiter = new RateLimiter(); // in-memory store, single process

const decision = await limiter.check(
  "login", // scope — the bucket id
  "ip:203.0.113.7", // subject — the caller identity
  ["6/5m | Too many login attempts, wait {{delta}}"],
);
if (!decision.allowed) {
  // decision.retryAfterMs, decision.message → your 429
}
```

Use it directly when you need programmatic throttling (inside a workflow step, a queue consumer, an SMS sender). For HTTP routes, prefer the decorator + interceptors — they emit the response headers and the 429 for you.

## Rules

A rule is a string in the compact grammar, or an equivalent object:

```
'<limit>/<window>'                      // '6/5m'
'<limit> per <window>'                  // '6 per 5m'
'<limit>/<window> | <message template>' // '6/5m | Too many attempts, wait {{delta}}'
```

- Window units: `ms | s | m | h | d` — `'500ms'`, `'90s'`, `'5m'`, `'1h'`, `'2d'`.
- Object form: `{ limit: 6, window: "5m" }` or `{ limit: 6, window: 300_000 }` (`window` as a string uses the same unit grammar; as a number it is milliseconds).
- Several rules stack — every rule is counted on every check, and **all** must pass. Stacking a short window on a long one is the standard mitigation for fixed-window boundary bursts: `['1/1s', '30/1m']`.

`parseRateLimitRule(input)` normalizes any input form to `{ limit, window /* ms */, message? }`. Parsing is **eager** everywhere in the stack — a bad rule string throws at boot/decoration time, never per request.

### Message templates

Each rule may carry its own 429 message after `|`; `check()` also accepts a `defaultMessage` for rules without one. Placeholders:

| Placeholder             | Renders as                                           |
| ----------------------- | ---------------------------------------------------- |
| `{{limit}}` / `{{max}}` | The rule's limit, e.g. `6`                           |
| `{{window}}`            | Humanized window: `"5 minutes"`, `"1 hour"`          |
| `{{delta}}`             | Humanized time until retry: `"4 minutes 32 seconds"` |

The built-in default is `"Too many requests. Please try again in {{delta}}."` Humanization shows at most the two largest units and rounds sub-second values up to `"1 second"`.

## `check()` and the decision

```ts
const decision = await limiter.check(scope, subject, rules, { defaultMessage });
```

`RateLimitDecision` carries everything a transport needs:

| Field          | Meaning                                                                                  |
| -------------- | ---------------------------------------------------------------------------------------- |
| `allowed`      | `false` once any rule's count exceeds its limit                                          |
| `limit`        | Limit of the **governing rule** — the violated one, else the lowest-remaining one        |
| `remaining`    | Remaining budget of the governing rule                                                   |
| `resetAt`      | ms epoch when the governing window resets                                                |
| `resetAfterMs` | ms until reset, **measured with the limiter's own clock** — derive header math from this |
| `retryAfterMs` | Present when rejected: ms until the governing window frees capacity                      |
| `message`      | Present when rejected: rendered from the violated rule's template                        |
| `policies`     | Every evaluated (normalized) rule — feeds the `RateLimit-Policy` header                  |

When several rules are violated at once, the governing rule is the one whose window frees capacity **last** — a shorter hint would invite retries that are guaranteed to be rejected. When all pass, it's the rule with the lowest `remaining` (the most restrictive one), so headers always describe the tightest budget.

::: warning Use `resetAfterMs`, not `resetAt - Date.now()`
The limiter runs on an injectable clock. Re-subtracting the wall clock drifts under injected clocks (tests) and duplicates work — `resetAfterMs` is the delta the limiter already computed.
:::

## How counting works (and why TTL doesn't matter for correctness)

The algorithm is a **fixed window with window-aligned keys**: for each rule the current window starts at `floor(now / window) * window`, and that start timestamp is embedded in the store key (`<scope>:<subject>:<ruleIndex>:<windowStart>`, scope/subject URI-encoded so IPv6 addresses and `:`-containing ids can't collide). Consequences you can rely on:

- A new window is automatically a **new key** — one atomic increment decides; there is no check-then-write race, and two concurrent requests can never both sneak under the limit.
- The store TTL (set to `window × 2`) is pure garbage collection. A lost or wrong TTL leaks a few dead bytes but **never** double-counts or extends a window.
- Rejected requests count too — they cannot extend a fixed window, so accounting stays consistent without a refund path.

What it deliberately is not: a sliding window or token bucket. Per-key storage is O(1) and each rule costs one store operation; the boundary-burst tradeoff is handled by rule stacking (above).

## Stores

The storage contract is minimal — implement it to back the limiter with anything:

```ts
interface RateLimitStore {
  /** Atomically increment `key`, setting `ttlMs` expiry when the key is created; returns the new count. */
  hit(key: string, ttlMs: number): Promise<number>;
  /** Optional: drop a counter (tests / admin unblock). */
  reset?(key: string): Promise<void>;
}
```

### `RateLimitStoreMemory`

The zero-config default (`new RateLimiter()` creates one). In-process `Map` with lazy eviction on access, a `cleanup()` sweep for long-lived processes (same pattern as `DenylistStoreMemory`), and `clear()` for test-harness resets. **Single process only** — each instance/pod counts independently.

### `RateLimitStoreRedis`

Lives on the `@aooth/auth/redis` subpath next to the other Redis adapters, and uses the same structural [`RedisLike`](./stores#redislike-structural-typing) seam — no dependency on a specific Redis client:

```ts
import { Redis } from "ioredis";
import { RateLimiter } from "@aooth/auth";
import { RateLimitStoreRedis } from "@aooth/auth/redis";

const limiter = new RateLimiter({
  store: new RateLimitStoreRedis({ redis: new Redis(process.env.REDIS_URL!) }),
});
```

Keys are `aooth:rl:<limiter key>` (prefix configurable via `prefix`). Each `hit` is one `INCR`, plus one `PEXPIRE` on the first increment of a window. This is the store to use for any multi-instance deployment — budgets are shared across pods.

::: tip `RedisLike` requires `pexpire` and `incr`
The structural interface deliberately exposes `pexpire(key, ttlMs)` (milliseconds) instead of `expire` — a raw seconds-based client would satisfy an `expire` shape while silently setting 1000× TTLs. `ioredis` matches by shape; `node-redis` (`redis@4+`) users wrap the camelCase methods — see [Stores](./stores#redislike-structural-typing) for the adapter snippet.
:::

## Injectable clock

`RateLimiter` follows the repo-wide clock pattern — pass `{ clock }` for deterministic window math in tests (no timers, no sleeps):

```ts
let now = 1_000_000_800_000;
const limiter = new RateLimiter({ clock: { now: () => now } });
// ... exhaust a '2/1m' budget, then:
now += 60_000; // next window — budget restored, no waiting
```

The memory store shares the limiter's clock automatically when created by the limiter; pass the same clock explicitly if you construct the store yourself.

## DOs and DON'Ts

- **DO** stack a short rule on a long one (`'1/1s', '30/1m'`) for burst control — **not** expect a single fixed window to smooth boundary bursts.
- **DO** wire `RateLimitStoreRedis` for anything multi-instance — the memory store is per-process, so N pods silently multiply every budget by N.
- **DO** derive retry hints from `resetAfterMs` / `retryAfterMs` — not by re-subtracting `Date.now()`.
- **DON'T** re-parse rule strings per request in your own call paths — parse once at startup with `parseRateLimitRule` and pass the normalized objects (`check()` fast-paths already-normalized rules).
- **DON'T** use this as account lockout. `UserService` lockout ([Password & Lockout](../user/policy)) is per-account and persistent, and only counts failed credential attempts; this limiter is per-caller and windowed. They are complementary layers.

## See also

- [Rate Limiting in Moost](../moost/rate-limit) — `@RateLimit()` decorator, the interceptor pair, response headers, key strategies.
- [Stores](./stores) — the `RedisLike` structural seam shared by all Redis adapters.
- [API reference](/api/auth#ratelimiter) — exact signatures for `RateLimiter`, stores, and rule helpers.
