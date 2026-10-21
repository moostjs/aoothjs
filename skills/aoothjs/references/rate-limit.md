# Rate limiting

Core: `RateLimiter` (`@aooth/auth`) — fixed window, window-aligned keys, `check()` counts / `peek()` reads. Moost: `@RateLimit(...)` metadata + `rateLimitInterceptors()` PAIR enforcing it (429 + `RateLimit-*` headers).

## Quick start

```ts
import { RateLimiter } from "@aooth/auth";
import { RateLimitStoreRedis } from "@aooth/auth/redis";
import { authGuardInterceptor, Public, RateLimit, rateLimitInterceptors } from "@aooth/auth-moost";

const limiter = new RateLimiter({ store: new RateLimitStoreRedis({ redis }) });
app.applyGlobalInterceptors(authGuardInterceptor(), ...rateLimitInterceptors({ limiter })); // SPREAD

@Controller("api")
class Api {
  @Public()
  @RateLimit("20/1m") // policy 1: per IP
  @RateLimit("5/15m", { key: perAccountKey, id: "acct" }) // policy 2: independent bucket
  @Post("login")
  login() {}
}
```

## Invariants

| #   | Rule                                                                                                                                                                                                                                                                                                                                                                                                                          |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Register the PAIR with a spread.** `BEFORE_GUARD` phase owns `'ip'` / function-keyed policies; `AFTER_GUARD` owns named subjects (`'user'`, `'session'`, `'auto'`, app kinds via `setRateLimitSubject`). Dropping one silently disables its policies.                                                                                                                                                                       |
| 2   | **Stacked `@RateLimit` decorators = INDEPENDENT policies** (own key + bucket; all must pass) — since 0.2; before, the last one silently replaced the others. Several rules in ONE decorator share one key + bucket. Buckets: `<Class>.<method>`, `…#1`, `…#2` unless `id` given — positional, so reordering decorators moves counters: give every stacked policy an explicit `id`. Method-level policies replace class-level. |
| 3   | **Metadata shape (since 0.2):** `TRateLimitMeta.rateLimitPolicies: { rules, options? }[]` replaces `rateLimitRules` / `rateLimitOptions`. Only matters to code reading the mate.                                                                                                                                                                                                                                              |
| 4   | **Key function** runs PRE-guard (no `useAuth()` / subjects). May return a composite subject (`ip                                                                                                                                                                                                                                                                                                                              | user:<submitted name>`) or `null`/`undefined`to SKIP the policy (nothing counted) — e.g. count only submissions carrying a password. All policies skipped →`useRateLimit().decision === null`, no headers. |
| 5   | **Decision across policies:** the rejecting one (frees capacity last), else least remaining. `RateLimit-Limit/Remaining/Reset` from it; `RateLimit-Policy` lists every evaluated policy. `useRateLimit().decision` = that governing decision.                                                                                                                                                                                 |
| 6   | **`trustProxy: true` reads the LEFT-MOST `x-forwarded-for` — spoofable behind appending proxies.** Never enable it in examples/defaults; only when the proxy in front overwrites the header.                                                                                                                                                                                                                                  |
| 7   | **`limiter.peek(scope, subject, rules)`** = same decision, nothing spent (`remaining` left, `allowed` = would a check pass). Needs `store.get()` — `RateLimitStoreMemory` / `RateLimitStoreRedis` have it (since 0.2); custom store without it → throws. Stores also gained optional `expire(key, ttlMs)` (sliding TTL); `RateLimitStoreMemory({ maxEntries })` caps counters (oldest dropped).                               |
| 8   | **Not for calendar quotas.** Windows are fixed durations aligned to the Unix epoch — a "N per calendar day/month in the user's timezone" allowance is a DB ledger, not `@RateLimit`.                                                                                                                                                                                                                                          |
| 9   | **Not account lockout.** `UserService` lockout counts failed credentials per account; limits count requests per caller. Use both.                                                                                                                                                                                                                                                                                             |
| 10  | **Multi-instance → `RateLimitStoreRedis`.** The default memory limiter is per process AND per `rateLimitInterceptors()` call.                                                                                                                                                                                                                                                                                                 |
| 11  | **Testing:** pass your own `new RateLimiter({ store })` (memory store you hold) to `rateLimitInterceptors`, call `store.clear()` between tests; inject `clock` into the limiter for window stepping.                                                                                                                                                                                                                          |
| 12  | `@RateLimit(...)` is enforced only when the interceptors are installed — this includes the bundled `GET /auth/invite/post-redemption` (`30/5m`).                                                                                                                                                                                                                                                                              |

## Key imports

```ts
import {
  RateLimiter,
  RateLimitStoreMemory,
  parseRateLimitRule,
  renderRateLimitMessage,
} from "@aooth/auth";
import type {
  RateLimitDecision,
  RateLimitRule,
  RateLimitRuleInput,
  RateLimitStore,
} from "@aooth/auth";
import { RateLimitStoreRedis } from "@aooth/auth/redis";
import {
  RateLimit,
  RateLimited,
  rateLimitInterceptors,
  useRateLimit,
  setRateLimitSubject,
  getRateLimitSubject,
  getRateLimitMate,
} from "@aooth/auth-moost";
import type {
  RateLimitDecoratorOptions,
  RateLimitKeyStrategy,
  TRateLimitMeta,
} from "@aooth/auth-moost";
```

## References

| Domain      | File                             | When                                          |
| ----------- | -------------------------------- | --------------------------------------------- |
| Controllers | [controllers.md](controllers.md) | guard ordering, bundled routes                |
| Auth stores | [auth-stores.md](auth-stores.md) | `RedisLike` seam shared with the Redis stores |

## See also

Docs: https://aoothjs.dev/auth/rate-limit · https://aoothjs.dev/moost/rate-limit
