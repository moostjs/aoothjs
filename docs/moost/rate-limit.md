# Rate Limiting

`@aooth/auth-moost` turns the [core `RateLimiter`](../auth/rate-limit) into declarative HTTP throttling: a `@RateLimit()` decorator on controllers/methods, a global interceptor pair that enforces it, draft IETF `RateLimit-*` headers on every response of a limited route, and a proper `429` with `Retry-After` and a templated message on rejection.

```ts
import { RateLimiter } from "@aooth/auth";
import { RateLimitStoreRedis } from "@aooth/auth/redis";
import { authGuardInterceptor, RateLimit, rateLimitInterceptors } from "@aooth/auth-moost";

const limiter = new RateLimiter({ store: new RateLimitStoreRedis({ redis }) });

app.applyGlobalInterceptors(
  authGuardInterceptor({ auth }),
  ...rateLimitInterceptors({ limiter, trustProxy: true }), // NOTE the spread — it's a PAIR
);

@Controller("auth")
class LoginController {
  @Public()
  @RateLimit("6/5m | Too many login attempts, please wait {{delta}}")
  @Post("login")
  login() {
    /* ... */
  }

  @RateLimit("30/1m", { key: "user" }) // guarded route: one budget per user
  @Get("sessions")
  sessions() {
    /* ... */
  }
}
```

The primary target is **open (public) endpoints** — login, invite acceptance, password reset, OAuth/DCR — keyed by client IP. The same decorator works on guarded endpoints keyed by user id.

## `@RateLimit(...rules, options?)`

Method or class decorator (method-level metadata **replaces** class-level; class-level covers methods without their own). Variadic rules in the [string/object grammar](../auth/rate-limit#rules), plus an optional trailing options object:

```ts
@RateLimit('6/5m | Too many attempts, wait {{delta}}')     // one rule + message
@RateLimit('1/1s', '30/1m')                                // stacked windows
@RateLimit('100/1h', { key: 'user' })                      // per-user budget
@RateLimit({ limit: 5, window: '5m' }, { id: 'password-reset', message: '…' })
@RateLimit(false)                                          // opt out of app-wide default rules
```

| Option    | Effect                                                                                                                              |
| --------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `key`     | [Key strategy](#key-strategies) for this route; overrides the interceptor default.                                                  |
| `message` | Default 429 template for rules without an inline `\| message`.                                                                      |
| `id`      | Bucket id — handlers sharing an `id` share counters. Default scope is `<ControllerClass>.<methodName>`, i.e. per-handler isolation. |

The decorator is metadata-only (the `@Public()` pattern): it writes to the moost mate and does nothing by itself — enforcement lives in the interceptors. Rules are parsed eagerly, so a bad rule string throws at decoration (boot) time, not per request.

## `rateLimitInterceptors(options?)` — the interceptor pair

Returns **two** interceptor definitions — register with a spread, globally or via [`RateLimited`](#ratelimited-per-controller-sugar). Options:

| Option       | Default | Effect                                                                                                                                                            |
| ------------ | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `limiter`    | —       | The shared `RateLimiter` — wire your `RateLimitStoreRedis` here. Omitted: a memory-store limiter is created once per factory call (single-process dev/test only). |
| `rules`      | —       | App-wide default rules applied to **every** HTTP route without its own `@RateLimit` metadata. Routes opt out with `@RateLimit(false)`.                            |
| `key`        | `'ip'`  | Default key strategy for routes whose decorator doesn't set one.                                                                                                  |
| `trustProxy` | `false` | Use the left-most `x-forwarded-for` entry as the client IP. Enable behind a proxy/load balancer; leave off otherwise (the header is spoofable).                   |
| `headers`    | `true`  | Emit draft `RateLimit-*` headers on every response of a limited route.                                                                                            |
| `message`    | —       | App-wide default 429 message template.                                                                                                                            |

### Why a pair: flood rejection before credential work

`authGuardInterceptor` is **not free on public routes** — when any `Authorization` header is present (even garbage), it runs full credential validation (a credential-store lookup or JWT verification) before tolerating the failure on `@Public()` routes. A limiter running after the guard would let an attacker force that work on every flood request. So enforcement is split by the route's _effective key strategy_, decided statically from metadata:

| Phase                                  | Owns routes keyed by     | Why there                                                                        |
| -------------------------------------- | ------------------------ | -------------------------------------------------------------------------------- |
| `BEFORE_GUARD` (before the auth guard) | `'ip'` / custom function | Floods are rejected before any token/credential work.                            |
| `AFTER_GUARD` (after the auth guard)   | `'user'` / `'auto'`      | Needs `useAuth()` populated; targets authed traffic where the guard runs anyway. |

Exactly one phase evaluates each request, and the decision slot doubles as a dedup marker — registering the pair both globally and per-controller never double-counts.

::: warning Register the PAIR, always
`app.applyGlobalInterceptors(...rateLimitInterceptors(opts))` — with the spread. Dropping the pre-guard interceptor silently loses flood protection on ip-keyed routes; dropping the post-guard one silently disables every `key: 'user'` route.
:::

### Limiter sharing

Pass one `limiter` instance and reuse it everywhere (global registration, `RateLimited` controllers, programmatic `check()` calls in workflow steps). The zero-config fallback is deliberate but narrow: created once in the factory closure, stable across requests, but private to that interceptor pair and single-process — anything beyond dev needs an explicit limiter. DI is intentionally not consulted (`RateLimiter` is a plain class from `@aooth/auth`, not `@Injectable`).

## Key strategies

```ts
type RateLimitKeyStrategy = "ip" | "user" | "auto" | (() => string | Promise<string>);
```

| Strategy | Subject             | Use for                                                                                                           |
| -------- | ------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `'ip'`   | `ip:<addr>`         | Public endpoints (the default). Honors `trustProxy`.                                                              |
| `'user'` | `u:<userId>`        | Guarded endpoints — one budget per user regardless of source IP. Anonymous callers fall back to `ip:<addr>`.      |
| `'auto'` | same as `'user'`    | Alias — reads better on mixed public/authed routes (the anonymous-fallback makes the two behaviorally identical). |
| function | whatever it returns | Custom identity — runs inside the event context, so any composable works (tenant id, API key, `userId + ip`).     |

Precedence: decorator `key` option → interceptor `key` option → `'ip'`.

## Response headers — the full 429 contract

With `headers: true` (default), every response of a rate-limited route carries the draft IETF `RateLimit-*` fields, computed from the [governing rule](../auth/rate-limit#check-and-the-decision):

```
RateLimit-Limit: 6
RateLimit-Remaining: 2
RateLimit-Reset: 272                    ← delta-seconds until window reset
RateLimit-Policy: 6;w=300, 100;w=3600   ← every configured rule
```

On rejection, additionally:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 272
{ "statusCode": 429, "message": "Too many login attempts, please wait 4 minutes 32 seconds" }
```

The body is the standard moost `HttpError` JSON with the rule's rendered [message template](../auth/rate-limit#message-templates). `headers: false` suppresses the `RateLimit-*` fields but keeps `Retry-After` and the 429 body. Legacy `X-RateLimit-*` names are deliberately not emitted.

## `RateLimited()` — per-controller sugar

The `AuthGuarded` counterpart, for limiting one controller (or method) without a global registration:

```ts
import { RateLimited } from "@aooth/auth-moost";

@RateLimited({ limiter })
@Controller("reports")
class ReportsController {
  @RateLimit("10/1m")
  @Get("heavy")
  heavy() {
    /* ... */
  }
}
```

It attaches **both** phases via two `@Intercept`s, so you can't accidentally lose one. Combining it with a global registration is safe — the decision slot prevents double counting.

## `useRateLimit()` — reading the decision

```ts
import { useRateLimit } from "@aooth/auth-moost";

const { decision } = useRateLimit(); // RateLimitDecision | null
```

Returns the decision the interceptor computed for the current event, or `null` when the route has no rules (or the interceptors aren't installed). Workflow child events inherit the originating HTTP event's slot through the parent chain — same as `useAuth()`. For programmatic checks with no decorator at all (e.g. inside a login workflow step), hold a reference to the shared `RateLimiter` and call [`check()`](../auth/rate-limit#check-and-the-decision) directly.

## DOs and DON'Ts

- **DO** spread the pair: `...rateLimitInterceptors(opts)` — **not** register a single element of the returned array.
- **DO** pass a shared `limiter` backed by `RateLimitStoreRedis` in any multi-instance deployment — the fallback memory limiter is per-process **and** per-factory-call.
- **DO** set `trustProxy: true` only when actually behind a trusted proxy — otherwise clients can rotate budgets by forging `x-forwarded-for`.
- **DO** use `@RateLimit(false)` to exempt health checks / internal routes when app-wide default `rules` are configured.
- **DO** give intentionally-shared budgets an explicit `id` — **not** rely on the default scope, which isolates per handler (`<ControllerClass>.<methodName>`).
- **DON'T** expect `key: 'user'` to 429 anonymous floods _per user_ — anonymous callers share the IP fallback budget, and on guarded routes the auth guard 401s them before the post-guard phase runs (a missing token yields `401`, not `429`).
- **DON'T** use this instead of account lockout — `UserService` lockout counts failed credential attempts per account; this counts requests per caller. Complementary layers.

## See also

- [Rate Limiting (Core)](../auth/rate-limit) — rule grammar, decision fields, fixed-window semantics, memory/Redis stores.
- [AuthGuard & useAuth](./auth-guard) — the guard the pre/post phases bracket.
- [Decorators](./decorators) — the full decorator matrix.
- [API reference](/api/auth-moost#ratelimit) — exact signatures.
