# Rate Limiting

`@aooth/auth-moost` turns the [core `RateLimiter`](../auth/rate-limit) into declarative HTTP throttling: a `@RateLimit()` decorator on controllers/methods, a global interceptor pair that enforces it, draft IETF `RateLimit-*` headers on every response of a limited route, and a proper `429` with `Retry-After` and a templated message on rejection.

```ts
import { RateLimiter } from "@aooth/auth";
import { RateLimitStoreRedis } from "@aooth/auth/redis";
import { authGuardInterceptor, RateLimit, rateLimitInterceptors } from "@aooth/auth-moost";

const limiter = new RateLimiter({ store: new RateLimitStoreRedis({ redis }) });

app.applyGlobalInterceptors(
  authGuardInterceptor(),
  ...rateLimitInterceptors({ limiter }), // NOTE the spread — it's a PAIR
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

The primary target is **open (public) endpoints** — login, invite acceptance, password reset, token refresh, OAuth/DCR — keyed by client IP. aooth's own refresh, invite and authorization-server token routes ship [limits of their own](#bundled-limits). The same decorator works on guarded endpoints keyed by user id.

## `@RateLimit(...rules, options?)`

Method or class decorator. Variadic rules in the [string/object grammar](../auth/rate-limit#rules), plus an optional trailing options object:

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

### Stacking decorators — independent policies

Each `@RateLimit(...)` on the same method is an **independent policy** with its own key strategy and its own bucket; a request must pass all of them:

```ts
@Public()
@RateLimit("20/1m")                                    // per client IP
@RateLimit("5/15m", { key: perAccountKey, id: "login-account" }) // per submitted account
@Post("login")
login() { /* ... */ }
```

- Several rules inside **one** decorator (`@RateLimit('1/1s', '30/1m')`) share one key and one bucket; separate decorators do not.
- Each stacked policy gets its own bucket (`<ControllerClass>.<methodName>`, `…#1`, `…#2`) unless it names one with `id`. The positional suffixes follow decorator order, so reordering or inserting a decorator moves counters between buckets — **give every stacked policy an explicit `id`**.
- Method-level policies still **replace** class-level ones; class-level policies cover methods without their own. See [Which policies apply to a route](#which-policies-apply).

::: warning Since 0.2: a second `@RateLimit` no longer replaces the first
Before 0.2 the bottom-most decorator silently won and the others were ignored. Code that reads the metadata directly sees a new shape: `TRateLimitMeta.rateLimitPolicies` (one `{ rules, options? }` per decorator) replaces `rateLimitRules` / `rateLimitOptions`.
:::

## `rateLimitInterceptors(options?)` — the interceptor pair

Returns **two** interceptor definitions — register with a spread, globally or via [`RateLimited`](#ratelimited-per-controller-sugar). Options:

| Option       | Default | Effect                                                                                                                                                                                                                              |
| ------------ | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `limiter`    | —       | The shared `RateLimiter` — wire your `RateLimitStoreRedis` here. Omitted: a memory-store limiter is created once per factory call (single-process dev/test only).                                                                   |
| `rules`      | —       | App-wide default rules applied to **every** HTTP route without its own `@RateLimit` metadata. Routes opt out with `@RateLimit(false)`.                                                                                              |
| `key`        | `'ip'`  | Default key strategy for routes whose decorator doesn't set one.                                                                                                                                                                    |
| `trustProxy` | `false` | **Deprecated** (one-time warning; removed in 0.3). `true` still trusts exactly one proxy hop, read from the app's `proxyHeaders` family. Configure [`trustProxy` on the HTTP app](#client-ip-behind-a-proxy) instead.               |
| `headers`    | `true`  | Emit draft `RateLimit-*` headers on every response of a limited route.                                                                                                                                                              |
| `message`    | —       | App-wide default 429 message template.                                                                                                                                                                                              |
| `policies`   | —       | Re-tune declared policies by `id` without redeclaring their routes: new rules replace the declared ones (key strategy, id and message stay); `false` switches one off. An unknown id throws. See [Bundled limits](#bundled-limits). |

### Client IP behind a proxy {#client-ip-behind-a-proxy}

Every client IP aooth keys on — `'ip'` rate-limit buckets, the one-time-code failure budgets, the IP recorded on sessions and device-trust bindings — is the one the HTTP app resolves (`useRequest().getIp()`). Tell the HTTP app which proxies to trust, and which header family they write:

```ts
import { createHttpApp } from "@wooksjs/event-http";

const http = new MoostHttp(
  createHttpApp({
    trustProxy: ["10.0.0.0/8"], // your load balancer's addresses (or a hop count, or a predicate)
    proxyHeaders: "x-forwarded", // or 'forwarded' (RFC 7239), whichever your proxy writes
  }),
);
```

Without `trustProxy` on the app, forwarding headers are ignored and the socket peer is the client.

::: warning Since 0.2.7: the limiter's own `trustProxy` is deprecated
`rateLimitInterceptors({ trustProxy: true })` is still honoured, with a one-time warning: it trusts exactly one hop — whatever its address — and now reads the header family the app's `proxyHeaders` names (it used to read `X-Forwarded-For` even under `proxyHeaders: 'forwarded'`, letting a client pick its own bucket). While it is set it also decides the client IP of the one-time-code budgets and session metadata. It is removed in 0.3: move the setting to the HTTP app as above, and prefer an address list over a hop count when the app is also reachable directly.
:::

### Why a pair: flood rejection before credential work

`authGuardInterceptor` is **not free on public routes** — when any `Authorization` header is present (even garbage), it runs full credential validation (a credential-store lookup or JWT verification) before tolerating the failure on `@Public()` routes. A limiter running after the guard would let an attacker force that work on every flood request. So enforcement is split by the route's _effective key strategy_, decided statically from metadata:

| Phase                                  | Owns routes keyed by                                     | Why there                                                                                            |
| -------------------------------------- | -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `BEFORE_GUARD` (before the auth guard) | `'ip'` / custom function                                 | Floods are rejected before any token/credential work.                                                |
| `AFTER_GUARD` (after the auth guard)   | any named subject (`'user'`, `'session'`, `'tenant'`, …) | Needs the [subjects map](#the-subject-seam-setratelimitsubject) / auth context the guards establish. |

The phase is decided **per policy**: a route that stacks an ip-keyed and a user-keyed policy is checked by both phases, each counting its own policies. A per-event phase marker prevents double counting when the pair is registered both globally and per-controller.

::: warning Register the PAIR, always
`app.applyGlobalInterceptors(...rateLimitInterceptors(opts))` — with the spread. Dropping the pre-guard interceptor silently loses flood protection on ip-keyed routes; dropping the post-guard one silently disables every `key: 'user'` route.
:::

### Limiter sharing

Pass one `limiter` instance and reuse it everywhere (global registration, `RateLimited` controllers, programmatic `check()` calls in workflow steps). The zero-config fallback is deliberate but narrow: created once in the factory closure, stable across requests, but private to that interceptor pair and single-process — anything beyond dev needs an explicit limiter. DI is intentionally not consulted (`RateLimiter` is a plain class from `@aooth/auth`, not `@Injectable`).

## Key strategies

```ts
type RateLimitKeyStrategy =
  | "ip"
  | "user"
  | "auto"
  | "session"
  | "refresh-token"
  | (string & {}) // any named subject kind — see the subject seam below
  | (() => string | null | undefined | Promise<string | null | undefined>);
```

| Strategy          | Subject                   | Use for                                                                                                                                                                                                                                                     |
| ----------------- | ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `'ip'`            | `ip:<addr>`               | Public endpoints (the default). The IP the HTTP app resolves ([behind a proxy](#client-ip-behind-a-proxy)). Evaluated **pre-guard**.                                                                                                                        |
| `'user'`          | `u:<userId>`              | Guarded endpoints — one budget per user regardless of source IP. Anonymous callers fall back to `ip:<addr>`.                                                                                                                                                |
| `'session'`       | `s:<sessionId>`           | One budget per **login/device** — a stolen refresh token can't burn the whole user's budget.                                                                                                                                                                |
| `'refresh-token'` | `rt:<hash of the token>`  | The refresh token the request presents — the body's `refreshToken`, else the refresh cookie — hashed, so the bearer secret never becomes a counter key. One budget per token, whatever the IP. A request without one **skips** the policy (no IP fallback). |
| `'auto'`          | same as `'user'`          | Alias — reads better on mixed public/authed routes (the anonymous-fallback makes the two behaviorally identical).                                                                                                                                           |
| any other name    | whatever the app supplied | App-defined subject kinds (`'tenant'`, `'apiKey'`, plan tier, …) populated via [`setRateLimitSubject`](#the-subject-seam-setratelimitsubject).                                                                                                              |
| function          | whatever it returns       | Custom resolver — runs inside the event context **pre-guard**, so it must be self-sufficient (see below). `null` / `undefined` skips the policy.                                                                                                            |

Precedence: decorator `key` option → interceptor `key` option → `'ip'`. Every **named** strategy is evaluated in the post-guard phase and falls back to the IP budget when nobody populated the subject — a misconfigured kind degrades to flood protection, never to one global bucket. The exception is `'refresh-token'`, which skips the policy when no token is presented.

### The subject seam — `setRateLimitSubject()`

Named strategies read from a per-event **subjects map**: subject kind → resolved caller identity. Any GUARD-priority (or earlier) code writes into it; the post-guard rate-limit phase reads from it. The map is read **first** — when it's empty, the built-in kinds `user` (`u:<userId>`) and `session` (`s:<sessionId>`) derive from the auth context aooth's guard established, and `refresh-token` from the presented refresh token, so with aooth auth alone nothing needs to write the map at all.

A custom IAM, tenant resolver, or API-key gateway supplies its own subjects the same way:

```ts
import { setRateLimitSubject } from "@aooth/auth-moost";
import { defineBeforeInterceptor, TInterceptorPriority } from "moost";

const myIamGuard = defineBeforeInterceptor(async () => {
  const principal = await resolveFromMyIam(); // your own validation
  setRateLimitSubject("user", `iam:${principal.sub}`);
  setRateLimitSubject("tenant", `t:${principal.org}`);
}, TInterceptorPriority.GUARD);
```

Routes then key on those kinds with no custom functions anywhere:

```ts
@RateLimit('30/1m',  { key: 'user' })    // per IAM principal
@RateLimit('100/1m', { key: 'tenant' })  // org-wide budget
```

Rules of the seam:

- Values are used **verbatim** as the counter subject — include your own prefix (`iam:`, `t:`) so distinct kinds can't collide in a shared-`id` bucket.
- An explicit write **wins** over aooth's built-in `user`/`session` derivation, regardless of guard ordering — the app knows better.
- Writers must run at `GUARD` priority or earlier; the post-guard phase is the reader. A subject written later (e.g. inside the handler) is invisible to the limiter.

### Custom key functions run pre-guard

The function form is pinned to the **pre-guard** phase (that's its point — flood rejection before credential work), so it cannot read anything GUARD-priority code sets, including `useAuth()` and the subjects map. Use it only for identities derivable from the raw request (an API-key header, a route param, the submitted form). For anything resolved by a guard, use a named subject instead.

A key function can also:

- **return a composite subject** — e.g. client IP + submitted username, so one attacker cannot lock a victim out by exhausting a username-only budget;
- **return `null` / `undefined` to skip** the policy for this request — nothing is counted. Use it to count only the requests that matter, e.g. only workflow submissions that carry a password.

```ts
import { useRequest } from "@wooksjs/event-http";

@RateLimit("10/15m", {
  id: "password-attempts",
  key: async () => {
    const form = await readSubmittedForm(); // your helper: the parsed body's input.formData
    if (typeof form?.password !== "string") return null; // not a password submission — skip
    return `ip:${useRequest().getIp()}|user:${String(form.username ?? "").toLowerCase()}`;
  },
})
```

When every policy of a route skips, the request carries no decision and no `RateLimit-*` headers.

## Bundled limits {#bundled-limits}

aooth's own controllers declare these policies; like every `@RateLimit` they are enforced only when the interceptor pair is installed:

| Route                                                                                                                            | Policy id                      | Rule     | Key                                             | Why                                                                                                                                                                                        |
| -------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ | -------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `POST /auth/refresh`                                                                                                             | `aooth.refresh`                | `150/5m` | `'ip'`                                          | Checked before the auth guard: a flood of junk tokens from one caller costs no credential lookups.                                                                                         |
| `POST /auth/refresh`                                                                                                             | `aooth.refresh-token`          | `10/1m`  | `'refresh-token'`                               | Caps re-presenting one refresh token from any number of IPs — a client presents a token about once per access-token lifetime (once, with rotation).                                        |
| `GET /auth/invite/post-redemption`                                                                                               | `aooth.invite-post-redemption` | `30/5m`  | `'ip'`                                          | An anonymous lookup by user id.                                                                                                                                                            |
| `POST /auth/token`                                                                                                               | `aooth.token`                  | `150/5m` | `'ip'`                                          | Every grant: code redemptions and refreshes cost store work.                                                                                                                               |
| `POST /auth/token`                                                                                                               | `aooth.token-refresh`          | `10/1m`  | the `refresh_token` of a refresh grant (hashed) | Like `aooth.refresh-token`, for OAuth clients.                                                                                                                                             |
| `POST /auth/register`                                                                                                            | `aooth.register`               | `20/1h`  | `'ip'`                                          | Each dynamic client registration writes a row.                                                                                                                                             |
| auth workflow: each recovery code, magic link or signup code requested                                                           | `aooth.send`                   | `20/15m` | `'ip'`                                          | Every request that could send (whether or not it does) — against mail-bombing an inbox. Enforced inside the workflow; over the limit the request answers the coded `429` and the run ends. |
| auth workflow: each code sent after a first factor (email/SMS second factor, MFA enrolment, channel check, federated link proof) | `aooth.send-user`              | `10/1h`  | the account (`user:<id>`)                       | Whoever holds a password can make the account's phone or inbox receive codes — against SMS pumping. Same answer as `aooth.send`.                                                           |

The refresh limits key on the IP for floods and on the token itself for replays — not on the session: the session is known only after the token is looked up, which is the work the limit guards. A request without a refresh token is not counted against a token budget; the handler answers `401` (`MISSING_REFRESH_TOKEN`).

Change or switch them off with `policies`, by policy id:

```ts
app.applyGlobalInterceptors(
  ...rateLimitInterceptors({
    limiter,
    policies: {
      "aooth.refresh": "600/5m", // a large NAT shares one IP
      "aooth.refresh-token": false, // switched off
    },
  }),
);
```

`policies` takes the **ids** of declared policies: the bundled ones above and every `@RateLimit({ id })` your code declares (declare before you configure — import your controllers first). An unknown id throws when the pair is created, so a typo cannot silently leave a limit in force. Rules are parsed when the pair is created; an empty rule list throws (use `false`).

## Which policies apply to a route {#which-policies-apply}

A route is governed by the **first** of these that exists — they never combine:

1. **Method-level** policies — the method's own `@RateLimit`s, including those it inherits from a base class. The bundled routes above all carry method-level policies, and a subclass of `AuthController` (or `AuthorizeController`) inherits them.
2. **Class-level** `@RateLimit` on the controller.
3. The interceptor's app-wide default `rules`.

So a class-level `@RateLimit` on your subclass of an aooth controller **never applies to the bundled routes** (`/auth/refresh`, `/auth/token`, `/auth/register`, invite redemption, …) — their inherited method-level policies win. To change their limits:

- re-tune them by id with [`policies`](#bundled-limits) — the usual way;
- or override the handler and put your own method-level `@RateLimit` on it (it replaces the inherited policies of that method).

## Response headers — the full 429 contract

With `headers: true` (default), every response of a rate-limited route carries the draft IETF `RateLimit-*` fields. `Limit` / `Remaining` / `Reset` come from the governing decision — the rejecting policy, else the one with the least budget left (the same rule [`check()`](../auth/rate-limit#check-and-the-decision) applies across rules); `RateLimit-Policy` lists every evaluated policy:

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
{
  "statusCode": 429,
  "error": "Too Many Requests",
  "message": "Too many login attempts, please wait 4 minutes 32 seconds",
  "code": "RATE_LIMITED",
  "params": { "policy": "AuthController.triggerWf", "limit": 6, "window": 300, "retryAfter": 272 }
}
```

The body is the standard moost `HttpError` JSON: `message` is the rule's rendered [message template](../auth/rate-limit#message-templates) (English by default), `code` is always `RATE_LIMITED`, and `params` holds the limited `policy` (its `id`, default `<Class>.<method>` and `#<n>` for stacked policies — set an `id` to give it a stable public name), the violated rule's `limit`, its `window` in seconds and `retryAfter` in seconds (the `Retry-After` value). To localize, translate by `code` + `params` — on the client, or on the server in the HTTP app's error-body hook — instead of parsing `message`. `headers: false` suppresses the `RateLimit-*` fields but keeps `Retry-After` and the 429 body. Legacy `X-RateLimit-*` names are deliberately not emitted.

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

It attaches **both** phases via two `@Intercept`s, so you can't accidentally lose one. Combining it with a global registration is safe — a per-event phase marker prevents double counting.

## `useRateLimit()` — reading the decision

```ts
import { useRateLimit } from "@aooth/auth-moost";

const { decision } = useRateLimit(); // RateLimitDecision | null
```

Returns the governing decision for the current event (across every evaluated policy), or `null` when the route has no rules, every policy skipped, or the interceptors aren't installed. Workflow child events inherit the originating HTTP event's slot through the parent chain — same as `useAuth()`. For programmatic checks with no decorator at all (e.g. inside a login workflow step), hold a reference to the shared `RateLimiter` and call [`check()`](../auth/rate-limit#check-and-the-decision) directly — or [`peek()`](../auth/rate-limit#peek-reading-the-budget-without-spending-it) to show "N left" without spending budget.

## Testing

Pass your own limiter to the interceptors so tests control the store, and clear it between tests:

```ts
import { RateLimiter, RateLimitStoreMemory } from "@aooth/auth";

const store = new RateLimitStoreMemory();
app.applyGlobalInterceptors(...rateLimitInterceptors({ limiter: new RateLimiter({ store }) }));

afterEach(() => store.clear()); // fresh budgets for every test
```

Inject a `clock` into the `RateLimiter` (and the store) to step through windows deterministically — see [Injectable clock](../auth/rate-limit#injectable-clock).

## DOs and DON'Ts

- **DO** spread the pair: `...rateLimitInterceptors(opts)` — **not** register a single element of the returned array.
- **DO** pass a shared `limiter` backed by `RateLimitStoreRedis` in any multi-instance deployment — the fallback memory limiter is per-process **and** per-factory-call.
- **DO** configure `trustProxy` / `proxyHeaders` on the HTTP app — **not** on `rateLimitInterceptors` (deprecated since 0.2.7, removed in 0.3).
- **DO** stack decorators for "per IP **and** per account" limits — each is its own policy — and give each an explicit `id`.
- **DO** use `@RateLimit(false)` to exempt health checks / internal routes when app-wide default `rules` are configured.
- **DO** re-tune the [bundled limits](#bundled-limits) with `policies` — **not** by subclassing the controller to redeclare a route.
- **DON'T** expect a class-level `@RateLimit` on a subclass of an aooth controller to cover its bundled routes — their method-level policies win ([precedence](#which-policies-apply)).
- **DO** give intentionally-shared budgets an explicit `id` — **not** rely on the default scope, which isolates per handler (`<ControllerClass>.<methodName>`).
- **DO** supply app-defined subjects (`tenant`, `apiKey`, external-IAM principals) from a GUARD-priority interceptor via `setRateLimitSubject` — **not** from a custom key function, which runs pre-guard and can't see guard state.
- **DON'T** expect `key: 'user'` to 429 anonymous floods _per user_ — anonymous callers share the IP fallback budget, and on guarded routes the auth guard 401s them before the post-guard phase runs (a missing token yields `401`, not `429`).
- **DON'T** use this instead of account lockout — `UserService` lockout counts failed credential attempts per account; this counts requests per caller. Complementary layers.
- **DON'T** build daily / monthly allowances ("50 exports per calendar month in the user's timezone") on `@RateLimit` — its windows are fixed, epoch-aligned durations, not calendar periods. Keep such quotas as a ledger in your database.

## See also

- [Rate Limiting (Core)](../auth/rate-limit) — rule grammar, decision fields, fixed-window semantics, memory/Redis stores.
- [AuthGuard & useAuth](./auth-guard) — the guard the pre/post phases bracket.
- [Decorators](./decorators) — the full decorator matrix.
- [API reference](/api/auth-moost#ratelimit) — exact signatures.
