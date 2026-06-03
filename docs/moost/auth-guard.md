# AuthGuard & `useAuth`

This page answers: _how does `authGuardInterceptor` decide who's authenticated, what does it stash on the event chain, and how do I read it back inside a handler?_

## `authGuardInterceptor(opts?)`

```ts
import { authGuardInterceptor } from "@aooth/auth-moost";

app.applyGlobalInterceptors(authGuardInterceptor({ cookie: { secure: false } }));
```

A factory that returns a `defineBeforeInterceptor` at `TInterceptorPriority.GUARD`. The factory call is the resolution point: `resolveAuthOptions(opts)` runs **once** and the resolved options are stashed on every event slot the interceptor sees. All later `useAuth()` calls read from that slot.

### Event-kind contract

The guard is **HTTP-only**. On non-HTTP events (WF, CLI, WS) it is a no-op.

Workflow child events started with `start({ eventContext: current() })` still see the parent HTTP event's `AuthContext` through Moost's `parent` chain — so `useAuth()` inside a `@Step` reads the original HTTP request's user.

### Token extraction precedence

| If…                                                                                           | Then…                                 |
| --------------------------------------------------------------------------------------------- | ------------------------------------- |
| `enableBearer && Authorization: Bearer <t>` is present                                        | Bearer wins.                          |
| `enableBearer` is true but no bearer header, `enableCookie` is true, access cookie is present | Cookie wins.                          |
| Both transports disabled                                                                      | No token; treated as unauthenticated. |

The same precedence is reused by [`useAuth().extractToken()`](#useauth-extracttoken-token-undefined) so workflow finalize steps can re-read whatever the guard actually accepted.

### Public-route handling

Method-level then class-level `authPublic` metadata is consulted. On `@Public()` routes:

| Scenario      | Behavior                                                             |
| ------------- | -------------------------------------------------------------------- |
| No token      | `setAuthContext(ctx, null)`, return. Handler runs with null context. |
| Invalid token | Same null behavior — never throws on a public route.                 |
| Valid token   | `setAuthContext(ctx, authContext)` and continue.                     |

### Protected routes

| Scenario      | Behavior                                         |
| ------------- | ------------------------------------------------ |
| No token      | `throw new HttpError(401, "Unauthorized")`       |
| Invalid token | `throw new HttpError(401, "Invalid credential")` |
| Valid token   | `setAuthContext(ctx, authContext)` and continue  |

::: warning The guard never auto-refreshes
Even if the access token is expired but the refresh cookie is fresh, the guard returns 401. The refresh exchange is a separate REST endpoint — see [REST Controllers](./controllers).
:::

::: warning 403 is NOT the auth guard's concern
Authorization (and 403s) are owned by [`arbacAuthorizeInterceptor`](./arbac-authorize). The auth guard answers "do I know who you are?" only.
:::

## `AuthGuarded(opts)` — per-controller sugar

`AuthGuarded(opts)` is sugar for `@Intercept(authGuardInterceptor(opts))`. Use it when you want to attach the guard to one controller instead of globally — for example, mounting a private admin sub-app at a different cookie path.

```ts
@Controller("admin")
@AuthGuarded({ cookie: { name: "admin_session", path: "/admin" } })
class AdminController {
  @Get("dashboard")
  dashboard() {
    /* ... */
  }
}
```

## `useAuth()` — the composable

`useAuth()` is a `defineWook` returning an `AuthBindings` object memoized per event. Every call after the first one in the same event returns the same instance.

```ts
import { useAuth } from "@aooth/auth-moost";

const auth = useAuth();
auth.isAuthenticated();         // boolean
auth.getAuthContext();          // AuthContext | null
auth.getUserId();               // string  — throws 401 if null
auth.options;                   // ResolvedAuthOptions — throws 500 if no guard
auth.extractToken();            // string | undefined
auth.writeCookies(issueResult); // set Set-Cookie headers
auth.clearCookies();            // clear both cookies
auth.buildLoginResponse(uid, issue);    // AuthLoginResponse
auth.buildFinishedCookies(issue);       // WfFinishedResponse["cookies"]
auth.cookieAttrs(extra?);       // raw cookie attrs (CookieSetSerialized)
```

### `getAuthContext<TClaims>(): AuthContext<TClaims> | null`

Returns the stashed context or `null`. Generic so you can type your custom claims:

```ts
const ctx = useAuth().getAuthContext<{ tenantId: string }>();
if (ctx) {
  const tenant = ctx.claims.tenantId;
}
```

### `getUserId(): string`

Returns the resolved user id, or **throws `HttpError(401, "Not authenticated")`** when no context. The `@UserId()` parameter decorator delegates to this method.

### `isAuthenticated(): boolean`

Non-throwing boolean version of `getUserId()`. Use it when a handler accepts both anonymous and authenticated callers.

### `options` (getter): `ResolvedAuthOptions`

Returns the resolved options object stashed by the factory. **Throws `HttpError(500)`** when no `authGuardInterceptor(opts)` has run on the chain — a configuration error, not a runtime fallback. Workflows depend on this for `auth.buildFinishedCookies(...)` to know the cookie name / path / Secure flag.

::: warning `useAuth().options` throws 500 outside the guard chain
This is intentional. The package treats "the guard never ran" as a deployment bug, not a runtime condition. If you need the auth options inside a non-HTTP event, attach `authGuardInterceptor` to a parent HTTP event (workflows naturally inherit it through Moost's `parent` chain).
:::

### `extractToken(): string | undefined`

Same Bearer-wins precedence as the guard. Returns the raw token string, or `undefined` when no token is present at all.

### `writeCookies(issue: IssueResult)` / `clearCookies()`

Writes (or clears) the `aooth_session` + `aooth_refresh` `Set-Cookie` headers. **No-op when `enableCookie === false`.** The refresh cookie is written with a narrow path scoped to `AuthController`'s actual `refresh` route — auto-derived from Moost's route table at boot so it follows any mount prefix. See [Config Reference](./config) for the rationale and override.

### `buildLoginResponse(userId, issue): AuthLoginResponse`

Constructs the JSON body used by the workflow `issue` step and `/auth/refresh`. Token fields (`accessToken`, `refreshToken`) are **populated only when `enableBearer === true`**; for cookie-only deployments the body carries `userId` and the two `expiresAt` timestamps and nothing else.

### `buildFinishedCookies(issue): WfFinishedResponse["cookies"]`

Builds the `cookies` map that goes into the workflow `WfFinished` envelope. Used by the workflows' finalize step variants that need to attach cookies via the raw envelope path (auto-login on login / invite / recovery / signup):

```ts
useWfFinished().set({
  type: "data",
  value: envelope,
  cookies: auth.buildFinishedCookies(issue),
});
```

### `cookieAttrs(extra?)`

Returns the raw cookie attributes object (`{ httpOnly, secure, sameSite, domain, path }`). Useful when you want to set a custom cookie with the same SameSite / Secure / Domain as the auth cookies (e.g. a CSRF token cookie).

## When `useAuth()` runs without a guard

The four scenarios you can hit:

| Scenario                                                                                | Outcome                                               |
| --------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| Handler is on a route covered by a global `authGuardInterceptor(opts)`                  | All methods work.                                     |
| Handler is on a route with `@AuthGuarded(opts)` only                                    | All methods work.                                     |
| Handler is on a route with **no** auth guard at all, calls `useAuth().getAuthContext()` | Returns `null` (no context was set).                  |
| Same, but calls `useAuth().options`                                                     | **Throws `HttpError(500)`** — fail-loud config error. |

## See also

- [REST Controllers](./controllers) — the `/auth/logout` / `/auth/refresh` / `/auth/status` / `/auth/trigger` endpoints all consume `useAuth()` internally.
- [Decorators](./decorators) — `@Public()`, `@UserId()`, `@AuthGuarded()`.
- [Config Reference](./config) — `AuthOptions` field-by-field.
