# controllers

REST surface and composables. Covers `AuthController`'s five endpoints, `authGuardInterceptor` options, `useAuth()` / `useArbac()` API, the decorator quartet, and the 401-vs-403 split. Workflow internals live in [workflows.md](workflows.md); DB scoping in [db-controllers.md](db-controllers.md).

## Contents

- [`AuthController` REST surface](#authcontroller-rest-surface)
- [Subclassing `AuthController.triggerWf()`](#subclassing-authcontrollertriggerwf)
- [`authGuardInterceptor(opts)`](#authguardinterceptoropts)
- [`useAuth()` API](#useauth-api)
- [`useArbac()` API](#usearbac-api)
- [Decorators](#decorators)
- [401 vs 403](#401-vs-403)

## `AuthController` REST surface

Class-decorated `@Controller("auth") @ArbacResource("auth")`. Constructor `(auth: AuthCredential, @Optional() users?: UserService)` — `users` is optional; only `GET /auth/invite/post-redemption` reads it (returns 500 when unset). Five of the six routes are `@Public()`; auth is enforced **inside** those handler bodies (defence-in-depth) so anonymous callers can still reach login / refresh / invite-redeem. The exception is `POST /auth/change-password`, which is ARBAC-gated (NOT `@Public()`) — see its row.

| Method | Path                           | Decorators                                                                                                      | Body                                       | Response                      | Notes                                                                                                                                                                                                                                                                                                                                   |
| ------ | ------------------------------ | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------ | ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| POST   | `/auth/logout`                 | `@Public()`                                                                                                     | `AuthLogoutBody { refreshToken? }`         | `AuthOkResponse { ok: true }` | Defence-in-depth 401 if null context. Revokes THIS device's whole session family by `sessionId` (`revokeSession`), with access/refresh token-level revokes + `{ refreshToken? }` body as fallback (covers stateless), then `clearCookies()`. The logged-out session leaves `listSessions` immediately on a stateful store.              |
| POST   | `/auth/refresh`                | `@Public()`                                                                                                     | `AuthRefreshBody { refreshToken? }`        | `AuthLoginResponse`           | Reads body OR refresh cookie. 401 on `AuthError`. Returns new access+refresh, writes cookies.                                                                                                                                                                                                                                           |
| GET    | `/auth/status`                 | `@Public()`                                                                                                     | —                                          | `AuthContext`                 | 401 when no context. Handler runs with null context (defence-in-depth) and explicitly null-checks.                                                                                                                                                                                                                                      |
| POST   | `/auth/trigger`                | `@Public() @WfTrigger({ allow: DEFAULT_AUTH_WORKFLOWS })`                                                       | `{ wfs?, input?: { action?, formData? } }` | `WfFinished` envelope         | Single entry point covering `auth/login/flow`, `auth/invite/start`, `auth/recovery/flow`, `auth/signup/flow`. Body fields documented in [workflows.md § wire contract](workflows.md#wire-contract-auth-trigger).                                                                                                                        |
| GET    | `/auth/invite/post-redemption` | `@Public()`                                                                                                     | `?uid=<userId>`                            | `WfFinished` envelope         | Idempotent "already accepted" envelope for re-clicked invite links after the wf state row is evicted (resume would `410`). Needs the `@Optional()` `UserService` (500 if unset); `404` if invite still pending.                                                                                                                         |
| POST   | `/auth/change-password`        | `@ArbacResource("auth.change-password") @ArbacAction("self") @WfTrigger({ allow: [CHANGE_PASSWORD_WORKFLOW] })` | `{ wfs?, input?: { action?, formData? } }` | `WfFinished` envelope         | GUARDED trigger for `auth/change-password/flow` (NOT `@Public()`, NOT in `DEFAULT_AUTH_WORKFLOWS`). 401 if unauthenticated; 403 unless the principal's role grants `allow("auth.change-password","*")`. Method-level `@ArbacResource` overrides the class `"auth"`. See [workflows.md § change-password](workflows.md#change-password). |

`DEFAULT_AUTH_WORKFLOWS = ["auth/login/flow", "auth/invite/start", "auth/recovery/flow", "auth/signup/flow"] as const`. The change-password wfid is exported separately as `CHANGE_PASSWORD_WORKFLOW = "auth/change-password/flow"` — deliberately excluded from the public trigger's allow-list. (`auth/signup/flow` IS public but gated by `resolveSignupPolicy().allowSignup`, default off.)

### DTOs

```ts
interface AuthLogoutBody {
  refreshToken?: string;
}
interface AuthRefreshBody {
  refreshToken?: string;
}
interface AuthLoginResponse {
  userId: string;
  accessExpiresAt: number;
  refreshExpiresAt?: number;
  accessToken?: string; // omitted when enableBearer === false
  refreshToken?: string; // omitted when enableBearer === false
}
interface AuthOkResponse {
  ok: true;
}
```

## Subclassing `AuthController.triggerWf()`

To add app-specific workflows to the single trigger route, subclass `AuthController` and override `triggerWf()` with an extended allow-list. `@Inherit()` carries the parent's `@Get("status")` / `@Post("logout")` / `@Post("refresh")` metadata — without it those endpoints disappear when moost re-scans the subclass.

```ts
@Inherit()
@Controller("auth")
class AppAuthController extends AuthController {
  constructor(auth: AuthCredential, @Optional() users?: UserService) {
    super(auth, users); // forward both so post-redemption keeps working
  }
  @Post("trigger")
  @Public()
  @WfTrigger({ allow: [...DEFAULT_AUTH_WORKFLOWS, "project.handover"] })
  override triggerWf(): void {
    /* body intentionally empty — interceptor does the work */
  }
}
app.registerControllers(AppAuthController);
```

The handler body is intentionally empty. `@WfTrigger` is an after-interceptor at `INTERCEPTOR` priority: when the handler returns `undefined`, it `instantiate(WfTriggerProvider)`s the provider and replies with `provider.handle(opts)`. To short-circuit, return any non-`undefined` value from your override.

## `authGuardInterceptor(opts)`

Factory — returns a `defineBeforeInterceptor` at `TInterceptorPriority.GUARD`. HTTP-only — on non-HTTP events (WF, CLI, WS) it returns immediately. `AuthGuarded(opts)` is `@Intercept(authGuardInterceptor(opts))` sugar for per-controller mounting.

`AuthOptions` fields:

| Field                | Default                            | Notes                                                                                                                                                                                                                                                   |
| -------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cookie.name`        | `'aooth_session'`                  | Access cookie name.                                                                                                                                                                                                                                     |
| `cookie.secure`      | `true`                             | HTTPS-only — flip to `false` for local HTTP dev.                                                                                                                                                                                                        |
| `cookie.sameSite`    | `'lax'`                            | `'lax' \| 'strict' \| 'none'`.                                                                                                                                                                                                                          |
| `cookie.httpOnly`    | `true`                             | —                                                                                                                                                                                                                                                       |
| `cookie.path`        | `'/'`                              | —                                                                                                                                                                                                                                                       |
| `cookie.domain`      | undefined                          | —                                                                                                                                                                                                                                                       |
| `refreshCookie.name` | `'aooth_refresh'`                  | —                                                                                                                                                                                                                                                       |
| `refreshCookie.path` | _auto-derived_ (`'/auth/refresh'`) | **Narrow path** so refresh isn't sent to other endpoints. Auto-derived at boot from `AuthController`'s actual mounted route (follows any mount prefix, e.g. `/api/auth/refresh`); set explicitly to override; ambiguous → keeps default + boot warning. |
| `refreshCookie.*`    | inherit from `cookie`              | `secure`, `sameSite`, `httpOnly`, `domain` defaults inherited.                                                                                                                                                                                          |
| `enableCookie`       | `true`                             | Disable to suppress cookie writes/reads entirely.                                                                                                                                                                                                       |
| `enableBearer`       | `true`                             | Bearer wins over cookie. Also gates `accessToken`/`refreshToken` fields in `AuthLoginResponse`.                                                                                                                                                         |

Algorithm:

1. Skip if `ctx.get(eventTypeKey) !== "http"`.
2. Stash resolved options into the per-event slot `authOptionsKey` (read later by `useAuth()`).
3. Extract token: Bearer first, then cookie.
4. Read method-level then class-level `authPublic` mate.
5. Public route:
   - No token → `setAuthContext(ctx, null)`, return.
   - Invalid token → `setAuthContext(ctx, null)`, return.
6. Protected route:
   - No token → `throw new HttpError(401, "Unauthorized")`.
   - Invalid token → `throw new HttpError(401, "Invalid credential")`.

**Never auto-refreshes** — refresh is a separate REST endpoint.

## `useAuth()` API

`useAuth()` is a `defineWook` returning an `AuthBindings` object memoized per event.

| Method                              | Returns                                       | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ----------------------------------- | --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `getAuthContext<TClaims>()`         | `AuthContext<TClaims> \| null`                | The stashed context.                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `getUserId()`                       | `string`                                      | Throws `HttpError(401, "Not authenticated")` when no context. **Returns the stable surrogate `id`** — the token `sub` claim `auth.issue(subject)` set, which is the base model's `@meta.id`. `AtscriptArbacUserProvider`'s default lookup chain (`@arbac.userId` → preferredId → `@meta.id`) already resolves to it, so do NOT add `@arbac.userId username` — that points the lookup at `username` while the subject is the `id` → every request 401s "user not found". |
| `isAuthenticated()`                 | `boolean`                                     | —                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `getSessionId()`                    | `string \| undefined`                         | "This device" — `AuthContext.sessionId`. See [sessions.md](sessions.md).                                                                                                                                                                                                                                                                                                                                                                                                |
| `listSessions(opts?)`               | `Promise<SessionInfo[] \| EnrichedSession[]>` | Session facade, scoped to current user. Reads the guard-stashed `AuthCredential`; off-request → `HttpError(500)`. See [sessions.md](sessions.md).                                                                                                                                                                                                                                                                                                                       |
| `revokeSession(sessionId)`          | `Promise<void>`                               | Revoke one of the current user's sessions.                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `revokeOtherSessions()`             | `Promise<number>`                             | Log out everywhere else; keeps current. Throws `HttpError(401)` if no current session.                                                                                                                                                                                                                                                                                                                                                                                  |
| `options` (getter)                  | `ResolvedAuthOptions`                         | **Throws `HttpError(500)`** when no `authGuardInterceptor` on chain — configuration error.                                                                                                                                                                                                                                                                                                                                                                              |
| `extractToken()`                    | `string \| null`                              | Bearer-wins precedence, same logic as the guard.                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `writeCookies(issue)`               | `void`                                        | Writes `aooth_session` + `aooth_refresh` Set-Cookie headers. No-op when `enableCookie === false`.                                                                                                                                                                                                                                                                                                                                                                       |
| `clearCookies()`                    | `void`                                        | Clears both cookies.                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `buildLoginResponse(userId, issue)` | `AuthLoginResponse`                           | Token fields populated only when `enableBearer === true`.                                                                                                                                                                                                                                                                                                                                                                                                               |
| `buildFinishedCookies(issue)`       | `Record<string, ...>`                         | Builds the `cookies` map for `WfFinishedResponse["cookies"]` — used by workflow finalize steps.                                                                                                                                                                                                                                                                                                                                                                         |
| `cookieAttrs(extra?)`               | `CookieAttrs`                                 | Raw cookie attrs for ad-hoc Set-Cookie writes.                                                                                                                                                                                                                                                                                                                                                                                                                          |

Internal helper `setAuthContext(ctx, value)` is the **only** writer — exported solely for use by the guard.

## `useArbac()` API

Returns `ArbacBindings`. **Not** a `defineWook` — re-resolves metadata per call. See invariant #4 in `SKILL.md`.

| Field / Method                      | Type                                    | Notes                                                                                                                                                                                                                            |
| ----------------------------------- | --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `resource`                          | `string`                                | Strict resolution: `mMeta.arbacResourceId → cMeta.arbacResourceId → cMeta.id → constructor.name`.                                                                                                                                |
| `action`                            | `string`                                | Resolution chain: `mMeta.arbacActionId → mMeta.atscript_db_action.name → cMeta.arbacActionId → mMeta.id → cc.getMethod()`. The `atscript_db_action` read is a deliberate side-channel into `@atscript/moost-db` method metadata. |
| `isPublic`                          | `boolean`                               | `mMeta.arbacPublic \|\| cMeta.arbacPublic`.                                                                                                                                                                                      |
| `getScopes<TScope>()`               | `TScope[] \| undefined`                 | Reads the per-event scopes slot set by `arbacAuthorizeInterceptor` on allow.                                                                                                                                                     |
| `setScopes(scopes)`                 | `void`                                  | Writes the scopes slot — used by the interceptor and `AsArbacDbController.transformFilter()`.                                                                                                                                    |
| `evaluate({ resource?, action? }?)` | `Promise<{ allowed, scopes?, userId }>` | Instantiates `ArbacUserProviderToken` and `MoostArbac` via DI; builds `{ id, roles, attrs: id => provider.getAttrs(id) }`; calls `arbac.evaluate(...)`. Throws if resource/action unresolved.                                    |
| `evaluateOrThrow(...)`              | same                                    | Throws `HttpError(403, "Forbidden: ${r}/${a}")` on deny.                                                                                                                                                                         |

`arbacAuthorizeInterceptor` short-circuits when `!action || !resource || isPublic` — public bypass works across HTTP / WF / CLI / WS event kinds.

## Decorators

| Decorator              | Target             | Writes                                   | Notes                                                                                                    |
| ---------------------- | ------------------ | ---------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `@Public()`            | class \| method    | `authPublic=true` + `arbacPublic=true`   | Dual-purpose. Imported from `@aooth/auth-moost`.                                                         |
| `@UserId()`            | parameter          | `Resolve(() => useAuth().getUserId())`   | No `@User()` counterpart — `AuthContext` is credential context only.                                     |
| `@AuthGuarded(opts)`   | class \| method    | `@Intercept(authGuardInterceptor(opts))` | Per-controller mounting sugar — use when you don't want the guard globally.                              |
| `@ArbacResource(name)` | class \| method    | `arbacResourceId`                        | —                                                                                                        |
| `@ArbacAction(name)`   | method (typically) | `arbacActionId`                          | —                                                                                                        |
| `@ArbacAuthorize()`    | class \| method    | wraps `arbacAuthorizeInterceptor`        | Implemented as `Authenticate(arbacAuthorizeInterceptor)` so `@moostjs/swagger` sees auth-guard metadata. |

`@ArbacPublic` and `@ArbacScopes` are intentionally **not exported**. Use `@Public()` for both auth+arbac bypass; read scopes via `useArbac().getScopes<T>()`.

`TArbacMeta = { arbacResourceId?, arbacActionId?, arbacPublic? }` is **declaration-merged** into `moost`'s `TMoostMetadata`.
`TAuthMeta = { authPublic? }` is declaration-merged the same way.

## 401 vs 403

| Status | Source                              | Trigger                                                                                                                                                      |
| ------ | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 401    | `authGuardInterceptor`              | Protected route + no token / invalid token.                                                                                                                  |
| 401    | `useAuth().getUserId()`             | Public route ran the handler with null context, then handler called `getUserId()`.                                                                           |
| 401    | `arbacAuthorizeInterceptor`         | Any non-`HttpError` raised during `evaluate()` (e.g. user provider rejection) is rethrown as `HttpError(401)` preserving the original message.               |
| 403    | `arbacAuthorizeInterceptor`         | `evaluate({...})` returned `{ allowed: false }`. Message: `Insufficient privileges for action "${action}" on resource "${resource}"`.                        |
| 403    | `useArbac().evaluateOrThrow()`      | Manual deny path.                                                                                                                                            |
| 404    | `AsArbacDbController.assertInScope` | Caller knows PK but row falls outside the union of role scope filters. Message: `Not found`. (Hides existence — see [db-controllers.md](db-controllers.md).) |

The auth guard never issues 403. The arbac interceptor never issues 401 from a "valid token, wrong role" path — that path is always 403.
