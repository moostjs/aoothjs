# ARBAC Authorize

This page answers: _how does `arbacAuthorizeInterceptor` resolve the resource and action, how does it call the engine, and how does the handler read back the scopes the engine returned?_

## `arbacAuthorizeInterceptor`

```ts
import { arbacAuthorizeInterceptor } from "@aoothjs/arbac-moost";

app.applyGlobalInterceptors(arbacAuthorizeInterceptor);
```

A `defineBeforeInterceptor` at `TInterceptorPriority.GUARD`. Algorithm:

1. Pull `setScopes`, `evaluate`, `resource`, `action`, `isPublic` from `useArbac()`.
2. Short-circuit (no-op) when `!action || !resource || isPublic`. Public bypass and "no metadata at all" pass through. Works across event kinds — HTTP, WF, CLI, WS.
3. `await evaluate()`. On `allowed: false` → `throw HttpError(403, 'Insufficient privileges for action "${action}" on resource "${resource}"')`. On `allowed: true` → `setScopes(scopes)` for downstream `getScopes()` reads.
4. Any **non-`HttpError`** raised during evaluation (e.g. the user provider couldn't find the user) is rethrown as `HttpError(401)` preserving the original message.

The interceptor is decorated with `Object.assign(..., { __authTransports: {} as TAuthTransportDeclaration })` so `@moostjs/swagger` sees it as an auth-guard with no transport requirement: ARBAC enforces **authorization, not authentication**. Pair it with `authGuardInterceptor` upstream.

::: warning Strict-by-default action resolution
A handler with no decorators at all gets `resource = ClassName`, `action = methodName`. A globally-applied `arbacAuthorizeInterceptor` will then **deny** unless a matching grant exists in `MoostArbac`. There is no "permissive default". This is a deliberate fail-closed design — accidentally exposing a route without auth requires deleting decorators, not adding them.
:::

## `@ArbacAuthorize()` — per-handler attach

`@ArbacAuthorize()` is sugar that wraps `arbacAuthorizeInterceptor` via `Authenticate()`, so `@moostjs/swagger` picks up the auth-guard metadata. Use it when you do **not** apply the interceptor globally:

```ts
@Controller("articles")
@ArbacResource("articles")
class ArticlesController {
  @Get(":id")
  @ArbacAction("read")
  @ArbacAuthorize()
  async read(@Param("id") id: string) {
    /* ... */
  }
}
```

When the interceptor is global, `@ArbacAuthorize()` is redundant — both attach the same interceptor at the same priority, so the second copy is a no-op. Most apps pick one strategy and stick to it.

## The 401 vs 403 split

| Cause                                                                       | Response                                                                       |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| No token / invalid token (caught by [`authGuardInterceptor`](./auth-guard)) | `401 Unauthorized` / `401 Invalid credential`                                  |
| User provider can't find the user (e.g. JWT subject doesn't map to a row)   | `401 <original message>` — non-`HttpError` rewrapped                           |
| User found, but no role grants this `resource`/`action`                     | `403 Insufficient privileges for action "${action}" on resource "${resource}"` |
| `@Public()` route, no token                                                 | Handler runs with null context (no 401, no 403)                                |

## `useArbac()` — the composable

```ts
const arbac = useArbac();
arbac.resource; // string  — resolved resource id
arbac.action; // string  — resolved action id
arbac.isPublic; // boolean — true if @Public()
arbac.getScopes(); // TScope[] | undefined — set by the interceptor on allow
arbac.setScopes(s); // back-channel used by the interceptor itself
arbac.evaluate(); // returns { allowed, scopes?, userId }
arbac.evaluateOrThrow(); // same but throws 403 on deny
```

::: warning `useArbac` is intentionally NOT a wook
Workflow events created via `WfTriggerProvider.handle()` carry the originating HTTP `EventContext` as `parent`. A wook cache would traverse the parent chain and replay the **HTTP request's** first-resolution `(resource, action)` tuple, silently bypassing the class-level `@ArbacResource` on the workflow controller. So `useArbac()` re-resolves metadata per call. The cost is a few mate reads per request — well under a millisecond.
:::

### Resource resolution chain

| Step | Lookup                                                                           |
| ---- | -------------------------------------------------------------------------------- |
| 1    | Method-level `arbacResourceId` mate (set by `@ArbacResource(...)` on the method) |
| 2    | Class-level `arbacResourceId` mate (set by `@ArbacResource(...)` on the class)   |
| 3    | Class-level `id` mate (set by Moost's `@Controller(id)`)                         |
| 4    | `constructor.name`                                                               |

Step 4 is the strict-by-default fallback. A bare `class FooController` with no decorators resolves to `resource = "FooController"`. **No global authorize interceptor will ever allow that** unless you wrote a role with `allow('FooController', '*')`.

### Action resolution chain

| Step | Lookup                                                                                                                    |
| ---- | ------------------------------------------------------------------------------------------------------------------------- |
| 1    | Method-level `arbacActionId` mate (set by `@ArbacAction(...)`)                                                            |
| 2    | Method-level `atscript_db_action.name` mate (set by `@atscript/moost-db`'s declarative actions — deliberate side-channel) |
| 3    | Class-level `arbacActionId` mate                                                                                          |
| 4    | Method-level `id` mate                                                                                                    |
| 5    | The raw method name via `cc.getMethod()`                                                                                  |

The `atscript_db_action` read is how `AsArbacDbController` lets `@atscript/moost-db`'s declarative actions (`@Action('publish')`-style decorators) flow into ARBAC without you having to write `@ArbacAction` twice.

### `isPublic`

`mMeta.arbacPublic || cMeta.arbacPublic`. Both flags are written by [`@Public()`](./decorators) — the auth-moost decorator writes **both** `authPublic` and `arbacPublic` so a single decorator hides a route from both guards.

### `getScopes<TScope>(): TScope[] | undefined` / `setScopes(scopes)`

Reads and writes the per-event scopes slot keyed by `arbacScopesKey = key('arbac.scopes')`. The interceptor writes via `setScopes(...)`; handler code reads via `getScopes<TScope>()`.

```ts
@Get(":id")
@ArbacAction("read")
async read(@Param("id") id: string) {
  const scopes = useArbac().getScopes<MyScope>();
  return db.articles.find(id, { restrict: mergeScopes(scopes) });
}
```

For DB-backed CRUD, [`AsArbacDbController`](./db-controllers) auto-applies scopes inside its hooks — no explicit `getScopes()` call needed.

### `evaluate({ resource?, action? }?)`

Instantiates `ArbacUserProviderToken` and `MoostArbac` via `cc.instantiate(...)`, builds `{ id, roles, attrs: id => provider.getAttrs(id) }`, and calls `arbac.evaluate(...)`. Returns `{ allowed, scopes?, userId }`.

Throws if `resource` or `action` cannot be resolved through their resolution chains (i.e. you passed neither and the metadata is missing).

### `evaluateOrThrow(...)`

Identical to `evaluate(...)` but throws `HttpError(403, "Forbidden: ${r}/${a}")` on deny. Use it in handlers that perform a secondary ARBAC check against a different resource:

```ts
@Post("publish")
async publish(@Param("id") id: string) {
  await useArbac().evaluateOrThrow({ resource: "articles", action: "publish" });
  return articles.publish(id);
}
```

## Per-request flow

```
HTTP request
   │
   ▼
authGuardInterceptor                  (GUARD; sets AuthContext)
   │
   ▼
arbacAuthorizeInterceptor             (GUARD; calls useArbac().evaluate())
   │   │
   │   ├─ useArbac() reads (resource, action, isPublic) from mate
   │   ├─ instantiate(ArbacUserProviderToken).getUserId() → reads useAuth()
   │   ├─ provider.getRoles(userId), provider.getAttrs(userId)
   │   └─ MoostArbac.evaluate({resource,action}, {id,roles,attrs})
   │       → { allowed, scopes }
   │
   ▼  on allow: setScopes(scopes); continue
       on deny:  HttpError(403)
       on user-provider error: HttpError(401)
   │
   ▼
Handler — useArbac().getScopes<TScope>() reads back scopes
```

## See also

- [Decorators](./decorators) — `@ArbacResource`, `@ArbacAction`, `@ArbacAuthorize`, `@Public()`.
- [DB Controllers](./db-controllers) — how `AsArbacDbController` consumes the scopes automatically.
- [Atscript Models](./atscript) — building the `ArbacUserProvider` from a `.as` annotated user type.
