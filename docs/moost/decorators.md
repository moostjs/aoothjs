# Decorators

This page is the canonical reference for every decorator the two packages export. If a decorator name does not appear here, it does not exist — see the [No-such-decorator section](#decorators-that-do-not-exist) below.

## Matrix

| Decorator                        | Target                            | Package                | Effect                                                                                                                                                                               |
| -------------------------------- | --------------------------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `@Public()`                      | class / method                    | `@aoothjs/auth-moost`  | Sets BOTH `authPublic=true` AND `arbacPublic=true` on the mate. Single decorator hides the route from both guards.                                                                   |
| `@UserId()`                      | parameter                         | `@aoothjs/auth-moost`  | Resolves to `useAuth().getUserId()`. Throws `401` if no context.                                                                                                                     |
| `@AuthGuarded(opts)`             | class / method                    | `@aoothjs/auth-moost`  | Sugar for `@Intercept(authGuardInterceptor(opts))`.                                                                                                                                  |
| `@ArbacResource(name)`           | class / method                    | `@aoothjs/arbac-moost` | Sets `arbacResourceId` on the mate.                                                                                                                                                  |
| `@ArbacAction(name)`             | class / method (typically method) | `@aoothjs/arbac-moost` | Sets `arbacActionId` on the mate.                                                                                                                                                    |
| `@ArbacAuthorize()`              | class / method                    | `@aoothjs/arbac-moost` | Wraps `arbacAuthorizeInterceptor` via `Authenticate()` so swagger picks up auth-guard metadata.                                                                                      |
| `@WfTrigger({ allow?, token? })` | method                            | `@aoothjs/auth-moost`  | Wraps a method in `defineAfterInterceptor` at INTERCEPTOR priority; instantiates `WfTriggerProvider` and replies with its `handle(opts)` when the inner handler returns `undefined`. |

## `@Public()`

```ts
import { Public } from "@aoothjs/auth-moost";

@Public()
@Post("logout")
async logout() { /* ... */ }
```

The dual-purpose decorator. Writes `authPublic=true` AND `arbacPublic=true` on the moost mate. Effect:

- **Auth guard**: no token → null context, handler runs anonymously. Invalid token → still null context (never throws).
- **ARBAC interceptor**: short-circuit, no scope resolution. `useArbac().isPublic` reads `true`.

::: warning `@Public()` is dual-purpose — you cannot ARBAC-gate an `@Public()` route
This is the single biggest foot-gun the API tries to prevent. The combined write was an explicit design choice: an earlier draft had `@AuthPublic()` and `@ArbacPublic()` as separate decorators, and consumers kept forgetting one, producing routes that were "public to the auth guard but ARBAC-denied to anonymous callers" or vice versa.
:::

If you genuinely need "anonymous, but ARBAC-checked" semantics (e.g. an anonymous role on `MoostArbac`), apply only `@ArbacResource` / `@ArbacAction` without `@Public()` and configure the auth guard to issue an anonymous context.

## `@UserId()`

```ts
import { UserId } from "@aoothjs/auth-moost";

@Get("me")
whoami(@UserId() userId: string) {
  return { userId };
}
```

A parameter decorator. Delegates to `Resolve(() => useAuth().getUserId())`. **Throws `HttpError(401, "Not authenticated")`** when no context — same as the underlying `getUserId()` call.

There is **no `@User()` counterpart** by design: `AuthContext` is credential context only (userId + claims + token metadata). The user _record_ lives in your `UserService`/database — fetch it with `await userService.getUser(useAuth().getUserId())` if you need it inside the handler.

## `@AuthGuarded(opts)`

Sugar for `@Intercept(authGuardInterceptor(opts))`. Use it when you want a per-controller guard instead of the global one:

```ts
@Controller("admin")
@AuthGuarded({ cookie: { name: "admin_session", path: "/admin" } })
class AdminController {
  /* ... */
}
```

## `@ArbacResource(name)` and `@ArbacAction(name)`

```ts
@Controller("articles")
@ArbacResource("articles")
class ArticlesController {
  @Get(":id")
  @ArbacAction("read")
  async read(@Param("id") id: string) {
    /* ... */
  }

  @Post()
  @ArbacAction("create")
  async create(@Body() body: NewArticle) {
    /* ... */
  }
}
```

Both write through `getArbacMate()` which is the shared moost `Mate` typed with `TArbacMeta = { arbacResourceId?, arbacActionId?, arbacPublic? }`. `TArbacMeta` is **declaration-merged** into Moost's `TMoostMetadata`.

`@ArbacResource` is most naturally a class decorator (one resource per controller). `@ArbacAction` is most naturally a method decorator (one action per endpoint). Both can be applied at either level — see the [resolution chain](./arbac-authorize#resource-resolution-chain).

## `@ArbacAuthorize()`

Wraps `arbacAuthorizeInterceptor` via `Authenticate(arbacAuthorizeInterceptor)`. Two reasons to use it:

1. You apply the interceptor per-handler instead of globally.
2. You want `@moostjs/swagger` to mark the endpoint as auth-required in the generated OpenAPI document.

When the interceptor is global, `@ArbacAuthorize()` is structurally redundant (attaches the same interceptor at the same priority — moost dedupes by reference).

## `@WfTrigger({ allow?, token? })`

Method decorator used on the `AuthController.triggerWf()` endpoint (and your subclasses of it). When the wrapped handler returns `undefined`, the after-interceptor instantiates `WfTriggerProvider` and replies with its `handle(opts)`. Subclasses that need to short-circuit return any non-`undefined` value.

```ts
@Inherit()
@Controller("auth")
class MyAuthController extends AuthController {
  @Post("trigger")
  @Public()
  @WfTrigger({ allow: [...DEFAULT_AUTH_WORKFLOWS, "project.handover"] })
  override triggerWf(): void {
    /* intentionally empty */
  }
}
```

See [REST Controllers](./controllers) and [Workflows](./workflows) for full coverage of the trigger surface.

## Mate types

The mate shape is two small interfaces, declaration-merged into Moost's `TMoostMetadata`:

```ts
// from @aoothjs/auth-moost
interface TAuthMeta {
  authPublic?: boolean;
}

// from @aoothjs/arbac-moost
interface TArbacMeta {
  arbacResourceId?: string;
  arbacActionId?: string;
  arbacPublic?: boolean;
}
```

Accessors:

```ts
import { getAuthMate } from "@aoothjs/auth-moost";
import { getArbacMate } from "@aoothjs/arbac-moost";

const authMeta = getAuthMate().read(SomeClass); // class-level
const authMeta = getAuthMate().read(SomeClass.prototype, "methodName"); // method-level
```

Most apps never touch the mate directly. The decorators above are the supported surface.

## Decorators that do NOT exist

The following names are commonly searched for but are **not exported**. Don't try to import them.

| Name              | Why it doesn't exist                                                               | Use instead                                                                                                                |
| ----------------- | ---------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `@ArbacPublic()`  | The split-decorator design was a foot-gun; combined into auth-moost's `@Public()`. | `@Public()` from `@aoothjs/auth-moost`.                                                                                    |
| `@AuthPublic()`   | Same.                                                                              | `@Public()`.                                                                                                               |
| `@ArbacScopes()`  | Scopes are a runtime concept (produced by the engine, not declared via metadata).  | `useArbac().getScopes<TScope>()` directly in the handler.                                                                  |
| `@User()`         | `AuthContext` is credential context, not user record.                              | `useAuth().getAuthContext()` for the credential context, or `userService.getUser(useAuth().getUserId())` for the user row. |
| `@Roles('admin')` | Roles live in `MoostArbac` rules, not in route metadata.                           | `arbac.registerRole(defineRole().allow(...).build())` and let the interceptor enforce it.                                  |

::: warning No `@ArbacPublic()` — use `@Public()`
`@ArbacPublic` is not exported from `@aoothjs/arbac-moost`. The `arbacPublic` mate flag is written by `@aoothjs/auth-moost`'s combined `@Public()`. The two packages share this single decorator on purpose; splitting them was a foot-gun.
:::

## See also

- [AuthGuard & useAuth](./auth-guard) — how `@Public()` is interpreted by the auth side.
- [ARBAC Authorize](./arbac-authorize) — how `@ArbacResource` / `@ArbacAction` / `@Public()` are interpreted by the ARBAC side.
- [REST Controllers](./controllers) — `@WfTrigger` on `/auth/trigger`.
