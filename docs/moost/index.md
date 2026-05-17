# Moost Integration

This section answers: _how do I plug aoothjs into a Moost HTTP app, in what order, with which decorators, and which extension seams should I override?_ It covers two packages that together form the framework glue layer:

| Package                                                                                     | Concern                                                                                                                                                                |
| ------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`@aoothjs/auth-moost`](https://github.com/moostjs/aoothjs/tree/main/packages/auth-moost)   | Authentication. `authGuardInterceptor`, `useAuth()`, `AuthController`, `LoginWorkflow` / `RecoveryWorkflow` / `InviteWorkflow`, magic-link outlets.                    |
| [`@aoothjs/arbac-moost`](https://github.com/moostjs/aoothjs/tree/main/packages/arbac-moost) | Authorization. `arbacAuthorizeInterceptor`, `useArbac()`, `@ArbacResource` / `@ArbacAction` / `@ArbacAuthorize`, `AsArbacDbController`, atscript-driven user provider. |

The two packages share one decorator on purpose: [`@Public()`](./decorators) writes both `authPublic=true` and `arbacPublic=true`, so a single annotation hides a route from both guards. Splitting the two into separate decorators was — in practice — a foot-gun.

::: warning Both guards are GUARD-priority interceptors
The auth guard and the ARBAC interceptor are both `defineBeforeInterceptor` at `TInterceptorPriority.GUARD`. The auth guard runs first (it has no dependencies on ARBAC state); the ARBAC interceptor calls `useAuth().getUserId()` indirectly through your `ArbacUserProvider`. Apply them in that order.
:::

## Where to start

| If you want to…                                                                                         | Read                                 |
| ------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| Bootstrap a fresh app with both layers wired                                                            | [Setup](./setup)                     |
| Understand `authGuardInterceptor` token extraction, public-route handling, 401 mapping                  | [AuthGuard & useAuth](./auth-guard)  |
| Understand `arbacAuthorizeInterceptor` resource/action resolution, scope plumbing, 403 mapping          | [ARBAC Authorize](./arbac-authorize) |
| Look up every decorator and composable in one place                                                     | [Decorators](./decorators)           |
| Wire up `/auth/logout` / `/auth/refresh` / `/auth/status` / `/auth/trigger`                             | [REST Controllers](./controllers)    |
| Configure `LoginWorkflow` / `RecoveryWorkflow` / `InviteWorkflow`, subclass them, hook the email outlet | [Workflows](./workflows)             |
| Add ARBAC scopes to your `AsDbController`-derived REST endpoints                                        | [DB Controllers](./db-controllers)   |
| Drive `@arbac.*` annotations from `.as` user models                                                     | [Atscript Models](./atscript)        |
| Wire an audit sink                                                                                      | [Audit Log](./audit)                 |
| Look up `AuthOptions` and per-workflow tuning knobs                                                     | [Config Reference](./config)         |

## Mental model

```
HTTP request
   │
   ▼
authGuardInterceptor (GUARD)        ← reads bearer / cookie token, sets AuthContext or null
   │
   ▼
arbacAuthorizeInterceptor (GUARD)   ← resolves resource/action via @ArbacResource/@ArbacAction
   │                                   evaluates against ArbacUserProvider(roles, attrs)
   │                                   sets per-event scopes; 403 on deny
   ▼
@Intercept / @Pipe (INTERCEPTOR / PIPE priorities)
   │
   ▼
Handler
   │  useAuth().getUserId()          ← throws 401 if no context
   │  useArbac().getScopes()         ← reads scopes set by the interceptor
   ▼
Response
```

Workflow events (`@moostjs/event-wf`) inherit the originating HTTP event's `AuthContext` and option slot through Moost's `parent` chain. `useAuth()` and `useArbac()` traverse the parent chain so handler code inside a `@Step` can call them as if it were running inline. See [Workflows](./workflows) for the details.
