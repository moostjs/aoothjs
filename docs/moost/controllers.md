# REST Controllers

This page documents the bundled `AuthController` — its seven endpoints (five `@Public()`, two ARBAC-gated), their decorators, request/response shapes, and how to subclass it to extend the workflow allow-list.

## `AuthController`

```ts
import { AuthController } from "@aooth/auth-moost";

app.registerControllers(AuthController);
```

Decorated `@Controller("auth") @ArbacResource("auth")`. Constructor takes a DI-provided `AuthCredential` plus an `@Optional()` `UserService`:

```ts
constructor(
  protected readonly auth: AuthCredential,
  @Optional() protected readonly users?: UserService,
)
```

`users` is optional — only `GET /auth/invite/post-redemption` reads it directly (returns 500 when unset); the other routes work without a `UserService` on the controller (the workflow-dispatching routes resolve `UserService` through the workflow, not this field).

**Five endpoints are `@Public()`; two are ARBAC-gated.** The public ones enforce authentication **inside** the handler bodies as defence-in-depth — every endpoint that requires a context calls `useAuth().getAuthContext()` and returns 401 if it's null. The reason they're public is that the routes themselves must be reachable to anonymous callers (a logged-out user trying to log in, an expired-access-token caller refreshing, an unauthenticated invitee redeeming a magic link). The remaining two — `POST /auth/change-password` and `POST /auth/add-mfa` — are **not** `@Public()`: they are authenticated self-service flows gated by `@ArbacResource(...) @ArbacAction("self")`, so the guard rejects anonymous (401) and unprivileged (403) callers before the handler runs (see their rows).

## Endpoint table

| Method | Path                           | Decorators                                                                                                      | Body                                       | Response                      | Notes                                                                                                                                                                                                                                                                                                                                                    |
| ------ | ------------------------------ | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------ | ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST` | `/auth/logout`                 | `@Public()`                                                                                                     | `AuthLogoutBody { refreshToken? }`         | `AuthOkResponse { ok: true }` | Defence-in-depth 401 if null context. Revokes the current session's whole token family (`revokeSession`), with token-level revokes as fallback, then `clearCookies()`.                                                                                                                                                                                   |
| `POST` | `/auth/refresh`                | `@Public()`                                                                                                     | `AuthRefreshBody { refreshToken? }`        | `AuthLoginResponse`           | Falls back to the refresh cookie. 401 on `AuthError`. Returns new access+refresh, writes cookies.                                                                                                                                                                                                                                                        |
| `GET`  | `/auth/status`                 | `@Public()`                                                                                                     | —                                          | `AuthContext`                 | 401 when no context.                                                                                                                                                                                                                                                                                                                                     |
| `POST` | `/auth/trigger`                | `@Public() @WfTrigger({ allow: DEFAULT_AUTH_WORKFLOWS })`                                                       | `{ wfs?, input?: { action?, formData? } }` | `WfFinished` envelope         | The single entry-point covering `auth/login/flow`, `auth/invite/start`, `auth/recovery/flow`, `auth/signup/flow`.                                                                                                                                                                                                                                        |
| `GET`  | `/auth/invite/post-redemption` | `@Public()`                                                                                                     | `?uid=<userId>`                            | `WfFinished` envelope         | Idempotent "already accepted" envelope for re-clicked invite links after the wf state row is evicted. Needs `UserService`.                                                                                                                                                                                                                               |
| `POST` | `/auth/change-password`        | `@ArbacResource("auth.change-password") @ArbacAction("self") @WfTrigger({ allow: [CHANGE_PASSWORD_WORKFLOW] })` | `{ wfs?, input?: { action?, formData? } }` | `WfFinished` envelope         | **Gated** trigger for `auth/change-password/flow` — NOT `@Public()`, NOT in `DEFAULT_AUTH_WORKFLOWS`. 401 if unauthenticated, 403 unless the role grants `allow("auth.change-password", "*")`. The method-level `@ArbacResource` overrides the class `"auth"`. See [Workflows — Change password](./workflows#change-password-auth-change-password-flow). |
| `POST` | `/auth/add-mfa`                | `@ArbacResource("auth.add-mfa") @ArbacAction("self") @WfTrigger({ allow: [ADD_MFA_WORKFLOW] })`                 | `{ wfs?, input?: { action?, formData? } }` | `WfFinished` envelope         | **Gated** trigger for `auth/add-mfa/flow` — the profile-maintenance twin of change-password. NOT `@Public()`, NOT in `DEFAULT_AUTH_WORKFLOWS`. 401/403 identical to above but keyed on `allow("auth.add-mfa", "*")`. See [Workflows — Add MFA method](./workflows#add-mfa-auth-add-mfa-flow).                                                            |

`DEFAULT_AUTH_WORKFLOWS` is the exported `as const` allow-list:

```ts
export const DEFAULT_AUTH_WORKFLOWS = [
  "auth/login/flow",
  "auth/invite/start",
  "auth/recovery/flow",
  "auth/signup/flow",
] as const;
```

The two gated flows are **not** in this list — `auth/change-password/flow` (`CHANGE_PASSWORD_WORKFLOW`) and `auth/add-mfa/flow` (`ADD_MFA_WORKFLOW`) are each dispatched from their own ARBAC-guarded route above, so they are unreachable from the public `/auth/trigger`. `auth/signup/flow` is public (gated by `resolveSignupPolicy().allowSignup`, off by default) — see [Workflows — Self-signup](./workflows#self-signup-auth-signup-flow).

## `POST /auth/logout`

```ts
// minimal
POST /auth/logout
Cookie: aooth_session=<access>
Content-Type: application/json

{ "refreshToken": "<optional>" }
```

Response: `{ "ok": true }`.

Behaviour:

1. If `useAuth().getAuthContext()` is null → `throw HttpError(401, "Not authenticated")`. (Defence-in-depth — the route is `@Public()` only so the handler is reachable.)
2. **Ends THIS device's whole session family.** Resolves the current `sessionId` from the auth context and best-effort calls `auth.revokeSession(userId, sessionId)` — revoking every token in the family (access + refresh + all rotations) on a store that can enumerate. This is what "log out" means now that a session is a token family: the SPA can't read the httpOnly refresh cookie, and that cookie's narrow path keeps it off `/auth/logout`, so the token-level revokes below can't reach the refresh credential on their own.
3. **Token-level fallback.** Pulls the access token via `useAuth().extractToken()` and a `refreshToken` from the body, and best-effort revokes each. This covers stateless stores (where `revokeSession` is a no-op) and is a harmless no-op once the family is already gone. Failures are silently swallowed (logout must not block on a denied revoke).
4. Calls `useAuth().clearCookies()` to clear both `Set-Cookie` headers.

Net effect: a logged-out device disappears from `auth.listSessions(userId)` immediately on a stateful store — it no longer lingers for the refresh TTL — while the user's _other_ devices keep working.

::: warning Refresh cookie path is narrow on purpose
The default `refreshCookie.path` is `/auth/refresh` (auto-derived to the controller's actual mount, see [Config Reference](./config)), so browsers won't send it to any other path. `/auth/logout` therefore can't read the refresh cookie — which is exactly why logout revokes the whole family by `sessionId` rather than relying on the cookie. A body `refreshToken` field is still accepted as a belt-and-suspenders fallback (and for stateless stores). If you widen the path (e.g. to `/`), you lose the CSRF-resistance benefit — the refresh cookie is now sent on every request.
:::

## `POST /auth/refresh`

```ts
// minimal
POST /auth/refresh
Cookie: aooth_refresh=<refresh>
Content-Type: application/json

{}
```

Response: `AuthLoginResponse`.

Behaviour:

1. Pulls `refreshToken` from the body, falls back to the refresh cookie (path-scoped so it actually arrives here).
2. If missing → 401 `Refresh token required`.
3. Calls `auth.refresh(refreshToken)`. On `AuthError` → 401 with the original message.
4. Writes new `Set-Cookie` for both access + refresh via `useAuth().writeCookies(issue)`.
5. Returns `useAuth().buildLoginResponse(userId, issue)`.

## `GET /auth/status`

Response: `AuthContext` (the stashed context).

```ts
// minimal
GET /auth/status
Cookie: aooth_session=<access>
```

Returns `{ userId, claims, expiresAt, ... }`. **401 if no context** (defence-in-depth — null bodies are not acceptable for a status check).

Use this for an SPA's "am I logged in?" probe on page load. Pair with `/auth/refresh` to bootstrap: if `/auth/status` returns 401, the SPA tries `/auth/refresh` and re-probes.

## `POST /auth/trigger`

The single workflow trigger endpoint. The request body shape is `@atscript/moost-wf`'s wf-trigger contract — the wf engine reads the action + form data directly from `body.input`:

```ts
POST /auth/trigger
Content-Type: application/json

{
  "wfs":  "<resume-token>",          // resume an in-flight workflow (absent on start)
  "input": {
    "action":   "forgotPassword",    // alt-action name (forgotPassword, signup, magicLink, sso-<id>)
    "formData": { /* values for the current paused step */ }
  }
}
```

On **start** (no `wfs`), the workflow id is supplied by the client's `<AsWfForm :name="…">` (e.g. `auth/login/flow`) — the trigger rejects any id not in `allow`. On **resume**, the `wfs` token carries the id. Response: `WfFinished` envelope (paused form, finished, or aborted) — see [Workflows](./workflows#finish-error-envelopes).

Behaviour:

1. The handler body is intentionally empty (`override triggerWf(): void { }`). `@WfTrigger({ allow: DEFAULT_AUTH_WORKFLOWS })` wraps it as a `defineAfterInterceptor` that:
   - Instantiates `WfTriggerProvider`.
   - Reads the trigger payload from body/query/cookie according to the provider's `token` wire config.
   - Dispatches into the requested workflow (rejecting any wfid not in `allow`).
   - Pauses on a form-input step → returns a paused envelope.
   - Finishes → returns the `WfFinished` envelope.
2. Cookies attached by the login/auto-login finalize steps flow through the `cookies` field on the envelope (built via `useAuth().buildFinishedCookies(issue)`).

## `GET /auth/invite/post-redemption`

A side route for re-clicked invite magic links. When an invitee clicks an already-redeemed link, the wf state row has been evicted (the resume returns `410`), so the workflow can't re-enter to render the idempotent "already accepted" envelope. The magic-link URL carries the invitee `uid` (from `buildMagicLinkUrl(kind, token, { userId })`), and this route rebuilds the same envelope from it:

```ts
GET /auth/invite/post-redemption?uid=<userId>
```

Resolves the user via the `@Optional()` `UserService` (500 if no `UserService` is wired), returns a `WfFinished` "already accepted" envelope when the invite is redeemed, or `404` when the invite is still pending. Override `protected resolveInvitePostRedemption()` to keep the `loginUrl` / `alreadyAcceptedRedirectUrl` in sync with your workflow opts.

## DTOs

```ts
// AuthLogoutBody
interface AuthLogoutBody {
  refreshToken?: string;
}

// AuthRefreshBody
interface AuthRefreshBody {
  refreshToken?: string;
}

// AuthLoginResponse
interface AuthLoginResponse {
  userId: string;
  accessExpiresAt: number;
  refreshExpiresAt?: number;
  accessToken?: string; // populated only when enableBearer === true
  refreshToken?: string; // same
}

// AuthOkResponse
interface AuthOkResponse {
  ok: true;
}
```

When `enableBearer === false`, the `accessToken` and `refreshToken` fields are omitted from the response — the browser MUST rely on cookies. The `userId` and `accessExpiresAt` fields are still useful for SPAs to schedule their next status probe.

## Subclassing `AuthController`

The most common subclass extends the workflow allow-list. Two patterns:

### Pattern A — override `triggerWf` with a wider `allow`

```ts
import { AuthController, DEFAULT_AUTH_WORKFLOWS, Public, WfTrigger } from "@aooth/auth-moost";
import { AuthCredential } from "@aooth/auth";
import { UserService } from "@aooth/user";
import { Inherit, Controller, Optional } from "moost";
import { Post } from "@moostjs/event-http";

@Inherit()
@Controller("auth")
class MyAuthController extends AuthController {
  constructor(auth: AuthCredential, @Optional() users?: UserService) {
    super(auth, users); // forward both so post-redemption keeps working
  }

  @Post("trigger")
  @Public()
  @WfTrigger({
    allow: [...DEFAULT_AUTH_WORKFLOWS, "project.handover", "tenant.onboard"],
  })
  override triggerWf(): void {
    // body intentionally empty — see AuthController.triggerWf
  }
}
```

::: warning `@Inherit()` is mandatory on the subclass
Without `@Inherit()`, moost re-scans method decorators only on the subclass body and the unoverridden endpoints (`logout`, `refresh`, `status`) disappear from the route table. The `@Inherit()` decorator flows the parent class's `@Get('status')` / `@Post('logout')` / `@Post('refresh')` metadata down.
:::

### Pattern B — replace `triggerWf` entirely

If you need conditional logic — e.g. routing to a different wf based on a header — return a non-`undefined` value from your override; the after-interceptor will skip the default `handle()` dispatch and use your return value as the response.

```ts
@Post("trigger")
@Public()
@WfTrigger({ allow: [...DEFAULT_AUTH_WORKFLOWS] })
override async triggerWf(): Promise<unknown> {
  const tenant = useRequest().rawRequest.headers["x-tenant"];
  if (tenant === "demo") return { wfid: "demo.login.short-circuit" };
  // returning undefined falls through to the default WfTriggerProvider.handle()
  return undefined;
}
```

See [Workflows](./workflows#wftriggerprovider) for the provider subclassing pattern (state store, outlets, token wire).

## See also

- [Workflows](./workflows) — what happens inside `/auth/trigger`.
- [AuthGuard & useAuth](./auth-guard) — the composable used by every endpoint above.
- [Config Reference](./config) — `AuthOptions` field-by-field.
