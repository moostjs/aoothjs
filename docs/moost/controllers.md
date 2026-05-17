# REST Controllers

This page documents the bundled `AuthController` — its four endpoints, their decorators, request/response shapes, and how to subclass it to extend the workflow allow-list.

## `AuthController`

```ts
import { AuthController } from "@aooth/auth-moost";

app.registerControllers(AuthController);
```

Decorated `@Controller("auth") @ArbacResource("auth")`. Constructor takes a DI-provided `AuthCredential`:

```ts
constructor(private readonly auth: AuthCredential)
```

All four endpoints are `@Public()`. Authentication is enforced **inside** the handler bodies as defence-in-depth — every endpoint that requires a context calls `useAuth().getAuthContext()` and returns 401 if it's null. The reason they're public is that the routes themselves must be reachable to anonymous callers (a logged-out user trying to log in, an expired-access-token caller refreshing).

## Endpoint table

| Method | Path            | Decorators                                                | Body                                | Response                      | Notes                                                                                                                     |
| ------ | --------------- | --------------------------------------------------------- | ----------------------------------- | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `POST` | `/auth/logout`  | `@Public()`                                               | `AuthLogoutBody { refreshToken? }`  | `AuthOkResponse { ok: true }` | Defence-in-depth 401 if null context. Best-effort revokes both tokens (failures silently ignored), then `clearCookies()`. |
| `POST` | `/auth/refresh` | `@Public()`                                               | `AuthRefreshBody { refreshToken? }` | `AuthLoginResponse`           | Falls back to the refresh cookie. 401 on `AuthError`. Returns new access+refresh, writes cookies.                         |
| `GET`  | `/auth/status`  | `@Public()`                                               | —                                   | `AuthContext`                 | 401 when no context.                                                                                                      |
| `POST` | `/auth/trigger` | `@Public() @WfTrigger({ allow: DEFAULT_AUTH_WORKFLOWS })` | `{ wfid?, wfs?, input?, action? }`  | `WfFinished` envelope         | The single entry-point covering `auth.login`, `auth.recovery`, `auth.invite`.                                             |

`DEFAULT_AUTH_WORKFLOWS` is the exported `as const` allow-list:

```ts
export const DEFAULT_AUTH_WORKFLOWS = ["auth.login", "auth.recovery", "auth.invite"] as const;
```

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
2. Pulls the access token via `useAuth().extractToken()`. Best-effort calls `auth.revoke(accessToken)`. Failures are silently swallowed (logout must not block on a denied revoke).
3. Pulls `refreshToken` from the body. **No cookie fallback** — the refresh cookie's narrow path (`/auth/refresh`) means browsers don't send it to `/auth/logout`. If the client wants the refresh token revoked too, it must include it in the body.
4. Calls `useAuth().clearCookies()` to clear both `Set-Cookie` headers.

::: warning Refresh cookie path is narrow on purpose
The default `refreshCookie.path` is `/auth/refresh`, so browsers won't send it to any other path. That's why `/auth/logout` accepts a body `refreshToken` field rather than relying on the cookie. If you widen the path (e.g. to `/`), you lose the CSRF-resistance benefit — the refresh cookie is now sent on every request.
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

The single workflow trigger endpoint. The request body shape comes from `@atscript/moost-wf`'s standard wf-trigger contract:

```ts
POST /auth/trigger
Content-Type: application/json

{
  "wfid": "auth.login",     // or "auth.recovery" / "auth.invite"; ignored if wfs is present
  "wfs":  "<resume-token>", // resume an in-flight workflow; mutually exclusive with wfid
  "input": { /* form values for the current paused step */ },
  "action": "forgotPassword" // alt-action name (e.g. forgot-password, signup, magicLink, sso-<id>)
}
```

Response: `WfFinished` envelope (either a paused form, a finished response, or an aborted response) — see [Workflows](./workflows#the-wffinished-envelope-contract).

Behaviour:

1. The handler body is intentionally empty (`override triggerWf(): void { }`). `@WfTrigger({ allow: DEFAULT_AUTH_WORKFLOWS })` wraps it as a `defineAfterInterceptor` that:
   - Instantiates `WfTriggerProvider`.
   - Reads the trigger payload from body/query/cookie according to the provider's `tokenWire` config.
   - Dispatches into the requested workflow (rejecting any wfid not in `allow`).
   - Pauses on a form-input step → returns a paused envelope.
   - Finishes → returns the `WfFinished` envelope (data, redirect, choice, or aborted).
2. Cookies attached by workflow finalize steps (login `issue`, recovery `autoLoginFinish`, invite `autoLoginFinish`) flow through the `cookies` field on the envelope.

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
import { Inherit, Controller } from "moost";
import { Post } from "@moostjs/event-http";

@Inherit()
@Controller("auth")
class MyAuthController extends AuthController {
  constructor(auth: AuthCredential) {
    super(auth);
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
