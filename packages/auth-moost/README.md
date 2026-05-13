# @aoothjs/auth-moost

Moost integration for `@aoothjs/auth`. Ships an `AuthGuard` interceptor, a
`useAuth()` composable, an `AuthController` with five REST endpoints, and three
workflow controllers (`auth.login`, `auth.recovery`, `auth.invite`) driven by
`@atscript/moost-wf` typed forms.

## Install

```bash
pnpm add @aoothjs/auth-moost @aoothjs/auth @aoothjs/user
```

Peer dependencies:

| Peer                  | Required for                                  |
| --------------------- | --------------------------------------------- |
| `moost`               | always                                        |
| `@moostjs/event-http` | always (REST endpoints + cookie reads)        |
| `@wooksjs/event-core` | always                                        |
| `@wooksjs/event-http` | always                                        |
| `@moostjs/event-wf`   | workflows (`setupAuthWorkflows`)              |
| `@atscript/moost-wf`  | workflows (`@FormInput()` form metadata)      |
| `@atscript/typescript`| atscript form types (optional, type-only)     |

## Minimal setup

```ts
import { createHttpApp } from "@wooksjs/event-http";
import { MoostHttp } from "@moostjs/event-http";
import { Moost } from "moost";
import { AuthCredential, CredentialStoreMemory } from "@aoothjs/auth";
import { UserService, UserStoreMemory } from "@aoothjs/user";
import { setupAuthMoost } from "@aoothjs/auth-moost";

const auth = new AuthCredential({
  store: new CredentialStoreMemory(),
  method: "token",
  accessTtl: 60 * 60 * 1000, // 1h
  refresh: { ttl: 30 * 24 * 60 * 60 * 1000, rotation: "sliding" },
});
const users = new UserService(new UserStoreMemory());

const moost = new Moost();
moost.adapter(new MoostHttp(createHttpApp()));

setupAuthMoost(moost, { authCredential: auth, userService: users });

await moost.init();
```

`setupAuthMoost()` registers `AuthCredential`, `MoostAuthConfig`, and
`UserService` as DI singletons, applies `authGuardInterceptor` globally, and
auto-registers `AuthController` at `/auth`. Every handler is **protected by
default**; opt out with `@Public()`.

> Note: `applyGlobalInterceptors` and `registerControllers` append. Call
> `setupAuthMoost()` exactly once per Moost instance.

## Transport

The guard reads the access token from `Authorization: Bearer <token>` first
and falls back to a cookie when a Bearer header is absent. The refresh token
travels in a separate cookie scoped to `/auth/refresh`. Both transports are
configurable per app.

| Option          | Default                                                              | Notes                              |
| --------------- | -------------------------------------------------------------------- | ---------------------------------- |
| `enableCookie`  | `true`                                                               | Read access/refresh from cookies   |
| `enableBearer`  | `true`                                                               | Read access from `Authorization`   |
| `cookie`        | `{ name: 'aooth_session', secure: true, sameSite: 'lax', httpOnly: true, path: '/' }` | Access-token cookie attributes     |
| `refreshCookie` | `{ name: 'aooth_refresh', path: '/auth/refresh', ... }`              | Inherits secure/sameSite/httpOnly  |
| `endpoints`     | `true`                                                               | Skip `AuthController` registration |

```ts
setupAuthMoost(moost, {
  authCredential: auth,
  userService: users,
  cookie: { secure: false }, // dev only
  enableBearer: false,        // cookie-only deployment
});
```

## Concepts

### `AuthContext`

Re-exported from `@aoothjs/auth`. Minimal shape:

```ts
interface AuthContext<TClaims extends object = object> {
  userId: string;
  method: "session" | "token";
  credentialId: string;
  expiresAt: number;
  claims?: TClaims;
}
```

### `AuthGuard`

The `authGuardInterceptor` runs at `TInterceptorPriority.GUARD` on every HTTP
event:

1. Extract token (Bearer > cookie precedence).
2. Validate via `AuthCredential.validate()`.
3. Populate the `AuthContext` slot in the event context.
4. On unprotected (`@Public()`) routes, missing/invalid tokens leave the
   slot `null` and the handler runs. On protected routes, the guard throws
   `HttpError(401)`.

The guard never auto-refreshes — `/auth/refresh` is a separate endpoint. The
guard no-ops on non-HTTP event contexts (workflow steps, CLI).

### `useAuth()`

```ts
import { useAuth } from "@aoothjs/auth-moost";

@Controller("orders")
class OrdersController {
  @Get()
  async list() {
    const { getCurrentUserId, getCurrentUser, isAuthenticated } = useAuth();
    return ordersForUser(getCurrentUserId());
  }
}
```

| Method               | Behavior                                                            |
| -------------------- | ------------------------------------------------------------------- |
| `getCurrentUser()`   | Returns `AuthContext` or `null` (e.g. on `@Public()` routes)        |
| `getCurrentUserId()` | Returns the userId; throws `HttpError(401)` when no AuthContext     |
| `isAuthenticated()`  | `true` when `getCurrentUser()` is non-null                          |

`useAuth()` reads from the slot populated by the guard. On `@Public()` routes
with an invalid token, `getCurrentUser()` returns `null` rather than throwing.

### `@Public()`

```ts
import { Public } from "@aoothjs/auth-moost";

@Controller("docs")
class DocsController {
  @Get("public")
  @Public()
  async docs() { /* runs even without a valid token */ }
}
```

Method-level decoration overrides class-level.

## REST endpoints

`AuthController` is mounted at `/auth` when `endpoints: true` (the default).

| Method | Path              | Visibility   | Purpose                                            |
| ------ | ----------------- | ------------ | -------------------------------------------------- |
| `POST` | `/auth/login`     | `@Public()`  | Verify credentials, issue tokens, write cookies    |
| `POST` | `/auth/logout`    | Protected    | Revoke access + refresh, clear cookies             |
| `POST` | `/auth/refresh`   | `@Public()`  | Rotate refresh token, issue new access             |
| `GET`  | `/auth/status`    | Protected    | Return current `AuthContext`                       |
| `POST` | `/auth/password`  | Protected    | Verify current password, set new, revoke all       |

### Request / response bodies

```ts
// POST /auth/login
{ username: string, password: string }
→ { userId, accessToken?, refreshToken?, accessExpiresAt, refreshExpiresAt? }

// POST /auth/logout
{ refreshToken?: string } // falls back to cookie if path allows
→ { ok: true }

// POST /auth/refresh
{ refreshToken?: string } // falls back to cookie
→ same shape as login response

// GET /auth/status
→ AuthContext

// POST /auth/password
{ currentPassword: string, newPassword: string }
→ { ok: true }
```

`accessToken` / `refreshToken` are populated only when `enableBearer: true`.
With Bearer disabled the response still echoes `userId` + `accessExpiresAt` so
the client can schedule a silent refresh.

> Note: `AuthController` assumes `AuthContext.userId === username`. Login
> issues the credential with the resolved username, and `/auth/password`
> reads it back via `useAuth().getCurrentUserId()`. Apps that map userIds to
> opaque ids (UUIDs, internal pks) must disable the controller and ship a
> subclass:
>
> ```ts
> setupAuthMoost(moost, { authCredential, userService, endpoints: false });
> moost.registerControllers(MyAuthController);
> ```

## Workflows

The workflow half of this package is independent of `setupAuthMoost()` and
configured separately via `setupAuthWorkflows()`.

```ts
import { AsWfStore } from "@atscript/moost-wf/store";
import {
  setupAuthWorkflows,
  type EmailSender,
  type BuildMagicLinkUrl,
} from "@aoothjs/auth-moost";

const emailSender: EmailSender = {
  async send(event) {
    // event.kind ∈ {'recovery.magicLink','invite.magicLink','mfa.code'}
    await myMailer.queue(event.recipient, event.kind, event);
  },
};
const buildMagicLinkUrl: BuildMagicLinkUrl = (kind, token) =>
  `https://app.example.com/wf/trigger?wfs=${token}`;

setupAuthWorkflows(moost, {
  emailSender,
  buildMagicLinkUrl,
  wfStateStore: new AsWfStore({ table: wfStateTable }),
  // Optional knobs:
  recoveryTokenTtlMs: 60 * 60 * 1000,        // 1h
  inviteTokenTtlMs:   7 * 24 * 60 * 60 * 1000, // 7d
  mfaCodeTtlMs:       5 * 60 * 1000,         // 5m
  workflows: { login: true, recovery: true, invite: false },
});
```

`setupAuthWorkflows()` registers `MoostAuthWorkflowConfig` as a DI singleton,
applies `formInputInterceptor()` globally, and conditionally registers
`LoginWorkflow`, `RecoveryWorkflow`, `InviteWorkflow` controllers.

> Note: setting up workflows does **not** mount an HTTP trigger route. The
> consumer mounts trigger endpoint(s) that call `wf.handleOutlet({...})` —
> see "Workflow trigger recipe" below.

### The three workflows

| Workflow ID      | Steps                                                | Final response                              |
| ---------------- | ---------------------------------------------------- | ------------------------------------------- |
| `auth.login`     | `credentials` → (optional `mfa`) → `issue`            | Login response + cookies                    |
| `auth.recovery`  | `recoveryRequest` → `recoverySendLink` → `recoverySetPassword` | Login response + cookies                    |
| `auth.invite`    | `inviteCreate` → `inviteSendLink` → `inviteAccept`    | Login response + cookies                    |

Each workflow yields atscript form schemas to the client between steps via
the HTTP outlet. The frontend renders them with `<AsWfForm name="auth.login" />`
(from `@atscript/vue-wf`) and submits responses to the same trigger route.

### `EmailSender` interface

```ts
import type { AuthEmailEvent, EmailSender } from "@aoothjs/auth-moost";

interface AuthEmailEvent {
  kind: "recovery.magicLink" | "invite.magicLink" | "mfa.code";
  recipient: string;
  url?: string;           // magic-link events only
  code?: string;          // mfa.code only (v2, not emitted in v1)
  expiresAt: number;      // Unix ms
  username?: string;
  metadata?: Record<string, unknown>; // invites carry { roles }
}

interface EmailSender {
  send(event: AuthEmailEvent): Promise<void>;
}
```

v1 emits `recovery.magicLink` and `invite.magicLink`. `mfa.code` is reserved
for the v2 email-OTP MFA method — current v1 MFA is TOTP only.

### `buildMagicLinkUrl(kind, token)`

Consumer-supplied URL builder. The recommended convention is
`?wfs=<token>` so the frontend can mount `<AsWfForm initialToken="...">` to
resume the paused workflow.

### Workflow forms

The bundled `.as` form models ship under `@aoothjs/auth-moost/atscript`:

| Form                    | Used by                            |
| ----------------------- | ---------------------------------- |
| `LoginCredentialsForm`  | `auth.login` step 1                |
| `MfaCodeForm`           | `auth.login` step 2 (conditional)  |
| `EmailIdentifierForm`   | `auth.recovery` step 1             |
| `SetPasswordForm`       | `auth.recovery` step 3, `auth.invite` step 3 |
| `InviteForm`            | `auth.invite` step 1               |

```ts
import { LoginCredentialsForm } from "@aoothjs/auth-moost/atscript";
```

The `.as` source ships in `package.json#exports` so consumer atscript projects
can `extends` these interfaces:

```ts
import { LoginCredentialsForm } from '@aoothjs/auth-moost/atscript/models'

export interface MyLoginForm extends LoginCredentialsForm {
    @ui.form.label 'Tenant'
    tenant: string
}
```

> Note: forms are **not** swappable via `setupAuthWorkflows()` config. The
> `@FormInput()` decorator captures form metadata at decoration time — there
> is no runtime form-swap hook. Consumers wanting a different shape disable
> the bundled workflow (`workflows: { login: false }`) and register their own
> workflow controller using the same primitives.

### Workflow trigger recipe

Mount one or two HTTP routes that call `wf.handleOutlet(...)`. The
recommended shape is **two triggers** — a public one for self-service flows
and an admin-gated one for invite:

```ts
import { current } from "@wooksjs/event-core";
import { Body, Post } from "@moostjs/event-http";
import {
  createHttpOutlet,
  HandleStateStrategy,
  handleWfOutletRequest,
  MoostWf,
} from "@moostjs/event-wf";
import { AsWfStore } from "@atscript/moost-wf/store";
import { Controller, Inject, useControllerContext } from "moost";
import { ArbacAuthorize } from "@aoothjs/arbac-moost";
import {
  createAuthEmailOutlet,
  MoostAuthWorkflowConfig,
  Public,
} from "@aoothjs/auth-moost";

const wfStore = new AsWfStore({ table: wfStateTable });
const handleStrategy = new HandleStateStrategy({ store: wfStore });

@Controller("wf")
class WfTriggerController {
  constructor(@Inject(MoostWf) private wf: MoostWf) {}

  // Public: login + recovery.
  @Post("trigger")
  @Public()
  async publicTrigger(@Body() _body: unknown) {
    const cfg = await useControllerContext().instantiate(MoostAuthWorkflowConfig);
    return this.wf.handleOutlet({
      allow: ["auth.login", "auth.recovery"],
      state: handleStrategy,
      outlets: [createHttpOutlet(), createAuthEmailOutlet(cfg)],
      token: { read: ["body", "query"], write: "body", name: "wfs" },
    });
  }

  // Admin-only: invite. MUST be guarded.
  @Post("admin/invite")
  @ArbacAuthorize()
  async inviteTrigger(@Body() _body: unknown) {
    const cfg = await useControllerContext().instantiate(MoostAuthWorkflowConfig);
    return this.wf.handleOutlet({
      allow: ["auth.invite"],
      state: handleStrategy,
      outlets: [createHttpOutlet(), createAuthEmailOutlet(cfg)],
      token: { read: ["body", "query"], write: "body", name: "wfs" },
    });
  }
}
```

The invite-accept magic link points the user back at the public trigger
(`?wfs=<token>`). The state strategy's `consume(token)` runs before the
`allow:` check, so the resume token resolves even though `auth.invite` is
not in the public route's allow-list.

> Note: in production you may need to invoke `handleWfOutletRequest` directly
> instead of `wf.handleOutlet(...)` to forward the HTTP `eventContext` into
> `wfApp.start/resume`. This is required when steps call
> `useWfFinished().set({ cookies })` — otherwise the cookies write to the
> workflow's isolated context and never reach the HTTP response. See
> `__test__/workflow-utils.ts` for the verbatim pattern.

### `AsWfStore` — handle-strategy state persistence

Recovery and invite both require **handle-strategy** state persistence (not
the encapsulated strategy): the magic-link token must be single-use, which
relies on the state store's `consume()` semantics. Encapsulated tokens carry
their state in the token itself and cannot be revoked after a refresh —
unsafe for invites.

`AsWfStore` from `@atscript/moost-wf/store` is a `WfStateStore` backed by a
`@atscript/db` table — wire it as shown above.

## Security

| Concern                         | Built-in behavior                                                                    |
| ------------------------------- | ------------------------------------------------------------------------------------ |
| Cookie defaults                 | `httpOnly: true`, `secure: true`, `sameSite: 'lax'`; refresh scoped to `/auth/refresh` |
| Logout revokes both tokens      | Access + refresh both revoked (refresh accepted via body if cookie path is narrowed) |
| Password change cascade         | `/auth/password` revokes ALL credentials for the user — defends against the stolen-token + password-change race |
| TOTP comparison                 | Constant-time inside `@aoothjs/user`'s `verifyTotpCode`                              |
| Login / recovery enumeration    | Uniform error responses (`Invalid credentials`) and uniform recovery success message |
| Magic-link tokens               | 256 bits of CSPRNG (`base64url`, 43 chars). Single-use via `HandleStateStrategy.consume()` |
| CSRF                            | **Not** included — consumer adds CSRF tokens / `SameSite=Strict` per threat model    |
| Invite admin protection         | **Consumer-side** — see workflow trigger recipe                                      |

The invite workflow does **not** authenticate the caller of step 1. Putting
`'auth.invite'` in a public trigger's `allow:` list exposes an
invite-email-spam vector. Always mount invite under a separate admin-guarded
route.

## moost-wf quirks worth knowing

Documented learnings from the workflow implementation:

1. **`useWfFinished().set(...)` does not halt.** Later steps still run unless
   gated by a `condition: (ctx) => ...` on the schema. Use a context flag to
   short-circuit.
2. **Outlet-emitting steps re-run on resume.** Use a `linkSent` boolean in
   context so resends don't fire a second email. The bundled
   `recoverySendLink` and `inviteSendLink` use this pattern.
3. **`MoostWf.handleOutlet()` does not forward the HTTP `eventContext` to
   `wfApp.start/resume`.** To preserve cookies and `useWfFinished()` payloads,
   call `handleWfOutletRequest` directly with `eventContext: current()` —
   see the test fixture for the exact wiring.
4. **Step IDs are global per workflow router.** Two workflows can't share an
   id. The bundled flows use prefixes (`recoverySendLink`, `inviteSendLink`,
   etc.).
5. **`@StepTTL` requires compile-time constants.** TTL cannot be driven from
   `MoostAuthWorkflowConfig`. Consumers wanting different TTLs ship their own
   workflow class.
6. **`@FormInput()` runtime form-swap is not supported.** Form metadata is
   captured at decoration time. Override = ship your own workflow controller.

## API surface

```ts
// Setup
export { setupAuthMoost, type SetupAuthMoostOptions }
export { setupAuthWorkflows, type AuthWorkflowsOptions }
export { MoostAuthConfig, type ResolvedAuthCookieConfig }
export { MoostAuthWorkflowConfig, type ResolvedAuthWorkflowsConfig }
export {
  DEFAULT_RECOVERY_TOKEN_TTL_MS,
  DEFAULT_INVITE_TOKEN_TTL_MS,
  DEFAULT_MFA_CODE_TTL_MS,
}

// Composables + decorators
export { useAuth, type AuthBindings }
export { Public }

// Guard (auto-applied by setupAuthMoost; export for testing)
export { authGuardInterceptor }

// Controllers
export { AuthController }              // subclass for non-username userId mapping
export {
  LoginWorkflow,    type LoginWfCtx,
  RecoveryWorkflow, type RecoveryWfCtx,
  InviteWorkflow,   type InviteWfCtx,
  parseInviteRoles,
}

// Email outlet
export { createAuthEmailOutlet }

// Cookie + token helpers (rarely used directly)
export { buildLoginResponse, clearAuthCookies, writeAuthCookies, cookieAttrs }
export { extractAccessToken }

// Re-exports from @aoothjs/auth for ergonomic single-import
export type {
  AuthContext, IssueResult,
  AuthEmailEvent, AuthEmailKind, BuildMagicLinkUrl, EmailSender, MagicLinkKind,
}
export { generateMagicLinkToken }

// DTOs
export type {
  AuthLoginBody, AuthLoginResponse, AuthOkResponse,
  AuthRefreshBody, AuthLogoutBody, AuthPasswordChangeBody,
}

// Form metadata sub-export
export {
  LoginCredentialsForm, MfaCodeForm, EmailIdentifierForm,
  SetPasswordForm, InviteForm,
} from "@aoothjs/auth-moost/atscript"
```
