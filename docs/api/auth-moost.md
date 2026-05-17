# `@aoothjs/auth-moost` API Reference

Complete export reference for `@aoothjs/auth-moost`. See the [Moost Integration Guide](/moost/), [AuthGuard & useAuth](/moost/auth-guard), [REST Controllers](/moost/controllers), and [Workflows](/moost/) for narrative documentation.

## Classes

### `AuthController`

```ts
@Controller("auth")
@ArbacResource("auth")
class AuthController {
  constructor(auth: AuthCredential);
}
```

REST surface — see the [Controllers](#rest-endpoints) section below for the four endpoints. Subclass and override `triggerWf()` to extend the workflow allow-list. See [REST Controllers](/moost/controllers).

### `WfTriggerProvider`

```ts
@Injectable()
class WfTriggerProvider {
  constructor(wf: MoostWf);
  handle(opts?: { allow?: string[]; token?: WfOutletTokenConfig }): Promise<unknown>;
}
```

Singleton owning workflow state, outlets, and the token wire. Defaults: `HandleStateStrategy({ store: WfStateStoreMemory() })`, `[createAsHttpOutlet()]`, `{ read: ['body','query','cookie'], write: 'body', name: 'wfs' }`. Bind a subclass via `setReplaceRegistry([WfTriggerProvider, MyProvider])`.

**Protected — assign in your subclass constructor**: `state: WfStateStrategy`, `outlets: WfOutlet[]`, `token: WfOutletTokenConfig`. Reassign these in the subclass `constructor` to swap the state store, register additional outlets, or override the token wire.

```ts
@Injectable()
class MyWfTriggerProvider extends WfTriggerProvider {
  constructor(wf: MoostWf) {
    super(wf);
    this.state = new HandleStateStrategy({ store: new AsWfStore({ table }) });
    this.outlets = [
      ...this.outlets,
      createAuthEmailOutlet({ emailSender, buildMagicLinkUrl, magicLinkTtlMs }),
    ];
  }
}
```

See [Workflows](/moost/).

### `LoginWorkflow`

```ts
@Public()
@Injectable("FOR_EVENT")
@Controller()
@Workflow("auth.login")
class LoginWorkflow {
  constructor(opts: LoginWorkflowOpts, users: UserService, auth: AuthCredential);
}
```

Workflow class with steps spanning credentials → enrollment → MFA → device trust → forced password change → terms/profile/consent → tenant/persona select → concurrency limit → finalize. Critical invariant: every terminal step gates on `!ctx.aborted`. Override `protected` methods to wire delivery, audit, redirect, trusted-device storage. See [Workflows](/moost/).

### `RecoveryWorkflow`

```ts
@Public()
@Injectable("FOR_EVENT")
@Controller()
@Workflow("auth.recovery")
class RecoveryWorkflow {
  constructor(opts: RecoveryWorkflowOpts, users: UserService, auth: AuthCredential);
}
```

Magic-link OR OTP password-reset workflow. Anti-enumeration: unknown email still emits a generic `{ sent: true }` response. After reset, calls `auth.revokeAllForUser(userId)`. Override `emailToUserId` if `username !== email`. See [Workflows](/moost/).

### `InviteWorkflow`

```ts
@ArbacResource("auth.invite")
@ArbacAction("start")
@Injectable("FOR_EVENT")
@Controller()
class InviteWorkflow {
  constructor(opts: InviteWorkflowOpts, users: UserService, auth: AuthCredential);
}
```

Registers three wfids: `auth.invite`, `auth.reInvite`, `auth.cancelInvite`. Phase A (admin) is ARBAC-gated by the class-level `@ArbacResource("auth.invite")` + `@ArbacAction("start")` grant. Phase B (anonymous magic-link resume) is per-step `@Public()` — there is no class-level `@Public()`. Server-side role-whitelist enforcement on admin-submitted roles. See [Workflows](/moost/).

## Functions

### `authGuardInterceptor`

```ts
function authGuardInterceptor(opts?: AuthOptions): TInterceptorFn;
```

Factory returning a `defineBeforeInterceptor` at `TInterceptorPriority.GUARD`. HTTP-only (no-op on WF/CLI/WS). Resolves `AuthOptions` once and stashes onto the event slot — every later `useAuth()` reads from the same slot. Bearer beats cookie when both transports are enabled. On `@Public()` routes, sets `null` context and runs the handler. On protected routes, throws `HttpError(401)`. Never auto-refreshes. See [AuthGuard & useAuth](/moost/auth-guard).

### `useAuth`

```ts
function useAuth(): AuthBindings;

interface AuthBindings {
  getAuthContext<TClaims>(): AuthContext<TClaims> | null;
  getUserId(): string; // throws HttpError(401)
  isAuthenticated(): boolean;
  readonly options: ResolvedAuthOptions; // throws HttpError(500) if guard missing
  extractToken(): string | undefined;
  writeCookies(issue: IssueResult): void;
  clearCookies(): void;
  buildLoginResponse(userId: string, issue: IssueResult): AuthLoginResponse;
  buildFinishedCookies(issue: IssueResult): WfFinishedResponse["cookies"];
  cookieAttrs(extra?: Partial<CookieAttrs>): CookieAttrs;
}
```

`defineWook` returning per-event memoized bindings. The `options` getter throws `HttpError(500)` if no `authGuardInterceptor` is on the chain — configuration error, not runtime fallback. `buildLoginResponse` populates token fields only when `enableBearer === true`. See [AuthGuard & useAuth](/moost/auth-guard).

### `getAuthMate`

```ts
function getAuthMate(): Mate<TAuthMeta>;
interface TAuthMeta {
  authPublic?: boolean;
}
```

Shared moost `Mate` typed with `TAuthMeta`. Declaration-merged into `TMoostMetadata`. See [Decorators](/moost/decorators).

### `createAuthEmailOutlet`

```ts
function createAuthEmailOutlet(deps: {
  emailSender: EmailSender;
  buildMagicLinkUrl: BuildMagicLinkUrl;
  magicLinkTtlMs: (kind: AuthEmailKind) => number;
}): Outlet;
```

Builds the email outlet that delivers magic links. Wraps `@moostjs/event-wf`'s `createEmailOutlet(send)` and translates workflow tokens into `AuthEmailEvent` payloads via the consumer's `EmailSender` + `BuildMagicLinkUrl`. Add to `WfTriggerProvider.outlets`. See [Workflows](/moost/).

## Decorators

### `@Public`

```ts
function Public(): ClassDecorator & MethodDecorator;
```

Writes **both** `authPublic=true` AND `arbacPublic=true`. Bypasses both the auth guard and the ARBAC interceptor. You cannot ARBAC-gate an `@Public()` route — splitting them into two decorators was a deliberately-rejected design. See [Decorators](/moost/decorators).

### `@UserId`

```ts
function UserId(): ParameterDecorator;
```

Parameter decorator delegating to `Resolve(() => useAuth().getUserId())`. Throws `HttpError(401)` if no auth context. There is **no `@User()` counterpart** — `AuthContext` is credential context only, not a user record. See [Decorators](/moost/decorators).

### `@AuthGuarded`

```ts
function AuthGuarded(opts?: AuthOptions): ClassDecorator & MethodDecorator;
```

Sugar for `@Intercept(authGuardInterceptor(opts))`. Attaches the guard to a single controller instead of globally. See [AuthGuard & useAuth](/moost/auth-guard).

### `@WfTrigger`

```ts
function WfTrigger(opts?: { allow?: string[]; token?: WfOutletTokenConfig }): MethodDecorator;
```

Method decorator wrapping `defineAfterInterceptor` at `INTERCEPTOR` priority. When the handler returns `undefined`, the interceptor instantiates `WfTriggerProvider` and replies with `provider.handle(opts)`. Return a non-`undefined` value from the handler to short-circuit. `opts.token` overrides the provider's default wire (`WfOutletTokenConfig` from `@moostjs/event-wf`). See [Workflows](/moost/).

## REST endpoints

`AuthController` mounts four routes — all `@Public()`:

| Method | Path            | Body                               | Response              | Notes                                                                                                                           |
| ------ | --------------- | ---------------------------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `POST` | `/auth/logout`  | `AuthLogoutBody`                   | `AuthOkResponse`      | Defence-in-depth 401 on null context. Best-effort revokes both tokens.                                                          |
| `POST` | `/auth/refresh` | `AuthRefreshBody`                  | `AuthLoginResponse`   | Falls back to refresh cookie. 401 on `AuthError`.                                                                               |
| `GET`  | `/auth/status`  | —                                  | `AuthContext`         | 401 when no context.                                                                                                            |
| `POST` | `/auth/trigger` | `{ wfid?, wfs?, input?, action? }` | `WfFinished` envelope | Single entry-point for `auth.login`, `auth.recovery`, `auth.invite`. Decorated `@WfTrigger({ allow: DEFAULT_AUTH_WORKFLOWS })`. |

See [REST Controllers](/moost/controllers).

## Constants

### `DEFAULT_AUTH_WORKFLOWS`

```ts
const DEFAULT_AUTH_WORKFLOWS = ["auth.login", "auth.recovery", "auth.invite"] as const;
```

Default `allow` list for `@WfTrigger` on `AuthController.trigger()`. Subclasses override `triggerWf()` to extend. See [REST Controllers](/moost/controllers).

## DTOs

### `AuthLogoutBody`

```ts
interface AuthLogoutBody {
  refreshToken?: string;
}
```

Refresh cookie's narrow `/auth/refresh` path means it is NOT auto-sent to `/auth/logout`. Explicit body field falls back to cookie. See [REST Controllers](/moost/controllers).

### `AuthRefreshBody`

```ts
interface AuthRefreshBody {
  refreshToken?: string;
}
```

Same fallback semantics as `AuthLogoutBody`. See [REST Controllers](/moost/controllers).

### `AuthLoginResponse`

```ts
interface AuthLoginResponse {
  userId: string;
  accessExpiresAt: number;
  refreshExpiresAt?: number;
  accessToken?: string; // only when enableBearer === true
  refreshToken?: string; // only when enableBearer === true
}
```

Token fields are suppressed when `enableBearer: false` — browser must rely on cookies. See [REST Controllers](/moost/controllers).

### `AuthOkResponse`

```ts
interface AuthOkResponse {
  ok: true;
}
```

Used by `/auth/logout`. See [REST Controllers](/moost/controllers).

## Workflow option types

### `LoginWorkflowOpts`

```ts
interface LoginWorkflowOpts {
  alternateCredentials?: {
    forgotPassword?: boolean;
    signup?: boolean;
    magicLink?: boolean;
    ssoProviders?: Array<{ id: string; label: string; url: string }>;
    recoveryUrl?: string;
    signupUrl?: string;
    embedRecovery?: boolean;
  };
  guards?: { emailVerifiedRequired?: boolean; passwordExpiry?: boolean; passwordInitial?: boolean };
  enrollment?: { ensureEmail?: boolean; ensurePhone?: boolean };
  mfa?: {
    enabled?: boolean;
    transports?: Array<"sms" | "email" | "totp">;
    backupCodes?: boolean;
    enrollRequired?: boolean;
    pincodeTtlMs?: number; // default 5 * 60_000
    pincodeResendTimeoutMs?: number;
    pincodeLength?: number;
  };
  deviceTrust?: {
    enabled?: boolean;
    optIn?: boolean;
    cookieName?: string; // default 'aooth_trusted_device'
    ttlMs?: number; // default 24h
    skipsMfa?: boolean;
    bindsTo?: "cookie" | "cookie+ip";
  };
  acceptance?: {
    termsVersion?: string;
    profileCompleteRequired?: boolean;
    consentMarketing?: boolean;
  };
  multiContext?: { tenantSelect?: boolean; personaSelect?: boolean };
  sessionPolicy?: { concurrencyLimit?: { max: number; onLimit: "reject" | "kickPrompt" } };
  finalize?: {
    auditLogin?: boolean;
    notifyNewDevice?: boolean;
    redirect?: "referer" | "home" | false | null;
  };
  forms?: Record<string, TAtscriptAnnotatedType>;
}
```

See [Workflows](/moost/).

### `RecoveryWorkflowOpts`

```ts
interface RecoveryWorkflowOpts {
  delivery?: {
    mode?: "magicLink" | "otp" | "choice";
    magicLinkTtlMs?: number; // default 60 * 60_000
    otp?: {
      transports?: Array<"sms" | "email">;
      codeLength?: number; // default 6
      ttlMs?: number; // default 5 * 60_000
      resendCooldownMs?: number; // default 60_000
    };
  };
  preReset?: { requireKnownFactor?: boolean };
  postReset?: {
    revokeAllSessions?: boolean; // default true
    freshLoginRequired?: boolean; // default false
    loginUrl?: string; // default '/login'
  };
  altActions?: { backToLogin?: boolean };
  audit?: { enabled?: boolean };
  forms?: Record<string, TAtscriptAnnotatedType>;
}
```

See [Workflows](/moost/).

### `InviteWorkflowOpts`

```ts
interface InviteWorkflowOpts {
  adminForm?: { collectRoles?: boolean };
  send?: { mode?: "email" | "shareableLink" | "choice"; tokenTtlMs?: number /* 7d */ };
  accept?: {
    alreadyAcceptedRedirectUrl?: string;
    freshLoginRequired?: boolean;
    loginUrl?: string;
    showConfirmation?: boolean;
    confirmationMessage?: string;
  };
  cancellation?: { allowed?: boolean };
  audit?: { enabled?: boolean };
  forms?: Record<string, TAtscriptAnnotatedType>;
}
```

See [Workflows](/moost/).

## Re-exports from `@aoothjs/auth`

Re-exported for convenience so consumers don't need a second import:

- [`AuthContext`](./auth#authcontext-tclaims)
- [`IssueResult`](./auth#issueresult)
- [`EmailSender`](./auth#emailsender)
- [`BuildMagicLinkUrl`](./auth#buildmagiclinkurl)
- [`AuthEmailEvent`](./auth#authemailevent)
- [`AuthEmailKind`](./auth#authemailkind)

## Audit types

### `AuditEvent` / `AuditEmitter`

```ts
interface AuditEvent {
  kind: string;
  userId?: string;
  workflow?: string;
  ip?: string;
  userAgent?: string;
  [k: string]: unknown;
}
interface AuditEmitter {
  emit(event: AuditEvent): Promise<void> | void;
}
```

Package ships **no concrete sink** — workflows fire audit events through their `protected audit(event)` method (default no-op). Built-in event kinds: `login.success`, `recovery.requested`, `recovery.completed`, `invite.created`, `invite.resent`, `invite.accepted`, `invite.cancelled`. See [Audit Log](/moost/).

## Config types

### `AuthOptions`

```ts
interface AuthOptions {
  cookie?: {
    name?: string;
    secure?: boolean;
    sameSite?: "lax" | "strict" | "none";
    httpOnly?: boolean;
    path?: string;
    domain?: string;
  };
  refreshCookie?: {
    name?: string;
    path?: string;
    secure?: boolean;
    sameSite?: "lax" | "strict" | "none";
    httpOnly?: boolean;
    domain?: string;
  };
  enableCookie?: boolean;
  enableBearer?: boolean;
}
```

Defaults: `cookie.name='aooth_session'`, `secure=true`, `sameSite='lax'`, `httpOnly=true`, `path='/'`. `refreshCookie.path='/auth/refresh'` (narrow path). `enableCookie=true`, `enableBearer=true`. Bearer wins when both transports are enabled. See [Config Reference](/moost/).

## Subpath: `@aoothjs/auth-moost/atscript`

```ts
import * as forms from "@aoothjs/auth-moost/atscript";
```

Re-exports the form types from `src/atscript/models/forms.as`:

`LoginCredentialsForm`, `MfaCodeForm`, `BackupCodeForm`, `EmailIdentifierForm`, `SetPasswordForm`, `InviteForm`, `InviteEmailForm`, `InviteSendModeForm`, `Select2faForm`, `PincodeForm`, `AskEmailForm`, `AskPhoneForm`, `TermsAcceptForm`, `ProfileCompleteForm`, `ConsentMarketingForm`, `TenantSelectForm`, `PersonaSelectForm`, `ConcurrencyLimitForm`, `MagicLinkRequestForm`, `RecoveryModeSelectForm`, `RecoveryFactorForm`.

Every form is replaceable per-workflow through `opts.forms.<formName>`. See [Atscript Models](/moost/) and [Workflows](/moost/).
