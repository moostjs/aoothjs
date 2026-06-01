# `@aooth/auth-moost` API Reference

Complete export reference for `@aooth/auth-moost`. See the [Moost Integration Guide](/moost/), [AuthGuard & useAuth](/moost/auth-guard), [REST Controllers](/moost/controllers), and [Workflows](/moost/workflows) for narrative documentation.

Subpath exports: `.` (main, **ESM-only**), `./atscript` (bundled form models, ESM-only), `./atscript/models` + `./atscript/models.as`.

## Classes

### `AuthWorkflow`

```ts
@Inherit()
@Controller() // SINGLETON
class AuthWorkflow {
  constructor(
    opts: Partial<AuthWorkflowOpts>,
    users: UserService,
    auth: AuthCredential,
    consentStore: ConsentStore,
  );
}
```

The single unified workflow class. Replaces the former `LoginWorkflow` / `RecoveryWorkflow` / `InviteWorkflow` quartet. Declares **three** `@Workflow` methods, each `@Public()`:

| Method         | Workflow id          | Covers                                     |
| -------------- | -------------------- | ------------------------------------------ |
| `loginFlow`    | `auth/login/flow`    | login + MFA + enrollment + finalize        |
| `inviteFlow`   | `auth/invite/start`  | admin invite → anonymous magic-link accept |
| `recoveryFlow` | `auth/recovery/flow` | magic-link **or** OTP password reset       |

`AuthWorkflowOpts` is **infrastructure-only**; policy lives on `protected resolveXxx(ctx)` getters (each paired with a `@Step("prepare-<group>")`). Per-flow code discriminates by ctx-slot presence (`ctx.admin` / `ctx.accept` / `ctx.postReset`), never a flow-name field. Subclass with `@Inherit() @Controller()`, re-declare the 4-arg constructor (so TS emits `design:paramtypes`), override the hooks you need, and bind via `setReplaceRegistry([AuthWorkflow, MyAuth])`. See [Workflows](/moost/workflows) and [packages/auth-moost/CLAUDE.md](https://github.com/moostjs/aoothjs/blob/main/packages/auth-moost/CLAUDE.md).

**Protected override surface** (defaults are no-ops or hardcoded policy):

- `deliver(payload: AuthDeliveryPayload): void | Promise<void>` — outbound dispatch for direct sends (MFA / recovery / enroll pincodes, new-device notice). Route by `payload.kind` + `payload.channel`. NOT used for the invite magic link (emitted via the wf outlet). There is **no `audit()` method.**
- `resolveXxx(ctx: AuthWfCtx)` policy getters — the override seam for context-varying policy. Return `T | Promise<T>` (never `async` on the default). The set: `resolveDeviceTrust`, `resolveMfaPolicy`, `resolveEnrollment`, `resolveSessionPolicy`, `resolveFinalize`, `resolveGuards`, `resolveLockout`, `resolveAlternateCredentials`, `resolveOtpDisclosure`, `resolveRiskStepUp`, `resolveRedirect`, `resolveRecoveryUrl`, `resolveRecoveryAltActions`, `resolveAdminForm`, `resolveAccept`, `resolvePostReset`, `resolvePincodeForm` / `resolvePincodeTarget` / `resolvePincodeAltAction`.
- `getAvailableRoles(): string[] | undefined` — selectable role whitelist for the admin invite form (default `undefined` = no whitelist).
- `loadActiveSessionsCount(username)` — async data fetcher for concurrency-limit policy.

**Error posture** — `@Step` bodies throw exactly two shapes: `throw wf.requireInput({ errors, formMessage? })` for retriable input errors (engine re-renders the form under the SAME `wfs` handle; token survives), and `throw new HttpError(<status>, <msg>)` for terminal failures (token consumed). See [Error patterns](/moost/workflows#error-patterns).

### `WfTriggerProvider`

```ts
@Injectable()
class WfTriggerProvider {
  constructor(wf: MoostWf, auth: AuthCredential);
  handle(opts?: { allow?: string[]; token?: WfOutletTokenConfig }): Promise<unknown>;
  // override seams:
  protected storeStrategy(): WfStateStrategy;
  protected wfStateSecret(): string | Buffer;
  protected wfStateEncapsulatedTtlMs(): number | undefined;
  // protected fields:
  protected outlets: WfOutlet[];
  protected token: WfOutletTokenConfig;
}
```

Singleton owning workflow-state persistence, outlets, and the token wire. State is a **named-strategy registry**, not a single strategy: every workflow **starts** on the `encapsulated` strategy (the registry default) — state rides inside the SPA-held token, so an idle login form persists **zero** server-side rows and a restart can never `410 Gone` it. A later step calls `swapStrategy('store')` to move durable.

Both registry entries default to `EncapsulatedStateStrategy`. To make `store` durable, override **`storeStrategy()`** to return a real `HandleStateStrategy` (do **not** assign a `this.state` field — that field no longer exists). The encapsulated secret defaults to `auth.deriveStateKey("wf-state")` (HKDF-derived, stable across restarts). `handle()` forwards the `strategy` run-option into `wfApp.start`/`resume` — required, or the wf adapter throws `Key "wf.strategyName" is not set`.

```ts
@Injectable()
class MyWfTriggerProvider extends WfTriggerProvider {
  constructor(wf: MoostWf, auth: AuthCredential) {
    super(wf, auth);
    this.outlets = [
      ...this.outlets,
      createAuthEmailOutlet({ emailSender, buildMagicLinkUrl, magicLinkTtlMs }),
    ];
  }
  protected override storeStrategy(): WfStateStrategy {
    return new HandleStateStrategy({ store: new AsWfStore({ table }) });
  }
}
// app.setReplaceRegistry(createReplaceRegistry([WfTriggerProvider, MyWfTriggerProvider]))
```

`HandleStateStrategy` / `EncapsulatedStateStrategy` / `WfStateStrategy` come from `@moostjs/event-wf`; `AsWfStore` from `@atscript/moost-wf`. See [Workflows — state strategy](/moost/workflows#workflow-state-strategy).

### `AuthController`

```ts
@Controller("auth")
@ArbacResource("auth")
class AuthController {
  constructor(auth: AuthCredential, @Optional() users?: UserService);
}
```

REST surface — see [REST endpoints](#rest-endpoints) below for the five routes. `users` is `@Optional()`: only `GET /auth/invite/post-redemption` reads it (returns 500 when unset); the other four routes work without a `UserService`. Subclass and override `triggerWf()` to extend the workflow allow-list. See [REST Controllers](/moost/controllers).

### `SessionsController`

```ts
@Controller("auth")
@ArbacResource("auth.sessions")
class SessionsController {
  constructor(auth: AuthCredential, enricher: SessionEnricherProvider);
}
```

Optional, opt-in by registration. Mounts `GET /auth/sessions` (`read`), `GET /auth/sessions/of/:userId` (`readAny`), `DELETE /auth/sessions/:sessionId` (`revoke`), `DELETE /auth/sessions?others=true` (`revoke`) — all under the `auth.sessions` ARBAC resource, none `@Public()`. A bare `DELETE /auth/sessions` is 400. Requires a stateful credential store. See [Sessions](/moost/sessions).

### `SessionEnricherProvider`

```ts
@Injectable() // SINGLETON
class SessionEnricherProvider {
  enrich(session: SessionInfo): EnrichedSession | Promise<EnrichedSession>;
}
```

Injectable read-time enricher used by `SessionsController`. Default is identity (aooth ships no UA/geo). Subclass + `setReplaceRegistry([SessionEnricherProvider, MyEnricher])` to add `device` / `browser` / `os` / `location`. See [Sessions](/moost/sessions).

### `ConsentStore`

```ts
@Injectable() // SINGLETON
class ConsentStore {
  getPendingConsents(username: string | undefined): Promise<ConsentDescriptor[]>;
  save(username: string, events: ConsentEvent[]): Promise<void>;
  read(username: string, filter?: { id?: string }): Promise<ConsentEvent[]>;
  recordOtpChannelConsent(
    username: string,
    channel: "email" | "sms",
    target: string,
    disclosure: string,
  ): Promise<void>;
}

interface ConsentDescriptor {
  id: string;
  text: string; // markdown links allowed
  required?: string; // non-empty ⇒ mandatory; the string IS the error message
  version?: string;
}

interface ConsentEvent {
  id: string;
  accepted: boolean; // false rows are persisted too (audit-grade "was asked")
  version?: string;
  at: number;
}
```

Customer-overridable DI seam for the consent universe + persistence. All four methods are no-op defaults — extend the class and register the replacement via `setReplaceRegistry([ConsentStore, MyConsentStore])`. **`getPendingConsents(username)` is user-scoped only** — the returned set must NOT vary by workflow or channel; OTP channel-ownership disclosures are recorded separately via `recordOtpChannelConsent`. Pending descriptors are transported to the SPA carrier form (via `@wf.context.pass`) and rendered by the `AsConsentArray` component. See [Workflows — ConsentStore](/moost/workflows#consent-collection).

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
  getSessionId(): string | undefined; // "this device" — AuthContext.sessionId
  // Session facade, scoped to the current user (see Sessions):
  listSessions(opts?: { enrich?: SessionEnricher }): Promise<SessionInfo[] | EnrichedSession[]>;
  revokeSession(sessionId: string): Promise<void>;
  revokeOtherSessions(): Promise<number>; // throws HttpError(401) if no current session
  readonly options: ResolvedAuthOptions; // throws HttpError(500) if guard missing
  extractToken(): string | undefined;
  writeCookies(issue: IssueResult): void;
  clearCookies(): void;
  buildLoginResponse(userId: string, issue: IssueResult): AuthLoginResponse;
  buildFinishedCookies(issue: IssueResult): WfFinishedResponse["cookies"];
  cookieAttrs(extra?: Partial<CookieAttrs>): CookieAttrs;
}
```

`defineWook` returning per-event memoized bindings. The `options` getter throws `HttpError(500)` if no `authGuardInterceptor` is on the chain — configuration error, not runtime fallback. `buildLoginResponse` populates token fields only when `enableBearer === true`. The session facade (`listSessions` / `revokeSession` / `revokeOtherSessions`) resolves the guard-stashed `AuthCredential`; calling it off-request throws `HttpError(500)`. See [AuthGuard & useAuth](/moost/auth-guard) and [Sessions](/moost/sessions).

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
interface AuthEmailOutletDeps {
  emailSender: EmailSender;
  buildMagicLinkUrl: BuildMagicLinkUrl; // (kind, token, ctx?: { userId? }) => string
  magicLinkTtlMs: (kind: AuthEmailKind) => number;
}
function createAuthEmailOutlet(deps: AuthEmailOutletDeps): WfOutlet;
```

Builds the email outlet that delivers the invite magic link. Wraps `@atscript/moost-wf`'s outlet primitive and translates workflow tokens into `AuthEmailEvent` payloads via the consumer's `EmailSender` + `BuildMagicLinkUrl`. The `buildMagicLinkUrl` callback receives a third `{ userId }` arg for the invite kind (used by the post-redemption side route). Add to `WfTriggerProvider.outlets`. See [Workflows](/moost/workflows).

### Workflow helpers

```ts
function parseInviteRoles(input?: string[]): string[]; // trim + dedupe role ids
function stripReservedUserKeys(profile: Record<string, unknown>): Record<string, unknown>;
const RESERVED_USER_KEYS: ReadonlySet<string>; // keys profile forms must never carry
function buildInviteAlreadyAcceptedEnvelope(opts: {
  loginUrl: string;
  alreadyAcceptedRedirectUrl: string;
}): FinishWfOpts; // shared "already accepted" finish envelope
```

Exported so subclasses (and `AuthController.invitePostRedemption`) reuse the same role parsing, mass-assignment guard, and idempotent-redirect envelope.

### `deriveWfStateSecret`

```ts
function deriveWfStateSecret(secret: string): Buffer;
```

SHA-256-derives the exact 32-byte key `EncapsulatedStateStrategy` requires from an arbitrary-length app secret. Override `WfTriggerProvider.wfStateSecret()` with `deriveWfStateSecret(env.MY_SECRET)` when the credential store has no reusable secret to HKDF-derive from (i.e. the atscript-db store, the recommended default for [Sessions](/moost/sessions)). Deterministic — stable across restarts. See [Workflows](/moost/workflows).

### `generateMagicLinkToken`

Re-exported from `@aooth/auth` — see [`@aooth/auth` API](./auth#generatemagiclinktoken).

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

Method decorator wrapping `defineAfterInterceptor` at `INTERCEPTOR` priority. When the handler returns `undefined`, the interceptor instantiates `WfTriggerProvider` and replies with `provider.handle(opts)`. Return a non-`undefined` value from the handler to short-circuit. `opts.token` overrides the provider's default wire (`WfOutletTokenConfig` from `@moostjs/event-wf`). See [Workflows](/moost/workflows).

## REST endpoints

`AuthController` mounts **five** routes — all `@Public()`:

| Method | Path                           | Body / Query                               | Response              | Notes                                                                                                                        |
| ------ | ------------------------------ | ------------------------------------------ | --------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `POST` | `/auth/logout`                 | `AuthLogoutBody`                           | `AuthOkResponse`      | Defence-in-depth 401 on null context. Best-effort revokes both tokens.                                                       |
| `POST` | `/auth/refresh`                | `AuthRefreshBody`                          | `AuthLoginResponse`   | Falls back to refresh cookie. 401 on `AuthError`.                                                                            |
| `GET`  | `/auth/status`                 | —                                          | `AuthContext`         | 401 when no context.                                                                                                         |
| `POST` | `/auth/trigger`                | `{ wfs?, input?: { action?, formData? } }` | `WfFinished` envelope | Single entry-point for the three `AuthWorkflow` schemas. `@WfTrigger({ allow: DEFAULT_AUTH_WORKFLOWS })`.                    |
| `GET`  | `/auth/invite/post-redemption` | `?uid=<userId>`                            | `WfFinished` envelope | Idempotent "already accepted" envelope for re-clicked invite links (after the wf state row is evicted). Needs `UserService`. |

See [REST Controllers](/moost/controllers).

## Constants

### `DEFAULT_AUTH_WORKFLOWS`

```ts
const DEFAULT_AUTH_WORKFLOWS = [
  "auth/login/flow",
  "auth/invite/start",
  "auth/recovery/flow",
] as const;
```

Default `allow` list for `@WfTrigger` on `AuthController.triggerWf()`. Subclasses override `triggerWf()` with a different `@WfTrigger({ allow })` to extend. See [REST Controllers](/moost/controllers).

## DTOs

### `AuthLogoutBody` / `AuthRefreshBody`

```ts
interface AuthLogoutBody {
  refreshToken?: string;
}
interface AuthRefreshBody {
  refreshToken?: string;
}
```

The refresh cookie's narrow `/auth/refresh` path means it is NOT auto-sent to `/auth/logout`. Explicit body field falls back to cookie. See [REST Controllers](/moost/controllers).

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

## Workflow option + payload types

### `AuthWorkflowOpts` / `ResolvedAuthWorkflowOpts`

```ts
interface AuthWorkflowOpts {
  autoLoginOnInvite?: boolean; // default true
  autoLoginOnRecover?: boolean; // default false
  mfa?: {
    pincodeLength?: number; // 6
    pincodeTtlMs?: number; // 5 min
    pincodeResendTimeoutMs?: number; // 60s
    pincodeMaxAttempts?: number; // 5
  };
  recoveryStateTtlMs?: number; // 1h
  loginUrl?: string; // '/login'
  totpIssuer?: string; // 'aooth'
  deviceTrust?: { cookieName?: string; ttlMs?: number; bindsTo?: "cookie" | "cookie+ip" };
  forms?: {
    /* one TAtscriptAnnotatedType slot per bundled form — see the form list below */
  };
}
```

**Infrastructure-only.** Every field is optional; the constructor runs `mergeAuthWorkflowOpts(opts)` to produce a fully-populated `ResolvedAuthWorkflowOpts` read as `this.opts.<group>.<field>` without optional chaining. Policy NEVER lives here — if a knob varies by request/tenant/user it belongs on a `resolveXxx(ctx)` getter. Replace any bundled form per-slot via `opts.forms.<field>`. See [Workflows](/moost/workflows) and [Config Reference](/moost/config).

### `AuthDeliveryPayload`

```ts
type AuthDeliveryPayload =
  | {
      kind: "mfa-pincode";
      channel: "sms" | "email";
      recipient: string;
      code: string;
      expiresInMs: number;
    }
  | {
      kind: "recovery-pincode";
      channel: "email";
      recipient: string;
      code: string;
      expiresInMs: number;
    }
  | {
      kind: "enroll-pincode";
      channel: "sms" | "email";
      recipient: string;
      code: string;
      expiresInMs: number;
    }
  | { kind: "invite-link"; channel: "email"; recipient: string; url: string; expiresInMs: number }
  | {
      kind: "new-device-notice";
      channel: "email";
      recipient: string;
      deviceLabel?: string;
      loginAt: number;
    };
```

The discriminated union passed to `AuthWorkflow.deliver(payload)`. Branch on `kind` for per-purpose templates and on `channel` for transport. See [Delivery](/auth/delivery).

### Workflow context types

The `@wf.context.pass` slots and policy-resolver return shapes are exported for typing subclass overrides: `AuthWfCtx`, `AuthWfCompletionState`, `AuthWfConsentsState`, `AuthWfMfaEnrollState`, `AuthWfPasswordUiState`, `AuthWfPincodeUiState`, `ConsentDescriptorLike`, `MfaSummary`, `MfaTransport`, `LoginRedirect`, `SsoProvider`, `ConcurrencyLimitOptions`. `AuthWfCtx` has **no `flow` field** — discriminate by ctx-slot presence (`ctx.admin` / `ctx.accept` / `ctx.postReset`).

## Re-exports from `@aooth/auth`

Re-exported for convenience so consumers don't need a second import:

- [`AuthContext`](./auth#authcontext-tclaims), [`IssueResult`](./auth#issueresult)
- [`EmailSender`](./auth#emailsender), [`SmsSender`](./auth#smssender)
- [`AuthEmailEvent`](./auth#authemailevent), [`AuthEmailKind`](./auth#authemailkind), [`AuthSmsEvent`](./auth#authsmsevent), [`AuthSmsKind`](./auth#authsmskind)
- [`BuildMagicLinkUrl`](./auth#buildmagiclinkurl)

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

These types are exported for consumers who wire their own audit sink. The bundled `AuthWorkflow` does **not** fire audit events itself (there is no `audit()` hook) — emit your own from a subclass step body or an interceptor. See [Audit Log](/moost/audit).

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

Defaults: `cookie.name='aooth_session'`, `secure=true`, `sameSite='lax'`, `httpOnly=true`, `path='/'`. `refreshCookie.path='/auth/refresh'` (narrow path). `enableCookie=true`, `enableBearer=true`. Bearer wins when both transports are enabled. `ResolvedAuthCookieConfig` / `ResolvedAuthOptions` are the resolved (defaults-applied) views. See [Config Reference](/moost/config).

## Subpath: `@aooth/auth-moost/atscript`

```ts
import * as forms from "@aooth/auth-moost/atscript";
```

Re-exports the **18** bundled form types from `src/atscript/models/forms.as`:

`WithInlineConsentForm` (base), `LoginCredentialsForm`, `MfaCodeForm`, `EmailIdentifierForm`, `SetPasswordForm`, `InviteForm`, `Select2faForm`, `PincodeForm`, `AskEmailForm`, `AskPhoneForm`, `EnrollPickMethodForm`, `EnrollAddressForm`, `EnrollConfirmForm`, `TermsBumpForm`, `ConcurrencyLimitForm`, `MagicLinkRequestForm`, `RecoveryModeSelectForm`, `RecoveryFactorForm`.

Several forms carry `@ui.form.component` annotations pointing at SPA components from `@atscript/vue-aooth`: `WithInlineConsentForm.consents → AsConsentArray`, `SetPasswordForm.passwordRules → AsPasswordRules`, `EnrollConfirmForm.qrCode → AsQrCode`. Replace any form per-workflow via `opts.forms.<field>` (typically `extends` the bundled one). See [Atscript Models](/moost/atscript) and [SPA Components](/moost/spa-components).
