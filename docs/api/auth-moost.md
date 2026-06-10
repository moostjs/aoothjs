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

| Method         | Workflow id          | Covers                                               |
| -------------- | -------------------- | ---------------------------------------------------- |
| `loginFlow`    | `auth/login/flow`    | login + MFA + enrollment + finalize                  |
| `inviteFlow`   | `auth/invite/start`  | admin invite → anonymous magic-link accept           |
| `recoveryFlow` | `auth/recovery/flow` | magic-link **or** OTP password reset                 |
| `signupFlow`   | `auth/signup/flow`   | verify-first self-signup → set password → auto-login |

`AuthWorkflowOpts` is **infrastructure-only**; policy lives on `protected resolveXxx(ctx)` getters (each paired with a `@Step("prepare-<group>")`). Per-flow code discriminates by ctx-slot presence (`ctx.admin` / `ctx.accept` / `ctx.postReset` / `ctx.signup`), never a flow-name field. Subclass with `@Inherit() @Controller()`, re-declare the 4-arg constructor (so TS emits `design:paramtypes`), override the hooks you need, and bind via `setReplaceRegistry([AuthWorkflow, MyAuth])`. See [Workflows](/moost/workflows) and [packages/auth-moost/CLAUDE.md](https://github.com/moostjs/aoothjs/blob/main/packages/auth-moost/CLAUDE.md).

**Protected override surface** (defaults are no-ops or hardcoded policy):

- `deliver(payload: AuthDeliveryPayload): void | Promise<void>` — outbound dispatch for direct sends (MFA / recovery / enroll pincodes, new-device notice). Route by `payload.kind` + `payload.channel`. NOT used for the invite magic link (emitted via the wf outlet). There is **no `audit()` method.**
- `resolveXxx(ctx: AuthWfCtx)` policy getters — the override seam for context-varying policy. Return `T | Promise<T>` (never `async` on the default). The set: `resolveDeviceTrust`, `resolveMfaPolicy`, `resolveEnrollment`, `resolveSessionPolicy`, `resolveFinalize`, `resolveGuards`, `resolveLockout`, `resolveAlternateCredentials`, `resolveSignupPolicy`, `resolveChangePasswordPolicy`, `resolveOtpDisclosure`, `resolveRiskStepUp`, `resolveRedirect`, `resolveRecoveryUrl`, `resolveRecoveryAltActions`, `resolveAdminForm`, `resolveAccept`, `resolvePostReset`, `resolvePincodeForm` / `resolvePincodeTarget` / `resolvePincodeAltAction`, `resolveRecoveryChannel` (M1 OTP transport for the typed identifier), `resolveRecoveryDeliverySource` (M1 `typed` vs M2 `registered`), `resolvePromoteHandleField` (confirmed channel → login-handle column). `resolveSignupPolicy` returns `{ allowSignup, collectUsername }` — `allowSignup` defaults `false` (self-signup off / invite-only); `prepareUser` is shared with invite (signup passes empty `roles` + no `invitedBy`). The sync helper `selectRecoveryRegisteredMethod(user)` (not a `resolveXxx`) picks the M2 OTP recipient (SMS-first, then email). Recovery-channel / handle-promotion seams are documented in [Phone, recovery channels & handle promotion](/moost/recovery-and-handles).
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

REST surface — see [REST endpoints](#rest-endpoints) below for the seven routes (five `@Public()`, two ARBAC-gated). `users` is `@Optional()`: only `GET /auth/invite/post-redemption` reads it directly (returns 500 when unset); the other routes work without a `UserService` on the controller. Subclass and override `triggerWf()` to extend the workflow allow-list. See [REST Controllers](/moost/controllers).

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

Customer-overridable DI seam for the consent universe + persistence. All four methods are no-op defaults — extend the class and register the replacement via `setReplaceRegistry([ConsentStore, MyConsentStore])`. **`getPendingConsents` is user-scoped only** — its argument is the **stable user id** (the workflow passes `ctx.subject`), and the returned set must NOT vary by workflow or channel; OTP channel-ownership disclosures are recorded separately via `recordOtpChannelConsent`. Pending descriptors are transported to the SPA carrier form (via `@wf.context.pass`) and rendered by the `AsConsentArray` component. See [Workflows — ConsentStore](/moost/workflows#consent-collection).

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
  getAuthContext<TPayload>(): AuthContext<TPayload> | null;
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

`AuthController` mounts **seven** routes — five `@Public()`, two ARBAC-gated authenticated self-service flows:

| Method | Path                           | Body / Query                               | Response              | Notes                                                                                                                                                                                |
| ------ | ------------------------------ | ------------------------------------------ | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `POST` | `/auth/logout`                 | `AuthLogoutBody`                           | `AuthOkResponse`      | `@Public()`. Defence-in-depth 401 on null context. Revokes this session's whole token family (`revokeSession`), token-level revokes as fallback.                                     |
| `POST` | `/auth/refresh`                | `AuthRefreshBody`                          | `AuthLoginResponse`   | `@Public()`. Falls back to refresh cookie. 401 on `AuthError`.                                                                                                                       |
| `GET`  | `/auth/status`                 | —                                          | `AuthContext`         | `@Public()`. 401 when no context.                                                                                                                                                    |
| `POST` | `/auth/trigger`                | `{ wfs?, input?: { action?, formData? } }` | `WfFinished` envelope | `@Public() @WfTrigger({ allow: DEFAULT_AUTH_WORKFLOWS })`. Single entry-point for the public schemas (login / invite / recovery / signup).                                           |
| `GET`  | `/auth/invite/post-redemption` | `?uid=<userId>`                            | `WfFinished` envelope | `@Public()`. Idempotent "already accepted" envelope for re-clicked invite links (after the wf state row is evicted). Needs `UserService`.                                            |
| `POST` | `/auth/change-password`        | `{ wfs?, input?: { action?, formData? } }` | `WfFinished` envelope | **Gated** — `@ArbacResource("auth.change-password") @ArbacAction("self") @WfTrigger({ allow: [CHANGE_PASSWORD_WORKFLOW] })`. 401/403 before handler.                                 |
| `POST` | `/auth/add-mfa`                | `{ wfs?, input?: { action?, formData? } }` | `WfFinished` envelope | **Gated** — `@ArbacResource("auth.add-mfa") @ArbacAction("self") @WfTrigger({ allow: [ADD_MFA_WORKFLOW] })`. Authenticated "Manage MFA" flow (add / change / remove, step-up first). |

See [REST Controllers](/moost/controllers).

## Constants

### `DEFAULT_AUTH_WORKFLOWS`

```ts
const DEFAULT_AUTH_WORKFLOWS = [
  "auth/login/flow",
  "auth/invite/start",
  "auth/recovery/flow",
  "auth/signup/flow",
] as const;
```

Default `allow` list for `@WfTrigger` on `AuthController.triggerWf()`. Subclasses override `triggerWf()` with a different `@WfTrigger({ allow })` to extend. See [REST Controllers](/moost/controllers).

### `CHANGE_PASSWORD_WORKFLOW` / `ADD_MFA_WORKFLOW`

```ts
const CHANGE_PASSWORD_WORKFLOW = "auth/change-password/flow";
const ADD_MFA_WORKFLOW = "auth/add-mfa/flow";
```

Workflow ids for the two **gated** self-service flows, exported separately and deliberately **excluded** from `DEFAULT_AUTH_WORKFLOWS`. Each is the sole entry on its own route's `@WfTrigger({ allow })` (`POST /auth/change-password`, `POST /auth/add-mfa`), so neither is reachable from the public `/auth/trigger`. Enable a flow by granting its ARBAC resource (`allow("auth.change-password", "*")` / `allow("auth.add-mfa", "*")`); omit the grant to disable it entirely — the privilege **is** the switch. See [Workflows — Change password](/moost/workflows#change-password-auth-change-password-flow) and [Add MFA method](/moost/workflows#add-mfa-auth-add-mfa-flow).

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
      kind: "signup-pincode"; // verify-first self-signup email-ownership OTP
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

The `@wf.context.pass` slots and policy-resolver return shapes are exported for typing subclass overrides: `AuthWfCtx`, `AuthWfCompletionState`, `AuthWfConsentsState`, `AuthWfMfaEnrollState`, `AuthWfPasswordUiState`, `AuthWfPincodeUiState`, `AuthWfSignupState`, `ConsentDescriptorLike`, `MfaSummary`, `MfaTransport`, `LoginRedirect`, `SsoProvider`, `ConcurrencyLimitOptions`. `AuthWfCtx` has **no `flow` field** — discriminate by ctx-slot presence (`ctx.admin` / `ctx.accept` / `ctx.postReset` / `ctx.signup`).

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

## Federated login (OAuth2 / OIDC)

The Moost wiring of [`@aooth/idp`](/api/idp). See [Federated Login (OAuth)](/moost/oauth) for the narrative.

### `OAuthController`

```ts
@Controller("auth/oauth")
class OAuthController {
  // ctor: (registry, auth, users, @Inject(FEDERATED_IDENTITY_STORE_TOKEN) federated)
  identities(): Promise<ConnectedAccount[]>; //                  GET identities        — self-scoped
  link(@Param provider, @Query redirect?): Promise<string>; //   GET :provider/link    — self-scoped, 302
  unlink(@Param provider, @Param subject): Promise<{ ok: true }>; // DELETE :provider/:subject
}
```

Mounted REST surface for federated ACCOUNT MANAGEMENT — the routes are self-scoped (`@Public()`, identity from `useAuth().getUserId()`). Anonymous LOGIN is NOT here: it's the login form's SSO button → `AuthWorkflow.beginSso`. `identities` lists the caller's connected accounts; `link` mints a signed state + PKCE-from-seed and 302s to the provider for an account link; `unlink` disconnects an identity (last-credential guard, then revokes the user's sessions). The callback is bridged by the SPA into `/auth/trigger` (`auth/login/flow`). Subclass to override `defaultRedirect()` or to add `@ArbacAction(...)`.

### `ConnectedAccount`

```ts
interface ConnectedAccount {
  provider: string;
  subject: string; // (provider, subject) is the unlink key
  linkedAt: number;
  lastLoginAt?: number;
  email?: string;
  emailVerified?: boolean;
  displayName?: string;
  avatarUrl?: string;
}
```

Wire shape of `GET /auth/oauth/identities` — a display projection of a `FederatedIdentity` row (the surrogate `id` and the caller's own `userId` are dropped).

### `OAuthRuntime`

```ts
@Injectable()
class OAuthRuntime {
  constructor(registry: OAuthProviderRegistry, federated: FederatedLoginService);
}
```

DI holder bundling the two app-provided federated-login singletons the `sso-callback` / `prove-control` steps resolve (via `useControllerContext().instantiate(OAuthRuntime)`), so `AuthWorkflow`'s ctor stays unchanged.

### DI token + HTTP helpers

```ts
const FEDERATED_IDENTITY_STORE_TOKEN = "aooth:FederatedIdentityStore";
const OAUTH_CSRF_COOKIE = "aooth_oauth";
function oauthCsrfCookieAttrs(opts: {
  secure: boolean;
  maxAgeSec?: number;
  path?: string;
}): TCookieAttributesInput;
function isSafeRelativeRedirect(target: string | undefined): target is string; // open-redirect §7
function resolveOAuthRedirect(requested: string | undefined, fallback: string): string;
```

The abstract `FederatedIdentityStore` binds under a **string token** (moost can't use an abstract class as a class-reference DI token). There is **no** OAuth flow store — the round-trip is stateless (PKCE verifier + nonce are derived from the signed-state seed, never persisted). `OAUTH_CSRF_COOKIE` is the Lax double-submit cookie; `isSafeRelativeRedirect` rejects the §7 open-redirect bypass list (`//evil`, `/\evil`, absolute URLs, control chars).

### Federated leg of `auth/login/flow` + `ctx.oauth`

Federated login is merged into `auth/login/flow` (no separate OAuth workflow). The `sso-callback` step (`condition: !!ctx.idpInbound`) runs the verified exchange (verify state + CSRF double-submit + RE-derive verifier from the seed + verified ID-token exchange + `resolveUser`/`linkIdentity` + account-state gate); on `needs-link` it stashes `ctx.pendingLink` and diverts to the `prove-control` step (password or OTP-fallback proof, with `resend`) before setting `ctx.subject`, then the shared login tail runs. `AuthWfCtx.oauth?: AuthWfOAuthState` (`{ provider, outcome?, isNew?, redirect? }`; `outcome` includes `'interactively-linked'`) is the flow discriminator.

## Authorization server

The Moost HTTP layer for the authorization server (aoothjs AS an OAuth/OIDC provider for its own clients). The framework-agnostic stores, policies, signer, and claims resolver live in [`@aooth/auth/authz`](/api/auth#authz-subpath). See [Authorization Server](/moost/authorization-server) for the narrative + wiring.

### `AuthorizeController`

```ts
@Controller("auth")
class AuthorizeController {
  // ctor: (auth, @Inject(CLIENT_REDIRECT_POLICY_TOKEN) policy,
  //        @Inject(PENDING_AUTHORIZATION_STORE_TOKEN) pending,
  //        @Inject(AUTH_CODE_STORE_TOKEN) codes)
  authorize(/* @Query response_type, client_id?, redirect_uri, state?, code_challenge,
                code_challenge_method, scope?, nonce? */): Promise<string>; // GET authorize  → 302
  token(/* @Body { grant_type, code, code_verifier, client_id?, client_secret? } */): Promise<
    TokenSuccess | TokenError
  >; //                                     POST token
  discovery(): OidcDiscoveryDocument | TokenError; //   GET .well-known/openid-configuration (Tier 2)
  jwks(): Promise<{ keys: JWK[] }> | TokenError; //     GET jwks                             (Tier 2)
  // override seams (Tier 2 — getters, NOT DI; see below):
  protected getIdTokenSigner(): IdTokenSigner | undefined; //      default: undefined → 404 / no id_token
  protected getOidcClaimsResolver(): OidcClaimsResolver; //        default: NoopOidcClaimsResolver
  protected loginPath(): string; //                               default: "/login"
}
```

All routes are `@Public()`. `authorize` runs the trust gate (`policy.resolveClient`) FIRST, records the pending authorization (authority fixed here, plus a per-request browser-binding secret), drops the `aooth_authz` binding cookie, and 302s `/login?authz=<handle>`. The login workflow's `authz-consent` step then re-verifies that cookie and requires the user to explicitly approve the client before `mint-authz-code` mints a code (see [Consent gate & browser binding](/moost/authorization-server#consent-gate-browser-binding)). `token` consumes the single-use code, verifies PKCE, authenticates the client (Tier 2), and mints the access token and/or `id_token` — off the browser. `discovery` / `jwks` 404 when no signer is wired (Tier-1-only).

**The signer / claims resolver are getters, not DI tokens.** An optional `@Inject`/`@Optional` dependency panics in moost's `resolveMoost` route-table pass (triggered by `AuthController`'s `@MoostInit` refresh-cookie hook → _"Class is not Injectable and not Optional"_). A subclass overrides `getIdTokenSigner()` / `getOidcClaimsResolver()` and is registered in place of the base class (re-declare the ctor with the same three `@Inject` tokens — moost@0.6.x doesn't inherit `@Inject` across `extends`).

### `AuthorizeRuntime`

```ts
@Injectable()
class AuthorizeRuntime {
  constructor(
    @Inject(PENDING_AUTHORIZATION_STORE_TOKEN) pending: PendingAuthorizationStore,
    @Inject(AUTH_CODE_STORE_TOKEN) codes: AuthCodeStore,
  );
}
```

DI holder bundling the two stores the login-wf `mint-authz-code` terminal needs (a `@Step` body can't `@Inject` a string token, so it resolves this via `useControllerContext().instantiate(AuthorizeRuntime)`). Mirrors `OAuthRuntime`.

### DI tokens

```ts
const CLIENT_REDIRECT_POLICY_TOKEN = "aooth:ClientRedirectPolicy";
const PENDING_AUTHORIZATION_STORE_TOKEN = "aooth:PendingAuthorizationStore";
const AUTH_CODE_STORE_TOKEN = "aooth:AuthCodeStore";
```

Provide the concrete `ClientRedirectPolicy` (a `LoopbackClientPolicy`, `RegisteredClientPolicy`, or `CompositeClientPolicy`) + the two stores under these strings — all three are abstract/interface deps with no class reference to inject by.

### Browser-binding cookie

```ts
const AUTHZ_BINDING_COOKIE = "aooth_authz";
function authzBindingCookieAttrs(opts: {
  secure: boolean;
  maxAgeSec: number;
}): TCookieAttributesInput;
```

`AuthorizeController` sets this `httpOnly; SameSite=Lax` cookie at `/authorize` to the per-request `binding` secret; the `authz-consent` step constant-time-matches it before minting a code, so an `authz` handle phished into another browser is inert (parallel to the federated `OAUTH_CSRF_COOKIE` — the attrs delegate to `oauthCsrfCookieAttrs` with `path=/`). The controller passes `maxAgeSec` derived from the pending row's `expiresAt` (returned by `PendingAuthorizationStore.create`), so the cookie tracks the row's lifetime even for a store configured with a non-default `ttlMs`. Reference the name if a reverse proxy filters cookies by allowlist. Narrative: [Consent gate & browser binding](/moost/authorization-server#consent-gate-browser-binding).

## Subpath: `@aooth/auth-moost/atscript`

```ts
import * as forms from "@aooth/auth-moost/atscript";
```

Re-exports the **19** bundled form types from `src/atscript/models/forms.as`:

`WithInlineConsentForm` (base), `LoginCredentialsForm`, `MfaCodeForm`, `EmailIdentifierForm`, `SetPasswordForm`, `InviteForm`, `Select2faForm`, `PincodeForm`, `AskEmailForm`, `AskPhoneForm`, `EnrollPickMethodForm`, `EnrollAddressForm`, `EnrollConfirmForm`, `TermsBumpForm`, `ConcurrencyLimitForm`, `MagicLinkRequestForm`, `RecoveryModeSelectForm`, `RecoveryFactorForm`, `AuthorizeConsentForm` (the authorization-server consent prompt — [Consent gate](/moost/authorization-server#consent-gate-browser-binding)).

Several forms carry `@ui.form.component` annotations pointing at SPA components from `@atscript/vue-aooth`: `WithInlineConsentForm.consents → AsConsentArray`, `SetPasswordForm.passwordRules → AsPasswordRules`, `EnrollConfirmForm.qrCode → AsQrCode`. Replace any form per-workflow via `opts.forms.<field>` (typically `extends` the bundled one). See [Atscript Models](/moost/atscript) and [SPA Components](/moost/spa-components).
