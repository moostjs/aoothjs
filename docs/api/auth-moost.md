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

The single unified workflow class. Replaces the former `LoginWorkflow` / `RecoveryWorkflow` / `InviteWorkflow` quartet. Declares **six** `@Workflow` methods — four `@Public()`, two ARBAC-gated authenticated self-service flows (no `@Public()`; guarded by `@ArbacResource("auth.change-password" | "auth.add-mfa") @ArbacAction("self")` and excluded from `DEFAULT_AUTH_WORKFLOWS`):

| Method               | Workflow id                 | Covers                                                          |
| -------------------- | --------------------------- | --------------------------------------------------------------- |
| `loginFlow`          | `auth/login/flow`           | login + MFA + enrollment + finalize                             |
| `inviteFlow`         | `auth/invite/start`         | admin invite → anonymous magic-link accept                      |
| `recoveryFlow`       | `auth/recovery/flow`        | magic-link **or** OTP password reset                            |
| `signupFlow`         | `auth/signup/flow`          | verify-first self-signup → set password → auto-login            |
| `changePasswordFlow` | `auth/change-password/flow` | signed-in password change (gated, `POST /auth/change-password`) |
| `addMfaFlow`         | `auth/add-mfa/flow`         | signed-in MFA management (gated, `POST /auth/add-mfa`)          |

`AuthWorkflowOpts` is **infrastructure-only**; policy lives on `protected resolveXxx(ctx)` getters (each paired with a `@Step("prepare-<group>")`). Per-flow code discriminates by ctx-slot presence (`ctx.admin` / `ctx.accept` / `ctx.postReset` / `ctx.signup` / `ctx.changePassword` / `ctx.addMfa`), never a flow-name field. Subclass with `@Inherit() @Controller()`, re-declare the 4-arg constructor (so TS emits `design:paramtypes`), override the hooks you need, and bind via `setReplaceRegistry([AuthWorkflow, MyAuth])`. See [Workflows](/moost/workflows) and [packages/auth-moost/CLAUDE.md](https://github.com/moostjs/aoothjs/blob/main/packages/auth-moost/CLAUDE.md).

**Protected override surface** (defaults are no-ops or hardcoded policy):

- `deliver(payload: AuthDeliveryPayload): void | Promise<void>` — outbound dispatch for direct sends (MFA / recovery / enroll pincodes, new-device notice, security alerts). Route by `payload.kind` + `payload.channel`. NOT used for the invite magic link (emitted via the wf outlet). There is **no `audit()` method.**
- `sendSecurityAlert(ctx: AuthWfCtx, reason: string, context?: Record<string, unknown>): Promise<void>` — the blessed one-call alert path for risk overrides (e.g. impossible-travel from `resolveRiskStepUp`): emits a `security-alert` payload through `deliver()`. Recipient is `ctx.notice.email` (the proven-first correspondence chain); silent no-op when no provable inbox exists. Never called by the base class. See [Geo anomalies & impossible travel](/moost/workflows#geo-anomalies).
- `resolveXxx(ctx: AuthWfCtx)` policy getters — the override seam for context-varying policy. Return `T | Promise<T>` (never `async` on the default). The set: `resolveDeviceTrust`, `resolveMfaPolicy`, `resolveEnrollment`, `resolveSessionPolicy`, `resolveFinalize`, `resolveGuards`, `resolveLockout`, `resolveAlternateCredentials`, `resolveSignupPolicy`, `resolveChangePasswordPolicy`, `resolveOtpDisclosure`, `resolveRiskStepUp`, `resolveRedirect`, `resolveRecoveryUrl`, `resolveRecoveryAltActions`, `resolveAdminForm`, `resolveAccept`, `resolvePostReset`, `resolvePincodeForm` / `resolvePincodeTarget` / `resolvePincodeAltAction`, `resolveRecoveryChannel` (M1 OTP transport for the typed identifier), `resolveRecoveryDeliverySource` (M1 `typed` vs M2 `registered`), `resolvePromoteHandleField` (confirmed channel → login-handle column), `resolveEnrollPreConfirmed` (ctx-first extra args `(ctx, method, address)` — vouch a verified-by-construction enrolment address so `enroll-send` skips the pincode and `enroll-confirm` writes the confirmed factor with no code-entry pause; default `false`, see [Pre-seeded enrolment](/moost/workflows#pre-seeded-enrolment)), `resolveEnrollAddress` (ctx-first `(ctx, method)` — return a string to pin the sms/email enrolment address so the free-text form never renders, `'collect'` (default) to keep it; see [Pin the enrolment address](/moost/workflows#pin-enrolment-address)), `resolveTotpAccountLabel` (the account half of the authenticator's "issuer: account" TOTP label, baked into the `otpauth://` URI at provisioning time; default `ctx.email`, else the stored `username`), `resolveStepUpConfirmBeforeSend` (whether the manage-MFA step-up pauses for explicit consent before dispatching its sms/email pincode; default `true` — see [Manage MFA](/moost/workflows#add-mfa-auth-add-mfa-flow)), `resolveLockedMfaTransports`, `resolveFederatedEmailTrust` (does a provider's email claim count as correspondence inbox proof — default trusts exactly `email_verified === true`; see [Where security notices go](/moost/workflows#security-notices)), `resolveAuthzReauthPolicy` (returns `AuthzReauthPolicy { mode: 'consent-only' | 'always-reauth'; maxSessionAgeMs?; requireMfa? }` — whether an authorization-server login with a live browser session skips straight to the consent screen; consulted inline by `init-login` on authz STARTs only; default `{ mode: 'always-reauth' }`, see [Consent-only for live sessions](/moost/authorization-server#consent-only)). `resolveSignupPolicy` returns `{ allowSignup, collectUsername }` — `allowSignup` defaults `false` (self-signup off / invite-only); `prepareUser` is shared with invite (signup passes empty `roles` + no `invitedBy`). The sync helper `selectRecoveryRegisteredMethod(user)` (not a `resolveXxx`) picks the M2 OTP recipient (SMS-first, then email). Recovery-channel / handle-promotion seams are documented in [Phone, recovery channels & handle promotion](/moost/recovery-and-handles).
- `getAvailableRoles(): string[] | undefined` — selectable role whitelist for the admin invite form (default `undefined` = no whitelist).
- `duplicateInviteCheck(input: { email: string; existingUser: UserCredentials | null }): 'allow' | 'reject' | 'reuse' | Promise<…>` — structural duplicate rule for the invite admin form. Default: a `pendingInvitation` row → `'reuse'` (re-invite: the row is refreshed in place and a fresh full-TTL magic link is dispatched), any other existing row → `'reject'`, none → `'allow'`. See [Workflows — Invite](/moost/workflows#invite-auth-invite-start).
- `loadActiveSessionsCount(username)` — async data fetcher for concurrency-limit policy.
- `validateMfaAddress(ctx: AuthWfCtx, method: MfaTransport, value: string): string | undefined | Promise<string | undefined>` — server-side validation of the user-typed enrolment address (returned string = the form error). Ctx-first + async-capable so record-based rules (domain allowlists, match-the-account-email) load the row directly. Default: email-shape check / permissive E.164. To pin the address outright use `resolveEnrollAddress` instead.
- `buildAddMfaFinishEnvelope(ctx): WfFinished` — pure construction of `finish-add-mfa`'s outcome envelope (priority: removed → changed → added → blocked → nothing-available → cancelled); override to customize the manage-flow terminal copy/data.
- **Event hooks** `afterLogin` / `afterInvitationAccepted` / `afterSignup` / `afterPasswordReset` / `afterPasswordChanged` / `afterMfaChanged` `(ctx: AuthWfCtx): void | Promise<void>` — fired once at each flow's single completion point (default no-op); awaited, a throw propagates (login hooks fire before delivery → atomic). `afterLogin` is the `record-login` funnel every login routes through (interactive / federated / auto-login), firing after `account.lastLogin` is stamped and before the session/code is issued — it does **not** fire for the no-session fresh-login redirect or change-password rotation. See [Workflows — Event hooks](/moost/workflows#event-hooks).

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

### `rateLimitInterceptors`

```ts
function rateLimitInterceptors(opts?: RateLimitInterceptorOptions): TInterceptorDef[];

interface RateLimitInterceptorOptions {
  limiter?: RateLimiter; // default: memory-store limiter created once per factory call
  rules?: RateLimitRuleInput[]; // app-wide defaults for routes without @RateLimit metadata
  key?: RateLimitKeyStrategy; // default 'ip'
  trustProxy?: boolean; // default false
  headers?: boolean; // default true — draft RateLimit-* headers
  message?: string; // app-wide default 429 template
}
```

Factory returning the enforcement **pair** — a `BEFORE_GUARD` interceptor for `'ip'` / custom-keyed routes and an `AFTER_GUARD` one for `'user'` / `'auto'`-keyed routes. Register with a spread: `app.applyGlobalInterceptors(...rateLimitInterceptors(opts))`. HTTP-only; emits `RateLimit-*` (+ `Retry-After` on rejection) and throws `HttpError(429)`. See [Rate Limiting](/moost/rate-limit).

### `useRateLimit`

```ts
function useRateLimit(): RateLimitBindings;

interface RateLimitBindings {
  decision: RateLimitDecision | null; // null: no rules on the route / interceptors absent
}
```

Reads the decision the interceptor stored on the event slot. Plain function (not a cached wook); workflow child events inherit the HTTP parent's slot. See [Rate Limiting](/moost/rate-limit#useratelimit-reading-the-decision).

### `setRateLimitSubject` / `getRateLimitSubject`

```ts
function setRateLimitSubject(kind: string, subject: string, ctx?: EventContext): void;
function getRateLimitSubject(kind: string, ctx?: EventContext): string | undefined;
```

The named-subject seam: GUARD-priority code (a custom IAM, tenant resolver, API-key gateway) supplies the caller identity for routes keyed by `kind`; the post-guard rate-limit phase reads it. Values are used verbatim as the counter subject (include your own prefix). The map is read first, so an explicit write always wins over the built-in `user` (`u:<userId>`) / `session` (`s:<sessionId>`) kinds, which derive from the auth context when the map is empty. See [Rate Limiting — the subject seam](/moost/rate-limit#the-subject-seam-setratelimitsubject).

### `getRateLimitMate`

```ts
function getRateLimitMate(): Mate<TRateLimitMeta>;
interface TRateLimitMeta {
  rateLimitRules?: RateLimitRule[]; // normalized at decoration time
  rateLimitOptions?: RateLimitDecoratorOptions;
  rateLimitDisabled?: boolean; // @RateLimit(false)
}
```

Shared moost `Mate` typed with `TRateLimitMeta`. Declaration-merged into `TMoostMetadata`. See [Decorators](/moost/decorators).

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
function humanizeUserAgent(ua: string | undefined): string | undefined; // "Safari on macOS" — seen-device labels
function haversineKm(a: { lat: number; lon: number }, b: { lat: number; lon: number }): number; // great-circle km (WGS84 mean radius) — impossible-travel thresholds
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

### `@RateLimit`

```ts
function RateLimit(disabled: false): ClassDecorator & MethodDecorator;
function RateLimit(
  ...rulesAndOpts: [RateLimitRuleInput, ...Array<RateLimitRuleInput | RateLimitDecoratorOptions>]
): ClassDecorator & MethodDecorator;

interface RateLimitDecoratorOptions {
  // 'ip' | 'user' | 'auto' | 'session' | any named subject kind | () => string | Promise<string>
  key?: RateLimitKeyStrategy;
  message?: string; // default 429 template for rules without an inline one
  id?: string; // shared bucket id; default scope '<ControllerClass>.<methodName>'
}
```

Metadata-only rule declaration; variadic rules with an optional trailing options object (detected by the absence of a `limit` key). Method-level metadata replaces class-level. Rules parse eagerly — bad grammar throws at boot. Enforced by `rateLimitInterceptors` / `@RateLimited`. See [Rate Limiting](/moost/rate-limit#ratelimit-rules-options).

### `@RateLimited`

```ts
function RateLimited(opts?: RateLimitInterceptorOptions): ClassDecorator & MethodDecorator;
```

Attaches the `rateLimitInterceptors(opts)` **pair** via two `@Intercept`s — the `AuthGuarded` counterpart. Safe alongside a global registration (the decision slot dedups). See [Rate Limiting](/moost/rate-limit#ratelimited-per-controller-sugar).

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
  deviceRecognition?: {
    cookieName?: string; // `${deviceTrust.cookieName}_seen` → 'aooth_trusted_device_seen'
    ttlMs?: number; // 180 days
    maxDevices?: number; // 5 — `seenDevices` ledger cap, LRU-evicted beyond it
  };
  forms?: {/* one TAtscriptAnnotatedType slot per bundled form — see the form list below */};
}
```

**Infrastructure-only.** Every field is optional; the constructor runs `mergeAuthWorkflowOpts(opts)` to produce a fully-populated `ResolvedAuthWorkflowOpts` read as `this.opts.<group>.<field>` without optional chaining. Policy NEVER lives here — if a knob varies by request/tenant/user it belongs on a `resolveXxx(ctx)` getter. Replace any bundled form per-slot via `opts.forms.<field>`. See [Workflows](/moost/workflows) and [Config Reference](/moost/config).

`deviceRecognition` configures the always-on recognition cookie + `seenDevices` ledger — a notification suppressor only, never an MFA bypass (that is `deviceTrust`, which stays opt-in and strict). Recognition is cookie-only by design (never IP-bound) and requires `deviceTrust.secret` on the `UserService` — without it the `device-recognition` step silently no-ops. See [Device recognition](/moost/workflows#device-recognition).

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
    }
  | {
      kind: "security-alert"; // consumer-triggered (sendSecurityAlert) — never auto-sent
      channel: "email";
      recipient: string;
      reason: string; // machine-readable trigger, e.g. "impossible-travel"
      loginAt: number;
      context?: Record<string, unknown>; // free-form template data (distances, cities)
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
- [`RateLimiter`](./auth#ratelimiter), [`RateLimitStoreMemory`](./auth#ratelimitstorememory) and the rate-limit types ([`RateLimitDecision`](./auth#ratelimitdecision), [`RateLimitRule` / `RateLimitRuleInput`](./auth#ratelimitrule-ratelimitruleinput), [`RateLimitStore`](./auth#ratelimitstore), `RateLimiterOptions`) — the Redis store stays on [`@aooth/auth/redis`](./auth#ratelimitstoreredis)

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
  authorize(
    /* @Query response_type, client_id?, redirect_uri, state?, code_challenge,
                code_challenge_method, scope?, nonce?, resource? */
  ): Promise<string>; // GET authorize → 302
  token(
    /* @Body { grant_type, code?, code_verifier?, client_id?, client_secret?,
                   refresh_token?, resource? } */
  ): Promise<TokenSuccess | TokenError>; // POST token
  //   grant_type: "authorization_code" (code + PKCE) or "refresh_token" (rotate)
  discovery(): OidcDiscoveryDocument | TokenError; //   GET .well-known/openid-configuration (Tier 2)
  jwks(): Promise<{ keys: JWK[] }> | TokenError; //     GET jwks                             (Tier 2)
  oauthServerMetadata(): AuthorizationServerMetadata | TokenError; // GET .well-known/oauth-authorization-server
  register(/* @Body RFC 7591 metadata */): Promise<unknown>; //      POST register (404 unless DCR wired)
  // override seams (getters, NOT DI; see below):
  protected getIdTokenSigner(): IdTokenSigner | undefined; //      default: undefined → 404 / no id_token
  protected getOidcClaimsResolver(): OidcClaimsResolver; //        default: NoopOidcClaimsResolver
  protected loginPath(): string; //                               default: "/login"
  protected getIssuer(): string | undefined; //                   default: signer?.issuer — override for signer-less RFC 8414
  protected getDynamicClientRegistration(): DynamicClientRegistration | undefined; // default: undefined → DCR off
  protected scopesSupported(): string[] | undefined; //           default: undefined (RFC 8414 scopes_supported)
}
```

All routes are `@Public()`. `authorize` runs the trust gate (`policy.resolveClient`) FIRST, records the pending authorization (authority fixed here — incl. the resolved `clientName` for consent and the RFC 8707 `resource`, plus a per-request browser-binding secret), drops the `aooth_authz` binding cookie, and 302s `/login?authz=<handle>`. A repeated or oversized `resource` fails soft with `error=invalid_target`; the trust-gate 400 body is deliberately generic (with self-registered clients, distinguishing `invalid_client` from `invalid_redirect` is a client_id-existence oracle). The login workflow's `authz-consent` step then re-verifies the cookie and requires the user to explicitly approve the client before `mint-authz-code` mints a code (see [Consent gate & browser binding](/moost/authorization-server#consent-gate-browser-binding)). `token` with `grant_type=authorization_code` consumes the single-use code, verifies PKCE, authenticates the client, checks `resource` consistency (both legs present and different → `400 invalid_target`), and mints the access token and/or `id_token` — off the browser — plus a rotating `refresh_token` when the grant's `TokenPolicy.refresh` opted in. With `grant_type=refresh_token` it authenticates the presenting client, verifies the family's `metadata.authzClientId` binding BEFORE anything rotates (mismatch / no stamp — e.g. a browser-session refresh token — is `400 invalid_grant` with the family untouched), and rotates the pair; replay of an already-rotated token beyond the grace window revokes the whole family. See [the refresh grant](/moost/authorization-server#refresh-token-grant). `discovery` / `jwks` 404 when no signer is wired; `oauthServerMetadata` is **signer-independent** (404 only when `getIssuer()` is undefined) and advertises `registration_endpoint` when DCR is wired — as does `discovery` in a combined deployment. `register` is the RFC 7591 endpoint: JSON-only, 201 echoes all registered (server-narrowed) metadata with `client_id_issued_at` in seconds; a `client_secret_post` registration is echoed once with its minted `client_secret` + `client_secret_expires_at: 0` (public clients get no secret fields); `ClientRegistrationError` → `400 { error, error_description }`. See [Wiring — MCP connectors](/moost/authorization-server#wiring-mcp-connectors).

**The optional dependencies are getters, not DI tokens.** An optional `@Inject`/`@Optional` dependency panics in moost's `resolveMoost` route-table pass (triggered by `AuthController`'s `@MoostInit` refresh-cookie hook → _"Class is not Injectable and not Optional"_). A subclass overrides `getIdTokenSigner()` / `getOidcClaimsResolver()` / `getIssuer()` / `getDynamicClientRegistration()` / `scopesSupported()` and is registered in place of the base class (re-declare the ctor with the same `@Inject` tokens — moost@0.6.x doesn't inherit `@Inject` across `extends`). Never derive `getIssuer()` from the Host header — the metadata document is cacheable.

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
const DYNAMIC_CLIENT_STORE_TOKEN = "aooth:DynamicClientStore";
```

Provide the concrete `ClientRedirectPolicy` (a `LoopbackClientPolicy`, `RegisteredClientPolicy`, or `CompositeClientPolicy`) + the two stores under these strings — all abstract/interface deps with no class reference to inject by. `DYNAMIC_CLIENT_STORE_TOKEN` is for a DCR-enabling subclass: the **base** controller never injects it (DCR is optional, and an optional `@Inject` panics — see above); the subclass adds it as a required ctor param, builds a `DynamicClientRegistration` around it, and overrides the getter.

### Discovery / DCR re-exports

`buildAuthorizationServerMetadata`, `buildProtectedResourceMetadata`, `buildWwwAuthenticateBearerChallenge`, `canonicalizeIssuer`, and `DynamicClientRegistration` (+ their option/document types) are re-exported from [`@aooth/auth/authz`](/api/auth#authz-subpath) so a consumer can mount the root-level discovery documents (the RFC 8414 path-insertion form + the RFC 9728 PRM) and the 401 challenge from one import. See [Root-mounted discovery](/moost/authorization-server#wiring-mcp-connectors).

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

Re-exports the **28** bundled form types from `src/atscript/models/forms.as`:

`WithInlineConsentForm` (base), `LoginCredentialsForm`, `MfaCodeForm`, `EmailIdentifierForm`, `SignupForm`, `SetPasswordForm`, `ChangePasswordForm`, `InviteForm`, `Select2faForm`, `PincodeForm`, `AskEmailForm`, `AskPhoneForm`, `EnrollPickMethodForm`, `EnrollAddressForm`, `EnrollTotpQrForm`, `EnrollConfirmForm`, `ManageMfaForm`, `RemoveMfaConfirmForm`, `PasswordReauthForm`, `StepUpConfirmForm` (the manage step-up dispatch-consent notice — [Manage MFA](/moost/workflows#add-mfa-auth-add-mfa-flow)), `TermsBumpForm`, `ConcurrencyLimitForm`, `MagicLinkRequestForm`, `RecoveryModeSelectForm`, `RecoveryFactorForm`, `ProveControlForm`, `ProveControlOtpForm`, `AuthorizeConsentForm` (the authorization-server consent prompt — [Consent gate](/moost/authorization-server#consent-gate-browser-binding)).

Several forms carry `@ui.form.component` annotations pointing at SPA components from `@atscript/vue-aooth`: `WithInlineConsentForm.consents → AsConsentArray`, `SetPasswordForm.passwordRules → AsPasswordRules`, `EnrollConfirmForm.qrCode → AsQrCode`. Replace any form per-workflow via `opts.forms.<field>` (typically `extends` the bundled one). See [Atscript Models](/moost/atscript) and [SPA Components](/moost/spa-components).
