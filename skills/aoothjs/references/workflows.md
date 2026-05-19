# workflows

The three bundled workflows — `LoginWorkflow`, `RecoveryWorkflow`, `InviteWorkflow` — plus the `WfFinished` envelope contract, the `WfTrigger` machinery, and the bundled forms catalogue.

## Contents

- [Common recipe](#common-recipe)
- [LoginWorkflow — `auth.login`](#loginworkflow--authlogin)
- [RecoveryWorkflow — `auth.recovery`](#recoveryworkflow--authrecovery)
- [InviteWorkflow — `auth.invite` / `auth.reInvite` / `auth.cancelInvite`](#inviteworkflow--authinvite--authreinvite--authcancelinvite)
- [The `WfFinished` envelope](#the-wffinished-envelope)
- [`WfTrigger` machinery](#wftrigger-machinery)
- [Per-workflow options](#per-workflow-options)
- [Forms catalogue](#forms-catalogue)
- [Audit events](#audit-events)
- [Workflow wire protocol](#workflow-wire-protocol)

## Common recipe

All three workflow classes share:

- Class-level decorators on the BASE class: `@Public() @Injectable("FOR_EVENT") @Controller()` (except `InviteWorkflow`, where the class is `@ArbacResource('auth.invite') @ArbacAction('start')` and phase-B steps carry their own `@Public()`).
- A `@Workflow(id)` method with `@WorkflowSchema<Ctx>([{ id: "step" }, ...])` declaring the step catalog.
- `@Step("id")` handlers with `@WorkflowParam("context") ctx: Ctx`.
- A `protected` extension surface (`deliver`, `audit`, etc.) for app overrides.

Step IDs are workflow-scoped because `@moostjs/event-wf` registers `@Step('id')` globally — identical IDs across workflows would silently collide.

### Default opts subclasses (shipped)

When you accept the default opts, register the shipped opts-less subclasses instead of writing the empty-opts shim three times:

```ts
import {
  DefaultLoginWorkflow,
  DefaultRecoveryWorkflow,
  DefaultInviteWorkflow,
} from "@aooth/auth-moost";

app.registerControllers(
  AuthController,
  DefaultLoginWorkflow,
  DefaultRecoveryWorkflow,
  DefaultInviteWorkflow,
);
```

These exist because the base workflow constructors take `opts` as a non-class POJO first argument — moost's DI can't resolve interface types, so you'd otherwise need to subclass and call `super({}, users, auth)` three times. The `Default*` classes do exactly that and nothing else.

### Custom subclass pattern (override opts or hooks)

Use this when you need custom `opts`, `deliver`, `audit`, etc. — the `Default*` classes only cover the empty-opts case:

```ts
@Inherit() // carries base class meta (@Public, @Workflow, @Step, @ArbacResource)
@Injectable("FOR_EVENT") // moost@0.6.x does NOT inherit @Injectable across extends
@Controller()
class AppLoginWorkflow extends LoginWorkflow {
  constructor(users: UserService, auth: AuthCredential) {
    // MUST re-declare
    super(
      {
        /* opts */
      },
      users,
      auth,
    );
  }
  protected override async deliver(payload: DeliverPayload): Promise<void> {
    /* forward to your EmailSender / SmsSender */
  }
}
```

## LoginWorkflow — `auth.login`

Step phases. Each terminal step gates on `!ctx.aborted`.

| Phase | Steps                                                                                                                                                                               | Notes                                                                                                                                                                                                                                              |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0     | `init`                                                                                                                                                                              | Snapshots opts onto ctx via `snapshotOpts()`.                                                                                                                                                                                                      |
| 1     | `credentials`                                                                                                                                                                       | Happy path. Alt-actions (`forgotPassword`, `signup`, `magicLink`, per-SSO `<id>`) inspected on `input.action` BEFORE form validation; each triggers `finishWfWithRedirect(url, { reason })`. SSO emits per-provider `reason: 'sso-${id}'`.         |
| 3     | `ensureEmail` / `ensurePhone`                                                                                                                                                       | Enrollment loops.                                                                                                                                                                                                                                  |
| 4     | `check-trusted-device` → `prepare-mfa-options` → `select2fa` (if >1 method) → (`pincode-send-login` + `pincode-check-login`) \| `mfa-totp` → `mfa-enroll-required` → `risk-step-up` | MFA `while`-loop. Loop exits when `mfaChecked` flips true. Backup codes handled by `handleBackupCode` via `BackupCodeForm`.                                                                                                                        |
| —     | `device-trust`                                                                                                                                                                      | Issues an HMAC-signed trust cookie.                                                                                                                                                                                                                |
| 5     | `prepare-password-rules` + `create-password-form`                                                                                                                                   | Forced password change for `passwordInitial`. `logout` alt-action → `finishWfAborted("logout", { message })` and `ctx.aborted = true`.                                                                                                             |
| 6     | `terms-accept` / `profile-complete` / `consent-marketing`                                                                                                                           | `decline` alt-action on terms aborts.                                                                                                                                                                                                              |
| 7     | `tenant-select` / `persona-select`                                                                                                                                                  | Multi-context selection.                                                                                                                                                                                                                           |
| 8     | `concurrency-limit`                                                                                                                                                                 | `reject` → 429. `kickPrompt` → form with `logoutOthers` / `cancel` alt-actions.                                                                                                                                                                    |
| 9     | `issue` → `audit-login` → `notify-new-device` → `redirect`                                                                                                                          | Finalize. `issue` mints tokens via raw envelope path: `useWfFinished().set({ type: "data", value: envelope, cookies })`. `redirect` overrides issue's data envelope with an immediate-redirect envelope when `resolveRedirect(ctx)` returns a URL. |

**Protected extension surface**: `deliver(payload)`, `audit(event)`, `loadTrustedDevice`, `storeTrustedDevice`, `revokeTrustedDevice`, `issueTrustedDevice`, `applyProfile`, `applyConsentMarketing`, `loadTenants`, `loadPersonas`, `logoutOtherSessions`, `assessRiskStepUp`, `resolveRedirect`, `buildRecoveryUrl`, `snapshotOpts`.

## RecoveryWorkflow — `auth.recovery`

Linear with one branch (delivery mode) and one OTP `while`-loop.

```
recoveryInit
 → recoveryRequest                   (collects email; anti-enumeration: unknown email still emits generic finishWfWithData({ sent: true }))
 → recoverySelectMode                (only when delivery.mode === 'choice')
 → recoverySendMagicLink             (uses outletEmail)
   |  OR
   → recoverySendOtp + recoveryCheckOtp   (while-loop; alt-actions: resend, useDifferentTransport, backToLogin)
 → recoveryVerifyFactor              (when preReset.requireKnownFactor)
 → recoverySetPassword
 → recoveryRevokeSessions            (auth.revokeAllForUser)
 → recoveryAudit
 → recoveryFreshLoginFinish          (finishWfWithRedirect(loginUrl, { autoMs: 5000, skipLabel, message, reason: 'reset-success' }))
   |  OR
 → recoveryAutoLoginFinish           (mints tokens via raw useWfFinished().set({ ... }) path to attach cookies)
```

**Protected hooks**: `deliver`, `audit`, `emailToUserId(email)` (defaults to identity — apps where `username !== email` MUST override), `verifyRecoveryFactor`.

## InviteWorkflow — `auth.invite` / `auth.reInvite` / `auth.cancelInvite`

Two-phase: admin (gated) + anonymous magic-link resume (public).

### Phase A (admin) — gated by class-level `@ArbacResource('auth.invite') @ArbacAction('start')`

```
inviteInit
 → invitePrepareAvailableRoles       (calls protected getAvailableRoles())
 → inviteSelectSendMode               (only when send.mode === 'choice')
 → inviteAdminInviteForm              (collects email/firstName/lastName/roles;
                                       server-side whitelist enforcement rejects admin-submitted
                                       roles outside ctx.availableRoles)
 → inviteInferRolesStep
 → invitePreCreateUser                (users.createUser, then users.update(email, {account:{pendingInvitation:true}}))
```

### Boundary — `inviteSendInviteEmail` / `inviteReturnShareableLink` (both `@Public()`)

Emits `outletEmail(ctx.email, "invite.magicLink", { username, roles?, expiresAtMs })`. Idempotent on `ctx.linkSent`.

### Phase B (anonymous magic-link resume — all `@Public()`)

```
inviteCheckPendingInvitation         (410 when admin cancelled between send and click)
 → inviteIdempotentRedirect          (finishWfWithChoice({ message, primary: 'Go to sign-in', options?: ['Request a new invite'] }))
 → invitePreparePasswordRules
 → inviteCreatePasswordForm           (cancel alt-action keeps user + pendingInvitation flag)
 → inviteCollectProfile               (only when getProfileForm() returns a type)
 → inviteApplyProfile
 → inviteUnsetPendingInvitation
 → inviteActivateUser
 → inviteConfirmation
 → inviteFreshLoginFinish OR inviteAutoLoginFinish
```

### `auth.cancelInvite`

One-step flow: requires `cancellation.allowed`, looks up user, asserts `pendingInvitation`, hard-deletes via `users.deleteUser`, emits `finishWfWithData({ cancelled: true, email })`.

**Protected hooks**: `deliver`, `audit`, `prepareUser`, `getAvailableRoles`, `inferRoles`, `applyProfile` (defaults to deep-merge via `users.update`), `duplicateCheck`, `getProfileForm`, `snapshotOpts`.

## The `WfFinished` envelope

All terminal step responses flow through `WfFinished` envelope helpers from `@atscript/moost-wf`. Each builds the right envelope shape and calls wooks's `useWfFinished` under the hood.

| Helper                                                                     | Envelope                                                                                        | When used                                                                                                                                    |
| -------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `finishWfWithData(value, message?)`                                        | `{ finished: true, data: value, message? }`                                                     | Generic finished data response with optional banner. Recovery `request` (anti-enumeration), invite `cancellation`, recovery `finishGeneric`. |
| `finishWfWithMessage(message)`                                             | `{ finished: true, message }`                                                                   | Display-only finish; no data payload.                                                                                                        |
| `finishWfWithRedirect(target, { autoMs?, skipLabel?, message?, reason? })` | `{ finished: true, end: { action: 'redirect', target, autoMs, skipLabel, message?, reason? } }` | Login `redirect` step; recovery `freshLoginFinish` (5s countdown); login alt-actions (`forgotPassword`, `signup`, SSO).                      |
| `finishWfWithChoice({ message, primary, options? })`                       | `{ finished: true, end: { action: 'choice', message, primary, options } }`                      | Invite `idempotentRedirect`: primary CTA + optional secondary CTAs (e.g. "Request a new invite").                                            |
| `finishWfAborted(reason, { message? })`                                    | `{ finished: true, aborted: true, reason, message? }`                                           | Login `logout` alt-action; terms `decline`; concurrency-limit `cancel`; invite cancel.                                                       |

### Raw envelope path — for cookies

The high-level helpers do **not** accept cookies. When a finalize step needs to attach Set-Cookie headers (login `issue`, recovery `autoLoginFinish`, invite `autoLoginFinish`), workflows use the raw wooks path:

```ts
useWfFinished().set({
  type: "data",
  value: envelope, // shape matches WfFinished
  cookies: auth.buildFinishedCookies(issue), // from useAuth()
});
```

This is the ONLY supported way to attach cookies — do not duplicate cookie-attach logic outside `buildFinishedCookies`.

## `WfTrigger` machinery

### `@WfTrigger(opts: { allow?, token? })`

Method decorator. Wraps `defineAfterInterceptor` at `INTERCEPTOR` priority. When the handler returns `undefined`, the interceptor `instantiate(WfTriggerProvider)`s the provider and replies with its `handle(opts)`. Subclasses that need to short-circuit return any non-`undefined` value.

- `allow?: readonly string[]` — workflow id allow-list. Default: `DEFAULT_AUTH_WORKFLOWS`.
- `token?` — token wire override (transport, cookie name).

### `WfTriggerProvider` (default `@Injectable()` singleton)

Owns three knobs:

| Field      | Default                                                             | Override pattern                                                                                 |
| ---------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `state`    | `HandleStateStrategy({ store: WfStateStoreMemory() })`              | Subclass and assign `this.state = new HandleStateStrategy({ store: new AsWfStore({ table }) })`. |
| `outlets`  | `[createAsHttpOutlet()]`                                            | `this.outlets = [...this.outlets, createAuthEmailOutlet(deps), ...]`.                            |
| Token wire | `{ read: ['body', 'query', 'cookie'], write: 'body', name: 'wfs' }` | Override via `@WfTrigger({ token: { ... } })`.                                                   |

Subclass + bind via the replace registry:

```ts
@Injectable()
class AppWfTriggerProvider extends WfTriggerProvider {
  constructor(wf: MoostWf) {
    super(wf);
    this.state = new HandleStateStrategy({ store: wfStateStore });
    this.outlets = [
      ...this.outlets,
      createAuthEmailOutlet({
        emailSender,
        buildMagicLinkUrl,
        magicLinkTtlMs: (kind) => (kind === "invite.magicLink" ? 7 * 86_400_000 : 3_600_000),
      }),
    ];
  }
}
app.setReplaceRegistry(createReplaceRegistry([WfTriggerProvider, AppWfTriggerProvider]));
```

### `createAuthEmailOutlet(deps)`

Builds the email outlet that delivers magic links. Wraps `@moostjs/event-wf`'s `createEmailOutlet(send)` and translates workflow token into an `AuthEmailEvent { kind, recipient, url, expiresAt, username?, metadata? }` via:

| Dep                 | Type                                          | Purpose                                                                 |
| ------------------- | --------------------------------------------- | ----------------------------------------------------------------------- |
| `emailSender`       | `EmailSender`                                 | Concrete email transport.                                               |
| `buildMagicLinkUrl` | `BuildMagicLinkUrl = (kind, token) => string` | Per-app URL shape: `${FRONTEND_URL}/recover?wfs=${token}`, etc.         |
| `magicLinkTtlMs`    | `(kind: AuthEmailKind) => number`             | Per-kind TTL. Branch on `'invite.magicLink'` vs `'recovery.magicLink'`. |

`AuthEmailKind` covers `'recovery.magicLink' | 'invite.magicLink' | ...`.

**Invariant**: `createAuthEmailOutlet` `await`s `emailSender.send()`. Slow SMTP blocks the workflow response — wrap your sender in a queue/transport that returns once accepted, not once delivered.

## Per-workflow options

Each workflow takes a single options object as its first ctor arg. Nested groups; defaults applied per group.

### `LoginWorkflowOpts`

| Group                            | Key                                                                                                                                             | Default                                                   | Notes                                                             |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- | ----------------------------------------------------------------- |
| `alternateCredentials`           | `forgotPassword`, `signup`, `magicLink`, `ssoProviders[]`, `recoveryUrl`, `signupUrl`, `embedRecovery`                                          | —                                                         | Each enabled key adds an alt-action on the credentials step.      |
| `guards`                         | `emailVerifiedRequired`, `passwordExpiry`, `passwordInitial`                                                                                    | `false` / `false` / `false`                               | Gates after credentials.                                          |
| `enrollment`                     | `ensureEmail`, `ensurePhone`                                                                                                                    | `false` / `false`                                         | Phase-3 loops.                                                    |
| `mfa`                            | `enabled`, `transports: ('sms'\|'email'\|'totp')[]`, `backupCodes`, `enrollRequired`, `pincodeTtlMs`, `pincodeResendTimeoutMs`, `pincodeLength` | `true`, `['sms','email','totp']`, ..., `5min`, `60s`, `6` | —                                                                 |
| `deviceTrust`                    | `enabled`, `optIn`, `cookieName`, `ttlMs`, `skipsMfa`, `bindsTo: 'cookie'\|'cookie+ip'`                                                         | `false`, ..., `'aooth_trusted_device'`, `24h`             | —                                                                 |
| `acceptance`                     | `termsVersion`, `profileCompleteRequired`, `consentMarketing`                                                                                   | —                                                         | —                                                                 |
| `multiContext`                   | `tenantSelect`, `personaSelect`                                                                                                                 | `false` / `false`                                         | —                                                                 |
| `sessionPolicy.concurrencyLimit` | `{ max, onLimit: 'reject'\|'kickPrompt' }`                                                                                                      | —                                                         | `reject` → 429. `kickPrompt` → form with `logoutOthers`/`cancel`. |
| `finalize`                       | `auditLogin`, `notifyNewDevice`, `redirect: 'referer'\|'home'\|false\|null`                                                                     | `true` / `false` / —                                      | —                                                                 |
| `forms`                          | every form name in [Forms catalogue](#forms-catalogue)                                                                                          | bundled `.as` types                                       | Replace per-workflow.                                             |

### `RecoveryWorkflowOpts`

| Group                          | Key                                                   | Default            | Notes                                                                                              |
| ------------------------------ | ----------------------------------------------------- | ------------------ | -------------------------------------------------------------------------------------------------- |
| `delivery.mode`                | `'magicLink' \| 'otp' \| 'choice'`                    | `'magicLink'`      | `'choice'` renders `RecoveryModeSelectForm`.                                                       |
| `delivery.magicLinkTtlMs`      | `number`                                              | `60min`            | —                                                                                                  |
| `delivery.otp`                 | `{ transports, codeLength, ttlMs, resendCooldownMs }` | `6`, `5min`, `60s` | —                                                                                                  |
| `preReset.requireKnownFactor`  | `boolean`                                             | `false`            | Renders `RecoveryFactorForm`.                                                                      |
| `postReset.revokeAllSessions`  | `boolean`                                             | `true`             | Calls `auth.revokeAllForUser` after reset.                                                         |
| `postReset.freshLoginRequired` | `boolean`                                             | `false`            | When `true` → `freshLoginFinish` (countdown redirect). When `false` → `autoLoginFinish` (cookies). |
| `postReset.loginUrl`           | `string`                                              | `'/login'`         | Redirect target for `freshLoginFinish`.                                                            |
| `altActions.backToLogin`       | `boolean`                                             | `true`             | —                                                                                                  |
| `audit.enabled`                | `boolean`                                             | `true`             | —                                                                                                  |

### `InviteWorkflowOpts`

| Group                               | Key                                      | Default       | Notes                                                                                       |
| ----------------------------------- | ---------------------------------------- | ------------- | ------------------------------------------------------------------------------------------- |
| `adminForm.collectRoles`            | `boolean`                                | `true`        | When `false`, roles come from `inferRoles()` only.                                          |
| `send.mode`                         | `'email' \| 'shareableLink' \| 'choice'` | `'email'`     | `'choice'` renders `InviteSendModeForm`.                                                    |
| `send.tokenTtlMs`                   | `number`                                 | `7 days`      | —                                                                                           |
| `accept.alreadyAcceptedRedirectUrl` | `string`                                 | `'/login'`    | Target for `inviteIdempotentRedirect`.                                                      |
| `accept.freshLoginRequired`         | `boolean`                                | `false`       | `true` → `freshLoginFinish` countdown. `false` → `autoLoginFinish` cookies.                 |
| `accept.loginUrl`                   | `string`                                 | `'/login'`    | —                                                                                           |
| `accept.showConfirmation`           | `boolean`                                | `true`        | When `true` → `inviteConfirmation` pauses with `finishWfWithChoice` for user click-through. |
| `accept.confirmationMessage`        | `string`                                 | —             | Override default message.                                                                   |
| `cancellation.allowed`              | `boolean`                                | `true`        | Gates `auth.cancelInvite`. When `false`, the workflow throws.                               |
| `audit.enabled`                     | `boolean`                                | `true`        | —                                                                                           |
| `forms`                             | every form name                          | bundled types | —                                                                                           |

## Forms catalogue

`@aooth/auth-moost`'s `src/atscript/models/forms.as` defines 21 form interfaces. Every form is replaceable per-workflow via `opts.forms.<formName>`.

| Form                     | Workflow(s)             | Purpose                                                                                           |
| ------------------------ | ----------------------- | ------------------------------------------------------------------------------------------------- |
| `LoginCredentialsForm`   | Login                   | Username + password — phase-1 credentials.                                                        |
| `MfaCodeForm`            | Login                   | TOTP / OTP code — strict digits.                                                                  |
| `BackupCodeForm`         | Login                   | Backup code — alphanumeric + hyphen pattern.                                                      |
| `EmailIdentifierForm`    | Recovery                | Recovery initiation; annotated `@wf.context.pass 'defaults'` for `?username=` pre-fill.           |
| `SetPasswordForm`        | Login, Recovery, Invite | New password + confirm. Equality check is server-side.                                            |
| `InviteForm`             | Invite                  | Admin invite; annotated `@wf.context.pass 'availableRoles'` for role-picker options.              |
| `InviteEmailForm`        | Invite                  | Email-only — used by `auth.reInvite` `loadPendingUser` and `auth.cancelInvite`.                   |
| `InviteSendModeForm`     | Invite                  | Picker — `'email'` vs `'shareableLink'`.                                                          |
| `Select2faForm`          | Login                   | Picks an enrolled MFA method when >1 available.                                                   |
| `PincodeForm`            | Login, Recovery         | Generic 6-digit OTP; `rememberDevice` checkbox conditional on device-trust opts.                  |
| `AskEmailForm`           | Login                   | `ensureEmail` enrollment loop.                                                                    |
| `AskPhoneForm`           | Login                   | `ensurePhone` enrollment loop. E.164 normalization server-side.                                   |
| `TermsAcceptForm`        | Login                   | Phase-6 terms acceptance.                                                                         |
| `ProfileCompleteForm`    | Login, Invite           | Phase-6 / phase-B profile completion. Default minimal first/last name; replace for richer shapes. |
| `ConsentMarketingForm`   | Login                   | Marketing opt-in.                                                                                 |
| `TenantSelectForm`       | Login                   | Phase-7 tenant picker.                                                                            |
| `PersonaSelectForm`      | Login                   | Phase-7 persona picker.                                                                           |
| `ConcurrencyLimitForm`   | Login                   | Phase-8 `kickPrompt` form — `logoutOthers` vs `cancel`.                                           |
| `MagicLinkRequestForm`   | Login                   | Magic-link alt-action — accepts email OR username.                                                |
| `RecoveryModeSelectForm` | Recovery                | Picker — `'magicLink'` vs `'otp'`.                                                                |
| `RecoveryFactorForm`     | Recovery                | Factor verification when `preReset.requireKnownFactor`.                                           |

Annotations used: `@meta.label`, `@meta.required`, `@meta.sensitive`, `@ui.form.type`, `@ui.form.autocomplete`, `@expect.minLength`, `@expect.maxLength`, `@expect.pattern`, `@ui.form.fn.options`, `@wf.context.pass`.

## Audit events

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

Package ships **no concrete sink** — workflows fire audit events through their `protected audit(event)` method (default no-op). Override to forward to your audit table / log pipeline.

| Workflow | Event kinds                                                                                                      |
| -------- | ---------------------------------------------------------------------------------------------------------------- |
| Login    | `'login.success'` — `method = mfaMethod ?? 'mfa.skipped' ?? 'password'`, plus optional `tenantId`.               |
| Recovery | `'recovery.requested'` (with `email`), `'recovery.completed'` (with `deliveryMode`, optional `sessionsRevoked`). |
| Invite   | `'invite.created'`, `'invite.resent'`, `'invite.accepted'`, `'invite.cancelled'`.                                |

## Workflow wire protocol

`POST /auth/trigger` body shape:

```
Client → server:
  start                 { wfid: 'auth.login', input?: { ... } }
  submit / action       { wfs: '<token>', input?: { ... }, action?: '<name>' }

Server → client:
  next-step             { inputRequired: { payload, transport: 'http', context }, wfs }
  finished (envelope)   { finished: true, data?, message?, end?, aborted?, reason?, cookies? }
  outlet pause          { sent: true } | { outlet: '<name>' }
  error                 { error: { message, status? } }
```

Token transports (configured on `WfTrigger` / `WfTriggerProvider`): `'body'` (default), `'query'` (`?wfs=...`), `'cookie'`. Magic-link resume uses `'query'` so the URL is shareable.

The `cookies` map on finished envelopes is set by `useAuth().buildFinishedCookies(issue)` — see [the raw envelope path](#raw-envelope-path--for-cookies).
