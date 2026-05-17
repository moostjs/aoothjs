# Workflows

This page is the canonical reference for the three bundled `@moostjs/event-wf` workflows — `LoginWorkflow`, `RecoveryWorkflow`, `InviteWorkflow`. It covers each workflow's step phases, the unified `WfFinished` envelope contract, the protected extension surface, the `wf-trigger` machinery that drives them via `/auth/trigger`, and the subclassing pattern.

## The recipe

All three workflow classes share the same scaffolding:

```ts
@Public()
@Injectable("FOR_EVENT")
@Controller()
@Workflow("auth.<flow>")
@WorkflowSchema<Ctx>([
  /* step catalog */
])
class LoginWorkflow {
  constructor(opts: LoginWorkflowOpts, users: UserService, auth: AuthCredential) {
    /* ... */
  }

  @Step("init")
  protected init(ctx: Ctx) {
    /* ... */
  }

  // ... protected method overrides for senders / audit / role inference
}
```

::: warning Step IDs are workflow-scoped, but @Step('id') is registered globally
`@moostjs/event-wf` registers `@Step('id')` globally across the moost app — identical IDs across two workflows would silently collide. The bundled workflows prefix step IDs with the workflow's domain (`recoveryInit`, `inviteInit`, etc.) to stay out of each other's way. Follow the same convention when adding your own steps to a workflow subclass.
:::

::: warning Workflow class `@Public()` is critical
Without it the global `arbacAuthorizeInterceptor` resolves workflow-events to `(resource=workflow-class, action=step-name)` and **denies** anonymous logins. The `@Public()` on the workflow class is what lets unauthenticated callers run the login flow. (Invite's Phase A re-applies `@ArbacResource('auth.invite') @ArbacAction('start')` to gate admin-only initiation — see [InviteWorkflow](#inviteworkflow-three-wfids).)
:::

::: warning Subclasses MUST re-declare the constructor signature
TypeScript emits fresh `design:paramtypes` per class — a subclass that doesn't re-declare the constructor signature gets paramtypes `[]`, and Moost's DI can't resolve the constructor at instantiation time. `@Inherit()` carries the base class's `@Workflow` / `@WorkflowSchema` / `@Step` metadata, but it does not carry the TS-emitted reflection metadata. You must write the ctor yourself.
:::

## `LoginWorkflow` — wfid `auth.login`

The main happy-path workflow: credentials → enrollment → MFA → device trust → password change → terms/profile/consent → tenant/persona → concurrency → finalize.

### Step phases

| Phase | Steps                                                                                                                                                                                | Purpose                                                                                                                                                                                                                                                                    |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0     | `init`                                                                                                                                                                               | Snapshots `opts` onto `ctx`.                                                                                                                                                                                                                                               |
| 1     | `credentials`                                                                                                                                                                        | Main happy path. Alt-actions (`forgotPassword`, `signup`, `magicLink`, per-SSO `sso-${id}`) are inspected on `input.action` **before** form validation; each triggers `finishWfWithRedirect(url, { reason })`. SSO emits per-provider `reason: 'sso-${id}'` discriminator. |
| 3     | `ensureEmail` / `ensurePhone`                                                                                                                                                        | Enrollment loops. Force-prompt missing contact fields.                                                                                                                                                                                                                     |
| 4     | `check-trusted-device` → `prepare-mfa-options` → `select2fa` → `pincode-send-login` / `pincode-check-login` (sms/email) → `mfa-totp` (totp) → `mfa-enroll-required` → `risk-step-up` | MFA `while`-loop. Loop exits when `mfaChecked` flips true. Backup codes handled by `handleBackupCode` via `BackupCodeForm`.                                                                                                                                                |
| 4b    | `device-trust`                                                                                                                                                                       | Issues an HMAC-signed trust cookie (only when `deviceTrust.enabled && deviceTrust.optIn` and the user opted in via `PincodeForm.rememberDevice`).                                                                                                                          |
| 5     | `prepare-password-rules` + `create-password-form`                                                                                                                                    | Forced password change for initial passwords. `logout` alt-action calls `finishWfAborted("logout", { message })` and sets `ctx.aborted = true`.                                                                                                                            |
| 6     | `terms-accept` / `profile-complete` / `consent-marketing`                                                                                                                            | `decline` alt-action on terms aborts.                                                                                                                                                                                                                                      |
| 7     | `tenant-select` / `persona-select`                                                                                                                                                   | Multi-context selection when configured.                                                                                                                                                                                                                                   |
| 8     | `concurrency-limit`                                                                                                                                                                  | `reject` → 429, `kickPrompt` → `ConcurrencyLimitForm` with `logoutOthers`/`cancel` alt-actions.                                                                                                                                                                            |
| 9     | `issue` → `audit-login` → `notify-new-device` → `redirect`                                                                                                                           | Finalize. `issue` mints tokens and sets `useWfFinished().set({ type: "data", value: envelope, cookies })`. `redirect` overrides the data envelope with an immediate-redirect envelope when `resolveRedirect(ctx)` returns a URL.                                           |

::: warning `ctx.aborted` gating
Every terminal step gates on `!ctx.aborted`. Without this, abort alt-actions set via `finishWfAborted(...)` would be overwritten by token issuance.
:::

### Protected extension surface

| Method                                          | Default                                                        | Override for                                                      |
| ----------------------------------------------- | -------------------------------------------------------------- | ----------------------------------------------------------------- |
| `deliver(payload)`                              | no-op                                                          | Forward MFA pincodes / magic links to your email / SMS sender.    |
| `audit(event)`                                  | no-op                                                          | Wire your audit sink.                                             |
| `loadTrustedDevice(userId, cookieValue)`        | reads from in-memory map                                       | DB-backed trusted-device store.                                   |
| `storeTrustedDevice(userId, deviceId, opts)`    | writes to in-memory map                                        | Same.                                                             |
| `revokeTrustedDevice(userId, deviceId)`         | removes from in-memory map                                     | Same.                                                             |
| `issueTrustedDevice(userId)`                    | generates HMAC-signed cookie                                   | Custom cookie format.                                             |
| `applyProfile(input)`                           | calls `users.update(username, profile)`                        | Custom profile persistence.                                       |
| `applyConsentMarketing(input)`                  | calls `users.update(username, { account: { consents: ... } })` | Same.                                                             |
| `loadTenants(userId)`                           | returns `[]`                                                   | Tenant picker source.                                             |
| `loadPersonas(userId)`                          | returns `[]`                                                   | Persona picker source.                                            |
| `logoutOtherSessions(userId, currentSessionId)` | no-op                                                          | Concurrency-limit kick.                                           |
| `assessRiskStepUp(ctx)`                         | returns `false`                                                | Risk engine integration.                                          |
| `resolveRedirect(ctx)`                          | returns `null`                                                 | Where to send the user after issue (referrer / home / dashboard). |
| `buildRecoveryUrl(opts)`                        | returns `'/recover?...'`                                       | Where the `forgotPassword` alt-action redirects.                  |
| `snapshotOpts(opts)`                            | strips form classes                                            | Custom serialization (rare).                                      |

### `LoginWorkflowOpts` — key fields

| Field                                 | Default                    | Notes                                                                                                       |
| ------------------------------------- | -------------------------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | ------ | ----- | ------ |
| `alternateCredentials.forgotPassword` | `false`                    | Renders the `forgotPassword` alt-action on the credentials form.                                            |
| `alternateCredentials.signup`         | `false`                    | Renders `signup`.                                                                                           |
| `alternateCredentials.magicLink`      | `false`                    | Renders `magicLink`.                                                                                        |
| `alternateCredentials.ssoProviders[]` | `[]`                       | SSO buttons. Each has `{ id, label, iconUrl?, redirectUrl }`.                                               |
| `alternateCredentials.recoveryUrl`    | `'/recover'`               | Where forgot-password redirects.                                                                            |
| `alternateCredentials.embedRecovery`  | `false`                    | If true, runs the recovery flow inline instead of redirecting.                                              |
| `guards.emailVerifiedRequired`        | `false`                    | Force a confirmation pause when `account.emailVerified !== true`.                                           |
| `guards.passwordExpiry`               | `false`                    | Force a password-change pause when `password.expired === true`.                                             |
| `guards.passwordInitial`              | `true`                     | Force a password-change pause when `password.initial === true`.                                             |
| `enrollment.ensureEmail`              | `false`                    | Force email enrollment loop when missing.                                                                   |
| `enrollment.ensurePhone`              | `false`                    | Same for phone.                                                                                             |
| `mfa.enabled`                         | `true`                     | Master switch for the whole MFA loop.                                                                       |
| `mfa.transports[]`                    | `["sms", "email", "totp"]` | Restrict acceptable factor types.                                                                           |
| `mfa.backupCodes`                     | `true`                     | Allow `BackupCodeForm` fallback.                                                                            |
| `mfa.enrollRequired`                  | `false`                    | Force enrollment if the user has zero factors.                                                              |
| `mfa.pincodeTtlMs`                    | `5 * 60_000`               | OTP code lifetime.                                                                                          |
| `mfa.pincodeResendTimeoutMs`          | `30_000`                   | Cooldown between resends.                                                                                   |
| `mfa.pincodeLength`                   | `6`                        | OTP digit count.                                                                                            |
| `deviceTrust.enabled`                 | `false`                    | Master switch.                                                                                              |
| `deviceTrust.optIn`                   | `true`                     | Render the `rememberDevice` checkbox on `PincodeForm`.                                                      |
| `deviceTrust.cookieName`              | `'aooth_trusted_device'`   | Cookie name.                                                                                                |
| `deviceTrust.ttlMs`                   | `24 * 60 * 60_000`         | Cookie + record TTL.                                                                                        |
| `deviceTrust.skipsMfa`                | `true`                     | A trusted device skips the MFA loop.                                                                        |
| `deviceTrust.bindsTo`                 | `'cookie'`                 | `'cookie'                                                                                                   | 'cookie+ip'`. `cookie+ip` is stricter — see [Config Reference](./config). |
| `acceptance.termsVersion`             | `null`                     | Current terms version. If non-null and `user.account.termsAcceptedVersion !== this`, forces `terms-accept`. |
| `acceptance.profileCompleteRequired`  | `false`                    | Force the `profile-complete` step.                                                                          |
| `acceptance.consentMarketing`         | `false`                    | Force the `consent-marketing` step.                                                                         |
| `multiContext.tenantSelect`           | `false`                    | Force the `tenant-select` step.                                                                             |
| `multiContext.personaSelect`          | `false`                    | Force the `persona-select` step.                                                                            |
| `sessionPolicy.concurrencyLimit`      | `null`                     | `{ max, onLimit: 'reject'                                                                                   | 'kickPrompt' }`.                                                          |
| `finalize.auditLogin`                 | `true`                     | Whether to emit `login.success` audit event.                                                                |
| `finalize.notifyNewDevice`            | `false`                    | Whether to fire a "new device" notification.                                                                |
| `finalize.redirect`                   | `'referer'`                | `'referer'                                                                                                  | 'home'                                                                    | string | false | null`. |
| `forms.*`                             | bundled `.as` defaults     | Every form is replaceable per-workflow.                                                                     |

## `RecoveryWorkflow` — wfid `auth.recovery`

Password reset via magic link or OTP, with optional second-factor verification, post-reset session revocation, and either a fresh-login redirect or an auto-login finish.

### Step phases

| Step                                   | Purpose                                                                                                                                                                                        |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `recoveryInit`                         | Snapshots opts onto ctx.                                                                                                                                                                       |
| `recoveryRequest`                      | Collects email via `EmailIdentifierForm`. **Anti-enumeration**: unknown email still emits a generic `finishWfWithData({ sent: true })` — the response is indistinguishable from a known email. |
| `recoverySelectMode`                   | Rendered only when `delivery.mode === 'choice'`. Picks between `'magicLink'` and `'otp'`.                                                                                                      |
| `recoverySendMagicLink`                | Sends a magic link via `outletEmail` (the trigger-side mailer).                                                                                                                                |
| `recoverySendOtp` / `recoveryCheckOtp` | OTP `while`-loop. Alt-actions `resend`, `useDifferentTransport`, `backToLogin`.                                                                                                                |
| `recoveryVerifyFactor`                 | Rendered only when `preReset.requireKnownFactor`. Validates a known second factor (phone last-4 or current TOTP).                                                                              |
| `recoverySetPassword`                  | Collects the new password via `SetPasswordForm`, validates policy, persists via `users.changePassword`.                                                                                        |
| `recoveryRevokeSessions`               | Calls `auth.revokeAllForUser(userId)` when `postReset.revokeAllSessions`.                                                                                                                      |
| `recoveryAudit`                        | Emits `recovery.completed`.                                                                                                                                                                    |
| `recoveryFreshLoginFinish`             | `finishWfWithRedirect(loginUrl, { autoMs: 5000, skipLabel: 'Go now', message, reason: 'reset-success' })`. Rendered when `postReset.freshLoginRequired`.                                       |
| `recoveryAutoLoginFinish`              | Mints tokens via the raw `useWfFinished().set({ ... })` path to attach cookies. Rendered when `!postReset.freshLoginRequired`.                                                                 |

### `RecoveryWorkflowOpts` — key fields

| Field                           | Default                | Notes                                                 |
| ------------------------------- | ---------------------- | ----------------------------------------------------- | ----- | ---------- |
| `delivery.mode`                 | `'magicLink'`          | `'magicLink'                                          | 'otp' | 'choice'`. |
| `delivery.magicLinkTtlMs`       | `60 * 60_000`          | Magic link lifetime.                                  |
| `delivery.otp.transports`       | `['email']`            | OTP transports.                                       |
| `delivery.otp.codeLength`       | `6`                    | OTP digit count.                                      |
| `delivery.otp.ttlMs`            | `5 * 60_000`           | OTP lifetime.                                         |
| `delivery.otp.resendCooldownMs` | `60_000`               | Resend cooldown.                                      |
| `preReset.requireKnownFactor`   | `false`                | Require a known second factor before allowing reset.  |
| `postReset.revokeAllSessions`   | `true`                 | Kick every active session after reset.                |
| `postReset.freshLoginRequired`  | `false`                | Force the user to log in fresh instead of auto-login. |
| `postReset.loginUrl`            | `'/login'`             | Where the fresh-login redirect points.                |
| `altActions.backToLogin`        | `true`                 | Render the back-to-login alt-action.                  |
| `audit.enabled`                 | `true`                 | Whether to emit recovery audit events.                |
| `forms.*`                       | bundled `.as` defaults | Replaceable.                                          |

### Protected extension surface

| Method                             | Default                   | Override for                                                                                           |
| ---------------------------------- | ------------------------- | ------------------------------------------------------------------------------------------------------ |
| `deliver(payload)`                 | no-op                     | Send OTP emails / SMS. (Magic-link mode uses the email outlet on the trigger route, not this method.)  |
| `audit(event)`                     | no-op                     | Wire your audit sink.                                                                                  |
| `emailToUserId(email)`             | returns `email` unchanged | **MUST override** when `username !== email`. Resolves a recovery-step email to the canonical username. |
| `verifyRecoveryFactor(ctx, input)` | validates phone/totp      | Extend for security questions, hardware tokens, etc.                                                   |

## `InviteWorkflow` — three wfids

Registers `auth.invite`, `auth.reInvite`, `auth.cancelInvite`.

### Phase A — admin (gated by `@ArbacResource('auth.invite') @ArbacAction('start')`)

| Step                          | Purpose                                                                                                                                                     |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `inviteInit`                  | Snapshots opts onto ctx.                                                                                                                                    |
| `invitePrepareAvailableRoles` | Calls `getAvailableRoles()` protected method. Stashes onto `ctx.availableRoles`.                                                                            |
| `inviteSelectSendMode`        | Rendered when `send.mode === 'choice'`. Picks `'email'` or `'shareableLink'`.                                                                               |
| `inviteAdminInviteForm`       | Collects email/firstName/lastName/roles via `InviteForm`. **Server-side whitelist enforcement** rejects admin-submitted roles outside `ctx.availableRoles`. |
| `inviteInferRolesStep`        | Calls `inferRoles()` protected method to fill in implicit roles.                                                                                            |
| `invitePreCreateUser`         | Calls `users.createUser`, then `users.update(email, { account: { pendingInvitation: true } })`.                                                             |

### Boundary — `inviteSendInviteEmail` / `inviteReturnShareableLink` (`@Public()`)

Emits `outletEmail(ctx.email, "invite.magicLink", { username, roles?, expiresAtMs })`. Idempotent on `ctx.linkSent` — re-running the step is a no-op once the email has been queued.

### Phase B — anonymous magic-link resume (all `@Public()`)

| Step                           | Purpose                                                                                                                                     |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `inviteCheckPendingInvitation` | Returns 410 when an admin cancelled the invite between send and click.                                                                      |
| `inviteIdempotentRedirect`     | Emits `finishWfWithChoice({ message, primary: 'Go to sign-in', options?: ['Request a new invite'] })` when the invite was already accepted. |
| `invitePreparePasswordRules`   | Snapshots the password policy onto ctx.                                                                                                     |
| `inviteCreatePasswordForm`     | Cancel alt-action keeps user + `pendingInvitation` flag for re-invite.                                                                      |
| `inviteCollectProfile`         | Rendered only when `getProfileForm()` returns a non-null type.                                                                              |
| `inviteApplyProfile`           | Calls `applyProfile()` protected method.                                                                                                    |
| `inviteUnsetPendingInvitation` | Clears the `pendingInvitation` flag.                                                                                                        |
| `inviteActivateUser`           | Marks the user active.                                                                                                                      |
| `inviteConfirmation`           | Rendered when `accept.showConfirmation`. Pauses on a confirmation banner.                                                                   |
| `inviteFreshLoginFinish`       | Same shape as recovery's fresh-login finish.                                                                                                |
| `inviteAutoLoginFinish`        | Same shape as recovery's auto-login finish.                                                                                                 |

### `auth.cancelInvite`

One-step flow. Requires `cancellation.allowed`. Looks up the user, asserts `pendingInvitation`, hard-deletes via `users.deleteUser`, emits `finishWfWithData({ cancelled: true, email }, ...)`.

### `InviteWorkflowOpts` — key fields

| Field                               | Default                | Notes                                      |
| ----------------------------------- | ---------------------- | ------------------------------------------ | --------------- | ---------- |
| `adminForm.collectRoles`            | `true`                 | Render the roles picker on `InviteForm`.   |
| `send.mode`                         | `'email'`              | `'email'                                   | 'shareableLink' | 'choice'`. |
| `send.tokenTtlMs`                   | `7 * 24 * 60 * 60_000` | Magic link lifetime (7 days).              |
| `accept.alreadyAcceptedRedirectUrl` | `'/login'`             | Where the idempotent redirect points.      |
| `accept.freshLoginRequired`         | `false`                | Force fresh-login instead of auto-login.   |
| `accept.loginUrl`                   | `'/login'`             | Where the fresh-login redirect points.     |
| `accept.showConfirmation`           | `true`                 | Whether to pause on a confirmation banner. |
| `accept.confirmationMessage`        | `'Welcome!'`           | Banner text.                               |
| `cancellation.allowed`              | `true`                 | Whether `auth.cancelInvite` is enabled.    |
| `audit.enabled`                     | `true`                 | Whether to emit invite audit events.       |
| `forms.*`                           | bundled `.as` defaults | Replaceable.                               |

### Protected extension surface

| Method                  | Default                                 | Override for                                                                                                             |
| ----------------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `deliver(payload)`      | no-op                                   | Used by the manual-send fallback. The default magic-link send path goes through `outletEmail` (the trigger-side mailer). |
| `audit(event)`          | no-op                                   | Wire your audit sink.                                                                                                    |
| `prepareUser()`         | returns `{}`                            | Populate consumer-required user fields (e.g. `tenantId`) before `users.createUser` runs.                                 |
| `getAvailableRoles()`   | returns `[]`                            | Drive the `InviteForm` role-picker options.                                                                              |
| `inferRoles(input)`     | returns `input.roles`                   | Add implicit roles based on the invite payload.                                                                          |
| `applyProfile(input)`   | calls `users.update(username, profile)` | Custom profile persistence.                                                                                              |
| `duplicateCheck(email)` | calls `users.findByUsername(email)`     | Custom duplicate detection.                                                                                              |
| `getProfileForm()`      | returns `null`                          | Return your own `.as` type to enable the profile-collection step.                                                        |
| `snapshotOpts(opts)`    | strips form classes                     | Custom serialization (rare).                                                                                             |

## The `WfFinished` envelope contract

All three workflows go through one of four envelope helpers from `@atscript/moost-wf`:

| Helper                                                                     | Envelope shape                                                         | Used by                                                                           |
| -------------------------------------------------------------------------- | ---------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `finishWfWithData(value, message?)`                                        | `{ type: 'data', value, message? }`                                    | Recovery `recoveryRequest` (sent: true), invite `cancelInvite` (cancelled: true). |
| `finishWfWithRedirect(target, { autoMs?, skipLabel?, message?, reason? })` | `{ type: 'redirect', target, autoMs?, skipLabel?, message?, reason? }` | Login `forgotPassword`, recovery `freshLoginFinish`, invite `freshLoginFinish`.   |
| `finishWfWithChoice({ message, primary, options? })`                       | `{ type: 'choice', message, primary, options? }`                       | Invite `idempotentRedirect`.                                                      |
| `finishWfAborted(reason, { message? })`                                    | `{ type: 'aborted', reason, message? }`                                | Login `logout`, terms `decline`, concurrency `cancel`.                            |

### Raw envelope path for cookies

The high-level helpers above do **not** accept cookies. For paths that need to attach cookies (login `issue`, recovery `autoLoginFinish`, invite `autoLoginFinish`), workflows use the raw envelope path:

```ts
useWfFinished().set({
  type: "data",
  value: envelope,
  cookies: auth.buildFinishedCookies(issue),
});
```

`buildFinishedCookies(issue)` builds the cookies map from the `IssueResult`, respecting the `enableCookie` flag. See [AuthGuard & useAuth](./auth-guard#buildfinishedcookies-issue-wffinishedresponse-cookies).

### Test helpers

The package exports test helpers for narrowing envelope types in specs:

```ts
import { expectFinished, expectRedirect } from "@aoothjs/auth-moost";

const env = await response.json();
const data = expectFinished<{ sent: true }>(env); // narrows to type: 'data'
const redirect = expectRedirect(env); // narrows to type: 'redirect'
```

## `wf-trigger` — workflow trigger machinery

### `WfTrigger({ allow?, token? })`

A method decorator that wraps `defineAfterInterceptor` at `INTERCEPTOR` priority. When the wrapped handler returns `undefined`, the interceptor instantiates `WfTriggerProvider` and replies with its `handle(opts)`. Subclasses that need to short-circuit return any non-`undefined` value (see [Pattern B](./controllers#pattern-b-replace-triggerwf-entirely)).

`opts.allow` is an array of wfids to whitelist. The trigger rejects requests for wfids outside `allow` with a 400.

`opts.token` overrides the token wire — by default `{ read: ['body', 'query', 'cookie'], write: 'body', name: 'wfs' }`.

### `WfTriggerProvider`

The `@Injectable()` singleton owning workflow state + outlets + token wire. Default configuration:

```ts
this.state = new HandleStateStrategy({ store: WfStateStoreMemory() });
this.outlets = [createAsHttpOutlet()];
this.tokenWire = { read: ["body", "query", "cookie"], write: "body", name: "wfs" };
```

Production consumers subclass it to swap state store (`new AsWfStore({ table })`) and add outlets:

```ts
@Injectable()
class MyWfTriggerProvider extends WfTriggerProvider {
  constructor(wf: MoostWf) {
    super(wf);
    this.state = new HandleStateStrategy({ store: dbWfStore });
    this.outlets = [
      ...this.outlets,
      createAuthEmailOutlet({
        emailSender,
        buildMagicLinkUrl: (kind, token) => `${env.FRONTEND_URL}/redeem?wfs=${token}`,
        magicLinkTtlMs: (kind) =>
          kind === "invite.magicLink" ? 7 * 24 * 60 * 60_000 : 60 * 60_000,
      }),
    ];
  }
}

app.setReplaceRegistry(createReplaceRegistry([WfTriggerProvider, MyWfTriggerProvider]));
```

### `createAuthEmailOutlet(deps)`

Builds the email outlet that delivers magic links. Wraps `@moostjs/event-wf`'s `createEmailOutlet(send)` and translates the workflow token into an `AuthEmailEvent`:

```ts
interface AuthEmailEvent {
  kind: AuthEmailKind; // 'recovery.magicLink' | 'invite.magicLink' | ...
  recipient: string;
  url: string;
  expiresAt: number;
  username?: string;
  metadata?: Record<string, unknown>;
}
```

`deps`:

| Field                                  | Purpose                                                        |
| -------------------------------------- | -------------------------------------------------------------- |
| `emailSender: EmailSender`             | Your sender — receives the `AuthEmailEvent`.                   |
| `buildMagicLinkUrl: BuildMagicLinkUrl` | `(kind, token) => string`. Constructs the URL the user clicks. |
| `magicLinkTtlMs: (kind) => number`     | Per-kind TTL. Drives the `expiresAt` field on the event.       |

## Workflow context invariants

::: warning Use `delete ctx.field` not `ctx.field = undefined`
`AsWfStore` validates `state.context` against a JSON-anyOf schema and chokes on explicit `undefined` entries. The compiled schema treats `undefined` as a distinct type from "absent". Always use `delete ctx.someField`.
:::

::: warning Form classes are stripped from `ctx.opts` via `snapshotOpts()`
Forms are class references (not POJOs), so they cannot be serialized into the wf state store. `snapshotOpts()` runs once at `init` and strips the `forms.*` keys before `ctx.opts` is persisted. If you override `snapshotOpts`, preserve the form-stripping logic — otherwise the wf state store will fail to serialize.
:::

## Subclassing pattern — full template

```ts
import { LoginWorkflow, type LoginWorkflowOpts, type DeliverPayload } from "@aoothjs/auth-moost";
import { AuthCredential } from "@aoothjs/auth";
import { UserService } from "@aoothjs/user";
import { Inherit, Injectable, Controller } from "moost";

const myLoginOpts: LoginWorkflowOpts = {
  mfa: { enabled: true, transports: ["email", "totp"] },
  alternateCredentials: { forgotPassword: true },
  guards: { passwordInitial: true },
};

@Inherit() // flows @Workflow / @WorkflowSchema / @Step / @Public
@Injectable("FOR_EVENT") // re-applied: moost@0.6.x does NOT inherit @Injectable
@Controller() // re-applied: same reason
class MyLoginWorkflow extends LoginWorkflow {
  // RE-DECLARED constructor — TS emits design-paramtypes per class
  constructor(users: UserService, auth: AuthCredential) {
    super(myLoginOpts, users, auth);
  }

  protected override async deliver(payload: DeliverPayload): Promise<void> {
    if (payload.channel === "email") {
      await myEmailSender.send({
        /* ... */
      });
    } else {
      await mySmsSender.send({
        /* ... */
      });
    }
  }

  protected override async audit(event): Promise<void> {
    await auditTable.insert(event);
  }

  protected override async resolveRedirect(ctx): Promise<string | null> {
    return ctx.input?.next ?? "/dashboard";
  }
}

app.registerControllers(MyLoginWorkflow);
```

The same template applies to `RecoveryWorkflow` and `InviteWorkflow`. See [`packages/e2e-demo/src/app.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/e2e-demo/src/app.ts) for all three side-by-side.

## See also

- [REST Controllers](./controllers) — the `/auth/trigger` endpoint that dispatches into these workflows.
- [Audit Log](./audit) — what events each workflow emits.
- [Config Reference](./config) — full option tables.
