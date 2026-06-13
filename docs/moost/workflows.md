# Workflows

`@aooth/auth-moost` ships **one** workflow class — `AuthWorkflow` — that declares six `@moostjs/event-wf` schemas. It replaces the former `LoginWorkflow` / `RecoveryWorkflow` / `InviteWorkflow` quartet. This page is the narrative map: the policy model, the observable pauses of each flow, the extension seams, and the `wf-trigger` machinery that drives them via `/auth/trigger`. Full signatures live in the [API reference](/api/auth-moost). Client-side rendering of the forms lives in [SPA Components](./spa-components).

| `@Workflow` method   | Workflow id                 | Covers                                                                     |
| -------------------- | --------------------------- | -------------------------------------------------------------------------- |
| `loginFlow`          | `auth/login/flow`           | credentials → enrollment → MFA → finalize                                  |
| `inviteFlow`         | `auth/invite/start`         | admin invite → anonymous magic-link accept                                 |
| `recoveryFlow`       | `auth/recovery/flow`        | magic-link **or** OTP password reset                                       |
| `changePasswordFlow` | `auth/change-password/flow` | authenticated self-service password change                                 |
| `addMfaFlow`         | `auth/add-mfa/flow`         | authenticated self-service "Manage MFA" (add/change/remove, step-up first) |
| `signupFlow`         | `auth/signup/flow`          | verify-first self-signup → set password → auto-login                       |

The login, invite, recovery, and signup `@Workflow` bodies carry `@Public()` so the wf adapter can dispatch anonymous logins, magic-link clicks, and self-signups. Invite's admin-phase `@Step` methods deliberately omit `@Public()` — they are ARBAC-evaluated (the admin needs the `invite` permission). **Change-password and add-mfa are the two fully-gated flows**: neither flow's `@Workflow` body nor its `init` / `finish` steps is `@Public()` — they carry `@ArbacResource("auth.change-password")` / `@ArbacResource("auth.add-mfa")` + `@ArbacAction("self")`, so each runs only for an authenticated principal whose role grants that resource. See [Change password](#change-password-auth-change-password-flow) and [Add MFA method](#add-mfa-auth-add-mfa-flow).

## The policy model

Two layers, kept strictly separate:

- **`AuthWorkflowOpts` — infrastructure only.** Pincode timers, magic-link TTL, `loginUrl`, `totpIssuer`, device-trust cookie config, and the per-form schema slots. Passed as `Partial<AuthWorkflowOpts>` to the constructor; defaults applied by `mergeAuthWorkflowOpts`. Read as `this.opts.<group>.<field>`. See the [AuthWorkflowOpts reference](/api/auth-moost#authworkflowopts-resolvedauthworkflowopts).
- **`protected resolveXxx(ctx)` getters — policy.** Anything that varies by request / tenant / user (force MFA enrollment, device-trust posture, session-concurrency limit, redirect target, lockout posture, OTP disclosure copy, …). Each resolver has a paired `@Step("prepare-<group>")` that writes its result to `ctx.<group>`. Defaults are hardcoded in the resolver body — **policy never lives on opts.**

```ts
// ❌ wrong — policy on opts
new AuthWorkflow({ mfa: { enabled: true } }, ...) // no such field

// ✅ right — policy on a resolver
class MyAuth extends AuthWorkflow {
  protected override resolveMfaPolicy(ctx: AuthWfCtx) {
    return { required: this.tenantRequiresMfa(ctx.subject), transports: ["email", "totp"] };
  }
}
```

### Per-flow discrimination — ctx-slot presence, never a flow name

`AuthWfCtx` has **no `flow` field**. A resolver or step body that must branch reads which slot is populated:

| Slot present         | Flow                  |
| -------------------- | --------------------- |
| `ctx.admin`          | invite (admin phase)  |
| `ctx.accept`         | invite (accept phase) |
| `ctx.postReset`      | recovery              |
| `ctx.signup`         | self-signup           |
| `ctx.changePassword` | change-password       |
| `ctx.addMfa`         | add-mfa               |
| _(none of these)_    | login                 |

```ts
protected resolveRedirect(ctx: AuthWfCtx): string | undefined {
  if (ctx.accept) return this.opts.loginUrl;   // invite-accept
  if (ctx.postReset) return "/account/security"; // recovery
  return ctx.input?.next ?? "/dashboard";       // login
}
```

## The subclass recipe

```ts
import { AuthWorkflow, type AuthWfCtx, type AuthDeliveryPayload } from "@aooth/auth-moost";
import { AuthCredential } from "@aooth/auth";
import { UserService } from "@aooth/user";
import { ConsentStore } from "@aooth/auth-moost";
import { Controller, Inherit } from "moost";

@Inherit() // flows @Workflow / @WorkflowSchema / @Step / @Public metadata
@Controller() // SINGLETON — re-applied (moost@0.6.x does NOT inherit decorators)
class MyAuth extends AuthWorkflow {
  // RE-DECLARE the 4-arg constructor — TS emits design:paramtypes per class,
  // and without it moost's DI cannot resolve the constructor.
  constructor(users: UserService, auth: AuthCredential, consentStore: ConsentStore) {
    super({ loginUrl: "/sign-in", totpIssuer: "MyApp" }, users, auth, consentStore);
  }

  protected override async deliver(payload: AuthDeliveryPayload): Promise<void> {
    if (payload.channel === "email") await myEmailSender.send(/* … */);
    else await mySmsSender.send(/* … */);
  }

  protected override resolveRedirect(ctx: AuthWfCtx) {
    return ctx.input?.next ?? "/dashboard";
  }
}

app.setReplaceRegistry(createReplaceRegistry([AuthWorkflow, MyAuth]));
```

::: warning Re-apply `@Inherit() @Controller()` and re-declare the constructor
`@Inherit()` carries `@Workflow` / `@WorkflowSchema` / `@Step` / `@Public` metadata, but moost@0.6.x does **not** inherit `@Injectable`/`@Controller` across `extends`, and TS emits fresh `design:paramtypes` per class. A subclass missing either gets paramtypes `[]` and DI fails. Add `@Injectable("FOR_EVENT")` ONLY if the constructor reads request-scoped composables — `AuthWorkflow` holds no per-event state on `this`, so SINGLETON is correct.
:::

::: warning Step IDs are registered globally
`@moostjs/event-wf` registers every `@Step("id")` into one global registry — identical IDs on two classes silently collide. When adding steps in a subclass, pick IDs that won't clash with the base inventory. Never use a `resolveXxx` name as a `@Step` id or handler method name (that name is reserved for the policy getters).
:::

## Extension point catalog

Every `protected` member below is an override seam — change behavior by subclassing `AuthWorkflow` and overriding it (the [subclass recipe](#the-subclass-recipe) above). Resolvers return `T | Promise<T>` (never `async` on the default); each has a `prepare-<group>` `@Step` that writes its result to `ctx.<group>`. Full signatures live in the [API reference](/api/auth-moost); the narrative below (and the linked topic pages) shows how to use the high-traffic ones.

### Policy resolvers — context-varying policy (per request / tenant / user)

| Resolver                                                                         | Decides                                                                                 | Default                     | Flow(s)                                                                                          |
| -------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | --------------------------- | ------------------------------------------------------------------------------------------------ |
| `resolveMfaPolicy`                                                               | MFA mode / available transports / TOTP issuer                                           | `optional`, all transports  | login, invite, add-mfa                                                                           |
| `resolveEnrollment`                                                              | force a confirmed email/phone before issuing                                            | `ensureEmail/Phone: false`  | login                                                                                            |
| `resolveDeviceTrust`                                                             | trusted-device posture (enabled / optIn / skipsMfa)                                     | disabled                    | login                                                                                            |
| `resolveLockout`                                                                 | failed-login lockout mode (temporary / self-service / admin-only)                       | `temporary`                 | login, recovery                                                                                  |
| `resolveGuards`                                                                  | login-time guards (passwordInitial / passwordExpiry / emailVerifiedRequired)            | initial-password guard on   | login                                                                                            |
| `resolveSessionPolicy`                                                           | session concurrency limit                                                               | none                        | login                                                                                            |
| `resolveFinalize`                                                                | new-device notice ([recognition](#device-recognition)-gated) + post-login redirect mode | both off                    | login                                                                                            |
| `resolveRiskStepUp`                                                              | require an extra MFA round (risk-based)                                                 | `require: false`            | login                                                                                            |
| `resolveAlternateCredentials`                                                    | which login alt-actions show (forgotPassword / signup / magicLink / SSO list)           | forgot-password on          | login                                                                                            |
| `resolveSignupPolicy`                                                            | self-signup on/off + collectUsername                                                    | `allowSignup: false`        | signup                                                                                           |
| `resolveChangePasswordPolicy`                                                    | revokeOtherSessions + optional rate-limit                                               | revoke on                   | change-password                                                                                  |
| `resolveAccept`                                                                  | invite accept-tail (redirect / confirmation)                                            | redirect to `loginUrl`      | invite                                                                                           |
| `resolveAdminForm`                                                               | invite admin form (collectRoles)                                                        | `collectRoles: true`        | invite                                                                                           |
| `resolvePostReset`                                                               | recovery post-reset (revokeAllSessions / loginUrl)                                      | revoke all on               | recovery                                                                                         |
| `resolveRecoveryAltActions`                                                      | recovery alt-actions (backToLogin)                                                      | on                          | recovery                                                                                         |
| `resolveRecoveryChannel`                                                         | M1 OTP transport for the typed identifier                                               | `email`                     | recovery → [guide](./recovery-and-handles#recovery-channel-m1)                                   |
| `resolveRecoveryDeliverySource`                                                  | M1 (`typed`) vs M2 (`registered`) OTP delivery                                          | `typed`                     | recovery → [guide](./recovery-and-handles#registered-channel-recovery-m2)                        |
| `resolvePromoteHandleField`                                                      | which login-handle column a confirmed channel promotes into                             | `undefined` (off)           | login, invite, add-mfa → [guide](./recovery-and-handles#promote-a-confirmed-channel-to-a-handle) |
| `resolveEnrollPreConfirmed`                                                      | skip the enrol pincode for a verified-by-construction address                           | `false` (always prove)      | login, invite, add-mfa → [recipe](#pre-seeded-enrolment)                                         |
| `resolveEnrollAddress`                                                           | pin the sms/email enrolment address to an account record (free-text form never renders) | `'collect'` (free-text)     | login, invite, add-mfa → [recipe](#pin-enrolment-address)                                        |
| `resolveTotpAccountLabel`                                                        | the account half of the authenticator's "issuer: account" TOTP label                    | `ctx.email` → `username`    | login, invite, add-mfa                                                                           |
| `resolveStepUpConfirmBeforeSend`                                                 | ask explicit consent before the manage step-up dispatches its sms/email code            | `true` (ask first)          | add-mfa                                                                                          |
| `resolveOtpDisclosure`                                                           | per-channel consent copy under the address input                                        | empty                       | login, add-mfa                                                                                   |
| `resolveLockedMfaTransports`                                                     | factors the user may NOT change/remove (e.g. a handle-bound email/phone)                | `[]` (none locked)          | add-mfa                                                                                          |
| `resolveRedirect`                                                                | post-login redirect URL                                                                 | per `resolveFinalize`       | login                                                                                            |
| `resolveOAuthErrorRedirect`                                                      | federated-login failure redirect target                                                 | error page                  | login (SSO)                                                                                      |
| `resolveFederatedEmailTrust`                                                     | whether a provider's email claim counts as correspondence inbox proof                   | `email_verified === true`   | login (SSO) → [guide](#security-notices)                                                         |
| `resolvePincodeForm` / `resolvePincodeTarget` / `resolvePincodeAltAction`        | which OTP form, recipient+channel, alt-action mapping for the shared pincode pair       | MFA-vs-recovery by ctx slot | login, recovery                                                                                  |
| `resolveRecoveryUrl` _(sync helper)_                                             | URL the `forgotPassword` alt-action targets                                             | `loginUrl`-derived          | login                                                                                            |
| `resolveClientIp` / `resolveUserAgent` / `resolveIssueMetadata` _(sync helpers)_ | device-trust + audit metadata at issue time                                             | request headers             | login                                                                                            |

`selectRecoveryRegisteredMethod(user)` is a sync helper (not a resolver) paired with M2 — see its [guide](./recovery-and-handles#registered-channel-recovery-m2).

### Step extension-point stubs — no-op `@Step`s you override for new behavior

| `@Step`                                                          | Override to                                                        | Reached from           |
| ---------------------------------------------------------------- | ------------------------------------------------------------------ | ---------------------- |
| `extra-step`                                                     | add input pauses / persistence to the login + invite-accept tail   | login, invite          |
| `signup-extra-step`                                              | seed app rows / welcome email after self-signup creates the user   | signup                 |
| `promote-to-handle`                                              | (usually leave as-is; gate via `resolvePromoteHandleField`)        | login, invite, add-mfa |
| `magic-link-request` / `magic-link-send` / `magic-link-verified` | implement a magic-link login credential (bundled stubs are no-ops) | login                  |
| `passkey`                                                        | implement a passkey credential (bundled stub is a no-op)           | login                  |

### Lifecycle hooks

| Hook                                             | Override to                                                                                                                                                                | Default                            |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| `deliver(payload)`                               | route MFA / recovery / enrollment pincodes + new-device notices by `kind` + `channel` — see [below](#outbound-delivery-deliver-payload)                                    | no-op                              |
| `prepareUser(input)`                             | supply required app columns on a freshly-created row (shared by invite + signup)                                                                                           | `{}`                               |
| `inferAdminRoles(input)`                         | derive roles server-side from the admin invite payload                                                                                                                     | `[]`                               |
| `getAvailableRoles()`                            | whitelist selectable roles on the admin invite form                                                                                                                        | none                               |
| `duplicateInviteCheck(input)`                    | override the duplicate-invitee rule (`'allow' \| 'reject' \| 'reuse'`)                                                                                                     | re-invite pending; reject accepted |
| `logoutOtherSessions(username)`                  | customize the concurrency-limit eviction                                                                                                                                   | revoke all                         |
| `loadActiveSessionsCount(username)`              | count active sessions for the concurrency prompt                                                                                                                           | store-backed                       |
| `validateMfaAddress(ctx, method, value)`         | stricter rules on the user-typed enrolment address — ctx-first and async-capable, so record-based rules (domain allowlists, match-the-account-email) load the row directly | email-shape / permissive E.164     |
| `beginSso` / `oauthRuntime` / `authorizeRuntime` | federated-login wiring — see [Federated Login](./oauth)                                                                                                                    | runtime-resolved                   |

[`ConsentStore`](#consent-collection-consentstore) (`getPendingConsents` / `save` / `read` / `recordOtpChannelConsent`) and the [`WfTriggerProvider`](#wf-trigger-workflow-trigger-machinery) overrides (`storeStrategy` / `wfStateSecret` / `wfStateEncapsulatedTtlMs` / `stateRegistry`) are separate provider classes, documented in their own sections below.

### Event hooks

Six `after*` seams fire **once** at the single completion point of each flow — the place to provision a tenant, send a welcome email, push analytics, or sync an external directory. Each is `protected`, defaults to a **no-op**, receives the live `AuthWfCtx` (`ctx.subject` set; read `ctx.isFirstLogin`, `ctx.oauth`, `ctx.accept`, … for context), and is **`async`-capable**. They are **awaited and a throw propagates** — a failing hook aborts the run (the login hooks fire _before_ the session/code is delivered, so a throw fails the login atomically, with no half-issued session); wrap your own body in `try/catch` for best-effort behaviour.

| Hook                           | Fires when                                                                                                       | Also fires `afterLogin`?                |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| `afterLogin(ctx)`              | an authenticated **session** is established — interactive, federated (SSO), or invite/signup/recovery auto-login | —                                       |
| `afterInvitationAccepted(ctx)` | an invitee finished accepting (account activated), auto-login **or** fresh-login                                 | only on the auto-login path             |
| `afterSignup(ctx)`             | a self-signup account was created + activated                                                                    | yes (signup auto-logins)                |
| `afterPasswordReset(ctx)`      | a recovery reset completed — **even if** an `admin-only` lock survived                                           | only on the auto-login path             |
| `afterPasswordChanged(ctx)`    | an authenticated user changed their own password (change-password)                                               | no — it's a rotation, not a login       |
| `afterMfaChanged(ctx)`         | a factor was added / changed / removed (add-mfa) — **not** on cancel/no-change                                   | no — the session is kept, not re-issued |

**`afterLogin` is the login funnel.** It fires at the one `record-login` step every login flow routes through, right after `account.lastLogin` is stamped and before the terminal that issues the session (`issue`) or auth code (`mint-authz-code`). Because the funnel — not the delivery terminals — owns the stamp + hook, a login can't reach delivery without firing `afterLogin` exactly once, regardless of credential type (password / SSO / passwordless). It does **not** fire for finalize paths that establish no session: the invite/recovery _fresh-login_ redirect (the user signs in separately afterwards), nor for change-password's token rotation. Stamp-at-authenticated: an authorization-server login the user later **denies** at the consent screen still counts (they proved identity at the AS).

```ts
class AppAuthWorkflow extends AuthWorkflow {
  protected override async afterLogin(ctx: AuthWfCtx): Promise<void> {
    await analytics.track("login", { userId: ctx.subject, firstLogin: !!ctx.isFirstLogin });
  }
  protected override async afterInvitationAccepted(ctx: AuthWfCtx): Promise<void> {
    await provisionWorkspace(ctx.subject!); // an auto-login invite ALSO fires afterLogin
  }
}
```

## What the user sees

### Login (`auth/login/flow`)

A login run pauses on one or more of these forms before issuing tokens. Which pauses appear is driven by account state + your resolver overrides:

1. **Credentials** — username + password. Always. Alt-actions (`forgotPassword`, `signup`, `magicLink`, per-SSO `sso-${id}`) finish the run early via a redirect envelope.
2. **Channel enrollment** — email/phone, when `resolveEnrollment` requires a confirmed address the account lacks.
3. **MFA challenge** — when the user has a confirmed method (picker shown for multiple).
4. **MFA enrollment** — pick-method → address (sms/email) **or** TOTP QR step → confirm, when `resolveMfaPolicy` requires it and the user has none. TOTP shows its QR on a dedicated step _before_ code entry (see [SPA Components — AsQrCode](./spa-components#asqrcode-totp-enrollment)). The authenticator entry reads "issuer: account" — the issuer half is `opts.totpIssuer` / `resolveMfaPolicy().issuer`, the account half comes from `resolveTotpAccountLabel(ctx)` (default: `ctx.email`, else the user's `username`) and is baked into the `otpauth://` URI **forever** (re-labeling requires re-enrolment), so override it early if you want anything fancier than the username.
5. **Forced password change** — when the password is flagged initial or expired.
6. **Terms / consent** — when `ConsentStore.getPendingConsents` returns descriptors (rendered inline on the open form).
7. **Concurrency-limit prompt** — when `resolveSessionPolicy` sets a max-sessions limit and it's exceeded.
8. **Authorize consent** — only when the login was started from `GET /auth/authorize` (the [authorization-server](./authorization-server) flow). After authentication the run verifies the `aooth_authz` browser binding and pauses on `AuthorizeConsentForm`; **Authorize** mints the code, **Deny** returns `error=access_denied`. See [Consent gate & browser binding](./authorization-server#consent-gate-browser-binding).

The run finishes by issuing tokens (or a fresh-login redirect) — or, for an authorize-initiated login, by minting a single-use code to the requesting client instead of a browser session. Any user-initiated abort (`Cancel`, decline-terms) emits a structured `aborted` envelope via `abortWf`.

### Device recognition — when the "new sign-in" notice fires {#device-recognition}

aooth keeps two device concepts deliberately separate:

- **Trust** — "skip MFA on this device". Opt-in ("Remember this device" on the MFA form), short TTL, optionally IP-bound, gated by `resolveDeviceTrust`. Security-sensitive, so it stays strict.
- **Recognition** — "we've seen this device — don't email about a new sign-in". Pure noise control with no security bypass, so it is **always on**, long-lived, and never IP-bound. Without it, a user who declines remember-me (or whose trust cookie lapses or changes IP) would get a "new sign-in" email on every login.

Recognition rides its own cookie plus a per-user `seenDevices` ledger. On every successful login the `device-recognition` step (login finalize tail, before `issue`) verifies an arriving recognition cookie against the ledger — sliding its expiry on a hit, so active devices never age out — or mints and persists a fresh record labelled with a humanized user-agent summary ("Chrome on macOS"); `issue` then (re-)sets the cookie on the finish envelope. The notice fires only when the device was **not** recognized on arrival: the gate is `!ctx.isFirstLogin && !!ctx.finalize.notifyNewDevice && !ctx.trust.recognized` (a freshly minted record does not count as recognized for the current login). Trust semantics — what skips MFA — are completely unchanged.

| Login from…                                  | MFA     | "New sign-in" email                     |
| -------------------------------------------- | ------- | --------------------------------------- |
| brand-new device                             | full    | yes — once                              |
| seen device, "Remember this device" declined | full    | no                                      |
| seen device, valid trust cookie              | skipped | no                                      |
| seen device, **expired** trust cookie        | full    | no (previously: yes)                    |
| 6th device (cap eviction)                    | full    | evicted device emails again on next use |

Infrastructure knobs live on the `deviceRecognition` opts group: `cookieName` (default `<deviceTrust.cookieName>_seen`, i.e. `aooth_trusted_device_seen`), `ttlMs` (default 180 days), `maxDevices` (ledger cap, default 5 — expired records drop first, then the least-recently-verified are evicted). See the [AuthWorkflowOpts reference](/api/auth-moost#authworkflowopts-resolvedauthworkflowopts) and the [`@aooth/user` seen-device methods](/api/user#userservice-t-extends-object-object) the step calls.

**Configure `deviceTrust.secret` or recognition is silently off.** Recognition tokens are signed with the same `UserService` `deviceTrust.secret` as trust tokens (domain-separated payloads — the two token kinds are not interchangeable), and without the secret the step no-ops, leaving the legacy notify-on-every-unrecognized-login behavior. Recognition does **not** require `resolveDeviceTrust` to be enabled — it works with device trust fully disabled.

**Hygiene:** the `revoke-sessions` step (change-password + recovery reset) clears the whole ledger. Each device re-mints on its next login, so the single fresh "new sign-in" notice after a password change is deliberate signal, not a regression.

### Where security notices go {#security-notices}

The notice needs an email recipient, and not every account has email MFA. The recipient is resolved by [`UserService.getCorrespondenceEmail`](/api/user#userservice-t-extends-object-object) — a PROVEN-first chain: `account.verifiedEmail`, then the first confirmed email-MFA method (also a proven inbox), then your `@aooth.user.email`-annotated column (when `UserServiceConfig.emailField` names it — app-canonical but unproven). Proven-first is deliberate for security notices: when an address changes, the notice should reach the inbox someone actually demonstrated control of, mirroring the standard "your email was changed" notice going to the OLD address. The login flow falls back to this chain whenever no confirmed email-MFA method set the recipient — so invited or self-signed-up users with **zero MFA** still receive new-device notices.

`account.verifiedEmail` is captured automatically wherever a flow proves inbox ownership: invite acceptance (the magic-link click), signup (the pre-create OTP), recovery (only when the reset code was actually delivered over email — recorded against the address it went to), email channel/MFA confirmation, and federated logins. The capture is correspondence-only — it never becomes a login handle and never resolves accounts.

Two override seams:

- **`UserService.getCorrespondenceEmail(user)`** — replace the chain to source the address from anywhere (a profile table, a tenant directory, a CRM). The default is sync, but the return type admits a `Promise`, so an `async` override just works.
- **`resolveFederatedEmailTrust(ctx, profile)`** — should a federated provider's email claim count as inbox proof? The default trusts exactly the provider's `email_verified === true` claim: a provider trusted to _authenticate_ the user is strictly more trusted than its email claim. Override to exclude a provider whose claim shouldn't be taken at face value (e.g. an internal OIDC issuer that stamps `email_verified` on unverified directory entries). The capture is idempotent — an already-current address skips the write.

One note for subclass authors: the three email slots are separately owned — `ctx.notice.email` is the security-notice recipient (server-only; may be seeded without any code sent), `ctx.channel.email` is the enrollment target, and `ctx.email` is the flow-subject address recovery/invite/signup use (the login flow never writes it). The email channel-enrollment gates key on `ctx.channel.email` — the ask→verify progress marker, mirroring `channel.phone` — never on `ctx.email`. Full signatures: [`setVerifiedEmail` / `getCorrespondenceEmail`](/api/user#userservice-t-extends-object-object) and the [resolver set](/api/auth-moost#authworkflow).

### Geo anomalies & impossible travel (recipe) {#geo-anomalies}

aooth ships **no geo resolution and no default thresholds** — detection is consumer policy. What the framework provides is the three outlets the policy composes from: per-session metadata persistence, the MFA re-arm hook, and the alert path.

1. **Capture geo per session.** `CredentialMetadata` is declaration-merge extensible; add your geo fields and stamp them in a `resolveIssueMetadata` override (the default already records IP + User-Agent). With CloudFront in front, the viewer-location headers are already on the request:

   ```ts
   declare module "@aooth/auth" {
     interface CredentialMetadata {
       geoLat?: number;
       geoLon?: number;
       geoCity?: string;
     }
   }

   protected override resolveIssueMetadata(ctx: AuthWfCtx): CredentialMetadata | undefined {
     const headers = useHeaders(); // cloudfront-viewer-latitude / -longitude / -city
     const lat = Number(headers["cloudfront-viewer-latitude"]);
     const lon = Number(headers["cloudfront-viewer-longitude"]);
     return {
       ...super.resolveIssueMetadata(ctx),
       ...(Number.isFinite(lat) && { geoLat: lat }),
       ...(Number.isFinite(lon) && { geoLon: lon }),
     };
   }
   ```

2. **Detect in `resolveRiskStepUp`.** The `risk-step-up` step runs inside login's MFA loop — _before_ `issue` mints the current session — so `auth.listSessions(ctx.subject)` returns prior logins only, newest first. Compare the request's geo against the most recent prior session's metadata with `haversineKm` and return `{ require: true, reason: "impossible-travel" }` past your threshold to clear `otp.verified` and re-arm the loop. One ordering caveat: re-arming cannot out-rank a **valid trust cookie** — `check-trusted-device` sits in the same loop and re-verifies on the next iteration, so a trusted device still skips the repeat challenge. If geo must out-rank device trust, also suppress the skip (e.g. return `skipsMfa: false` from `resolveDeviceTrust` when the anomaly fires).

3. **Alert with `sendSecurityAlert(ctx, reason, context?)`.** The blessed one-call alert path: it emits a `security-alert` payload through the same `deliver()` as every other notice. The recipient is `ctx.notice.email` — the proven-first correspondence chain above — and when no provable inbox exists the call is a silent no-op (same posture as the new-device notice). `reason` is the machine-readable trigger; `context` is free-form template data (distances, cities). The base class never sends one on its own.

```ts
protected override async resolveRiskStepUp(ctx: AuthWfCtx) {
  if (!ctx.subject) return { require: false };
  const here = this.readRequestGeo(); // your header/db lookup
  if (!here) return { require: false };
  const [prior] = (await this.auth.listSessions(ctx.subject)) // prior sessions only here
    .filter((s) => s.metadata?.geoLat !== undefined && s.metadata.geoLon !== undefined);
  if (!prior?.metadata) return { require: false };
  const km = haversineKm(
    { lat: prior.metadata.geoLat!, lon: prior.metadata.geoLon! },
    { lat: here.lat, lon: here.lon },
  );
  if (km <= 500) return { require: false }; // your threshold — aooth has no default
  await this.sendSecurityAlert(ctx, "impossible-travel", { distanceKm: Math.round(km) });
  return { require: true, reason: "impossible-travel" };
}
```

If you persist credentials through the atscript-db store, note the credential-metadata column is **consumer-declared**: the shipped `AoothAuthCredential` carries no `metadata` column. Declare a `@db.json` field on your extending model shaped as `AoothCredentialMetadataBase & { geoLat?: number, geoLon?: number, geoCity?: string }` (the exported `.as` type single-sources the framework-written envelope keys), mark it `@aooth.auth.metadata`, and thread `getAoothCredentialMetadataSpec(YourCredential).metadataField` into `CredentialStoreAtscriptDb` — the closed schema then validates your exact shape (the `.as` field is the runtime twin of the `CredentialMetadata` declaration merge above).

### Invite (`auth/invite/start`)

**Admin phase** (ARBAC-gated by the `invite` permission): the admin fills the invite form (email, optional name, optional roles — server-validated against `getAvailableRoles()`), then a magic link is emitted (idempotent — re-entry never double-sends) or a shareable link is returned.

**Re-inviting a pending user just works.** When the submitted email resolves to a row still parked on `account.pendingInvitation`, the default `duplicateInviteCheck` verdict is `'reuse'`: instead of erroring, `create-user` refreshes the existing record in place (freshly-picked roles, current `prepareUser` extras, pending re-asserted; password/MFA untouched) and `send-email` mints a brand-new full-TTL magic link — so an expired or lost invite is fixed by simply inviting the same email again. An email that resolves to an **accepted** account still rejects (`"User already exists"`); a `'reuse'` verdict forced onto an accepted account 409s as a logic error (`create-user` re-validates against a fresh read). Override the hook to return `'reject'` for pending rows if you want the strict legacy "Invite already pending" error, or `'allow'` for multi-tenant re-invites of the same email into a different tenant. Note the previous run's magic link (if unexpired) stays valid until its own TTL — consumers projecting a `subject` shadow column on the wf-state store (`@wf.store.fromContext 'subject'`) can delete the stale row in their `duplicateInviteCheck` override for an exactly-one-valid-link guarantee.

**Invitee phase** (anonymous magic-link resume): already-accepted / cancelled notices where applicable → set initial password → optional profile → optional confirmation banner → finish (auto-login when `autoLoginOnInvite`, else redirect to `loginUrl`). A re-clicked link whose state row was already evicted falls through to `GET /auth/invite/post-redemption`, which rebuilds the same idempotent "already accepted" envelope from the `uid` in the URL.

### Pre-seeded enrolment & verified-by-construction addresses {#pre-seeded-enrolment}

The shared MFA enrol trio splits collection from dispatch: `enroll-address` only **stages** the typed address, and the dedicated **`enroll-send`** step (gated `!ctx.pin`, the same canonical "send if no pin" pattern as the challenge pair) mints + delivers the one verification code — in the same engine pass, so the user experience is unchanged. The split is what makes **pre-seeding** safe: a consumer that already knows the address — typically `resolveAccept` staging the invited email — sets `ctx.mfaEnroll.address` up front, `enroll-address` self-skips (no redundant ask), and `enroll-send` still fires exactly once:

```ts
protected override resolveAccept(ctx: AuthWfCtx) {
  if (ctx.email) (ctx.mfaEnroll ??= {}).address ??= ctx.email; // the invited address
  return super.resolveAccept(ctx);
}
```

**Skipping the code entirely** — at invite accept the user is inside the flow _only because_ they redeemed a magic link delivered to that exact address, the same proof `activate-user` already trusts to write `account.verifiedEmail`. Re-proving the same inbox with a pincode in the same sitting is redundant friction, so `resolveEnrollPreConfirmed(ctx, method, address)` (default `false`) can vouch for it: `enroll-send` then dispatches nothing and `enroll-confirm` writes the confirmed factor (+ `verifiedEmail`, + default method) with **no code-entry pause**:

```ts
protected override resolveEnrollPreConfirmed(ctx: AuthWfCtx, method: MfaTransport, address: string) {
  return !!ctx.accept && method === "email" && address === ctx.email;
}
```

**Keep the equality check** — the magic-link proof transfers ONLY to the address it was delivered to; vouching for whatever the user typed would write an unproven inbox as a confirmed factor. TOTP is never asked (possession of an authenticator cannot be proven by construction), and a vouch never outlives its address (`useDifferentMethod`/cancel clear it with the rest of the enrol scratch). Deployments that prefer the double-check simply keep the default.

### Pin the enrolment address to an account record {#pin-enrolment-address}

Some deployments need the email/SMS factor **bound** to an account record rather than free-text — e.g. staff MFA locked to the work mailbox so portal access dies with it at offboarding; letting the user pincode-prove a personal inbox would defeat the control entirely. `resolveEnrollAddress(ctx, method)` (default `'collect'`) is that policy knob: return a string and `enroll-address` stages it (normalized) without ever rendering the free-text form — the user is never shown a form whose only valid input is one known string.

```ts
protected override async resolveEnrollAddress(ctx: AuthWfCtx, method: MfaTransport) {
  if (method !== "email") return "collect";
  const user = await this.users.getUser(ctx.subject!);
  return (user as { email?: string }).email ?? "collect"; // your @aooth.user.email handle column
}
```

A pinned address composes with everything above untouched: `enroll-address` self-skips its form, `enroll-send` dispatches the one code to it, and `resolveEnrollPreConfirmed` may vouch it — pin to a verified-by-construction address and the user gets the no-code path for free. The returned value is consumer-authoritative (no `validateMfaAddress` pass); a blank return falls back to `'collect'`. For nuanced rules on what the user **types** — domain allowlists, must-match-the-record comparisons — override the ctx-first, async-capable `validateMfaAddress(ctx, method, value)` instead and keep the form.

### Recovery (`auth/recovery/flow`)

Identifier (anti-enumeration: unknown identifiers get the same response) → delivery mode (magic-link / OTP) → OTP entry or magic-link click → optional known-factor verification → new password (revokes existing sessions) → finish (auto-login when `autoLoginOnRecover`, else fresh-login redirect).

Where the OTP is **delivered** is itself an extension seam: M1 sends it to the identifier the user typed (transport picked by `resolveRecoveryChannel`), M2 sends it to a channel already verified on the resolved row (`resolveRecoveryDeliverySource` + `selectRecoveryRegisteredMethod`). Logging in _by phone_ and auto-promoting a confirmed channel into a login handle (`resolvePromoteHandleField`) live alongside these — see [Phone, recovery channels & handle promotion](./recovery-and-handles).

### Change password (`auth/change-password/flow`) {#change-password-auth-change-password-flow}

The authenticated "change MY password" flow — for a signed-in user rotating their own credential (distinct from recovery, which is for users who are locked out). The single pause is `ChangePasswordForm` (current password + new + confirm, with the live password-rules readout); on submit it verifies the current password, applies the new one through `UserService.changePassword`, optionally revokes the user's other sessions, and re-issues the acting session on a fresh token (so the current device stays signed in, no ghost sessions survive).

**Identity is session-bound, never input.** `init-change-password` sets `ctx.subject` (the stable user id) from `useAuth().getUserId()` — there is no target-user parameter anywhere in the flow, so it is structurally "change my password", not "change someone's password".

**Fully ARBAC-gated, no `@Public()`.** Unlike the other (public) flows, the `@Workflow` body and every step carry `@ArbacResource("auth.change-password")` + `@ArbacAction("self")`. A customer enables the feature with a single grant — `allow("auth.change-password", "*")` — and forbids it (e.g. SSO-only orgs that disallow local password changes) by simply omitting that grant. There is no on/off opts flag; the privilege **is** the switch. See [ARBAC Authorize — gating a whole workflow](./arbac-authorize#gating-a-multi-step-workflow).

Policy lives on `resolveChangePasswordPolicy(ctx)` (override seam): `revokeOtherSessions` (default `true`) and an optional min-interval `rateLimit` (`{ minIntervalMs }`) that emits a terminal "try again later" before the form pause. Current-password re-entry is the primary protection; rate-limiting is optional defense-in-depth.

This flow is **not** in `DEFAULT_AUTH_WORKFLOWS`, so it is unreachable from the public `/auth/trigger` — it is dispatched from its own guarded `POST /auth/change-password` route (`CHANGE_PASSWORD_WORKFLOW`). See [REST Controllers](./controllers).

### Manage MFA (`auth/add-mfa/flow`) {#add-mfa-auth-add-mfa-flow}

The authenticated "Manage two-factor authentication" flow — the profile-maintenance twin of change-password — lets a signed-in user **add, change, or remove** their MFA factors on demand (distinct from login's _forced_ first-time enrollment). It is the same `@Workflow` as before (id `auth/add-mfa/flow`, route `POST /auth/add-mfa`, ARBAC resource `auth.add-mfa`); the behavior expanded from add-only to full management.

**Step-up first.** A user who already has a confirmed factor must **re-verify an existing one** before any change — `init-add-mfa` sets `ctx.addMfa.stepUpRequired`, and the flow runs the login MFA _challenge_ steps (`load-enrolled-mfa-methods` → `select-mfa-method` → pincode / `totp-check`) before showing the menu. This step-up deliberately omits the trusted-device skip: a trusted device cannot bypass it.

**…but consent before the code goes out.** Opening the manage dialog must never email/text the user as a side effect, so the sms/email step-up pauses on `StepUpConfirmForm` (`manage-stepup-confirm`) **before** `pincode-send`: "To continue, we will send a verification code to ma•••@x" with a Continue submit. A user who opened the dialog by mistake closes it with zero codes consumed and no resend cooldown burnt. The pause is skipped wherever consent already exists — an explicit pick on the factor picker counts (`Select2faForm`'s options show the masked destination, so choosing "Email (ma•••@x)" _is_ informed consent), a code already in flight never re-asks, and TOTP step-up dispatches nothing so it never pauses here. Restore the zero-click dispatch with `resolveStepUpConfirmBeforeSend(ctx)` → `false` (login's challenge keeps zero-click — it is mid-authentication, not a dialog side effect). If the user's only confirmed factor is of a kind the policy no longer allows — so nothing is MFA-challengeable (a tightened policy orphaned it) — `manage-password-reauth` falls back to re-verifying the **account password** (`UserService.verifyPassword`) instead, so identity is always re-proven before a change. A **zero-MFA** user has nothing to verify, so step-up + menu are skipped and the flow drops straight to the enrol picker — the first-time opt-in path. The enrol forms run in `'manage'` mode: their "Skip for now" action is hidden, and so is their built-in **Cancel** — the `cancel` action stays in the whitelist but the consumer renders its own cancel affordance (see **Host-rendered cancel** below). A cancel or exit **at any point — including on the step-up challenge — fails closed**: the step-up loop breaks on abort and the flow routes to the cancelled terminal, so no factor is ever changed without a completed challenge. (Login's challenge loop deliberately does _not_ adopt this abort-break, because exiting it without a paired failure terminal could issue a session.)

**The menu** (`manage-menu`, `ManageMfaForm`) offers one radio whose value encodes action + target: **Add** the un-enrolled transports (`ctx.addMfa.candidates`), **Change** or **Remove** the enrolled ones — _omitting_ any factor in `ctx.addMfa.locked` (see below). It never offers an operation that cannot succeed: when the user is down to their **last** confirmed factor under a `required` policy, the Remove option is omitted too (`removeBlocked`, with a one-line note explaining that the method can be changed but not removed) — otherwise the user would land on a confirm form whose only submit re-throws the keep-at-least-one guard, with no way out (the manage forms hide their built-in cancel). Add / Change route into the reused trio (`enroll-pick-method` → `enroll-address` / `enroll-totp-qr` → `enroll-send` → `enroll-confirm`); Remove routes to `confirm-remove-mfa`. The single `enroll-address` field is **transport-aware** — its label resolves to "Phone number" for sms and "Email address" for email (via `@ui.form.fn.label` reading `ctx.public.mfaEnroll.method`; `@meta.label 'Address'` is the static fallback when `@atscript/ui-fns` is absent).

**Enrolment is write-on-confirm (no strand, no clobber).** The enrol trio stages every candidate value — sms/email address or totp secret — in wf-state and writes the user record **only** once the new value's code verifies (`enroll-confirm` upserts it confirmed via `addMfaMethod`). So an ADD leaves no partial row, and a REPLACE keeps the old confirmed value live until it is atomically swapped — TOTP included: no single-slot clobber, no stash/restore, no crash window. A cancel, or a crafted `useDifferentMethod` (the manage forms hide **both** actions but they stay in the declared whitelist), therefore has nothing to undo — it can never strand or clobber the live factor, by construction. Removing the last confirmed factor is blocked only when the MFA policy mode is `required` — the menu omits that Remove option up front, and if a stale/crafted route reaches `confirm-remove-mfa` in an un-removable state anyway (last-required-factor, or a locked transport), the step **aborts to the finish terminal** with a reason-specific message (`{ added: false, reason: 'last-required-factor' | 'method-locked' }`) instead of pausing on a retryable form that can never succeed.

**Host-rendered cancel.** Every manage-MFA form hides its built-in `cancel` action (`@ui.form.fn.hidden '() => true'`) — but keeps it **in the action whitelist**, so it is still dispatchable. The intended pattern: render your **own** Cancel affordance (next to your submit) and dispatch the `cancel` action when the user abandons the flow. Doing so aborts the run server-side (→ the cancelled terminal) and lets the durable wf-state row be **cleaned up immediately** rather than left to expire — important once the flow has swapped to the `store` strategy. Since `@atscript/vue-wf@0.1.101`, `<AsWfForm>` exposes this on its instance: hold a template `ref` and call `form.value.action('cancel')`, gating the button on `form.value.supportsAction('cancel')` (which checks the form's **declared-action ids** — `@ui.form.action` ∪ `@wf.action.withData` — so it never renders on the reused login step-up challenge forms, which don't whitelist `cancel`). The demo's `WfHostCancelForm.vue` is the reference implementation — a thin `<AsWfForm ref>` wrapper that adds the Cancel button. (Pre-0.1.101 the only route was re-implementing the form with the headless `useWfForm()` engine and calling its `action('cancel')`; still valid, no longer necessary.)

**Locked (handle-bound) factors.** `resolveLockedMfaTransports(ctx)` (default `[]`) names factors the user may not change or remove here — typically an MFA `email`/`phone` whose value **is** a login handle (changing it would desync identity). Override it to compare each enrolled channel value against your `@aooth.user.email` / `@aooth.user.phone` handle columns (resolved at boot via `getAoothUserHandleSpec`). The menu omits locked factors from Change/Remove and re-checks server-side.

**Durable step-up state.** Once the step-up factor verifies, `manage-stepup-done` swaps off the cheap encapsulated start onto the durable `store` strategy (mirrors login's swap-after-credentials) — the pincode becomes single-use server state and the staged new factor lives server-side, not in the SPA-held token. Degrades to encapsulated when no durable store is wired.

**Identity is session-bound + fully ARBAC-gated**, exactly like change-password: `init-add-mfa` sets `ctx.subject` from `useAuth().getUserId()` (no target-user parameter), and the `@Workflow` body + the `init` / `finish` / manage steps carry `@ArbacResource("auth.add-mfa")` + `@ArbacAction("self")`. Enable with `allow("auth.add-mfa", "*")`; omit to disable. **Not** in `DEFAULT_AUTH_WORKFLOWS` — dispatched from its own guarded `POST /auth/add-mfa` route (`ADD_MFA_WORKFLOW`). The user keeps their current session — the finish is a plain data envelope (`{ added | changed | removed, method }`, or `{ added: false, reason }` for nothing-to-do / cancelled), no token re-issue. `UserService.removeMfaMethod` is still available for a direct domain call. See [REST Controllers](./controllers).

### Self-signup (`auth/signup/flow`)

Open self-registration for anonymous users — the reciprocal of login (signup is typically the _initial_ flow). Shape = recovery's email→OTP front + invite's create→set-password→activate tail, so it reuses those steps wholesale. The pauses: **`SignupForm`** (email — and the "I already have an account" action that cross-links to login) → **`PincodeForm`** (the emailed OTP) → **`SetPasswordForm`** (password chosen _after_ verification) → finish (auto-login, tokens issued).

**Verify-first, so the password is never held in workflow state across the OTP wait** — the account row is created only after the email is proven, and the password is set on the shared `SetPasswordForm` afterward.

**Anti-enumeration by construction.** Every submitted email gets the _same_ OTP pause — account existence is resolved only at `signup-create-user`, _after_ proof-of-ownership. A new email creates the user (inactive → password set → activated) and auto-logs-in; an already-registered email finishes with a redirect to `loginUrl` (reason `already-registered`) and **never** issues tokens. An attacker on the wire sees identical behavior either way.

**Off by default.** `resolveSignupPolicy(ctx)` returns `allowSignup: false` (invite-only is the safe default); a deployment opts into open self-serve by overriding it to `true` (and flips the login form's `signup` alt-action on via `resolveAlternateCredentials`). Required app columns (e.g. a NOT-NULL `tenantId`) come from the **same `prepareUser` hook invite uses** — an override distinguishes signup by the absence of `invitedBy` + empty `roles`. `signup-extra-step` is the post-creation extension seam (seed app rows, welcome email, etc.). It IS in `DEFAULT_AUTH_WORKFLOWS`, so it runs via the public `/auth/trigger`.

## Outbound delivery — `deliver(payload)`

Override `protected deliver(payload: AuthDeliveryPayload)` to route direct sends (MFA / recovery / enroll pincodes, new-device notice) by `payload.kind` and `payload.channel`. The invite magic link is **not** sent through `deliver` — it goes through the email outlet on the trigger route (the resume URL is minted by the engine after the step yields). There is **no `audit()` method** — see [Audit Log](./audit) for wiring your own. See [`AuthDeliveryPayload`](/api/auth-moost#authdeliverypayload).

## Consent collection — `ConsentStore`

`AuthWorkflow` takes `consentStore: ConsentStore` as its **4th** constructor param. On every run the `prepare-consents` step calls `getPendingConsents(ctx.subject)` — the argument is the **stable user id**, not the username — and writes the result to `ctx.consents.pending`; the bundled forms surface them inline as a `consents: string[]` field rendered by the `AsConsentArray` component. Signatures: [`ConsentStore` reference](/api/auth-moost#consentstore).

::: warning `getPendingConsents` is user-scoped only
The argument is the **stable user id** (the workflow passes `ctx.subject`). The returned descriptor set MUST NOT vary by workflow or transport channel — every flow consults the same user-level consent universe. OTP channel-ownership consent (which IS channel-specific) is captured separately via `recordOtpChannelConsent`.
:::

```ts
import { ConsentStore, type ConsentDescriptor, type ConsentEvent } from "@aooth/auth-moost";
import { Injectable } from "moost";

@Injectable() // SINGLETON
class MyConsentStore extends ConsentStore {
  override async getPendingConsents(userId: string | undefined): Promise<ConsentDescriptor[]> {
    if (!userId) return [];
    const accepted = await db.consents.find({ userId, id: "terms" });
    if (accepted.some((e) => e.version === "v2")) return [];
    return [
      {
        id: "terms",
        text: "I accept the updated [Terms](/terms) and [Privacy](/privacy)",
        required: "You must accept the updated terms to continue",
        version: "v2",
      },
    ];
  }

  override async save(username: string, events: ConsentEvent[]): Promise<void> {
    await db.consents.insertMany(events.map((e) => ({ ...e, username })));
  }
}

app.setReplaceRegistry(createReplaceRegistry([ConsentStore, MyConsentStore]));
```

### OTP-channel disclosure

For each OTP-via-email / OTP-via-sms channel the user enrolls, `resolveOtpDisclosure(ctx, channel)` stages a generic disclosure paragraph onto `ctx.channel.otpDisclosure`, rendered next to the address input so the user reads it before submitting (typing + submitting their address is implied consent). After the pincode validates and the method is confirmed, the step calls `recordOtpChannelConsent(username, channel, target, disclosure)` — so the audit record pins both the literal copy shown and the verified address. The default is disclosure-only (sufficient for transactional OTPs under TCPA / PECR / CASL / GDPR); override `recordOtpChannelConsent` for affirmative-consent capture.

## `wf-trigger` — workflow trigger machinery

### `WfTriggerProvider`

The `@Injectable()` singleton owning workflow-state persistence, outlets, and the token wire. Constructor is `(wf: MoostWf, auth: AuthCredential)`. Signatures: [`WfTriggerProvider` reference](/api/auth-moost#wftriggerprovider).

#### Workflow state strategy

State is a **named-strategy registry**, not a single strategy. Every workflow **starts** on the `encapsulated` strategy (the registry default): state rides inside the SPA-held token, so opening a login form persists **zero** server-side rows before the first validated input — a restart or eviction can no longer `410 Gone` an idle form. A later step calls `swapStrategy('store')` to move durable once there is real state worth persisting.

Both registry entries default to `EncapsulatedStateStrategy`. **To make `store` durable, override `storeStrategy()`** — do not assign a `this.state` field (it no longer exists):

```ts
import { WfTriggerProvider, createAuthEmailOutlet } from "@aooth/auth-moost";
import { HandleStateStrategy, MoostWf, type WfStateStrategy } from "@moostjs/event-wf";
import { AsWfStore } from "@atscript/moost-wf";
import { AuthCredential } from "@aooth/auth";
import { Injectable } from "moost";

@Injectable()
class MyWfTriggerProvider extends WfTriggerProvider {
  constructor(wf: MoostWf, auth: AuthCredential) {
    super(wf, auth);
    this.outlets = [
      ...this.outlets,
      createAuthEmailOutlet({
        emailSender,
        buildMagicLinkUrl: (kind, token, ctx) =>
          `${env.FRONTEND_URL}/redeem?wfs=${token}${ctx?.userId ? `&uid=${ctx.userId}` : ""}`,
        magicLinkTtlMs: (kind) =>
          kind === "invite.magicLink" ? 7 * 24 * 60 * 60_000 : 60 * 60_000,
      }),
    ];
  }
  protected override storeStrategy(): WfStateStrategy {
    return new HandleStateStrategy({ store: new AsWfStore({ table: db.tables.wfStates }) });
  }
}

app.setReplaceRegistry(createReplaceRegistry([WfTriggerProvider, MyWfTriggerProvider]));
```

The encapsulated token's secret defaults to `auth.deriveStateKey("wf-state")` (HKDF-derived from the auth secret, stable across restarts) — override `wfStateSecret()` for a dedicated secret, or `wfStateEncapsulatedTtlMs()` to expire idle forms. `HandleStateStrategy` / `EncapsulatedStateStrategy` come from `@moostjs/event-wf`; `AsWfStore` (a `@atscript/db`-table-backed store) from `@atscript/moost-wf`.

### `WfTrigger({ allow?, token? })`

Method decorator wrapping `defineAfterInterceptor` at `INTERCEPTOR` priority. When the wrapped handler returns `undefined`, the interceptor instantiates `WfTriggerProvider` and replies with `provider.handle(opts)`. `opts.allow` whitelists wfids (a request for a wfid outside `allow` is rejected). `opts.token` overrides the wire (default `{ read: ['body','query','cookie'], write: 'body', name: 'wfs' }`). Return a non-`undefined` value to short-circuit (see [Controllers — Pattern B](./controllers)).

### `createAuthEmailOutlet(deps)`

Builds the email outlet that delivers the invite magic link. `deps.buildMagicLinkUrl` is the 3-arg `BuildMagicLinkUrl` — `(kind, token, ctx?: { userId? }) => string` — where the `{ userId }` arg is supplied for the `invite.magicLink` kind so the URL can carry the invitee id for the post-redemption side route. Add the outlet to `WfTriggerProvider.outlets`. See [`createAuthEmailOutlet`](/api/auth-moost#createauthemailoutlet).

## Finish + error envelopes

Steps end a run with `finishWf(opts)` (success) or `abortWf(reason, opts)` (user-initiated abort), and re-pause on a retriable error with `wf.requireInput(...)`. `finishWf` / `abortWf` / `FinishWfOpts` / `WfFinished` are from `@atscript/moost-wf` — the unified envelope (`next: { trigger, action?, primary?, options? }`, auto-redirect countdown, manual choice, aborted soft-failure) is owned by that package; see the [atscript-ui-wf](https://ui.atscript.dev) docs for its full shape. The login path attaches session cookies to the finish envelope via `useAuth().buildFinishedCookies(issue)`.

### Error patterns — retriable vs terminal {#error-patterns}

`@Step` bodies throw exactly two shapes. Pick by asking: **can the user fix this from the form they are looking at?**

| Shape                                                             | Behaviour                                                                                                               | Use for                                                                                                                                        |
| ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `throw wf.requireInput({ errors, formMessage? })` — **retriable** | Engine re-persists state under the SAME `wfs` handle and re-renders the form with per-field errors. The token survives. | Wrong password, invalid OTP, mismatched confirm-password, duplicate email, missing required consent, account lockout, "session limit reached". |
| `throw new HttpError(<status>, <msg>)` — **terminal**             | The token is consumed; the SPA renders a final error. The run is over.                                                  | `500` state corruption, `501` not-implemented stubs, `410` cancelled invite, `403` feature disabled, `409` CAS exhausted.                      |

`wf` is the handle from `useAtscriptWf(FormSchema)`. The form payload + `@wf.context.pass` keys are auto-included in the re-render, so the SPA's next render sees fresh ctx without an extra round-trip.

```ts
// ✅ Retriable — user corrects input on the same form (token survives).
throw wf.requireInput({ formMessage: "Invalid credentials" });
throw wf.requireInput({ errors: { confirmPassword: "Passwords do not match" } });

// ❌ Terminal — not a client error; no form to retry from.
if (!ctx.subject) throw new HttpError(500, "Workflow state corrupted: missing subject");
if (!this.isCancellationEnabled()) throw new HttpError(403, "Invite cancellation is disabled");
```

::: warning Never throw `HttpError(4xx)` for a user-fixable input error
A terminal `HttpError` consumes the `wfs` token — the user's next submission lands on a dead handle and gets `410 Gone`. Use `wf.requireInput` for anything the user can correct from the open form.
:::

## Workflow state tokens (`wfs`)

The `wfs` URL / body / cookie token is the single resume handle for a paused run. It is **stable across**:

- **`wf.requireInput` retries** — the URL `wfs=…` stays live; the user fixes input and resubmits.
- **Browser refresh / bookmark / revisit** — the URL's `wfs=…` resumes at the current pause.
- **Multi-tab** — concurrent submissions on one token serialize; the loser gets the form re-render under the same handle.

The token mints fresh only at three boundaries: (1) **workflow start** (no incoming token); (2) **workflow finish** (no token persisted — a later `POST /auth/trigger` with the dead token returns `410 Gone`); (3) **workflow-id change** (replaying a `auth/login/flow` token against `auth/recovery/flow`).

::: warning Use `delete ctx.field`, not `ctx.field = undefined`
The state persistence layer JSON-schema-validates the serialized ctx and rejects `undefined` (allowed: string / number / boolean / null / array / object). To clear an optional ctx field at the end of a step body, `delete ctx.field` (or assign `false` / `null` if a forward step reads presence).
:::

## Rendering the forms (SPA)

The bundled forms are server-driven atscript types; the SPA renders them with `<AsWfForm>` (`@atscript/vue-wf`) and registers the aooth companion components (`AsConsentArray`, `AsPasswordRules`, `AsQrCode`) by name. See [SPA Components](./spa-components).

## See also

- [API reference](/api/auth-moost) — full signatures for `AuthWorkflow`, `AuthWorkflowOpts`, `ConsentStore`, `WfTriggerProvider`, `AuthDeliveryPayload`.
- [REST Controllers](./controllers) — the `/auth/trigger` endpoint that dispatches into these workflows.
- [SPA Components](./spa-components) — client-side rendering of the workflow forms.
- [Config Reference](./config) — `AuthOptions` + `AuthWorkflowOpts` defaults.
- [packages/auth-moost/CLAUDE.md](https://github.com/moostjs/aoothjs/blob/main/packages/auth-moost/CLAUDE.md) — the canonical workflow-authoring conventions.
