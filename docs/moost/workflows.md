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

| Slot present      | Flow                  |
| ----------------- | --------------------- |
| `ctx.admin`       | invite (admin phase)  |
| `ctx.accept`      | invite (accept phase) |
| `ctx.postReset`   | recovery              |
| `ctx.signup`      | self-signup           |
| _(none of these)_ | login                 |

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

| Resolver                                                                         | Decides                                                                           | Default                     | Flow(s)                                                                                          |
| -------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | --------------------------- | ------------------------------------------------------------------------------------------------ |
| `resolveMfaPolicy`                                                               | MFA mode / available transports / TOTP issuer                                     | `optional`, all transports  | login, invite, add-mfa                                                                           |
| `resolveEnrollment`                                                              | force a confirmed email/phone before issuing                                      | `ensureEmail/Phone: false`  | login                                                                                            |
| `resolveDeviceTrust`                                                             | trusted-device posture (enabled / optIn / skipsMfa)                               | disabled                    | login                                                                                            |
| `resolveLockout`                                                                 | failed-login lockout mode (temporary / self-service / admin-only)                 | `temporary`                 | login, recovery                                                                                  |
| `resolveGuards`                                                                  | login-time guards (passwordInitial / passwordExpiry / emailVerifiedRequired)      | initial-password guard on   | login                                                                                            |
| `resolveSessionPolicy`                                                           | session concurrency limit                                                         | none                        | login                                                                                            |
| `resolveFinalize`                                                                | new-device notice + post-login redirect mode                                      | both off                    | login                                                                                            |
| `resolveRiskStepUp`                                                              | require an extra MFA round (risk-based)                                           | `require: false`            | login                                                                                            |
| `resolveAlternateCredentials`                                                    | which login alt-actions show (forgotPassword / signup / magicLink / SSO list)     | forgot-password on          | login                                                                                            |
| `resolveSignupPolicy`                                                            | self-signup on/off + collectUsername                                              | `allowSignup: false`        | signup                                                                                           |
| `resolveChangePasswordPolicy`                                                    | revokeOtherSessions + optional rate-limit                                         | revoke on                   | change-password                                                                                  |
| `resolveAccept`                                                                  | invite accept-tail (redirect / confirmation)                                      | redirect to `loginUrl`      | invite                                                                                           |
| `resolveAdminForm`                                                               | invite admin form (collectRoles)                                                  | `collectRoles: true`        | invite                                                                                           |
| `resolvePostReset`                                                               | recovery post-reset (revokeAllSessions / loginUrl)                                | revoke all on               | recovery                                                                                         |
| `resolveRecoveryAltActions`                                                      | recovery alt-actions (backToLogin)                                                | on                          | recovery                                                                                         |
| `resolveRecoveryChannel`                                                         | M1 OTP transport for the typed identifier                                         | `email`                     | recovery → [guide](./recovery-and-handles#recovery-channel-m1)                                   |
| `resolveRecoveryDeliverySource`                                                  | M1 (`typed`) vs M2 (`registered`) OTP delivery                                    | `typed`                     | recovery → [guide](./recovery-and-handles#registered-channel-recovery-m2)                        |
| `resolvePromoteHandleField`                                                      | which login-handle column a confirmed channel promotes into                       | `undefined` (off)           | login, invite, add-mfa → [guide](./recovery-and-handles#promote-a-confirmed-channel-to-a-handle) |
| `resolveOtpDisclosure`                                                           | per-channel consent copy under the address input                                  | empty                       | login, add-mfa                                                                                   |
| `resolveLockedMfaTransports`                                                     | factors the user may NOT change/remove (e.g. a handle-bound email/phone)          | `[]` (none locked)          | add-mfa                                                                                          |
| `resolveRedirect`                                                                | post-login redirect URL                                                           | per `resolveFinalize`       | login                                                                                            |
| `resolveOAuthErrorRedirect`                                                      | federated-login failure redirect target                                           | error page                  | login (SSO)                                                                                      |
| `resolvePincodeForm` / `resolvePincodeTarget` / `resolvePincodeAltAction`        | which OTP form, recipient+channel, alt-action mapping for the shared pincode pair | MFA-vs-recovery by ctx slot | login, recovery                                                                                  |
| `resolveRecoveryUrl` _(sync helper)_                                             | URL the `forgotPassword` alt-action targets                                       | `loginUrl`-derived          | login                                                                                            |
| `resolveClientIp` / `resolveUserAgent` / `resolveIssueMetadata` _(sync helpers)_ | device-trust + audit metadata at issue time                                       | request headers             | login                                                                                            |

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

| Hook                                             | Override to                                                                                                                             | Default               |
| ------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------- | --------------------- |
| `deliver(payload)`                               | route MFA / recovery / enrollment pincodes + new-device notices by `kind` + `channel` — see [below](#outbound-delivery-deliver-payload) | no-op                 |
| `prepareUser(input)`                             | supply required app columns on a freshly-created row (shared by invite + signup)                                                        | `{}`                  |
| `inferAdminRoles(input)`                         | derive roles server-side from the admin invite payload                                                                                  | `[]`                  |
| `getAvailableRoles()`                            | whitelist selectable roles on the admin invite form                                                                                     | none                  |
| `duplicateInviteCheck(input)`                    | override the duplicate-invitee rule                                                                                                     | reject if user exists |
| `logoutOtherSessions(username)`                  | customize the concurrency-limit eviction                                                                                                | revoke all            |
| `loadActiveSessionsCount(username)`              | count active sessions for the concurrency prompt                                                                                        | store-backed          |
| `beginSso` / `oauthRuntime` / `authorizeRuntime` | federated-login wiring — see [Federated Login](./oauth)                                                                                 | runtime-resolved      |

[`ConsentStore`](#consent-collection-consentstore) (`getPendingConsents` / `save` / `read` / `recordOtpChannelConsent`) and the [`WfTriggerProvider`](#wf-trigger-workflow-trigger-machinery) overrides (`storeStrategy` / `wfStateSecret` / `wfStateEncapsulatedTtlMs` / `stateRegistry`) are separate provider classes, documented in their own sections below.

## What the user sees

### Login (`auth/login/flow`)

A login run pauses on one or more of these forms before issuing tokens. Which pauses appear is driven by account state + your resolver overrides:

1. **Credentials** — username + password. Always. Alt-actions (`forgotPassword`, `signup`, `magicLink`, per-SSO `sso-${id}`) finish the run early via a redirect envelope.
2. **Channel enrollment** — email/phone, when `resolveEnrollment` requires a confirmed address the account lacks.
3. **MFA challenge** — when the user has a confirmed method (picker shown for multiple).
4. **MFA enrollment** — pick-method → address (sms/email) **or** TOTP QR step → confirm, when `resolveMfaPolicy` requires it and the user has none. TOTP shows its QR on a dedicated step _before_ code entry (see [SPA Components — AsQrCode](./spa-components#asqrcode-totp-enrollment)).
5. **Forced password change** — when the password is flagged initial or expired.
6. **Terms / consent** — when `ConsentStore.getPendingConsents` returns descriptors (rendered inline on the open form).
7. **Concurrency-limit prompt** — when `resolveSessionPolicy` sets a max-sessions limit and it's exceeded.

The run finishes by issuing tokens (or a fresh-login redirect). Any user-initiated abort (`Cancel`, decline-terms) emits a structured `aborted` envelope via `abortWf`.

### Invite (`auth/invite/start`)

**Admin phase** (ARBAC-gated by the `invite` permission): the admin fills the invite form (email, optional name, optional roles — server-validated against `getAvailableRoles()`), then a magic link is emitted (idempotent — re-entry never double-sends) or a shareable link is returned.

**Invitee phase** (anonymous magic-link resume): already-accepted / cancelled notices where applicable → set initial password → optional profile → optional confirmation banner → finish (auto-login when `autoLoginOnInvite`, else redirect to `loginUrl`). A re-clicked link whose state row was already evicted falls through to `GET /auth/invite/post-redemption`, which rebuilds the same idempotent "already accepted" envelope from the `uid` in the URL.

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

**Step-up first.** A user who already has a confirmed factor must **re-verify an existing one** before any change — `init-add-mfa` sets `ctx.addMfa.stepUpRequired`, and the flow runs the login MFA _challenge_ steps (`load-enrolled-mfa-methods` → `select-mfa-method` → pincode / `totp-check`) before showing the menu. This step-up deliberately omits the trusted-device skip: a trusted device cannot bypass it. A **zero-MFA** user has nothing to verify, so step-up + menu are skipped and the flow drops straight to the enrol picker — the first-time opt-in path. The enrol forms run in `'manage'` mode: they show **Cancel** (the user opened this on purpose), never "Skip for now". A cancel or exit **at any point — including on the step-up challenge — fails closed**: the step-up loop breaks on abort and the flow routes to the cancelled terminal, so no factor is ever changed without a completed challenge. (Login's challenge loop deliberately does _not_ adopt this abort-break, because exiting it without a paired failure terminal could issue a session.)

**The menu** (`manage-menu`, `ManageMfaForm`) offers one radio whose value encodes action + target: **Add** the un-enrolled transports (`ctx.addMfa.candidates`), **Change** or **Remove** the enrolled ones — _omitting_ any factor in `ctx.addMfa.locked` (see below). Add / Change route into the reused trio (`enroll-pick-method` → `enroll-address` / `enroll-totp-qr` → `enroll-confirm`); Remove routes to `confirm-remove-mfa`.

**Change is verify-then-write (no strand).** Replacing an sms/email factor does **not** overwrite the stored row until the _new_ value's code verifies — the old value stays valid throughout. (TOTP has a single slot, so a replace provisions the new secret and stashes the old one; a cancel restores it.) Cancelling a replace — or a crafted `useDifferentMethod` (the manage forms hide it but it stays in their declared action whitelist) — is **replace-aware** and never deletes the still-confirmed factor mid-change. Removing the last confirmed factor is blocked only when the MFA policy mode is `required`.

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
