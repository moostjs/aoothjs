# E2E User Stories — Unified AuthWorkflow Matrix

**Status:** Updated for the unified `AuthWorkflow` shape. This document is the catalogue and walkthrough guide for `packages/e2e-demo/test-e2e/`.

The demo now uses one consumer subclass, `DemoAuthWorkflow extends AuthWorkflow`, for login, invite, and recovery. Variants are selected per request by `?variant=<name>` on `/wf`, forwarded as the `x-wf-variant` header, and resolved inside the unified workflow constructor/resolvers.

---

## 1. Scope Summary

| Area          | Workflow id          | Variant families                                                                                 | Coverage focus                                                                                                                               |
| ------------- | -------------------- | ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Login         | `auth/login/flow`    | credentials, MFA challenge, MFA enrolment, device trust, guards, consents, concurrency, redirect | The full login schema and the shared fragments (`mfaLoopSchema`, `passwordPhaseSchema`, `consentsPersistTailSchema`, `pincodeSendCheckPair`) |
| Recovery      | `auth/recovery/flow` | OTP-via-email, fresh-login, auto-login, short state TTL, resend cooldown, consent                | Reduced recovery scope: no magic-link delivery, no SMS recovery, no mode picker, no pre-reset factor, no workflow audit                      |
| Invite        | `auth/invite/start`  | admin no-roles/roles, TTL, confirmation, idempotent redirect, invite MFA enrolment, consent      | One invite schema with admin phase plus anonymous accept tail                                                                                |
| Unified class | all                  | constructor overlays, resolver dispatch, delivery union, shared forms/state                      | Proves one `DemoAuthWorkflow` subclass covers all three flows                                                                                |

**Out of scope for this unified pass:**

- Recovery magic-link delivery.
- Recovery SMS delivery and transport switching.
- Recovery choice mode.
- Recovery pre-reset factor checks.
- Workflow-level audit variants.
- Invite shareable-link/send-mode choice.
- Invite fresh-login policy via `accept.freshLoginRequired`.
- Invite cancellation-policy variants in the workflow class.

Those behaviors belonged to the previous split workflow surface. The unified workflow intentionally removed or deferred them.

---

## 2. Unified Demo Infrastructure

### 2.1 Single Workflow Class

The demo registers one replacement workflow class:

```ts
@Inherit()
@Injectable("FOR_EVENT")
@Controller()
class DemoAuthWorkflow extends AuthWorkflow {
  constructor(users: UserService, authCred: AuthCredential, consentStore: ConsentStore) {
    const header = readVariantHeader();
    const loginV = pickVariant(LOGIN_VARIANTS, header);
    const inviteV = pickVariant(INVITE_VARIANTS, header);
    const recoveryV = pickVariant(RECOVERY_VARIANTS, header);
    const merged = merge variant opts/authOpts onto base AuthWorkflowOpts;
    super(merged, users, authCred, consentStore);
  }
}
```

The class carries the old demo login/invite/recovery customizations as resolver overrides:

- Login policy: `resolveAlternateCredentials`, `resolveDeviceTrust`, `resolveEnrollment`, `resolveFinalize`, `resolveGuards`, `resolveSessionPolicy`.
- Shared MFA policy: `resolveMfaPolicy`, plus the demo’s `@Step("prepare-mfa")` override that applies `mfaCtx`.
- Invite policy: `resolveAdminForm`, `resolveAccept`, `prepareUser`, `getAvailableRoles`, `duplicateInviteCheck`.
- Recovery policy: `resolvePostReset`, `resolveRecoveryAltActions`, `emailToUserId`.
- Cross-flow delivery: `deliver(payload: AuthDeliveryPayload)`.

### 2.2 Variant Shape

Variant entries are not old per-workflow option objects. They use the unified shape:

```ts
type Variant = {
  opts?: Partial<AuthWorkflowOpts>;
  authOpts?: Partial<Pick<AuthWorkflowOpts, "mfa">>;
  policy?: Record<string, /* AuthWfCtx policy slot */ unknown>;
  mfaCtx?: {
    mfaMode?: "required" | "optional" | "disabled";
    availableMfaTransports?: MfaTransport[];
    currentMfa?: MfaTransport;
    enrollMethod?: MfaTransport;
  };
};
```

`policy` feeds `resolveXxx(ctx)` overrides. `mfaCtx` feeds the unified `prepare-mfa` step. `authOpts` exists only for cross-flow infrastructure overlays such as pincode resend timeout and workflow-state TTL.

### 2.3 Variant Presets Covered

Login variants:

| Variant                           | Purpose                                                    |
| --------------------------------- | ---------------------------------------------------------- |
| `minimal`                         | Password-only login, forgot-password enabled, MFA disabled |
| `mfa-totp`                        | Single TOTP challenge                                      |
| `mfa-full`                        | SMS/email/TOTP challenge coverage                          |
| `mfa-fast-resend`                 | MFA pincode resend cooldown coverage                       |
| `enrollment`                      | Email/phone channel enrolment plus MFA enrolment policy    |
| `device-trust`                    | Opt-in trusted-device cookie                               |
| `device-trust-no-optin`           | Device-trust enabled without checkbox                      |
| `device-trust-short-ttl`          | Trusted cookie expiry                                      |
| `guards`                          | Initial-password and email-required guards                 |
| `password-expired`                | Password rotation via `passwordExpiry`                     |
| `acceptance`                      | Mandatory consent defense path                             |
| `consent-array`                   | Inline required + optional consent                         |
| `terms-bump`                      | Standalone terms re-prompt                                 |
| `concurrency`                     | Kick-prompt session policy                                 |
| `concurrency-reject`              | Reject session policy                                      |
| `redirect-home`                   | Finalize redirect                                          |
| `full`                            | Every major login phase in one walkthrough                 |
| `mfa-enroll-required-totp`        | Required MFA enrolment with single TOTP transport          |
| `mfa-enroll-optional-full`        | Optional enrolment skip and method-switch coverage         |
| `mfa-enroll-optional-fast-resend` | Enrol-confirm resend cooldown coverage                     |

Recovery variants:

| Variant                | Purpose                                                                      |
| ---------------------- | ---------------------------------------------------------------------------- |
| default/no variant     | OTP-via-email recovery; fresh-login post-reset behaviour (redirect to login) |
| `recovery-auto-login`  | `autoLoginOnRecover=true`; reset finishes with tokens                        |
| `recovery-short-ttl`   | `recoveryStateTtlMs=1` — every recovery pause expires the persisted state    |
| `recovery-fast-resend` | Recovery pincode resend cooldown                                             |
| `recovery-terms-bump`  | Inline consent on recovery `SetPasswordForm`                                 |

Invite variants:

| Variant                    | Purpose                                    |
| -------------------------- | ------------------------------------------ |
| `email-no-roles`           | Admin invite form with no role picker      |
| `roles-profile`            | Role picker coverage                       |
| `confirmation-message`     | Confirmation finish copy                   |
| `idempotent-redirect`      | Already-accepted invite handling           |
| `invite-mfa-optional-full` | Invite accept-tail MFA enrolment           |
| `invite-terms`             | Inline consent on invite `SetPasswordForm` |

### 2.4 Test Infrastructure

- `POST /__test/reset` reseeds the DB and clears mailbox, consent, OTP-consent, active-session, and audit buffers.
- `GET /__test/emails` and `GET /__test/sms` expose captured delivery events.
- `GET /__test/consent-log/:username` exposes `ConsentStore.save` output.
- `GET /__test/otp-consent-log/:username` exposes OTP channel disclosure records.
- `POST /__test/allow-duplicate-invites` flips the duplicate-invite test flag for the store-level duplicate branch.

The SPA reads `?variant=<name>` on `/wf` and forwards it as `x-wf-variant` on every trigger/resume request. Invite links preserve `&variant=<name>` so the anonymous accept leg sees the same variant.

---

## 3. Unified AuthWorkflow Stories

These stories prove the e2e demo is testing the new class shape, not the retired split workflow surface.

| ID                  | Tier | Story                                                                                     | Assertions                                                                                                                                |
| ------------------- | ---- | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| WF-AUTH-UNIFIED-001 | P0   | `DemoAuthWorkflow` is the single replacement class for login, invite, recovery            | `app.registerControllers(DemoAuthController, DemoAuthWorkflow)` registers one class for all three flows; no per-flow workflow-class knobs |
| WF-AUTH-UNIFIED-002 | P0   | Constructor merges variant `opts` and `authOpts` before `super(...)`                      | `mfa-fast-resend`, `recovery-fast-resend` affect their flows without separate workflow option providers                                   |
| WF-AUTH-UNIFIED-003 | P0   | Resolver dispatch uses ctx/flow state, not class type                                     | Login policy overrides do not leak into invite/recovery; invite `adminForm` and recovery `postReset` resolve from the same class          |
| WF-AUTH-UNIFIED-004 | P0   | `deliver(payload)` handles every auth delivery kind                                       | Mailbox receives `mfa-pincode`, `enroll-pincode`, `recovery-pincode`, and `invite-link` as mapped email/SMS events                        |
| WF-AUTH-UNIFIED-005 | P1   | Shared pincode pair works for login MFA and recovery OTP                                  | Both flows enforce `ctx.pincode.resendAllowedAt`, set `ctx.otp.verified`, and clear `ctx.pin/pinExpire` after success                     |
| WF-AUTH-UNIFIED-006 | P1   | Shared password form handles login initial, login expired, invite initial, recovery reset | `ctx.password.changeReason` is `"initial"`, `"expired"`, or `"reset"` and copy/policies render through `SetPasswordForm`                  |
| WF-AUTH-UNIFIED-007 | P1   | Invite and login share the MFA enrolment loop                                             | Login and invite optional enrolment support skip, method switching, cleanup, and `ctx.otp.verified` loop exit                             |

---

## 4. Login Flow Stories

### Login Process

Default process:

1. `init-login`.
2. `credentials`.
3. Prepare login policies.
4. `prepare-semantic-flags` computes `isFirstLogin`, `newPasswordRequired`, and `password.changeReason`.
5. Optional email/phone channel enrolment.
6. Shared MFA loop: trusted-device check, existing-method challenge, or enrolment.
7. Device-trust issuance, with server guard preventing trust when `newPasswordRequired`.
8. Shared password phase if required.
9. Profile/extra-step/terms bump.
10. Consent persistence.
11. Session policy.
12. Issue tokens, optional new-device notification, redirect.

### Login Matrix

| ID                         | Tier | Variant                           | Story                                                                | Assertions                                                                                                                                                                                        |
| -------------------------- | ---- | --------------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WF-LOGIN-001               | P0   | `minimal`                         | Valid password issues tokens                                         | `LoginCredentialsForm` visible; forgot-password visible; finish data has `accessToken`                                                                                                            |
| WF-LOGIN-002               | P0   | `minimal`                         | Wrong password re-renders credentials form                           | User-readable invalid-credentials error; no tokens                                                                                                                                                |
| WF-LOGIN-003               | P0   | `minimal`                         | Forgot-password action redirects to recovery URL with typed username | Finish/redirect target includes `/recover?username=<typed>`                                                                                                                                       |
| WF-LOGIN-004               | P1   | `minimal`                         | Locked account returns friendly lockout error                        | 423/locked message surfaced                                                                                                                                                                       |
| WF-LOGIN-005               | P2   | `minimal`                         | Repeated bad passwords trigger durable lockout                       | Threshold attempt locks user; following login is blocked                                                                                                                                          |
| WF-LOGIN-006               | P0   | `full`                            | Signup action is visible when enabled                                | Button/action routes to `/signup`                                                                                                                                                                 |
| WF-LOGIN-007               | P0   | `mfa-full`                        | Multi-MFA user reaches default TOTP then can choose SMS              | `MfaCodeForm`, `useDifferentMethod`, `Select2faForm`, `PincodeForm` sequence                                                                                                                      |
| WF-LOGIN-008               | P0   | `mfa-totp`                        | Single TOTP user enters authenticator code                           | `MfaCodeForm`; no method picker; tokens issued                                                                                                                                                    |
| WF-LOGIN-009               | P1   | `mfa-full`                        | `useDifferentMethod` loops from pincode challenge to picker          | Form sequence returns to `Select2faForm`                                                                                                                                                          |
| WF-LOGIN-011               | P1   | `mfa-fast-resend`                 | Resend inside cooldown is blocked server-side                        | “Please wait” error; no second email                                                                                                                                                              |
| WF-LOGIN-012               | P1   | `mfa-fast-resend`                 | Resend after cooldown emits a new code                               | Two mailbox entries; codes differ                                                                                                                                                                 |
| WF-LOGIN-013               | P2   | `mfa-totp`                        | Wrong MFA code re-renders current form                               | `errors.code = "Invalid code"`                                                                                                                                                                    |
| WF-LOGIN-015               | P0   | `enrollment`                      | Missing confirmed email pauses on `AskEmailForm`                     | Email field/autocomplete visible; pincode verification follows                                                                                                                                    |
| WF-LOGIN-016               | P1   | `enrollment`                      | Already confirmed email skips `AskEmailForm`                         | Proceeds without email pause                                                                                                                                                                      |
| WF-LOGIN-017               | P1   | `enrollment`                      | Phone enrolment runs `AskPhoneForm` then pincode                     | SMS mailbox captures code; OTP disclosure logged                                                                                                                                                  |
| WF-LOGIN-018               | P0   | `device-trust`                    | Remembered device skips MFA on second login                          | First pass sets cookie; second pass reaches tokens without MFA                                                                                                                                    |
| WF-LOGIN-019               | P1   | `device-trust-no-optin`           | `rememberDevice` checkbox hidden when opt-in is disabled             | Checkbox absent                                                                                                                                                                                   |
| WF-LOGIN-020               | P2   | `device-trust-short-ttl`          | Expired trusted-device cookie does not skip MFA                      | Second login requires MFA                                                                                                                                                                         |
| WF-LOGIN-021               | P0   | `guards`                          | Initial password forces `SetPasswordForm`                            | `AsPasswordRules`; mismatch error; tokens after valid password                                                                                                                                    |
| WF-LOGIN-EXPIRED-01        | P0   | `password-expired`                | Expired password forces reset copy                                   | `password.changeReason="expired"`; tokens after valid password                                                                                                                                    |
| WF-LOGIN-024               | P1   | `terms-bump`                      | Missing required terms blocks submit                                 | `errors.consents` matches descriptor required text                                                                                                                                                |
| WF-LOGIN-025               | P1   | `consent-array`                   | Required + optional consent rows persist accepted/declined decisions | Two consent events; optional unchecked persists `accepted:false`                                                                                                                                  |
| WF-LOGIN-028               | P1   | `concurrency`                     | Session limit pauses on kick prompt                                  | Kick form visible                                                                                                                                                                                 |
| WF-LOGIN-029               | P1   | `concurrency`                     | Cancel from kick prompt aborts                                       | No tokens issued                                                                                                                                                                                  |
| WF-LOGIN-030               | P2   | `concurrency-reject`              | Reject policy blocks immediately                                     | User-readable session limit error; no kick form                                                                                                                                                   |
| WF-LOGIN-031               | P1   | `redirect-home`                   | Finalize redirect targets `/`                                        | Finish envelope next action is redirect `/`                                                                                                                                                       |
| WF-LOGIN-032               | P2   | `full`                            | One user traverses every major login phase (no profile-complete)     | Expected ordered form sequence; consent persisted; tokens/redirect at finish                                                                                                                      |
| WF-LOGIN-033               | P1   | `mfa-enroll-required-totp`        | Required single-transport TOTP enrolment auto-picks confirm          | No picker; TOTP secret/URI visible; tokens after code                                                                                                                                             |
| WF-LOGIN-034               | P1   | `mfa-enroll-optional-full`        | Optional enrolment skip finishes without MFA method                  | Skip action visible; user MFA methods unchanged                                                                                                                                                   |
| WF-LOGIN-035               | P1   | `mfa-enroll-optional-full`        | Use different method cleans unconfirmed method and returns to picker | Unconfirmed row removed; picker re-renders                                                                                                                                                        |
| WF-LOGIN-036               | P1   | `mfa-enroll-optional-fast-resend` | Enrol-confirm resend cooldown gates and then remints                 | `ctx.pincode.resendAllowedAt` behavior; codes differ after cooldown                                                                                                                               |
| WF-LOGIN-038               | P1   | `notify-new-device`               | New-device email fires once per unrecognized browser (trust off)     | Each fresh context emails exactly once; repeat login in same context suppressed; recognition cookie set sans remember-me                                                                          |
| WF-LOGIN-039               | P1   | `device-trust-short-ttl-notify`   | Expired trust cookie re-requires MFA but does not re-email           | 1st login emails once; 2nd login pauses on MFA again yet `notifyNewDevice` count stays 1                                                                                                          |
| WF-LOGIN-040               | P1   | `notify-new-device`               | Invited user with no MFA gets the new-device notice (verified email) | Invite accept writes `account.verifiedEmail`; notice arrives at the invited address exactly once; repeat login suppressed                                                                         |
| WF-LOGIN-041               | P2   | `geo-risk`                        | Impossible travel (Paris → Tokyo) fires exactly one security alert   | Per-session geo persisted via `resolveIssueMetadata`; one `securityAlert` to henry with reason/distance/cities; valid trust cookie still skips MFA (re-arm can't out-rank `check-trusted-device`) |
| WF-LOGIN-BUMP-01           | P1   | `terms-bump`                      | Standalone terms bump renders `TermsBumpForm`                        | Consent event `{id:"terms", version:"v3", accepted:true}`                                                                                                                                         |
| WF-LOGIN-HACK-CONSENT-01   | P1   | `acceptance`                      | Hand-rolled submit without required consent is rejected              | Required descriptor enforced server-side                                                                                                                                                          |
| WF-CONSENT-ARRAY-01        | P0   | `consent-array`                   | Initial-password carrier form renders two consents                   | `AsConsentArray` rows; consent log records both rows                                                                                                                                              |
| WF-LOGIN-OTP-DISCLOSURE-01 | P1   | `enrollment`                      | Phone enrolment records OTP disclosure after verification            | `/__test/otp-consent-log/t1_alice` contains SMS disclosure                                                                                                                                        |
| WF-PASSWORD-RULES-LIVE-01  | P0   | `guards`                          | Password rules update live while typing                              | `.as-password-rules-row[data-passed]` toggles as expected                                                                                                                                         |

---

## 5. Recovery Flow Stories

### Recovery Process

Reduced recovery process:

1. `init-recovery`.
2. `request` asks for email and resolves username without enumeration.
3. Prepare post-reset policy, recovery alt-actions, consents, and semantic password copy (`changeReason="reset"`).
4. OTP-via-email loop uses the shared `pincode-send` / `pincode-check` pair.
5. `SetPasswordForm` runs after `ctx.otp.verified`.
6. Optional session revocation.
7. Consent persistence.
8. `finalize-fresh-login` by default, or `finalize-auto-login` when `autoLoginOnRecover=true`.

### Recovery Matrix

| ID                     | Tier | Variant                    | Story                                                                                                           | Assertions                                                                                            |
| ---------------------- | ---- | -------------------------- | --------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| WF-RECOVERY-001        | P0   | default                    | Known email receives recovery pincode, enters OTP, resets password, fresh-login finish redirects without tokens | Email kind `recovery.pincode`; `SetPasswordForm` copy says reset; no `accessToken`; redirect to login |
| WF-RECOVERY-002        | P0   | default                    | Unknown email finishes generically                                                                              | No enumeration; no token; no mailbox event for ghost address                                          |
| WF-RECOVERY-003        | P1   | default                    | Password mismatch re-renders `SetPasswordForm`                                                                  | Inline `confirmPassword` error                                                                        |
| WF-RECOVERY-004        | P1   | `recovery-short-ttl`       | Expired recovery state cannot resume                                                                            | Error block visible; no `SetPasswordForm`                                                             |
| WF-RECOVERY-005        | P0   | default                    | Email OTP happy path                                                                                            | `PincodeForm` hint visible; `ctx.otp.verified` permits password form                                  |
| WF-RECOVERY-009        | P1   | default                    | Wrong OTP re-renders pincode form                                                                               | `errors.code = "Invalid code"`                                                                        |
| WF-RECOVERY-010        | P1   | `recovery-fast-resend`     | Resend inside cooldown is blocked                                                                               | No new email; “Please wait” error                                                                     |
| WF-RECOVERY-011        | P1   | `recovery-fast-resend`     | Resend after cooldown sends new code                                                                            | Two email codes, different values                                                                     |
| WF-RECOVERY-016        | P0   | `recovery-auto-login`      | Auto-login variant finishes with tokens after reset                                                             | `autoLoginOnRecover=true`; `accessToken` present                                                      |
| WF-RECOVERY-017        | P1   | default                    | `backToLogin` exits before email validation                                                                     | Finish reason `user-cancelled`; no token                                                              |
| WF-RECOVERY-018        | P2   | default or policy override | `revokeAllSessions=true` rejects old token after reset                                                          | Old session returns 401                                                                               |
| WF-RECOVERY-CONSENT-01 | P0   | `recovery-terms-bump`      | Recovery password form carries required terms consent                                                           | Consent log has `{id:"terms", version:"v2", accepted:true}`                                           |

Removed legacy recovery rows:

- Magic-link delivery.
- SMS OTP and transport switching.
- `RecoveryModeSelectForm`.
- `RecoveryFactorForm`.
- Workflow audit assertions.

---

## 6. Invite Flow Stories

### Invite Process

Default invite process:

1. Admin phase runs protected steps: init, admin form, optional roles, infer roles, prepare user extras, create user, send invite link.
2. Accept phase resumes publicly from the invite link.
3. Pending invitation is checked; already-accepted links route through idempotent finish.
4. Shared password phase sets invitee initial password.
5. Shared MFA loop can enrol a factor when variant enables it.
6. Optional profile and extra step.
7. Consent persistence.
8. Pending invitation is cleared, user is activated, optional confirmation rendered.
9. Finalize uses `autoLoginOnInvite`.

### Invite Matrix

| ID                   | Tier | Variant                    | Story                                                                       | Assertions                                                  |
| -------------------- | ---- | -------------------------- | --------------------------------------------------------------------------- | ----------------------------------------------------------- |
| WF-INVITE-001        | P0   | `email-no-roles`           | Admin invites new email, invitee redeems, tokens issued                     | No roles field; invite email/link captured; activated user  |
| WF-INVITE-002        | P1   | `email-no-roles`           | Admin invites existing (accepted) user                                      | Inline duplicate error                                      |
| WF-INVITE-005        | P0   | `roles-profile`            | Role picker accepts whitelisted role                                        | Role field visible; selected role persisted                 |
| WF-INVITE-006        | P1   | `roles-profile`            | Invalid role is rejected                                                    | Inline role error                                           |
| WF-INVITE-010        | P2   | `idempotent-redirect`      | Already-accepted link shows idempotent finish                               | Sign-in / request-new-invite actions visible                |
| WF-INVITE-018        | P2   | `email-no-roles`           | Duplicate override reaches store-level uniqueness failure                   | Store-level 409 surfaces                                    |
| WF-INVITE-020        | P2   | `confirmation-message`     | Confirmation message renders after activation                               | “Your account has been created.” visible                    |
| WF-INVITE-021        | P1   | `invite-mfa-optional-full` | Invite-tail optional MFA enrolment skip activates user                      | No MFA method persisted; account activated                  |
| WF-INVITE-022        | P1   | `invite-mfa-optional-full` | Invite-tail method switch cleans unconfirmed method and completes enrolment | TOTP cleanup; SMS enrolment succeeds                        |
| WF-INVITE-023        | P1   | `email-no-roles`           | Re-invite of a pending invitee issues a fresh link (`'reuse'` verdict)      | Second `{sent}`; second link differs from first and redeems |
| WF-INVITE-CONSENT-01 | P0   | `invite-terms`             | Invite password form carries required terms consent                         | Consent log has `{id:"terms", version:"v1", accepted:true}` |

Removed legacy invite rows:

- Shareable-link send mode.
- Send-mode choice form.
- Invite workflow audit variants.
- Workflow-level cancellation policy variant.
- `accept.freshLoginRequired`; use static `AuthWorkflowOpts.autoLoginOnInvite` instead.
- Accept-tail profile-collect form (WF-INVITE-007, -008). The unified workflow has no built-in profile step; consumers add their own override step if profile collection is needed.
- `@Workflow("auth/invite/cancel")` + `@Workflow("auth/invite/resend")` (WF-INVITE-015, -016, -017). Dropped in `6ff3efb` — invite is single-path email-only now.
- `magicLinkTtlMs` opt + `short-ttl-confirmation` variant (WF-INVITE-004, -019). Magic-link TTL is now owned by `@StepTTL(...)` on the workflow's `send-email` @Step; customers override the step and re-decorate. Tests dropped because they were verifying engine TTL behavior, already covered upstream in `@prostojs/wf`.
- `autoLoginOnInvite=false` finish-without-tokens (WF-INVITE-012). The opt still exists on `AuthWorkflowOpts`; no Playwright coverage planned (vitest covers the opts-merge contract).
- Invitee-abandons-password-form (WF-INVITE-003) and the legacy re-invite sub-workflows (WF-INVITE-013, -014). No dedicated resend workflow exists; re-inviting a pending user is now a first-class path THROUGH `auth/invite/start` itself — the default `duplicateInviteCheck` returns `'reuse'` for pending rows, covered by WF-INVITE-023. WF-INVITE-002 covers the reject branch for accepted users.

---

## 7. Render Assertion Catalog

| Class                         | Examples                                                    | Detection                                 |
| ----------------------------- | ----------------------------------------------------------- | ----------------------------------------- |
| Conditional action visibility | Forgot-password, signup, use-different-method, resend, skip | Role/button locators                      |
| Form sequence                 | Credentials → MFA → password → consent → finish             | Visible form fields and headings per step |
| Dynamic copy                  | MFA hint, reset password copy, expired password copy        | Text assertions                           |
| Default values                | `rememberDevice` unchecked/hidden, consent rows unchecked   | Checkbox state                            |
| Field absence                 | No roles field, no `rememberDevice`, no method picker       | `toHaveCount(0)`                          |
| Inline validation             | Invalid password/code/role/consent                          | Field-level errors                        |
| Finish envelope               | Tokens, redirect, abort/fresh-login                         | Parsed finish JSON                        |
| Mailbox content               | Invite link, MFA pincode, recovery pincode, enrol pincode   | `GET /__test/emails`, `GET /__test/sms`   |
| Consent log                   | Required and optional decisions                             | `GET /__test/consent-log/:username`       |
| OTP disclosure log            | Phone/email channel disclosure records                      | `GET /__test/otp-consent-log/:username`   |
| Password rules                | Live `data-passed` values                                   | `.as-password-rules-row[data-passed]`     |

---

## 8. Manual Walkthroughs

### 8.1 Unified Variant Routing

1. Start the demo: `cd packages/e2e-demo && DEMO_MODE=test SEED=true pnpm dev`.
2. Open `http://localhost:3001/wf?id=auth/login/flow&variant=mfa-fast-resend`.
3. Complete login until `PincodeForm`.
4. Click **Resend code** immediately.
5. Confirm the cooldown comes from the unified `AuthWorkflowOpts.mfa.pincodeResendTimeoutMs` overlay, not a login-only option object.

### 8.2 Consent Capture

1. Open `http://localhost:3001/wf?id=auth/login/flow&variant=consent-array`.
2. Sign in as `t1_alice` / `Password1!`.
3. Complete the password step until `AsConsentArray` is visible.
4. Submit without required terms and observe the descriptor error.
5. Tick terms, leave marketing unchecked, submit.
6. Inspect `curl http://localhost:3001/__test/consent-log/t1_alice`.

### 8.3 Recovery OTP

1. Open `http://localhost:3001/wf?id=auth/recovery/flow`.
2. Enter `alice@acme.test`.
3. Read the `recovery.pincode` email from the dev console or `/__test/emails`.
4. Submit the code.
5. Set a new password.
6. Confirm the default finish redirects to login without tokens. Repeat with `variant=recovery-auto-login` to verify token issuance.

### 8.4 Invite Accept With Variant Preservation

1. Sign in as admin on `auth/login/flow&variant=minimal`.
2. Open `http://localhost:3001/wf?id=auth/invite/start&variant=invite-terms`.
3. Invite `new-user@example.com`.
4. Open the invite URL from the mailbox. It carries `&variant=invite-terms`.
5. Set password and accept required terms.
6. Inspect the invitee consent log.

### 8.5 Password Rules

1. Open `http://localhost:3001/wf?id=auth/login/flow&variant=guards`.
2. Sign in as `t1_jack` / `Password1!`.
3. Complete required email verification.
4. On `SetPasswordForm`, type `short`, then `longenough1A!`.
5. Confirm `AsPasswordRules` rows update their `data-passed` values live.

### 8.6 OTP Disclosure

1. Open `http://localhost:3001/wf?id=auth/login/flow&variant=enrollment`.
2. Sign in as `t1_alice` / `Password1!`.
3. Complete phone enrolment.
4. Inspect `curl http://localhost:3001/__test/otp-consent-log/t1_alice`.
5. Confirm the record uses channel `sms` and includes the disclosure copy.

---

## 9. Maintenance Notes

- When adding a variant, update `src/variants.ts`, this document, and the home-page variant dropdown automatically sourced from the variant maps.
- When adding a new `AuthWorkflow` resolver override, add a unified-class story if the override dispatches differently per flow.
- Recovery stories must stay within the reduced OTP-email scope until recovery magic-link/SMS/choice/pre-factor support is intentionally reintroduced.
- Invite stories must avoid legacy send-mode/fresh-login/audit knobs; use `AuthWorkflowOpts` and `resolveAccept` fields that still exist.
- Any ctx rename that crosses a form boundary requires updating `.as` annotations and regenerating atscript output.
