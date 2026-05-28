# AuthWorkflow Unification — Design Doc

**Status**: Locked (2026-05-28). Implementation to follow in 5 phases (see §12).
**Pre-release**: All `@aooth/*` packages on `0.0.1-alpha.*`. No backwards-compat shims; consumers update with us.

---

## 1. Goals

Collapse `LoginWorkflow + InviteWorkflow + RecoveryWorkflow + AuthWorkflowBase` (4 classes, ~5000 LOC) into ONE class `AuthWorkflow` with three `@Workflow` methods.

- **No abstract base class** — single concrete class.
- **Steps shared by reference** — one `@Step` method body, referenced from multiple `@Workflow` schemas.
- **Schema fragments shared as plain consts** — only where the SAME ordered sequence appears in 2+ schemas (login + invite).
- **Customer override surface** stays `protected resolveXxx(ctx)` getters on the unified class.
- **Semantic flags drive behavior**, never `ctx.flow === 'invite'` branching. Each `@Workflow` schema's `init-*` step OR `prepare-semantic-flags` step writes the flags onto ctx (timing depends on what data is needed — invite-accept can set them in init since the values are static; login defers to `prepare-semantic-flags` because it needs the user record loaded first); downstream conditions and resolvers read them.

Aligned with project goals #1 (LOC reduction), #2 (extract shared ctx shape), #3 (per-WF extensions), #4 (re-usable pluggable schema), #5 (deduplication — but achieved WITHOUT a base class, since the orchestrator inheritance was itself the over-engineering being eliminated).

---

## 2. Key decisions (locked)

| Decision                                                | Value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Rationale                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- | ---------------------------------------------- |
| `isFirstLogin` derivation                               | `!user.lastLoginAt`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Admin-reset-then-changed-by-user is NOT a first login; only the absence of any prior login is.                                                                                                                                                                                                                                                                                                                                                                                     |
| Invite auto-login                                       | `AuthWorkflowOpts.autoLoginOnInvite: boolean` (default `true`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Static infra, not ctx-dependent.                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Recovery auto-login                                     | `AuthWorkflowOpts.autoLoginOnRecover: boolean` (default `false`)                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Same.                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Flow discrimination in step bodies                      | Semantic ctx flags (`isFirstLogin`, `newPasswordRequired`, etc.)                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Flow-name branching is indirect; the actual decision is the derived fact.                                                                                                                                                                                                                                                                                                                                                                                                          |
| Customer resolver discrimination                        | ctx-slot presence (`ctx.admin?` for invite admin, `ctx.postReset?` for recovery, etc.)                                                                                                                                                                                                                                                                                                                                                                                                                                         | Same reason — let the customer key on what they actually care about.                                                                                                                                                                                                                                                                                                                                                                                                               |
| `@Public()` placement                                   | Per-step (and per-`@Workflow` body)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Class can't be both public (login/recovery) and not-public (invite admin phase).                                                                                                                                                                                                                                                                                                                                                                                                   |
| File layout                                             | `packages/auth-moost/src/workflow/` (singular: one workflow with 3 schemas)                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Replaces `workflows/` plural; signals the architectural shift.                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Shared schema fragments                                 | `mfaLoopSchema`, `passwordPhaseSchema`, `consentsPersistTailSchema`, `pincodeSendCheckPair`                                                                                                                                                                                                                                                                                                                                                                                                                                    | Recovery has its own short schema but reuses `pincodeSendCheckPair` (same 2-step pair as login's MFA SMS/email sub-branch); login+invite share the larger fragments.                                                                                                                                                                                                                                                                                                               |
| `completion.passwordSet` + `completion.passwordChanged` | **Collapse to ONE flag** `completion.passwordCompleted`                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Same semantic event ("user just set/changed their password"); the two-flag split was accidental.                                                                                                                                                                                                                                                                                                                                                                                   |
| `prepare-mfa-setup` (login) hardcoded defaults          | Move to `resolveMfaPolicy(ctx)` resolver                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Today e2e-demo overrides the @Step body; cleaner via resolver.                                                                                                                                                                                                                                                                                                                                                                                                                     |
| **Recovery scope (this pass)**                          | **OTP via email only**. No magic-link delivery, no SMS, no pre-reset factor check, no mode picker.                                                                                                                                                                                                                                                                                                                                                                                                                             | Simplest path per "rip off the flexibility for now"; magic-link / SMS / factor-check can be re-added in a future pass when justified.                                                                                                                                                                                                                                                                                                                                              |
| **Verification flag is unified**                        | One `ctx.otp.verified` flag across login MFA + invite MFA + recovery (replaces `mfa.checked`).                                                                                                                                                                                                                                                                                                                                                                                                                                 | "MFA" names the capability; OTP names the mechanism actually used everywhere. Same flag, same step bodies (`pincode-send` / `pincode-check` / `totp-check`), step body picks the form via ctx-slot presence (`ctx.mfa?.method` set → MFA form, else → recovery form).                                                                                                                                                                                                              |
| **Audit is out of scope**                               | All audit policy, steps, resolvers, and ctx state are REMOVED.                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Audit handled at a separate level via interceptors (cross-cutting concern; not the workflow's job). No `resolveAudit`, no `prepare-audit`, no `audit-login` / `audit-recovery` steps, no `ctx.audit` group, no `finalize.auditLogin` field.                                                                                                                                                                                                                                        |
| **Rate limiting / attempt limits split**                | (a) Account-level lockout (failed-password counter, lock-after-N) stays in **UserService** — step bodies call lockout-aware ops (`users.verifyPassword`, `users.verifyPincode`). (b) Per-request rate limiting (recovery-request frequency, MFA-attempt frequency per IP/email) lives in the **wf-trigger / HTTP interceptor layer** — NOT in step bodies. (c) Pincode resend cooldown is the **only** rate-limit-style check inside a step body, and it's a one-line `resendAllowedAt > Date.now()` guard in `pincode-check`. | Two distinct concerns: lockout is durable account state (must survive across requests, owned by the user store); rate limiting is ephemeral per-window throughput protection (cross-cutting, owned by the HTTP layer — same pattern as audit). The pincode resend cooldown is an exception because it's process-internal state already on `ctx.pincode.resendAllowedAt`.                                                                                                           |
| **Notify-new-device scope**                             | Fires on login.flow only. NEVER fires on first login or invite (`!ctx.isFirstLogin` is part of the gate). Recovery deferred — see §13.                                                                                                                                                                                                                                                                                                                                                                                         | First-login devices aren't "new" in the meaningful sense; invite users are always first-login. Recovery+autologin notification deferred because it requires extending `ctx.trust` + device-trust check infrastructure to recovery's schema; out of scope for this pass.                                                                                                                                                                                                            |
| **Device-trust gating on password change**              | MFA forms (pincode + TOTP + select-2fa) HIDE the `rememberDevice` checkbox when `ctx.newPasswordRequired` is set. Schema order stays MFA → device-trust → password-phase.                                                                                                                                                                                                                                                                                                                                                      | Issuing a trusted-device token before the user has set their own password (initial admin-set password OR expired password) would let a temporary credential establish persistent device trust. Hiding the form field at the MFA step is better UX than moving device-trust to a standalone form AFTER password change. Because the form never collects `rememberDevice=true`, `ctx.trust.rememberDevice` stays falsy, and the `device-trust` step's condition `(!deviceTrust.optIn |     | trust.rememberDevice)` short-circuits to skip. |
| **Pincode UI state vs verification flag**               | `ctx.pincode` stays the UI hint group (`sentTo`, `codeLength`, `resendAllowedAt`) — form-facing via `@wf.context.pass 'pincode'`. `ctx.otp.verified` is the server-side verification flag (NOT form-facing).                                                                                                                                                                                                                                                                                                                   | One carrier per concern: form sees UI hints, server sees verification result. Avoids the @wf.context.pass annotation churn that moving UI state into `ctx.otp` would require.                                                                                                                                                                                                                                                                                                      |

---

## 3. File layout

```
packages/auth-moost/src/workflow/
  auth-workflow.ctx.ts       # AuthWfCtx interface + all sub-shapes
  auth-workflow.opts.ts      # AuthWorkflowOpts + ResolvedAuthWorkflowOpts
  auth-workflow.schemas.ts   # 4 shared schema-fragment consts
  auth-workflow.ts           # The class: 3 @Workflow + 66 @Step + 17 resolveXxx
```

Old `packages/auth-moost/src/workflows/` (plural) deleted in P5.

---

## 4. Unified `AuthWfCtx`

```typescript
export interface AuthWfCtx {
  // ── Identity ──
  username?: string;
  email?: string;

  // ── Server-only secrets (never @wf.context.pass) ──
  pin?: string;
  pinExpire?: number;
  aborted?: boolean;

  // ── Semantic flags (set by init step or post-credentials step) ──
  flow?: "login" | "invite" | "recovery"; // Audit/UI hint ONLY — never used for control flow
  isFirstLogin?: boolean; // login: !user.lastLoginAt | invite: true | recovery: n/a
  newPasswordRequired?: boolean; // login: guards.passwordInitial||passwordExpiry | invite: true | recovery: derived at set-password gate

  // ── Shared state groups (passed via @wf.context.pass) ──
  consents?: AuthWfConsentsState;
  pincode?: AuthWfPincodeUiState;
  mfaEnroll?: AuthWfMfaEnrollState;
  password?: AuthWfPasswordUiState;
  completion?: AuthWfCompletionState;

  // ── Resolved policy groups (set by prepare-* @Steps) ──
  profileCompleteRequired?: boolean; // [login]
  alternateCredentials?: AuthWfAltCredsPolicy; // [login]
  deviceTrust?: AuthWfDeviceTrustPolicy; // [login]
  enrollment?: AuthWfEnrollmentPolicy; // [login]
  finalize?: AuthWfFinalizePolicy; // [login]
  guards?: AuthWfGuardsPolicy; // [login]
  sessionPolicy?: AuthWfSessionPolicy; // [login]
  mfaPolicy?: AuthWfMfaPolicy; // [login + invite] {mode, availableTransports, issuer}
  adminForm?: AuthWfAdminFormPolicy; // [invite admin]
  accept?: AuthWfAcceptState; // [invite accept]
  postReset?: AuthWfPostResetState; // [recovery]
  recoveryAltActions?: AuthWfRecoveryAltActions; // [recovery]
  // Note: `ctx.audit` REMOVED — audit handled at interceptor level, not in workflow ctx.

  // ── Per-event state groups ──
  mfa?: AuthWfMfaState; // [login + invite] verification + challenge
  channel?: AuthWfChannelState; // [login] email/phone forced enrolment
  trust?: AuthWfTrustState; // [login] device-trust
  session?: AuthWfSessionState; // [login] session-policy
  altActions?: AuthWfAltActionsState; // [login] alt-cred mirror flags
  admin?: AuthWfAdminState; // [invite admin]
  otp?: AuthWfOtpState; // [all flows] verification result flag (one field: `verified`)

  // ── Low-cardinality top-level flags ──
  isPasswordInitial?: boolean; // [login] from guards
  isPasswordExpired?: boolean; // [login] from guards
  profileMissingFields?: string[]; // [login] consumer-marked
}
```

### Sub-shapes

```typescript
// Already exists today; unchanged
export interface AuthWfConsentsState {
  pending?: ConsentDescriptorLike[];
  accepted?: string[];
  decidedAt?: number;
  persisted?: boolean;
}

// UI hints for pincode entry — FORM-FACING via `@wf.context.pass 'pincode'` on PincodeForm.
// All three flows (login MFA SMS/email + recovery OTP + invite MFA enrol-confirm) write here.
export interface AuthWfPincodeUiState {
  sentTo?: string; // Masked target shown in form ("***@example.com" / "+1***1234")
  codeLength?: number; // Pincode digit count (mirrored to form for input width)
  resendAllowedAt?: number; // Resend cooldown (epoch ms) — replaces today's `mfa.pincodeCooldowns` + `otp.resendAllowedAt`. Reset on method/context switch.
}

// Enrolment running state. `pincodeCooldown` removed — cooldown for enrol-confirm's pincode
// entry uses the same `ctx.pincode.resendAllowedAt` slot as challenge-side pincode pair.
// (Enrolment and challenge can't be active simultaneously — the MFA loop alternates between
// the enrol trio and the challenge branch by ctx state, so a single cooldown slot is safe.)
export interface AuthWfMfaEnrollState {
  method?: MfaTransport;
  address?: string;
  secret?: string;
  uri?: string;
  availableTransports?: MfaTransport[];
  mode?: "required" | "optional";
  done?: boolean;
}

// FORM-FACING via `@wf.context.pass 'password'`. Read by SetPasswordForm to stage UI copy.
export interface AuthWfPasswordUiState {
  policies?: TransferablePolicy[]; // Set by `prepare-password-rules`
  changeReason?: "initial" | "expired" | "reset"; // CANONICAL WRITER: `prepare-semantic-flags`. login → "initial"|"expired"; invite → "initial"; recovery → "reset".
  heading?: string; // Set by `create-password-form` body (derived from `changeReason`)
  intro?: string; // Same — derived from `changeReason`
}

// Collapses passwordChanged + passwordSet → passwordCompleted
export interface AuthWfCompletionState {
  passwordCompleted?: boolean; // ← was passwordChanged (login/recovery) + passwordSet (invite)
  tokensIssued?: boolean;
  redirectUrl?: string;
  profileApplied?: boolean;
  pendingInvitationCleared?: boolean; // invite-only — fine to keep flow-specific names here, completion is a write-many bag
  activated?: boolean; // invite-only
  confirmationShown?: boolean; // invite-only
  sessionsRevoked?: boolean; // recovery-only — moved from postReset.sessionsRevoked
}

// New — unified MFA policy (replaces invite's separate `mfa.issuer` resolver shape)
export interface AuthWfMfaPolicy {
  mode: "required" | "optional" | "disabled";
  availableTransports: MfaTransport[];
  issuer: string; // for TOTP provisioning
}

// Login MFA-specific state (verification result migrated to `AuthWfOtpState`; cooldown migrated to `AuthWfPincodeUiState`)
export interface AuthWfMfaState {
  enrolledMethods?: MfaSummary[]; // User's confirmed MFA methods
  current?: MfaTransport; // Pre-selected default (auto-pick)
  method?: "sms" | "email" | "totp"; // Method selected for this verification round (drives form selection in pincode-send/check)
  saveAsDefault?: boolean; // Form checkbox: save as new default
  ignoreDefault?: boolean; // Skip default; user is re-picking
  runsRemaining?: number; // Risk-step-up counter (rerun loop iterations)
  methodCount?: number; // Mirror of enrolledMethods.length (form gate)
}
// Note: `mfa.checked` REMOVED — replaced by `ctx.otp.verified` (server-only, see AuthWfOtpState).
// Note: `mfa.pincodeCooldowns` REMOVED — replaced by `ctx.pincode.resendAllowedAt` (UI hint, single slot, reset on method switch).

// Invite accept policy + state — merged (state added: alreadyAccepted, profileFormPresent, profile)
// Note: `freshLoginRequired` is NOT here — the auto-login-vs-fresh choice is the static
// `AuthWorkflowOpts.autoLoginOnInvite` boolean (per §2 decision).
export interface AuthWfAcceptState {
  alreadyAcceptedRedirectUrl?: string; // policy
  loginUrl?: string; // policy
  showConfirmation?: boolean; // policy
  confirmationMessage?: string; // policy
  profileFormPresent?: boolean; // state (init-invite-accept)
  alreadyAccepted?: boolean; // state (check-pending-invitation)
  profile?: Record<string, unknown>; // state (collect-profile)
}

// Recovery — simplified to OTP-via-email only
// `AuthWfDeliveryState` removed entirely (no more mode/transport/picker config — always OTP-via-email).
// `AuthWfPreResetState` removed entirely (no pre-reset factor check).
// Note: `freshLoginRequired` removed — auto-login-vs-fresh-login choice is the static
// `AuthWorkflowOpts.autoLoginOnRecover` boolean (per §2 decision).
export interface AuthWfPostResetState {
  revokeAllSessions?: boolean;
  loginUrl?: string; // Target for fresh-login redirect (when autoLoginOnRecover=false)
}

// Verification result — SERVER-ONLY (NOT form-facing). One field; set true by ANY of:
// pincode-check, totp-check, enroll-confirm. Loop-exit signal in all flows.
export interface AuthWfOtpState {
  verified?: boolean;
}

// ... (remaining sub-shapes — same as today's LoginXxxState / InviteAdminState)
```

---

## 5. Unified `AuthWorkflowOpts`

```typescript
export interface AuthWorkflowOpts {
  // ── Finalize behavior (cross-flow) ──
  autoLoginOnInvite?: boolean; // default true
  autoLoginOnRecover?: boolean; // default false

  // ── Login-specific infra ──
  deviceTrust?: {
    cookieName?: string;
    ttlMs?: number;
    bindsTo?: "cookie" | "cookie+ip";
  };

  // ── Form schemas ──
  //
  // All forms live on the unified opts dict. Step methods (which access these forms) all live
  // on the unified `AuthWorkflow` class. The "[reached by: …]" annotation indicates which
  // `@Workflow` schemas currently traverse the step body that uses each form — this is a fact
  // about today's schemas, NOT a structural restriction. A future schema (e.g. an invite variant
  // that shares a magic link without a known email, or one that forces phone verification before
  // MFA enrol) can wire up any of these forms by adding the relevant step entries.
  //
  // Grouped by functional role.
  forms?: {
    // ── Authentication entry ──
    loginCredentials?: TAtscriptAnnotatedType; // [reached by: login] Username + password input
    invite?: TAtscriptAnnotatedType; // [reached by: invite admin] Email + roles selection
    recoveryEmailIdentifier?: TAtscriptAnnotatedType; // [reached by: recovery] Email entry to start recovery (renamed from `emailIdentifier`)

    // ── Channel enrolment (forced account-level email/phone verification, independent of MFA) ──
    // Today only login's Phase 3 traverses these. Structurally available to any flow that wires
    // up `prepare-enrollment` + `ask/:channel` steps in its schema.
    askEmail?: TAtscriptAnnotatedType; // [reached by: login Phase 3] Collect email; add unconfirmed channel; send pincode
    askPhone?: TAtscriptAnnotatedType; // [reached by: login Phase 3] Collect phone; same pattern

    // ── MFA enrolment (collect + verify a new MFA method) ──
    enrollPickMethod?: TAtscriptAnnotatedType; // [reached by: login + invite] Pick which MFA transport to enrol
    enrollAddress?: TAtscriptAnnotatedType; // [reached by: login + invite] Collect phone/email for the picked transport
    enrollConfirm?: TAtscriptAnnotatedType; // [reached by: login + invite] Verify pincode/TOTP and confirm the method as MFA

    // ── MFA challenge (verify an already-enrolled MFA method) ──
    // Today only login traverses these (invite users always have 0 enrolled methods, so the
    // challenge branch of the shared MFA loop skips by condition and routes to the enrol branch
    // instead). A future flow with pre-enrolled users would reach them naturally.
    select2fa?: TAtscriptAnnotatedType; // [reached by: login] Method picker when user has >1 enrolled method
    mfaCode?: TAtscriptAnnotatedType; // [reached by: login] TOTP challenge code entry
    pincode?: TAtscriptAnnotatedType; // [reached by: login MFA SMS/email challenge only] Pincode entry form WITH MFA challenge alt-actions (`useDifferentMethod` + `resend`). Picked by `pincode-send`/`pincode-check` step bodies when `ctx.mfa?.method` is set AND user has enrolled methods (challenge path). Invite users (zero enrolled methods) reach `enrollConfirm` instead, never this form.

    // ── Password ──
    setPassword?: TAtscriptAnnotatedType; // [reached by: login + invite + recovery] Set/change/reset password — copy customized via `ctx.password.changeReason`

    // ── Profile + consents ──
    profileComplete?: TAtscriptAnnotatedType; // [reached by: login] Single-step profile form (invite uses a tenant-supplied form via `getProfileForm()` callback)
    termsBump?: TAtscriptAnnotatedType; // [reached by: login] Standalone consent prompt when no carrier form ran in the flow (invite + recovery always have `SetPasswordForm` as carrier)

    // ── Session policy ──
    concurrencyLimit?: TAtscriptAnnotatedType; // [reached by: login] Reject-or-kick prompt when active sessions exceed limit

    recoveryPincode?: TAtscriptAnnotatedType; // [reached by: recovery] Pincode entry form WITH recovery alt-actions (`backToLogin` + `resend`). The unified `pincode-send`/`pincode-check` step bodies pick THIS form when `ctx.mfa?.method` is unset.
    // (Recovery mode picker `recoveryModeSelect` and pre-reset factor form `recoveryFactor` are deferred — no magic-link, no factor check in this pass.)
  };
}
```

Customer registration becomes one `createReplaceRegistry` entry instead of three.

---

## 6. Step inventory (full table)

66 step IDs total (after collapsing `pincode-send-login`/`send-otp` → `pincode-send`, `pincode-check-login`/`check-otp` → `pincode-check`, renaming `mfa-totp` → `totp-check`, and removing 3 audit steps). **All step methods live on the unified `AuthWorkflow` class** — one method per step ID, regardless of which `@Workflow` schemas reference it today. The Login/Invite/Recovery columns indicate which schemas currently traverse each step in the default configuration; a future schema (or a customer-defined override schema) can reference any step it needs.

`@Public()` column: `Y` = step is `@Public()`, `N` = arbac evaluates. `Body` = which file's body is the canonical source for the merge (mostly straightforward porting).

### Init + entry (4 steps)

| Step ID              | Method             | Public | Body source                      | Login | Invite   | Recovery |
| -------------------- | ------------------ | ------ | -------------------------------- | ----- | -------- | -------- |
| `init-login`         | `initLogin`        | Y      | new (sets `flow='login'`)        | ✓     |          |          |
| `init-invite-admin`  | `initInviteAdmin`  | N      | new (sets `flow='invite'`)       |       | ✓ admin  |          |
| `init-invite-accept` | `initInviteAccept` | Y      | merge: invite.init() + new flags |       | ✓ accept |          |
| `init-recovery`      | `initRecovery`     | Y      | new (sets `flow='recovery'`)     |       |          | ✓        |

### Authentication entry (2 steps)

| `credentials` | `credentials` | Y | login.credentials | ✓ | | |
| `request` | `request` | Y | recovery.request | | | ✓ |

### Prepare-\* policy steps (16 steps — audit removed)

| `prepare-semantic-flags` | `prepareSemanticFlags` | Y | new (canonical writer of `password.changeReason`; also `isFirstLogin` + `newPasswordRequired` for login/invite) | ✓ | ✓ accept | ✓ |
| `prepare-profile` | `prepareProfile` | Y | login | ✓ | | |
| `prepare-consents` | `prepareConsents` | Y | base | ✓ | ✓ accept | ✓ |
| `prepare-alternate-credentials` | `prepareAlternateCredentials` | Y | login | ✓ | | |
| `prepare-device-trust` | `prepareDeviceTrust` | Y | login | ✓ | | |
| `prepare-enrollment` | `prepareEnrollment` | Y | login | ✓ | | |
| `prepare-finalize` | `prepareFinalize` | Y | login | ✓ | | |
| `prepare-guards` | `prepareGuards` | Y | login | ✓ | | |
| `prepare-session-policy` | `prepareSessionPolicy` | Y | login | ✓ | | |
| `prepare-mfa` | `prepareMfa` | Y | merge: login.prepareMfaSetup + invite.prepareMfa + invite.setupMfa | ✓ | ✓ | |
| `prepare-admin-form` | `prepareAdminForm` | N | invite | | ✓ admin | |
| `prepare-available-roles` | `prepareAvailableRoles` | N | invite | | ✓ admin | |
| `prepare-accept` | `prepareAccept` | Y | invite | | ✓ accept | |
| `prepare-password-rules` | `preparePasswordRules` | Y | base | ✓ | ✓ accept | ✓ |
| `prepare-post-reset` | `preparePostReset` | Y | recovery | | | ✓ |
| `prepare-recovery-alt-actions` | `prepareRecoveryAltActions` | Y | recovery (renamed from `prepare-alt-actions` to disambiguate) | | | ✓ |

### Admin phase — invite-only (5 steps, all arbac-evaluated)

| `admin-form` | `adminForm` | N | invite | | ✓ admin | |
| `infer-roles` | `inferRoles` | N | invite | | ✓ admin | |
| `build-user-extras` | `buildUserExtras` | N | invite | | ✓ admin | |
| `create-user` | `createUser` | N | invite | | ✓ admin | |
| `send-email` | `sendInviteEmail` | Y | invite | | ✓ admin→public boundary | |

### Accept-tail — invite-only (5 steps, all public)

| `check-pending-invitation` | `checkPendingInvitation` | Y | invite | | ✓ accept | |
| `idempotent-redirect` | `idempotentRedirect` | Y | invite | | ✓ accept | |
| `unset-pending-invitation` | `unsetPendingInvitation` | Y | invite | | ✓ accept | |
| `activate-user` | `activateUser` | Y | invite | | ✓ accept | |
| `confirmation` | `confirmation` | Y | invite | | ✓ accept | |

### Password (1 step — collapsed across all three flows)

| `create-password-form` | `createPasswordForm` | Y | merge: login Phase5 + invite + recovery.set-password | ✓ | ✓ | ✓ |

### Channel enrolment — login-only (2 steps)

| `ask/:channel(email\|phone)` | `askChannel` | Y | login | ✓ | | |
| `verify/:channel(email\|phone)` | `verifyChannel` | Y | login | ✓ | | |

### MFA loop (shared, login + invite)

| `check-trusted-device` | `checkTrustedDevice` | Y | login | ✓ | | |
| `load-enrolled-mfa-methods` | `loadEnrolledMfaMethods` | Y | login | ✓ | | |
| `select-mfa-method` | `selectMfaMethod` | Y | login | ✓ | | |
| `select-2fa` | `select2fa` | Y | login | ✓ | | |
| `pincode-send` | `pincodeSend` | Y | merge: login.pincodeSendLogin + recovery.send-otp (one body; form selected by ctx-slot presence) | ✓ | | ✓ |
| `pincode-check` | `pincodeCheck` | Y | merge: login.pincodeCheckLogin + recovery.check-otp (one body; alt-actions routed by ctx-slot presence) | ✓ | | ✓ |
| `totp-check` | `totpCheck` | Y | login.mfaTotp (renamed for symmetry with pincode-check) | ✓ | | |
| `enroll-pick-method` | `enrollPickMethod` | Y | merge: login + invite | ✓ | ✓ | |
| `enroll-address` | `enrollAddress` | Y | merge: login + invite | ✓ | ✓ | |
| `enroll-confirm` | `enrollConfirm` | Y | merge: login + invite | ✓ | ✓ | |
| `risk-step-up` | `riskStepUp` | Y | login | ✓ | | |

### Login post-MFA tail

| `device-trust` | `deviceTrust` | Y | login | ✓ | | |
| `profile-complete` | `profileComplete` | Y | login | ✓ | | |
| `terms-bump-prompt` | `termsBumpPrompt` | Y | login | ✓ | | |
| `load-active-sessions` | `loadActiveSessions` | Y | login | ✓ | | |
| `concurrency-limit` | `concurrencyLimit` | Y | login | ✓ | | |

### Invite accept-tail profile

| `collect-profile` | `collectProfile` | Y | invite | | ✓ accept | |
| `apply-profile` | `applyProfile` | Y | invite | | ✓ accept | |

### Extra-step (login + invite, gated on `isFirstLogin`)

| `extra-step` | `extraStep` | Y | invite (no-op) — now reachable from login under `condition: isFirstLogin` | ✓ | ✓ | |

### Consents persistence (all three)

| `persist-consents` | `persistConsents` | Y | base | ✓ | ✓ | ✓ |

### Recovery delivery + post-reset

(Recovery's OTP verification reuses the unified `pincode-send` / `pincode-check` step pair above — same step bodies as login MFA, different form selected by ctx-slot presence.)

| `revoke-sessions` | `revokeSessions` | Y | recovery | | | ✓ |

### Finalize (per flow)

| `issue` | `issue` | Y | login | ✓ | | |
| `notify-new-device` | `notifyNewDevice` | Y | login | ✓ | | |
| `redirect` | `redirect` | Y | login | ✓ | | |
| `finalize-fresh-login` | `finalizeFreshLogin` | Y | merge: invite.freshLoginFinish + recovery.freshLoginFinish | | ✓ | ✓ |
| `finalize-auto-login` | `finalizeAutoLogin` | Y | merge: invite.autoLoginFinish + recovery.autoLoginFinish | | ✓ | ✓ |

`notify-new-device` is gated on `!ctx.isFirstLogin && !!ctx.finalize?.notifyNewDevice && !!ctx.trust?.newDevice` — so it never fires on first login (invite is always first-login, so it's structurally absent from invite anyway). Recovery does NOT fire notify-new-device in this pass (deferred — see §13).

### Alt-cred stubs (login-only, all `condition: false` placeholders)

| `magic-link-request` / `magic-link-send` / `magic-link-verified` / `passkey` / `sso-callback` | (stubs, 5 IDs) | Y | login | ✓ | | |

**Total: 66 distinct step IDs.**

### Step ID rename map (today → unified)

| From                                                   | To                                                                          | Reason                                                                                   |
| ------------------------------------------------------ | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `prepare-mfa-setup` (login)                            | `prepare-mfa`                                                               | Collapse with invite's                                                                   |
| `prepare-mfa` (invite)                                 | `prepare-mfa`                                                               | (unchanged)                                                                              |
| `setup-mfa` (invite)                                   | folded into `prepare-mfa` body                                              | One-liner auto-pick belongs in the prepare body                                          |
| `pincode-send-login` (login) + `send-otp` (recovery)   | `pincode-send`                                                              | Unified step body — one method, both flows. Form selected by `ctx.mfa?.method` presence. |
| `pincode-check-login` (login) + `check-otp` (recovery) | `pincode-check`                                                             | Same — unified body, sets `ctx.otp.verified = true` regardless of caller.                |
| `mfa-totp`                                             | `totp-check`                                                                | Symmetry with `pincode-check`; sets the same `ctx.otp.verified` flag.                    |
| `set-password` (recovery)                              | `create-password-form`                                                      | Collapse to shared body; copy customized via `ctx.password.changeReason="reset"`         |
| `audit` (recovery) + `audit-login`                     | (REMOVED)                                                                   | Audit handled at interceptor level, not as a workflow step.                              |
| `prepare-alt-actions` (recovery)                       | `prepare-recovery-alt-actions`                                              | Disambiguate from login's `prepare-alternate-credentials` (different concept)            |
| `fresh-login-finish` (invite + recovery)               | `finalize-fresh-login`                                                      | Verb-prefixed for clarity                                                                |
| `auto-login-finish` (invite + recovery)                | `finalize-auto-login`                                                       | Same                                                                                     |
| `init` (per-workflow)                                  | `init-login` / `init-invite-admin` / `init-invite-accept` / `init-recovery` | Split — bodies differ per flow                                                           |
| `redirect` (login)                                     | `redirect`                                                                  | Unchanged (login-only)                                                                   |

---

## 7. Resolver inventory (17 resolvers)

All on `class AuthWorkflow`. Default bodies hardcoded (per CLAUDE.md "policy lives on resolvers, not opts"). Customers override on subclass.

```typescript
class AuthWorkflow {
  // ── Login-relevant (7) ──
  protected resolveProfile(ctx: AuthWfCtx):
    { required: boolean } | Promise<{ required: boolean }>
  protected resolveAlternateCredentials(ctx: AuthWfCtx):
    NonNullable<AuthWfCtx['alternateCredentials']> | Promise<...>
  protected resolveDeviceTrust(ctx: AuthWfCtx):
    NonNullable<AuthWfCtx['deviceTrust']> | Promise<...>
  protected resolveEnrollment(ctx: AuthWfCtx):
    NonNullable<AuthWfCtx['enrollment']> | Promise<...>
  protected resolveFinalize(ctx: AuthWfCtx):
    NonNullable<AuthWfCtx['finalize']> | Promise<...>
  protected resolveGuards(ctx: AuthWfCtx):
    NonNullable<AuthWfCtx['guards']> | Promise<...>
  protected resolveSessionPolicy(ctx: AuthWfCtx):
    NonNullable<AuthWfCtx['sessionPolicy']> | Promise<...>

  // ── Shared login+invite (1) ──
  protected resolveMfaPolicy(ctx: AuthWfCtx):
    NonNullable<AuthWfCtx['mfaPolicy']> | Promise<...>
  // Default: { mode: "optional", availableTransports: ["sms","email","totp"], issuer: authOpts.totpIssuer }
  // Replaces today's:
  //   - login.prepareMfaSetup body's hardcoded defaults
  //   - invite.resolveMfa (which only returned {issuer})

  // ── Pincode variation seams (override points for unified pincode-send/check) ──
  // Default impls discriminate by ctx-slot presence (`ctx.mfa?.method` → MFA flavor, else → recovery).
  // Customers override these to redirect form choice / target / channel without touching step bodies.
  protected resolvePincodeForm(ctx: AuthWfCtx): TAtscriptAnnotatedType
  protected resolvePincodeTarget(ctx: AuthWfCtx):
    { address: string; channel: "sms" | "email" }
  protected resolvePincodeAltAction(ctx: AuthWfCtx, action: string):
    "resend" | "exit" | "useDifferentMethod" | undefined

  // ── Login-only async resolvers (2) ──
  protected resolveOtpDisclosure(ctx: AuthWfCtx, channel: "email" | "phone"):
    string | Promise<string>
  protected resolveRiskStepUp(ctx: AuthWfCtx):
    Promise<{ rerunMfa: boolean }>

  // ── Sync helpers (1) ──
  protected resolveRecoveryUrl(username: string | undefined, alt: AuthWfAltCredsPolicy): string

  // ── Invite-relevant (2) ──
  protected resolveAdminForm(ctx: AuthWfCtx):
    NonNullable<AuthWfCtx['adminForm']> | Promise<...>
  protected resolveAccept(ctx: AuthWfCtx):
    NonNullable<AuthWfCtx['accept']> | Promise<...>

  // ── Recovery-relevant (2) ──
  // Note: `resolveDelivery`, `resolvePreReset`, `resolveAudit` removed in this pass.
  // (Recovery is OTP-via-email only, no pre-reset factor check, no audit at workflow level.)
  protected resolvePostReset(ctx: AuthWfCtx):
    NonNullable<AuthWfCtx['postReset']> | Promise<...>
  protected resolveRecoveryAltActions(ctx: AuthWfCtx):
    NonNullable<AuthWfCtx['recoveryAltActions']> | Promise<...>
}
```

### Notes

- **`resolveMfa` (invite) is REMOVED**. Its only job was returning `{ issuer }`. The new `resolveMfaPolicy` returns `{ mode, availableTransports, issuer }` — covers both login's hardcoded defaults AND invite's customization seam.
- **Recovery's `resolveAltActions` renamed to `resolveRecoveryAltActions`** to avoid the name collision with login's `resolveAlternateCredentials` (different concept — one is "back to login" / "useDifferentTransport" / "resend"; the other is "forgot password" / "signup" / "magic-link").
- **`resolveFinalize` shape shrinks**: today it returns `{ auditLogin, notifyNewDevice, redirect }`. After audit removal: `{ notifyNewDevice, redirect }`. Login-only (recovery doesn't call it in this pass). The `notifyNewDevice` field stays as a tenant-level on/off knob (default `true`); the actual step gates ALSO on `!ctx.isFirstLogin` (per §2 decision).
- Return type stays `T | Promise<T>` union for sync fast-path preservation (per CLAUDE.md).

---

## 8. Shared schema fragments

In `auth-workflow.schemas.ts`:

```typescript
import type { TWorkflowSchema } from "@moostjs/event-wf";
import type { AuthWfCtx } from "./auth-workflow.ctx.ts";

/**
 * Shared MFA loop — challenge OR enrol. Used by login.flow + invite.start.
 * Loop exits when `ctx.otp.verified` flips true — set by ANY of: pincode-check (SMS/email challenge),
 * totp-check (TOTP challenge), enroll-confirm (forced enrolment of a new method, since enrol-confirm
 * verifies control of the new factor via pincode or TOTP).
 *
 * For invite users (zero enrolled methods), the enrol trio fires and its confirm step sets
 * `otp.verified=true`. For login users with enrolled methods, the challenge branches set it directly.
 */
export const mfaLoopSchema: TWorkflowSchema<AuthWfCtx> = [
  { id: "prepare-mfa" },
  {
    while: (ctx) => ctx.mfaPolicy?.mode !== "disabled" && !ctx.otp?.verified,
    steps: [
      {
        id: "check-trusted-device",
        condition: (ctx) =>
          !ctx.otp?.verified && !!ctx.deviceTrust?.enabled && !!ctx.deviceTrust?.skipsMfa,
      },
      { id: "load-enrolled-mfa-methods", condition: (ctx) => !ctx.otp?.verified },
      { id: "select-mfa-method", condition: (ctx) => !ctx.otp?.verified },
      {
        id: "select-2fa",
        condition: (ctx) =>
          !ctx.otp?.verified && !ctx.mfa?.method && (ctx.mfa?.enrolledMethods?.length ?? 0) > 1,
      },
      // SMS/email challenge pair — UNIFIED step bodies (also used by recovery's OTP loop).
      // `ctx.mfa.method` set → step body picks MFA-context form (`opts.forms.pincode`).
      {
        condition: (ctx) =>
          !ctx.otp?.verified && (ctx.mfa?.method === "sms" || ctx.mfa?.method === "email"),
        steps: pincodeSendCheckPair,
      },
      // TOTP challenge
      { id: "totp-check", condition: (ctx) => !ctx.otp?.verified && ctx.mfa?.method === "totp" },
      // Forced enrolment trio (fires when user has no enrolled methods)
      {
        condition: (ctx) =>
          !ctx.otp?.verified &&
          (ctx.mfa?.enrolledMethods?.length ?? 0) === 0 &&
          (ctx.mfaPolicy?.availableTransports?.length ?? 0) > 0,
        steps: [
          { id: "enroll-pick-method", condition: (ctx) => !ctx.mfaEnroll?.method },
          {
            id: "enroll-address",
            condition: (ctx) =>
              !!ctx.mfaEnroll?.method &&
              (ctx.mfaEnroll.method === "sms" || ctx.mfaEnroll.method === "email") &&
              !ctx.mfaEnroll.address,
          },
          {
            id: "enroll-confirm",
            condition: (ctx) =>
              !!ctx.mfaEnroll?.method &&
              (ctx.mfaEnroll.method === "totp" || !!ctx.mfaEnroll.address) &&
              !ctx.mfaEnroll.done,
          },
        ],
      },
      // Risk step-up — may clear otp.verified to re-arm the loop
      {
        id: "risk-step-up",
        condition: (ctx) => !!ctx.otp?.verified && !ctx.session?.riskStepUpEvaluated,
      },
    ],
  },
];

/**
 * Forced password change — used by login.flow + invite.start (NOT recovery — recovery's
 * gating differs: gated directly on `otp.verified`, NOT `newPasswordRequired`).
 */
export const passwordPhaseSchema: TWorkflowSchema<AuthWfCtx> = [
  {
    condition: (ctx) => !!ctx.newPasswordRequired && !ctx.completion?.passwordCompleted,
    steps: [{ id: "prepare-password-rules" }, { id: "create-password-form" }],
  },
];

/**
 * Batched consent persistence tail — used by all three flows.
 */
export const consentsPersistTailSchema: TWorkflowSchema<AuthWfCtx> = [
  {
    id: "persist-consents",
    condition: (ctx) =>
      (ctx.consents?.pending?.length ?? 0) > 0 &&
      !!ctx.consents?.decidedAt &&
      !ctx.consents?.persisted,
  },
];

/**
 * Canonical OTP send-then-check pair. Used by:
 * - Login's MFA-loop SMS/email challenge sub-branch (the outer MFA while provides iteration)
 * - Recovery's OTP while-loop (provides its own iteration)
 *
 * The step bodies are flow-agnostic — they read `ctx.mfa?.method` to pick form / target / alt-actions.
 * The pair is intentionally tiny but worth extracting: it encodes the "send if no pin, then check"
 * sequencing as one canonical pattern; changes to the pattern propagate to both call sites.
 */
export const pincodeSendCheckPair: TWorkflowSchema<AuthWfCtx> = [
  { id: "pincode-send", condition: (ctx) => !ctx.pin },
  { id: "pincode-check" },
];
```

---

## 9. The three `@Workflow` schemas (new shape)

### login.flow

```typescript
@Workflow("flow")
@Public()
@WorkflowSchema<AuthWfCtx>([
  { id: "init-login" },
  { id: "credentials" },
  { break: (ctx) => !ctx.username },

  // Resolve all policy groups
  { id: "prepare-profile" },
  { id: "prepare-consents" },
  { id: "prepare-alternate-credentials" },
  { id: "prepare-device-trust" },
  { id: "prepare-enrollment" },
  { id: "prepare-finalize" },
  { id: "prepare-guards" },
  { id: "prepare-session-policy" },

  // Semantic flags AFTER prepare-guards so it can read ctx.guards.* + ctx.isPasswordInitial/Expired
  // (which credentials sets inline). Idempotent on re-entry.
  { id: "prepare-semantic-flags" },

  // Alt-cred stub registration (always condition: false; consumer overrides)
  { condition: () => false, steps: [
    { id: "magic-link-request" },
    { id: "magic-link-send" },
    { id: "magic-link-verified" },
    { id: "passkey" },
    { id: "sso-callback" },
  ]},

  // Forced channel enrolment
  { id: "ask/email",   condition: (ctx) => (!!ctx.enrollment?.ensureEmail || !!ctx.guards?.emailVerifiedRequired) && !ctx.email },
  { id: "verify/email", condition: (ctx) => (!!ctx.enrollment?.ensureEmail || !!ctx.guards?.emailVerifiedRequired) && !!ctx.email && !ctx.channel?.emailConfirmed },
  { id: "ask/phone",   condition: (ctx) => !!ctx.enrollment?.ensurePhone && !ctx.channel?.phone },
  { id: "verify/phone", condition: (ctx) => !!ctx.enrollment?.ensurePhone && !!ctx.channel?.phone && !ctx.channel?.phoneConfirmed },

  // MFA loop (shared)
  ...mfaLoopSchema,

  // Post-MFA device-trust
  { id: "device-trust", condition: (ctx) =>
      !!ctx.deviceTrust?.enabled && !!ctx.otp?.verified && !!ctx.trust?.newDevice &&
      (!ctx.deviceTrust?.optIn || !!ctx.trust?.rememberDevice) },

  // Forced password change (shared) — uses semantic flag
  ...passwordPhaseSchema,
  { break: (ctx) => !!ctx.aborted },

  // Profile + extra-step
  { id: "profile-complete", condition: (ctx) =>
      !!ctx.profileCompleteRequired && !ctx.completion?.profileApplied &&
      (ctx.profileMissingFields?.length ?? 0) > 0 },
  { id: "extra-step", condition: (ctx) => !!ctx.isFirstLogin },
  { id: "terms-bump-prompt", condition: (ctx) =>
      (ctx.consents?.pending?.length ?? 0) > 0 && !ctx.consents?.decidedAt && !ctx.consents?.persisted },

  ...consentsPersistTailSchema,

  // Session policy
  { condition: (ctx) => !!ctx.sessionPolicy?.concurrencyLimit, steps: [
    { id: "load-active-sessions" },
    { id: "concurrency-limit", condition: (ctx) =>
        (ctx.session?.activeSessions ?? 0) >= ctx.sessionPolicy!.concurrencyLimit!.max },
  ]},
  { break: (ctx) => !!ctx.aborted },

  // Finalize (login-specific tail)
  { id: "issue", condition: (ctx) => !ctx.completion?.tokensIssued },
  { condition: (ctx) => !!ctx.completion?.tokensIssued, steps: [
    { id: "notify-new-device", condition: (ctx) =>
        !ctx.isFirstLogin && !!ctx.finalize?.notifyNewDevice && !!ctx.trust?.newDevice },
    { id: "redirect" },
  ]},
])
loginFlow(): void {}
```

### invite.start

```typescript
@Workflow("start")
@Public()
@WorkflowSchema<AuthWfCtx>([
  // ── Phase A: admin invites (arbac-protected) ──
  { id: "init-invite-admin" },
  { id: "prepare-admin-form" },
  { id: "prepare-available-roles", condition: (ctx) => !!ctx.adminForm?.collectRoles },
  { id: "admin-form", condition: (ctx) => !ctx.email },
  { id: "infer-roles", condition: (ctx) => !!ctx.email },
  { id: "build-user-extras", condition: (ctx) => !!(ctx.email && !ctx.username && !ctx.admin?.userExtras) },
  { id: "create-user", condition: (ctx) => !!(ctx.email && !ctx.username && !!ctx.admin?.userExtras) },
  { id: "send-email", condition: (ctx) => !!ctx.username },

  // ── Phase B: anonymous magic-link resume (all public) ──
  { condition: (ctx) => !!ctx.admin?.linkSent, steps: [
    { id: "init-invite-accept" },     // sets isFirstLogin=true, newPasswordRequired=true
    { id: "prepare-accept" },
    { id: "check-pending-invitation" },
    { id: "idempotent-redirect", condition: (ctx) => !!ctx.accept?.alreadyAccepted },
    { id: "prepare-consents" },
    { id: "prepare-semantic-flags" }, // idempotent re-write

    // Forced password change (shared) — invite always satisfies newPasswordRequired
    ...passwordPhaseSchema,

    // MFA loop (shared) — invite users have zero enrolled methods so the enrol trio fires
    ...mfaLoopSchema,

    // Profile (invite-specific 2-step pattern)
    { id: "collect-profile", condition: (ctx) =>
        !!ctx.accept?.profileFormPresent && !ctx.accept?.profile && !!ctx.completion?.passwordCompleted },
    { id: "apply-profile", condition: (ctx) =>
        !!ctx.accept?.profileFormPresent && !!ctx.accept?.profile &&
        !ctx.completion?.profileApplied && !!ctx.completion?.passwordCompleted },

    { id: "extra-step" },             // always fires for invite (isFirstLogin=true)

    ...consentsPersistTailSchema,

    { id: "unset-pending-invitation", condition: (ctx) =>
        !!ctx.completion?.passwordCompleted && !ctx.completion?.pendingInvitationCleared },
    { id: "activate-user", condition: (ctx) =>
        !!ctx.completion?.pendingInvitationCleared && !ctx.completion?.activated },
    { id: "confirmation", condition: (ctx) =>
        !!ctx.completion?.activated && !!ctx.accept?.showConfirmation && !ctx.completion?.confirmationShown },

    // Finalize (invite tail — gated by opts.autoLoginOnInvite)
    { id: "finalize-fresh-login", condition: (ctx) =>
        !!ctx.completion?.activated && !this.opts.autoLoginOnInvite },
    { id: "finalize-auto-login", condition: (ctx) =>
        !!ctx.completion?.activated && !!this.opts.autoLoginOnInvite && !ctx.completion?.tokensIssued },
  ]},
])
inviteFlow(): void {}
```

Note on `@Public()`: The `inviteFlow()` body itself is `@Public()` (so the wf adapter can dispatch start/resume on anonymous magic-link clicks). Admin-phase @Step methods are NOT `@Public()` — arbac evaluates them on first-pass when an admin starts the flow. Accept-tail @Step methods all are `@Public()` (anonymous resume).

### recovery.flow

```typescript
@Workflow("flow")
@Public()
@WorkflowSchema<AuthWfCtx>([
  { id: "init-recovery" },
  { id: "request" },
  { break: (ctx) => !ctx.username },

  { id: "prepare-post-reset" },
  { id: "prepare-recovery-alt-actions" },
  { id: "prepare-consents" },
  { id: "prepare-semantic-flags" },  // sets ctx.password.changeReason = "reset"

  // OTP-via-email loop — spreads the shared `pincodeSendCheckPair` (same step pair as login MFA).
  // Step bodies inspect `ctx.mfa?.method` (unset here → recovery context) and pick
  // `opts.forms.recoveryPincode` with recovery alt-actions.
  { while: (ctx) => !ctx.otp?.verified && !ctx.aborted,
    steps: pincodeSendCheckPair,
  },
  { break: (ctx) => !!ctx.aborted },

  // Password reset — gating differs from passwordPhaseSchema (no `newPasswordRequired` flag;
  // gated directly on OTP verification).
  { condition: (ctx) => !!ctx.otp?.verified,
    steps: [{ id: "prepare-password-rules" }, { id: "create-password-form" }],
  },
  { break: (ctx) => !!ctx.aborted },

  // Post-reset tail (recovery-specific)
  { condition: (ctx) => !!ctx.completion?.passwordCompleted, steps: [
    { id: "revoke-sessions", condition: (ctx) => !!ctx.postReset?.revokeAllSessions },
    ...consentsPersistTailSchema,
    { id: "finalize-fresh-login", condition: (ctx) => !this.opts.autoLoginOnRecover },
    { id: "finalize-auto-login", condition: (ctx) => !!this.opts.autoLoginOnRecover && !ctx.completion?.tokensIssued },
    // Note: notify-new-device is NOT fired here in this pass — see §13. Recovery's auto-login path
    // would need device-trust checking infrastructure (prepare-device-trust + check-trusted-device
    // + ctx.trust state) to be extended to recovery. Out of scope for the unification pass.
  ]},
])
recoveryFlow(): void {}
```

---

## 10. Step body merging notes (the tricky ones)

### `create-password-form` — merges 3 flows

Today: login's Phase 5 + invite's create-password-form + recovery's set-password are three separate bodies.

After: one body, parameterized by `ctx.password.changeReason`:

- Stages copy: `ctx.password.heading + ctx.password.intro` based on `changeReason` (`"initial" | "expired" | "reset"`). Each `@Workflow`'s init / prepare step sets the reason.
- Pauses for `SetPasswordForm` (same form everywhere).
- Validates password + match + policy (already shared logic).
- Calls `users.setPassword(username, password)`.
- Processes inline consents (already shared).
- Sets `completion.passwordCompleted = true`.

### `pincode-send` + `pincode-check` — merges login MFA + recovery OTP

Today: login's `pincode-send-login` / `pincode-check-login` (MFA SMS/email challenge) and recovery's `send-otp` / `check-otp` (recovery OTP) are four separate bodies that do effectively the same work.

After: TWO step bodies (`pincode-send`, `pincode-check`), each shared between login MFA challenge and recovery OTP. Variation handled by protected resolver methods that branch on ctx-slot presence:

- `resolvePincodeForm(ctx)`: `ctx.mfa?.method` set → `opts.forms.pincode` (MFA alt-actions); else → `opts.forms.recoveryPincode` (recovery alt-actions).
- `resolvePincodeTarget(ctx)`: returns the **raw** address (real email/phone, used as `deliver`'s recipient) + `channel`. MFA context → raw address resolved from the user's MFA method via `ctx.mfa.enrolledMethods` + `channel` from `ctx.mfa.method`; recovery → `{ address: ctx.email, channel: "email" }`. Masking is applied SEPARATELY by the step body when writing `ctx.pincode.sentTo` for UI display — never substitute the masked form for the real recipient passed to `deliver`.
- `resolvePincodeAltAction(ctx, action)`: routes form alt-action to canonical outcome (resend, exit, useDifferentMethod).

**Unified `deliver(payload)` contract**. Today's three workflows each call into delivery hooks with different positional / object shapes (e.g. recovery's `{ channel, kind, recipient, code, ... }` at `packages/auth-moost/src/workflows/recovery.workflow.ts:657`). The unified class consolidates to ONE protected method:

```typescript
type AuthDeliveryPayload =
  | { kind: "mfa-pincode"; channel: "sms" | "email"; recipient: string; code: string; expiresInMs: number }
  | { kind: "recovery-pincode"; channel: "email"; recipient: string; code: string; expiresInMs: number }
  | { kind: "enroll-pincode"; channel: "sms" | "email"; recipient: string; code: string; expiresInMs: number }
  | { kind: "invite-link"; channel: "email"; recipient: string; url: string; expiresInMs: number }
  | { kind: "new-device-notice"; channel: "email"; recipient: string; deviceLabel?: string; loginAt: number };

protected async deliver(payload: AuthDeliveryPayload): Promise<void> { /* customer-provided sink */ }
```

This is the single seam customers implement (or replace via DI) for outbound dispatch. The `kind` discriminator lets customers route by purpose (e.g. different templates per kind).

Step body logic (sketch):

```typescript
@Step("pincode-send")
async pincodeSend(@WorkflowParam("context") ctx: AuthWfCtx) {
  const target = await this.resolvePincodeTarget(ctx);
  const code = await this.users.mintPincode(this.authOpts.mfa);
  const kind = ctx.mfa?.method ? "mfa-pincode" : "recovery-pincode";
  await this.deliver({
    kind, channel: target.channel, recipient: target.address,
    code: code.plain, expiresInMs: this.authOpts.mfa.pincodeTtlMs,
  });
  (ctx.pincode ??= {}).sentTo = maskAddress(target.address);
  ctx.pincode.codeLength = this.authOpts.mfa.pincodeLength;
  ctx.pincode.resendAllowedAt = Date.now() + this.authOpts.mfa.pincodeResendTimeoutMs;
  ctx.pin = code.digest;        // server-only — verified by pincode-check
  ctx.pinExpire = Date.now() + this.authOpts.mfa.pincodeTtlMs;
  return useAtscriptWf(this.resolvePincodeForm(ctx)).requireInput({ /* form copy from ctx.pincode.* */ });
}

@Step("pincode-check")
async pincodeCheck(@WorkflowParam("context") ctx: AuthWfCtx) {
  const wf = useAtscriptWf(this.resolvePincodeForm(ctx));
  const action = wf.resolveAction();
  if (action) {
    const outcome = this.resolvePincodeAltAction(ctx, action);
    if (outcome === "resend") {
      // SERVER-SIDE cooldown enforcement (defence in depth — UI also gates).
      // Without this check, a client bypassing the cooldown UI could flood the delivery channel.
      if (ctx.pincode?.resendAllowedAt && ctx.pincode.resendAllowedAt > Date.now()) {
        throw wf.requireInput({ errors: { code: "Please wait before requesting a new code." } });
      }
      delete ctx.pin; delete ctx.pinExpire;
      return undefined;
    }
    if (outcome === "exit") { ctx.aborted = true; return undefined; }
    if (outcome === "useDifferentMethod") { delete ctx.mfa?.method; delete ctx.pin; delete ctx.pinExpire; return undefined; }
  }
  const { code } = wf.resolveInput();
  if (!this.users.verifyPincode(code, ctx.pin!, ctx.pinExpire!)) {
    throw wf.requireInput({ errors: { code: "Invalid code" } });
  }
  (ctx.otp ??= {}).verified = true;
  delete ctx.pin; delete ctx.pinExpire;
  return undefined;
}
```

`enroll-confirm` also sets `ctx.otp.verified = true` (alongside `ctx.mfaEnroll.done = true`) on success — same flag, since enrol-confirm also verifies an OTP. `totp-check` (renamed from `mfa-totp`) does likewise.

### Device-trust suppression on pending password change

MFA forms that should carry the `rememberDevice` checkbox: `PincodeForm`, `MfaCodeForm` (TOTP), `Select2faForm`. The atscript schemas must declare the field bound to `ctx.trust.rememberDevice`, with a `@ui.form.fn.*` expression reading `ctx.newPasswordRequired` to hide it when password change is pending.

**P1 implementation note**: today only `PincodeForm` has `rememberDevice`. `MfaCodeForm` and `Select2faForm` need the field ADDED + the `hidden` expression wired + `pnpm gen:atscript` regen. Surface in P1 deliverables (it's a form-schema change, not just a class change).

Server-side defence-in-depth: the `device-trust` step body MUST also explicitly bail when `ctx.newPasswordRequired` is true, even if `ctx.trust.rememberDevice` somehow got set (e.g., a misconfigured client). This is a one-line guard at the top of the step body:

```typescript
if (ctx.newPasswordRequired) return undefined;
```

The schema order (MFA → device-trust → passwordPhaseSchema) is preserved; the form-level hide + server-side guard together ensure no trusted-device token is issued before the user has set their own password.

### `prepare-mfa` — merges 3 bodies

Today: login's `prepare-mfa-setup` (hardcoded `mode="optional"` + transports + auto-pick from defaultMethod) + invite's `prepare-mfa` (just stashes `mfa.issuer`) + invite's `setup-mfa` (auto-pick single-transport into mfaEnroll.method).

After: one body:

1. Calls `resolveMfaPolicy(ctx)` → `{ mode, availableTransports, issuer }`.
2. Writes to `ctx.mfaPolicy`.
3. If `username` bound:
   - `users.getUser` → reads existing MFA methods.
   - If user has confirmed methods + defaultMethod → set `ctx.mfa.current` (challenge pre-pick).
   - Else if zero enrolled + single available transport → set `ctx.mfaEnroll.method` (enrolment pre-pick).
4. Idempotent on re-entry.

### `init-*` and `prepare-semantic-flags` — split work

`init-login`: BEFORE credentials. Sets `ctx.flow = 'login'`. No semantic flags (username not bound yet).

`prepare-semantic-flags`: AFTER all `prepare-*` policy steps complete, so it can read both `ctx.guards.*` (populated by `prepare-guards`) AND the top-level flags `ctx.isPasswordInitial / ctx.isPasswordExpired` (set inline by `credentials` — invariant: credentials remains responsible for these flags; `prepare-guards` is the canonical policy source). Reads `user.lastLoginAt` to compute `isFirstLogin`. Idempotent on re-entry.

**Canonical writer of `ctx.password.changeReason`** — sets the value that `create-password-form` reads to stage form copy:

| Flow                       | Writes                                                                                                          |
| -------------------------- | --------------------------------------------------------------------------------------------------------------- |
| login.flow                 | `"initial"` if `isPasswordInitial`, `"expired"` if `isPasswordExpired`, else `undefined` (skips password phase) |
| invite.start (accept tail) | `"initial"` (always — invite is first password)                                                                 |
| recovery.flow              | `"reset"` (always — recovery is always a password reset)                                                        |

Used in:

- login.flow: after `prepare-session-policy`. Computes `isFirstLogin`, `newPasswordRequired`, `password.changeReason`.
- invite.start (accept tail): after `prepare-accept`. Sets `isFirstLogin=true, newPasswordRequired=true, password.changeReason="initial"` (idempotent re-write of what `init-invite-accept` already set on most fields).
- recovery.flow: after `prepare-consents`. Sets `password.changeReason="reset"` (no other semantic flags — recovery doesn't use `isFirstLogin`; password gating uses `otp.verified` directly).

`init-invite-admin`: BEFORE admin-form. Sets `ctx.flow = 'invite'`. No semantic flags (admin phase doesn't need them).

`init-invite-accept`: ON magic-link resume. Sets `ctx.flow = 'invite'`, `isFirstLogin = true`, `newPasswordRequired = true`. Also stamps `ctx.accept.profileFormPresent` (today done by invite's init).

`init-recovery`: BEFORE request. Sets `ctx.flow = 'recovery'`. No semantic flags.

---

## 11. Customer migration notes

### Today

```typescript
@Inherit() @Controller()
class MyLogin extends LoginWorkflow {
  protected resolveProfile(ctx: LoginWfCtx) {
    return { required: this.tenantRequiresProfile() };
  }
}
@Inherit() @Controller()
class MyInvite extends InviteWorkflow {
  protected resolveAccept(ctx: InviteWfCtx) { ... }
}
app.setReplaceRegistry(createReplaceRegistry([
  LoginWorkflow, MyLogin,
  InviteWorkflow, MyInvite,
]));
```

### After

```typescript
@Inherit()
@Controller()
class MyAuth extends AuthWorkflow {
  protected resolveProfile(ctx: AuthWfCtx) {
    // Reached from login.flow ONLY (no other flow calls it).
    // Safe to assume login context.
    return { required: this.tenantRequiresProfile() };
  }
  protected resolveAccept(ctx: AuthWfCtx) {
    // Reached from invite.start ONLY (no other flow calls it).
    // Safe to assume invite-accept context.
    return { confirmationMessage: "Welcome!", showConfirmation: true };
  }
}
app.setReplaceRegistry(createReplaceRegistry([AuthWorkflow, MyAuth]));
```

Most resolvers are flow-specific by nature (only one schema calls them). The few that are theoretically cross-flow (e.g. `resolveProfile` could be called from any flow if we extended it) — customer discriminates via ctx-slot presence, never via `ctx.flow ===`:

```typescript
protected resolveSomething(ctx: AuthWfCtx) {
  if (ctx.admin) return { ...invite-flavored... };       // invite admin phase populates ctx.admin
  if (ctx.postReset) return { ...recovery-flavored... }; // recovery's prepare-post-reset populates ctx.postReset
  return { ...login-flavored... };                       // fallback
}
```

---

## 12. Migration phases

### P1 — Build `AuthWorkflow` alongside existing classes (additive)

**Deliverables**:

- `packages/auth-moost/src/workflow/auth-workflow.ctx.ts` — all interfaces
- `packages/auth-moost/src/workflow/auth-workflow.opts.ts` — `AuthWorkflowOpts` + resolved type
- `packages/auth-moost/src/workflow/auth-workflow.schemas.ts` — 4 fragment consts (`mfaLoopSchema`, `passwordPhaseSchema`, `consentsPersistTailSchema`, `pincodeSendCheckPair`)
- `packages/auth-moost/src/workflow/auth-workflow.ts` — the class with 3 `@Workflow` methods + 66 `@Step` methods + 17 `resolveXxx` methods
- `packages/auth-moost/src/__test__/auth-workflow.smoke.spec.ts` — minimal smoke tests: one happy-path through `loginFlow`, one through `inviteFlow` (admin→accept→activate), one through `recoveryFlow` (OTP-via-email: enter email → enter OTP → set new password → finalize), one lockout-triggering case to pin the UserService-lockout contract (per §13 risk 5)
- **Form-schema updates**: add `rememberDevice` field to `MfaCodeForm` and `Select2faForm` with `hidden = ctx.newPasswordRequired` `@ui.form.fn` expression, plus existing wiring on `PincodeForm`. Run `pnpm gen:atscript` to regenerate `.as.d.ts`. (Per §10 device-trust suppression rule.)

**Untouched**: old `workflows/` files, all existing test files, e2e-demo, harness. Old classes still operational. Workspace tests stay green at current baselines (135P/160F auth-moost, 8P/140F e2e-demo).

**Estimated**: 1 big orchestrator-implement run with 5–7 internal steps (ctx → opts → schemas → class skeleton → step bodies batch 1 → step bodies batch 2 → smoke tests).

### P2 — Migrate auth-moost unit tests

- All 28 spec files in `packages/auth-moost/src/__test__/` rebind from old classes to `AuthWorkflow`.
- `workflow-utils.ts` test helpers updated.
- `auth-workflow.base.spec.ts` deleted.
- Class-name-specific test names updated.

### P3 — Migrate e2e-demo unit/integration tests

- `wf-login.spec.ts`, `wf-invite.spec.ts`, `wf-recovery.spec.ts` rebind.
- `harness.ts` switches to new class.
- All 17 e2e-demo `test/` files green.

### P4 — Migrate e2e-demo SPA + variants

- `packages/e2e-demo/src/app.ts`: three `DemoXxxWorkflow` subclasses → one `DemoAuthWorkflow`. The variant-override `prepareMfaSetup` body becomes a `resolveMfaPolicy` override.
- `packages/e2e-demo/src/variants.ts`: flatten three variant shapes into one (or three nested under one root).
- Playwright suite stays green.

### P5 — Delete old code

- Delete `login.workflow.ts`, `invite.workflow.ts`, `recovery.workflow.ts`, `auth-workflow.base.ts`.
- Rename `packages/auth-moost/src/workflows/` → `packages/auth-moost/src/workflow/` (singular).
- Update package exports in `packages/auth-moost/package.json` + any sub-entry-points.
- Update `packages/auth-moost/CLAUDE.md` for the new shape (references to "LoginWorkflow" / etc. become "AuthWorkflow"; per-WF examples consolidate).
- Update root `CLAUDE.md` if it mentions the workflow class names.

---

## 13. Risks and open questions

### Risks

1. **Step ID collisions invisible in current code** — if any test references a step ID we're renaming, it'll silently break. The cross-package test audit in P2/P3 catches these.
2. **Wire-envelope `@wf.context.pass` annotations** — atscript-generated `.as.d.ts` files include explicit context-key whitelists. Any ctx-group rename (e.g. `passwordSet` → `passwordCompleted`) requires a corresponding annotation update in `packages/auth-moost/src/atscript/models/forms.as` and a `pnpm gen:atscript` regen run.
3. **MFA loop while-guard unification** — today login uses `!mfa.checked` and invite uses `!mfaEnroll.done`. Unified uses `!ctx.otp.verified`. Every verification path (pincode-check, totp-check, enroll-confirm) sets the same flag. `mfaEnroll.done` is retained as an auxiliary flag for downstream "did the user just enrol" detection but is no longer in the loop guard.
4. **Customer override granularity** — `class MyLogin extends LoginWorkflow` becomes `class MyAuth extends AuthWorkflow`. Documented behavioral change. Pre-release status (alpha) means no public consumers yet.
5. **Lockout depends on UserService methods being lockout-aware** — `verifyPassword`, `verifyPincode`, etc., must increment the failed-attempt counter and throw `UserAuthError("LOCKED")` when the threshold is reached. Step bodies pass through whatever the user store decides. If a future user-store implementation forgets lockout, the workflow gives no defence at the step level — rate limiting at the HTTP layer becomes the only protection. P1 smoke tests should include at least one lockout-triggering case (e.g., 5 bad pincodes → lock) to pin this contract.

### Open questions

None blocking. All key decisions in §2.

Implementation details to resolve mid-P1 (the coding agent surfaces them):

- Exact constructor signature of `AuthWorkflow` (DI param order).
- Whether to keep `LoginRedirect` type as-is or generalize it (probably keep — login-specific).

### Deferred features (intentionally out of scope this pass)

- **Recovery + auto-login notify-new-device**. The user's earlier directive was that notify-new-device should fire on recovery's auto-login path. Implementing this requires: (a) extending `ctx.trust` and `ctx.deviceTrust` to be populated in recovery's flow, (b) adding `prepare-device-trust` + `check-trusted-device` to recovery's schema, (c) making `prepare-finalize` shared so `ctx.finalize.notifyNewDevice` is available in recovery too. This is non-trivial scope expansion of recovery; deferred to a future pass once the unification baseline ships. Workaround: recovery users with `autoLoginOnRecover=true` who land on a new device WILL receive a notification on their NEXT login (login.flow's notify-new-device fires correctly), so the protection isn't lost — just delayed by one login.
- **Recovery magic-link delivery**, **OTP-via-SMS for recovery**, **recovery mode picker** (`delivery.mode === "choice"`), and **pre-reset factor check** (`preReset.*`). All removed in this pass per §2 ("rip off the flexibility for now"). Re-add when justified by product need.

---

## 14. Implementation kickoff

Once this doc is reviewed and locked, P1 starts via `/orchestrator-implement` with internal steps:

1. Create ctx + opts files (TS interfaces only — no runtime code).
2. Create schemas file (4 fragment consts).
3. Create class file: skeleton + constructor + resolveXxx defaults.
4. Port step bodies — batch 1 (prepare-_ + init-_).
5. Port step bodies — batch 2 (auth/credentials/request, password, MFA loop).
6. Port step bodies — batch 3 (flow-specific tails: admin/accept/recovery).
7. Smoke tests.

Each internal step compiles + tests green before the next. Single PR's worth of work.
