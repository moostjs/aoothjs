/**
 * Unified `AuthWfCtx` — context shape for the consolidated `AuthWorkflow`
 * class. One ctx interface covers all three `@Workflow` schemas
 * (`login.flow`, `invite.start`, `recovery.flow`); per-flow slots are
 * optional and discriminated by ctx-slot presence.
 *
 * Replaces the prior `LoginWfCtx` / `InviteWfCtx` / `RecoveryWfCtx` trio.
 */
import type { TransferablePolicy } from "@aooth/user";

export type MfaTransport = "sms" | "email" | "totp";

/** Per-user MFA method summary surfaced to forms via `@wf.context.pass 'mfa'`. */
export interface MfaSummary {
  kind: "sms" | "email" | "totp";
  methodName: string;
  masked: string;
  isDefault: boolean;
}

export type LoginRedirect = "referer" | "home" | false | null;

export interface SsoProvider {
  id: string;
  label: string;
  url: string;
}

export interface ConcurrencyLimitOptions {
  max: number;
  onLimit: "reject" | "kickPrompt";
}

/**
 * Consent descriptor wire shape — mirrors `ConsentDescriptor` from the
 * consent store without importing the runtime module (avoids cycles).
 */
export interface ConsentDescriptorLike {
  id: string;
  text: string;
  required?: string;
  version?: string;
}

/**
 * Consents — both server state (`accepted` / `decidedAt`) and the
 * UI-visible descriptor list (`pending`). Shipped via
 * `@wf.context.pass 'consents'`.
 */
export interface AuthWfConsentsState {
  pending?: ConsentDescriptorLike[];
  accepted?: string[];
  decidedAt?: number;
}

/**
 * UI hints for pincode entry — FORM-FACING via `@wf.context.pass 'pincode'`.
 * All three flows (login MFA SMS/email, recovery OTP, invite MFA
 * enrol-confirm) write here.
 *
 * `channelCooldowns` is the anti-ping-pong gate for the MFA-challenge loop:
 * a single `resendAllowedAt` is cleared on every `useDifferentMethod` so the
 * user's first attempt at the new channel isn't gated for the WRONG
 * channel's reason, BUT the per-channel timestamps in `channelCooldowns`
 * survive method-switching so ping-ponging (SMS → Email → SMS → …) cannot
 * be used to bypass the per-channel rate limit. `pincode-send` enforces the
 * per-channel gate before delivering; `select-2fa` enforces it BEFORE the
 * send to surface a per-channel error string on the form.
 */
export interface AuthWfPincodeUiState {
  sentTo?: string;
  codeLength?: number;
  resendAllowedAt?: number;
  channelCooldowns?: Partial<Record<MfaTransport, number>>;
}

/**
 * MFA enrolment running state. `pincodeCooldown` removed — enrol-confirm
 * uses the same `ctx.pincode.resendAllowedAt` slot as the challenge path.
 */
export interface AuthWfMfaEnrollState {
  method?: MfaTransport;
  address?: string;
  secret?: string;
  uri?: string;
  availableTransports?: MfaTransport[];
  mode?: "required" | "optional";
  done?: boolean;
}

/** FORM-FACING via `@wf.context.pass 'password'`. Read by `SetPasswordForm`. */
export interface AuthWfPasswordUiState {
  policies?: TransferablePolicy[];
  changeReason?: "initial" | "expired" | "reset";
  heading?: string;
  intro?: string;
}

/**
 * Completion outcome — carries data set by terminal steps. Step-completion
 * is encoded by the wf engine's cursor, NOT by ctx flags; only fields that
 * carry actual data (read downstream) live here.
 */
export interface AuthWfCompletionState {
  redirectUrl?: string;
}

/** Unified MFA policy — replaces login's hardcoded defaults + invite's `{issuer}` resolver. */
export interface AuthWfMfaPolicy {
  mode: "required" | "optional" | "disabled";
  availableTransports: MfaTransport[];
  issuer: string;
}

/**
 * MFA verification state. Verification result migrated to `AuthWfOtpState`;
 * cooldown migrated to `AuthWfPincodeUiState`.
 */
export interface AuthWfMfaState {
  enrolledMethods?: MfaSummary[];
  current?: MfaTransport;
  method?: "sms" | "email" | "totp";
  saveAsDefault?: boolean;
  ignoreDefault?: boolean;
  runsRemaining?: number;
  methodCount?: number;
}
// Note: `mfa.checked` REMOVED — replaced by `ctx.otp.verified`.
// Note: `mfa.pincodeCooldowns` REMOVED — replaced by `ctx.pincode.resendAllowedAt`.

/** Channel-onboarding state (login Phase 3). */
export interface AuthWfChannelState {
  emailConfirmed?: boolean;
  phone?: string;
  phoneConfirmed?: boolean;
  otpDisclosure?: string;
}

/** Device-trust state (login). */
export interface AuthWfTrustState {
  deviceTrustToken?: string;
  newDevice?: boolean;
  rememberDevice?: boolean;
  optIn?: boolean;
}

/** Session-policy state (login). */
export interface AuthWfSessionState {
  riskStepUpReason?: string;
  activeSessions?: number;
  riskStepUpEvaluated?: boolean;
}

/** Alt-credential mirror flags (login). */
export interface AuthWfAltActionsState {
  forgotPassword?: boolean;
  signup?: boolean;
  magicLink?: boolean;
  usedMagicLink?: boolean;
}

/** Alternate-credential policy (login). */
export interface AuthWfAltCredsPolicy {
  forgotPassword: boolean;
  signup: boolean;
  magicLink: boolean;
  magicLinkSkipsMfa: boolean;
  ssoProviders: SsoProvider[];
  recoveryUrl: string;
  signupUrl: string;
  embedRecovery: boolean;
}

/** Device-trust policy (login). */
export interface AuthWfDeviceTrustPolicy {
  enabled: boolean;
  optIn: boolean;
  skipsMfa: boolean;
}

/** Channel-enrolment policy (login). */
export interface AuthWfEnrollmentPolicy {
  ensureEmail: boolean;
  ensurePhone: boolean;
}

/** Finalize policy (login). `auditLogin` REMOVED — audit moved to interceptors. */
export interface AuthWfFinalizePolicy {
  notifyNewDevice: boolean;
  redirect: LoginRedirect;
}

/** Login-time guards policy. */
export interface AuthWfGuardsPolicy {
  passwordInitial: boolean;
  passwordExpiry: boolean;
  emailVerifiedRequired: boolean;
}

/** Session-policy (login). */
export interface AuthWfSessionPolicy {
  concurrencyLimit?: ConcurrencyLimitOptions;
}

/** Admin-form policy (invite admin phase). */
export interface AuthWfAdminFormPolicy {
  collectRoles: boolean;
}

/**
 * Invite-accept state (merged policy + state). No `freshLoginRequired` —
 * the auto-login choice is the static `AuthWorkflowOpts.autoLoginOnInvite`.
 */
export interface AuthWfAcceptState {
  alreadyAcceptedRedirectUrl?: string;
  loginUrl?: string;
  showConfirmation?: boolean;
  confirmationMessage?: string;
  alreadyAccepted?: boolean;
}

/**
 * Recovery post-reset state. `freshLoginRequired` removed — the choice is
 * the static `AuthWorkflowOpts.autoLoginOnRecover`.
 */
export interface AuthWfPostResetState {
  revokeAllSessions?: boolean;
  loginUrl?: string;
}

/** Recovery alt-actions policy. */
export interface AuthWfRecoveryAltActions {
  backToLogin: boolean;
}

/**
 * OTP verification flag — SERVER-ONLY (NOT form-facing). Set true by any
 * of: pincode-check, totp-check, enroll-confirm. Loop-exit signal.
 */
export interface AuthWfOtpState {
  verified?: boolean;
}

/** Invite admin-side (Phase A) state. */
export interface AuthWfAdminState {
  availableRoles?: string[];
  roles?: string[];
  userExtras?: Record<string, unknown>;
  /**
   * Outlet-pause idempotency marker for `send-email`. Flipped to `true`
   * after the first dispatch so the invitee's magic-link resume — which
   * re-executes the step body — short-circuits instead of dispatching a
   * second email and re-pausing. See `sendInviteEmail` for the why.
   */
  emailDispatched?: boolean;
}

/**
 * Pre-fill payload surfaced to forms via `@wf.context.pass 'defaults'`.
 * Used by recovery's `request` step to seed the email input from a
 * `?username=` query param carried from login's `forgotPassword` alt-action.
 */
export interface AuthWfDefaults {
  email?: string;
}

/**
 * Public-facing context surface — the **only** group form schemas may read
 * from via `@wf.context.pass 'public'`. Every other top-level key
 * (`ctx.mfa`, `ctx.pincode`, `ctx.trust`, etc.) is server-only and must
 * never be whitelisted on a form.
 *
 * Population is centralized in `AuthWorkflow.populatePublic(ctx)` which is
 * invoked by the `throwPublic` helper immediately before any
 * `requireInput`-style pause. Adding a new FE-consumed field has three
 * touch points: add it to a subgroup here, copy it in `populatePublic`,
 * and reference it in the form schema as `ctx.public.<group>.<field>`.
 *
 * Subgroups mirror the internal `ctx.<group>` shape one-for-one but only
 * carry the subset of fields that forms actually read. Internal-only
 * fields (e.g., `pincode.channelCooldowns`, `mfa.saveAsDefault`,
 * `mfa.current`, `mfa.ignoreDefault`, `trust.deviceTrustToken`,
 * `channel.phone`, `mfaEnroll.address`, …) are deliberately omitted so
 * they cannot leak to the wire.
 */
export interface AuthWfPublicState {
  /** Mirrors `ctx.consents` — pending descriptor list + decision marker. */
  consents?: { pending?: ConsentDescriptorLike[]; decidedAt?: number };
  /** Mirrors `ctx.altActions` — which alt-action buttons render on login. */
  altActions?: { forgotPassword?: boolean; signup?: boolean; magicLink?: boolean };
  /**
   * Mirrors `ctx.mfa` — only the fields forms read (method picker /
   * useDifferentMethod gating / transport-hint copy). Internal fields like
   * `saveAsDefault`, `ignoreDefault`, `current` stay on `ctx.mfa`.
   */
  mfa?: { method?: MfaTransport; methodCount?: number; enrolledMethods?: MfaSummary[] };
  /**
   * Mirrors `ctx.pincode` — masked recipient + code length + resend
   * timestamp. `channelCooldowns` (the per-channel anti-ping-pong ledger)
   * is deliberately omitted so the FE cannot see which other channels are
   * currently rate-limited.
   */
  pincode?: { sentTo?: string; codeLength?: number; resendAllowedAt?: number };
  /** Mirrors `ctx.trust.optIn` — gates the "Remember this device" checkbox. */
  trust?: { optIn?: boolean };
  /**
   * Mirrors `ctx.password` — policy ruleset for the live-rules renderer
   * plus the per-flow title / intro copy. `changeReason` stays internal —
   * the user-facing copy is already pre-rendered into `heading`/`intro`.
   */
  password?: { heading?: string; intro?: string; policies?: TransferablePolicy[] };
  /** Mirrors `ctx.admin.availableRoles` — the role picker for invites. */
  admin?: { availableRoles?: string[] };
  /** Mirrors `ctx.channel.otpDisclosure` — TCPA/PECR disclosure paragraph. */
  channel?: { otpDisclosure?: string };
  /**
   * Mirrors `ctx.mfaEnroll` — only what the enrolment forms display.
   * `address` stays internal (user-typed, no need to bounce it back).
   */
  mfaEnroll?: {
    method?: MfaTransport;
    mode?: "required" | "optional";
    availableTransports?: MfaTransport[];
    secret?: string;
    uri?: string;
  };
  /** Mirrors `ctx.defaults` — prefill source for the recovery email field. */
  defaults?: { email?: string };
  /**
   * Mirrors `ctx.newPasswordRequired` — hides "Remember this device" on
   * verify forms when a forced password change will follow.
   */
  newPasswordRequired?: boolean;
}

/** Unified workflow context shape — one type for all three flows. */
export interface AuthWfCtx {
  // ── Identity ──
  username?: string;
  email?: string;
  defaults?: AuthWfDefaults;

  // ── Server-only secrets (never @wf.context.pass) ──
  pin?: string;
  pinExpire?: number;
  /** Wrong-code attempt counter for the currently minted pincode. Reset by `mintPin`; incremented by `verifyPin`; cleared when the cap is hit (which also clears `pin`/`pinExpire` so the user must request a fresh code). */
  pinAttempts?: number;
  aborted?: boolean;

  // ── Semantic flags ──
  isFirstLogin?: boolean;
  newPasswordRequired?: boolean;
  // Mirrors `AuthWorkflowOpts.autoLoginOn{Invite|Recover}` onto ctx so the
  // finalize-* schema conditions can read it — wf engine invokes condition
  // closures as plain functions, so `this.opts` is not reachable from inside
  // the schema literal. Populated by `init-invite-admin` / `init-invite-accept`
  // (from `autoLoginOnInvite`) and `init-recovery` (from `autoLoginOnRecover`).
  autoLogin?: boolean;

  // ── Shared state groups (passed via @wf.context.pass) ──
  consents?: AuthWfConsentsState;
  pincode?: AuthWfPincodeUiState;
  mfaEnroll?: AuthWfMfaEnrollState;
  password?: AuthWfPasswordUiState;
  completion?: AuthWfCompletionState;

  // ── Resolved policy groups (set by prepare-* @Steps) ──
  alternateCredentials?: AuthWfAltCredsPolicy; // [login]
  deviceTrust?: AuthWfDeviceTrustPolicy; // [login]
  enrollment?: AuthWfEnrollmentPolicy; // [login]
  finalize?: AuthWfFinalizePolicy; // [login]
  guards?: AuthWfGuardsPolicy; // [login]
  sessionPolicy?: AuthWfSessionPolicy; // [login]
  mfaPolicy?: AuthWfMfaPolicy; // [login + invite]
  adminForm?: AuthWfAdminFormPolicy; // [invite admin]
  accept?: AuthWfAcceptState; // [invite accept]
  postReset?: AuthWfPostResetState; // [recovery]
  recoveryAltActions?: AuthWfRecoveryAltActions; // [recovery]
  // Note: `ctx.audit` REMOVED — audit handled at interceptor level.

  // ── Per-event state groups ──
  mfa?: AuthWfMfaState; // [login + invite]
  channel?: AuthWfChannelState; // [login]
  trust?: AuthWfTrustState; // [login]
  session?: AuthWfSessionState; // [login]
  altActions?: AuthWfAltActionsState; // [login]
  admin?: AuthWfAdminState; // [invite admin]
  otp?: AuthWfOtpState; // [all flows]

  // ── Low-cardinality top-level flags ──
  isPasswordInitial?: boolean; // [login]
  isPasswordExpired?: boolean; // [login]

  /**
   * FE-facing surface — the ONLY top-level ctx key whitelisted on form
   * schemas. Populated by `AuthWorkflow.populatePublic(ctx)` at every pause
   * boundary; see `AuthWfPublicState` for the exact mirror shape. Never
   * write to other `ctx.<group>` slots from form schemas — they're internal.
   */
  public?: AuthWfPublicState;
}
