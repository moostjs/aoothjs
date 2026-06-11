/**
 * Unified `AuthWfCtx` — context shape for the consolidated `AuthWorkflow`
 * class. One ctx interface covers all three `@Workflow` schemas
 * (`login.flow`, `invite.start`, `recovery.flow`); per-flow slots are
 * optional and discriminated by ctx-slot presence.
 *
 * Replaces the prior `LoginWfCtx` / `InviteWfCtx` / `RecoveryWfCtx` trio.
 */
import type { FederatedProfileSnapshot, TransferablePolicy } from "@aooth/user";

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
  /** Provider id — matches an `OAuthProviderRegistry` entry; sent as `ssoProvider` data on the `sso` action. */
  id: string;
  /** Provider display name — the bundled `AsSsoProviders` renders "Continue with {label}". */
  label: string;
  /** Optional icon hint for the button (e.g. an icon-class key the renderer maps). */
  icon?: string;
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
  /**
   * Drives skip / cancel visibility on the enrolment forms:
   * - `'optional'` — login/invite first-time opt-in: "Skip for now" shows.
   * - `'required'` — forced enrolment: neither skip nor cancel.
   * - `'manage'` — the standalone manage-MFA flow (user opened it on purpose):
   *   "Skip for now" is hidden, a "Cancel" action shows instead.
   */
  mode?: "required" | "optional" | "manage";
  done?: boolean;
  /**
   * Gates the standalone `enroll-totp-qr` step (TOTP only). Set once the user
   * has been shown the QR/secret and clicked Continue, so the QR pause fires
   * before — not alongside — the code-entry step. Shared by both surfaces.
   */
  qrSeen?: boolean;
  /**
   * When set, `enroll-confirm` does NOT make the freshly-confirmed method the
   * user's default. Set by `init-add-mfa` (the standalone add-MFA flow) when the
   * user already has a default — adding a secondary factor must not silently
   * change which method is challenged first. Unset on the login/invite forced-
   * enrolment path (the user has no default yet), so the first method still
   * becomes the default there — behaviour-preserving.
   */
  keepExistingDefault?: boolean;
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
  /** SSO providers offered on the login form — each renders a `sso-<id>` button. */
  ssoProviders?: SsoProvider[];
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

/**
 * Authenticated change-password policy (change-password.flow). Resolved by
 * `resolveChangePasswordPolicy`, written to `ctx.changePassword` by
 * `prepare-change-password`. The flow's whole purpose is gated on this slot's
 * presence (it's also the per-flow discriminator — see the package CLAUDE.md
 * flow-discrimination table).
 *
 * Primary protection is current-password re-entry (enforced by
 * `UserService.changePassword`), NOT rate limiting — so `rateLimit` is
 * optional and off by default.
 *
 * - `revokeOtherSessions` — on success, revoke every session for the user then
 *   re-issue the acting session a fresh token (OWASP Session Management: kill
 *   ghost sessions after a credential change). Default `true`.
 * - `rateLimit.minIntervalMs` — minimum gap between successive password changes
 *   (Okta "minimum password age"). Enforced against `password.lastChanged` with
 *   ZERO extra storage. Omit to disable.
 */
export interface AuthWfChangePasswordPolicy {
  revokeOtherSessions: boolean;
  rateLimit?: { minIntervalMs: number };
}

/**
 * Failed-login lockout posture. Picks HOW a tripped account lockout is lifted:
 * - `admin-only`   — permanent lock; only an admin (UserService.unlockAccount)
 *                    lifts it. The recovery flow may still reset the password
 *                    but does NOT unlock.
 * - `self-service` — permanent lock; completing the recovery (password-reset)
 *                    flow lifts it (`unlock-account` step).
 * - `temporary`    — timed lock; auto-expires after the configured duration
 *                    (UserService `lockout.duration`). Recovery does NOT
 *                    unlock early. This is the default (preserves prior behavior).
 *
 * The mode governs the lock DURATION the workflow asks UserService to apply on
 * the threshold trip (`temporary` → configured duration; the two permanent
 * modes → `0`) and whether recovery runs `unlock-account`. The attempt
 * THRESHOLD and the temporary DURATION themselves remain UserService config.
 */
export type AuthWfLockoutMode = "admin-only" | "self-service" | "temporary";

/** Lockout policy (login + recovery). */
export interface AuthWfLockoutPolicy {
  mode: AuthWfLockoutMode;
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
 * Federated-login (OAuth2 / OIDC) flow state. Populated by the `sso-callback`
 * @Step after a verified provider profile resolves to a user. The login flow
 * runs `sso-callback` (instead of `credentials`) when the start input carries
 * an OAuth callback (`ctx.idpInbound`); `ctx.oauth` set ⇒ this login run came
 * in through the federated leg (a discriminator usable by `resolveXxx` hooks,
 * alongside `ctx.accept` / `ctx.postReset` / `ctx.signup`).
 *
 * Carries NO secret material — the PKCE verifier / nonce / authorization `code`
 * are consumed inside `sso-callback`. The verifier + nonce are RE-DERIVED there
 * from the signed-state seed (HMAC, stateless — no server-side flow store),
 * never stored and never on ctx. Only the post-resolve audit/UX fields land here.
 */
export interface AuthWfOAuthState {
  /** The provider id (`google`, `oidc:<issuer>`, …) the subject authenticated with. */
  provider: string;
  /**
   * The `FederatedLoginService.resolveUser` outcome that set `ctx.subject`.
   * `interactively-linked` is the `prove-control` completion of a `needs-link`
   * (the user proved control of an existing account, after which the verified
   * identity was attached) — recorded distinctly from a returning `linked` for
   * audit fidelity.
   */
  outcome?: "linked" | "created" | "auto-linked" | "interactively-linked";
  /** `true` only for the `created` outcome (a brand-new federated account). */
  isNew?: boolean;
  /**
   * The validated post-login app redirect target carried across the OAuth
   * bounce (signed into `state`, re-validated against the allow-list in
   * `oauth-exchange`). Read by `resolveRedirect` so the `redirect` tail step
   * sends the SPA to the originating page. Same-origin relative path only.
   */
  redirect?: string;
}

/**
 * Pending interactive identity-link state — set by `sso-callback` when
 * `FederatedLoginService.resolveUser` returns `needs-link` (a verified
 * federated profile whose email matches an EXISTING local account under the
 * default `require-interactive-link` policy). The `prove-control` @Step reads
 * this to challenge the user for control of `candidateUserId`; on success it
 * calls `linkIdentity` and only THEN sets `ctx.subject`. Cleared
 * (`delete ctx.pendingLink`) once the link completes, the user cancels, or a
 * terminal failure fires.
 *
 * SECURITY: `candidateUserId` is UNTRUSTED until the proof passes — it must
 * NEVER be copied to `ctx.subject` before then, because `{ break: !ctx.subject }`
 * (the schema gate right after `sso-callback`) is what keeps an unproven user
 * out of the token-issuing tail. The `snapshot` has `profile.raw` stripped (raw
 * claims are never persisted — RFC §7). The OTP-proof code lives HERE, not on the
 * shared top-level `ctx.pin`, so it cannot collide with the post-link MFA loop's
 * own pincode in the same run.
 */
export interface AuthWfPendingLinkState {
  /** The existing local account the verified identity attaches to once control is proven. UNTRUSTED until then. */
  candidateUserId: string;
  /** Provider id (`google`, `oidc:<issuer>`, …) of the verified identity awaiting link. */
  provider: string;
  /** The IdP subject (`sub`) of the verified identity awaiting link. */
  subject: string;
  /** Display snapshot stamped onto the federated row on link (`profile.raw` stripped). */
  snapshot?: FederatedProfileSnapshot;
  /** Validated post-link app redirect, carried from the signed `state`. Same-origin relative path. */
  redirect?: string;
  /** Proof channel: `password` (account has a real password) or `otp` (passwordless → code to the account's OWN confirmed channel). */
  mode: "password" | "otp";
  /** OTP mode only — the candidate's confirmed channel the proof code is delivered to. */
  otpChannel?: "email" | "sms";
  /** OTP mode only — flipped `true` after the first code dispatch so a re-pause doesn't re-send. */
  sent?: boolean;
  /** OTP mode only — epoch ms before which a `resend` is refused (same per-pincode cooldown the MFA loop uses). Armed on every dispatch. */
  resendAllowedAt?: number;
  /** Masked candidate identifier shown on the prove-control form ("an account for a***@x.com exists"). Safe to expose. */
  hint?: string;
  /** OTP mode only — masked delivery target for the "code sent to …" copy. Safe to expose. */
  sentTo?: string;
  // ── OTP proof code — isolated from the MFA-loop's top-level `ctx.pin` ──
  pin?: string;
  pinExpire?: number;
  pinAttempts?: number;
}

/**
 * Standalone add-MFA flow state (`auth/add-mfa/flow`). Populated by
 * `init-add-mfa`; its presence on ctx is the flow discriminator (§ per-flow
 * discrimination — mirrors `ctx.changePassword` / `ctx.signup`). The flow
 * REUSES the login/invite enrolment trio (`enroll-pick-method` /
 * `enroll-address` / `enroll-confirm`), driving it via `ctx.mfaPolicy`
 * narrowed to the un-enrolled transports — so a logged-in user adds exactly the
 * methods they don't already have (single remaining transport auto-picks).
 */
export interface AuthWfAddMfaState {
  /**
   * Transports the user has NOT yet confirmed = resolved
   * `availableTransports` minus already-enrolled. The manage menu offers these
   * as "Add" options (a zero-MFA user goes straight to the enrol picker over
   * the same list). `finish-add-mfa` reads it to distinguish "nothing to add"
   * from "user cancelled".
   */
  candidates?: MfaTransport[];
  /**
   * Transports the user may NOT change or remove via this flow — resolved by
   * `resolveLockedMfaTransports` (default: none). A customer locks a factor
   * whose value IS a login handle (e.g. the MFA email equals the
   * `@aooth.user.email` handle) so the user can't silently desync it here.
   * Locked transports are omitted from the menu's Change/Remove options and
   * re-checked server-side in `manage-menu` / `confirm-remove-mfa`.
   */
  locked?: MfaTransport[];
  /**
   * `true` when the user already has ≥1 confirmed method, so the manage flow
   * must step-up (re-verify identity) BEFORE offering add/change/remove, and
   * shows the management menu. The METHOD of step-up is `stepUpMode`. `false`
   * (zero confirmed methods) skips both — the flow degrades to the first-time
   * enrol picker (the opt-in path).
   */
  stepUpRequired?: boolean;
  /**
   * How the step-up is performed (set by `init-add-mfa` when `stepUpRequired`):
   * - `'mfa'` — the user has ≥1 confirmed factor whose kind is still in the
   *   policy's `availableTransports`, so `mfaStepUpLoop` challenges it.
   * - `'password'` — every confirmed factor is of a kind the policy no longer
   *   allows (none is challengeable), so `manage-password-reauth` re-verifies
   *   via the account password instead. Fail-closed fallback that keeps "prove
   *   identity before managing factors" intact even after a policy tightening
   *   orphaned the only enrolled factor.
   */
  stepUpMode?: "mfa" | "password";
  /**
   * Set once the step-up factor verifies AND the flow has swapped off the
   * encapsulated start onto the durable `store` strategy (server-anchored,
   * replay-resistant). Gates the one-time swap + the management menu.
   */
  stepUpDone?: boolean;
  /** The management action the user picked on the menu. */
  action?: "add" | "replace" | "remove";
  /** The transport the chosen `action` applies to. */
  target?: MfaTransport;
  /** Set by `confirm-remove-mfa` so `finish-add-mfa` can report which factor was removed. */
  removed?: MfaTransport;
}

/**
 * Self-signup flow state. Populated by `init-signup` (policy from
 * `resolveSignupPolicy`) and `signup-form` (the `submitted` marker). Its
 * presence on ctx is the signup-flow discriminator (§ per-flow discrimination):
 * `ctx.signup` set ⇒ `auth/signup/flow` is running (mirrors `ctx.accept` /
 * `ctx.postReset` / `ctx.changePassword` for the other flows).
 */
export interface AuthWfSignupState {
  /** Resolved gate — `false` (the default) disables self-signup; `init-signup` emits a terminal "signups are disabled" finish. */
  allowSignup?: boolean;
  /** When `true`, the signup form collects a `username` distinct from the email; otherwise `username := email`. */
  collectUsername?: boolean;
  /** Set by `signup-form` once a valid email (+ optional username) is submitted — gates the OTP loop. */
  submitted?: boolean;
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
  /** Mirrors `ctx.altActions` — which alt-action buttons render on login (incl. SSO providers). */
  altActions?: {
    forgotPassword?: boolean;
    signup?: boolean;
    magicLink?: boolean;
    ssoProviders?: SsoProvider[];
  };
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
  mfaEnroll?: Pick<
    AuthWfMfaEnrollState,
    "method" | "mode" | "availableTransports" | "secret" | "uri"
  >;
  /**
   * Mirrors the manage-MFA menu inputs — the un-enrolled transports the user
   * can Add and the locked transports to omit from Change/Remove. The enrolled
   * method list the menu cross-references is `public.mfa.enrolledMethods`.
   */
  manage?: { candidates?: MfaTransport[]; locked?: MfaTransport[] };
  /** Mirrors `ctx.defaults` — prefill source for the recovery email field. */
  defaults?: { email?: string };
  /**
   * Mirrors `ctx.pendingLink` display fields — the proof `mode`, the masked
   * account `hint` ("an account for a***@x.com exists"), the masked delivery
   * `sentTo` (OTP mode), and the `resendAllowedAt` cooldown the resend button
   * reads to disable/count-down. Only masked/UX fields are projected — the
   * `candidateUserId` / provider `subject` / proof `pin` stay server-only.
   */
  proveControl?: {
    mode?: "password" | "otp";
    hint?: string;
    sentTo?: string;
    resendAllowedAt?: number;
  };
  /**
   * Mirrors `ctx.newPasswordRequired` — hides "Remember this device" on
   * verify forms when a forced password change will follow.
   */
  newPasswordRequired?: boolean;
  /**
   * Mirrors the display-only fields of `ctx.authz` — the requesting client's
   * id/name, granted scope, and the VALIDATED redirect host (the trustworthy
   * identity shown next to the attacker-choosable `clientName`), shown on the
   * authorize-consent form. The `handle` and the `approved` gate stay
   * server-only (never whitelisted onto the wire).
   */
  authz?: { clientName?: string; scope?: string; redirectHost?: string };
}

/** Unified workflow context shape — one type for all three flows. */
export interface AuthWfCtx {
  // ── Identity ── `subject` is the stable user id (the token subject), set by
  // the credentials/change-password/invite steps and passed to `auth.issue`.
  subject?: string;
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
  /**
   * Marks that the `promote-to-handle` @Step has already run for this flow, so
   * it fires once after a channel is confirmed and is skipped on every later
   * resume (the store write is idempotent, but re-running it each resume would
   * be wasteful). Server-only — never `@wf.context.pass`'d.
   */
  promoteToHandleDone?: boolean;

  // ── Resolved policy groups (set by prepare-* @Steps) ──
  alternateCredentials?: AuthWfAltCredsPolicy; // [login]
  deviceTrust?: AuthWfDeviceTrustPolicy; // [login]
  enrollment?: AuthWfEnrollmentPolicy; // [login]
  finalize?: AuthWfFinalizePolicy; // [login]
  guards?: AuthWfGuardsPolicy; // [login]
  lockout?: AuthWfLockoutPolicy; // [login + recovery]
  sessionPolicy?: AuthWfSessionPolicy; // [login]
  changePassword?: AuthWfChangePasswordPolicy; // [change-password] — also the flow discriminator
  signup?: AuthWfSignupState; // [signup] — also the flow discriminator
  addMfa?: AuthWfAddMfaState; // [add-mfa] — also the flow discriminator
  oauth?: AuthWfOAuthState; // [oauth] — also the flow discriminator
  pendingLink?: AuthWfPendingLinkState; // [login — federated needs-link, gates the prove-control step]
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
   * Captured by `init-login` when the START input is an OAuth callback (signed
   * `state` present). Presence routes the login schema to `sso-callback` and
   * skips `credentials`; `sso-callback` reads the callback inputs from HERE (not
   * the step input) because the wf engine clears the step input after
   * `init-login` runs — before `sso-callback` (the next step) executes.
   */
  idpInbound?: { code?: string; state: string; error?: string }; // [login — federated leg]

  /**
   * Authorization-server marker (AUTH-SERVER.md §4.4). Set when this login was
   * started from `GET /auth/authorize` — `init-login` raises it from the START
   * input `authz` (the opaque pending-authorization handle), and `sso-callback`
   * re-raises it from the federated `state.handle` when the user took a
   * "Continue with <provider>" detour mid-authorize. Presence routes the login
   * tail to the `authz-consent` → `mint-authz-code` terminal (deliver an auth
   * code to the client) INSTEAD of `issue`/`redirect` — no browser session is
   * minted. `clientName`/`scope`/`redirectHost` are staged by `authz-consent`
   * for the consent form's display copy (`redirectHost` is parsed from the
   * VALIDATED redirect — the trustworthy identity next to the registrant-chosen
   * name); `approved` is the explicit user-consent gate the `mint-authz-code`
   * terminal requires before it will mint a code.
   */
  authz?: {
    handle: string;
    clientName?: string;
    scope?: string;
    redirectHost?: string;
    approved?: boolean;
  }; // [login — authorization-server grant]

  /**
   * FE-facing surface — the ONLY top-level ctx key whitelisted on form
   * schemas. Populated by `AuthWorkflow.populatePublic(ctx)` at every pause
   * boundary; see `AuthWfPublicState` for the exact mirror shape. Never
   * write to other `ctx.<group>` slots from form schemas — they're internal.
   */
  public?: AuthWfPublicState;
}
