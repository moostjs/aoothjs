/**
 * Named workflow-option presets selected per-request via the `x-wf-variant`
 * HTTP header. Playwright sets the header on each `<AsWfForm>` trigger so the
 * single backend can serve every variant in `USER_STORIES.md` §3/4/5 without
 * spinning a fresh process per profile.
 *
 * The maps below are `Partial<...Opts>` (recovery + invite) or
 * `{ opts?, mfaCtx? }` (login) because the demo's `mergeWfOpts` two-level
 * deep merge layers `opts` on top of `demoLoginOpts` / `demoRecoveryOpts` /
 * `demoInviteOpts`, and `mfaCtx` is consumed by the `setMfaMode` /
 * `setMfaTransports` / `setCurrentMfa` overrides on `DemoLoginWorkflow`.
 *
 * PR9 stripped `mfa.mode` / `mfa.transports` from `LoginWorkflowOpts` and
 * `InviteWorkflowOpts`. Those values now live on ctx (populated by atomic
 * `@Step` setters) — variants that previously poked `mfa.mode` /
 * `mfa.transports` via opts now declare them under `mfaCtx`, applied by the
 * setter overrides on `DemoLoginWorkflow`. Other `mfa.*` keys
 * (`backupCodes`, `pincodeResendTimeoutMs`, …) remain on `opts.mfa`.
 */
import type {
  InvitePolicyOverrides,
  InviteWorkflowOpts,
  LoginPolicyOverrides,
  LoginWfCtx,
  LoginWorkflowOpts,
  MfaTransport,
  RecoveryPolicyOverrides,
  RecoveryWorkflowOpts,
} from "@aooth/auth-moost";

// Re-export so consumers that import the demo's variant types keep a single
// import surface (`@e2e-demo` re-exports from "./variants" elsewhere).
export type { InvitePolicyOverrides, LoginPolicyOverrides, RecoveryPolicyOverrides };

/**
 * Static MFA ctx overrides applied by `DemoLoginWorkflow`'s setter steps
 * (`setMfaMode` / `setMfaTransports` / `setCurrentMfa`). PR9 stripped the
 * equivalent `mfa.mode` / `mfa.transports` keys from `LoginWorkflowOpts`;
 * variants that previously poked them via opts now declare them here, applied
 * at request time by the demo's setter overrides. Shape mirrors the
 * `WithLoginMfaCtxOverrides` interface in `test/harness.ts`.
 */
export interface LoginMfaCtxOverrides {
  mfaMode?: "required" | "optional" | "disabled";
  availableMfaTransports?: MfaTransport[];
  currentMfa?: MfaTransport;
}

/**
 * Invite-side counterpart of `LoginMfaCtxOverrides`, applied by
 * `DemoInviteWorkflow`'s `inviteSetMfaMode` / `inviteSetMfaTransports` /
 * `inviteSetEnrollMethod` setter steps. Shape mirrors the
 * `WithInviteMfaCtxOverrides` interface in `test/harness.ts`.
 */
export interface InviteMfaCtxOverrides {
  mfaMode?: "required" | "optional" | "disabled";
  availableMfaTransports?: MfaTransport[];
  enrollMethod?: MfaTransport;
}

// `readVariantHeader` is intentionally NOT imported here — it pulls in
// `@wooksjs/event-http`, which transitively requires `node:async_hooks` and
// breaks the Vue dev-server client bundle when `HomePage.vue` imports the
// variant maps below. The server-side wiring imports it directly from
// `./variants-server` instead. See e2e-demo/CLAUDE.md if you're tempted to
// re-add it here — Playwright tests catch the regression at hydrate time.

/**
 * Per-request `AuthOpts` overlay applied by `DemoLoginWorkflow` /
 * `DemoRecoveryWorkflow` / `DemoInviteWorkflow` ctors (FOR_EVENT scope) on top
 * of the demo's singleton `AuthOpts` instance. After the AuthOpts reshape the
 * cross-workflow knobs (pincode timers, magic-link TTL) live on a SINGLETON
 * provider — variants that need to flip them per-request go through this
 * field instead. Note: `loginUrl` / `totpIssuer` are NOT included here because
 * no current variant flips them per-request (and singleton scope makes that
 * non-trivial; if a future variant needs them, add to the AuthOpts clone path
 * in `cloneAuthOptsWithVariant` in `src/app.ts`).
 */
export interface AuthOptsVariantOverrides {
  mfa?: { pincodeLength?: number; pincodeTtlMs?: number; pincodeResendTimeoutMs?: number };
  magicLinkTtlMs?: number;
}

/**
 * Login variant entry. `opts` carries login-only infrastructure overrides
 * (cookie name/TTL — magic-link TTL + pincode timers moved to `authOpts`).
 * `authOpts` carries per-request overlay onto the singleton `AuthOpts`
 * (pincode cooldown, magic-link TTL).
 * `policy` carries per-request policy groups (alternateCredentials, guards,
 * profile, …) applied by `DemoLoginWorkflow`'s `resolveXxx(ctx)` overrides.
 * `mfaCtx` carries the static MFA-ctx overrides written by the
 * `prepare-mfa-setup` step.
 */
export interface LoginVariant {
  opts?: Partial<LoginWorkflowOpts>;
  authOpts?: AuthOptsVariantOverrides;
  policy?: LoginPolicyOverrides;
  mfaCtx?: LoginMfaCtxOverrides;
}

/**
 * Invite variant entry. `opts` is forms-only after the AuthOpts reshape
 * (magic-link TTL + pincode timers moved). `authOpts` carries per-request
 * overlay onto the singleton `AuthOpts`. `policy` carries per-request policy
 * groups (adminForm, send, accept, cancellation, audit, mfa) applied by
 * `DemoInviteWorkflow`'s `resolveXxx(ctx)` overrides. `mfaCtx` carries the
 * static MFA-ctx overrides written by the `invite-setup-mfa` step.
 */
export interface InviteVariant {
  opts?: Partial<InviteWorkflowOpts>;
  authOpts?: AuthOptsVariantOverrides;
  policy?: InvitePolicyOverrides;
  mfaCtx?: InviteMfaCtxOverrides;
}

/**
 * Login profiles — keys mirror `USER_STORIES.md` §3 variants L-A…L-J plus the
 * dedicated `redirect-home` row used by WF-LOGIN-031.
 */
/**
 * Defaults for the alt-cred policy used in `policy.alternateCredentials`
 * payloads. Mirrors the base `LoginWorkflow.resolveAlternateCredentials`
 * defaults so a variant only needs to flip the flags it cares about.
 */
const ALT_DEFAULTS: NonNullable<LoginWfCtx["alternateCredentials"]> = {
  forgotPassword: true,
  signup: false,
  magicLink: false,
  magicLinkSkipsMfa: false,
  ssoProviders: [],
  recoveryUrl: "/recover",
  signupUrl: "/signup",
  embedRecovery: false,
};

export const LOGIN_VARIANTS: Record<string, LoginVariant> = {
  minimal: {
    // Explicit false on signup/magicLink so the variant clears the demo
    // defaults (which set signup:true for the dev-UI dropdown). Tests assert
    // those alt-action buttons are hidden under `minimal`.
    policy: {
      alternateCredentials: {
        ...ALT_DEFAULTS,
        forgotPassword: true,
        signup: false,
        magicLink: false,
      },
    },
    mfaCtx: { mfaMode: "disabled" },
  },
  "mfa-totp": {
    policy: { mfaConfig: { backupCodes: true } },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["totp"] },
  },
  "mfa-full": {
    policy: { mfaConfig: { backupCodes: true } },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["sms", "email", "totp"] },
  },
  enrollment: {
    policy: { enrollment: { ensureEmail: true, ensurePhone: true } },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["email", "sms", "totp"] },
  },
  "device-trust": {
    policy: { deviceTrust: { enabled: true, optIn: true, skipsMfa: true } },
    // Use email transport so the MFA pause renders `PincodeForm`, which
    // carries the `rememberDevice` checkbox (MfaCodeForm doesn't).
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["email"] },
  },
  guards: {
    policy: {
      guards: { passwordInitial: true, passwordExpiry: true, emailVerifiedRequired: true },
    },
    mfaCtx: { mfaMode: "disabled" },
  },
  // The prior `acceptance` variant relied on `policy.acceptance.termsVersion`
  // driving the standalone bump-prompt; Phase 5 moved the consent half to the
  // customer `ConsentStore` (`VARIANT_PENDING_CONSENTS['acceptance']` in
  // `app.ts`) and Phase 6 moved the `profileCompleteRequired` half to a
  // dedicated `profile.required` knob exercised here.
  acceptance: {
    policy: {
      profile: { required: true },
    },
  },
  // Phase 5 dynamic consent — the customer ConsentStore (DemoConsentStore)
  // keys its `getPendingConsents` off the `x-wf-variant` header to return a
  // 2-descriptor set for this variant (required terms + optional marketing).
  // No enrollment / no profile-complete on this profile so the workflow
  // lands on TermsBumpForm after credentials with the `AsConsentArray`
  // rendered for the `consents: string[]` field. Drives WF-CONSENT-ARRAY-01.
  "consent-array": {
    mfaCtx: { mfaMode: "disabled" },
  },
  // Standalone terms re-acceptance prompt — `termsVersion: 'v3'` (declared by
  // `DemoConsentStore.getPendingConsents` via `VARIANT_PENDING_CONSENTS` in
  // `app.ts`) with NO other carrier form (no enrollment / no profileComplete)
  // so the workflow lands on `TermsBumpForm` after credentials. Drives
  // WF-LOGIN-BUMP-01.
  "terms-bump": {
    mfaCtx: { mfaMode: "disabled" },
  },
  "multi-context": {
    policy: { multiContext: { tenantSelect: true, personaSelect: true } },
  },
  concurrency: {
    policy: { sessionPolicy: { concurrencyLimit: { max: 1, onLimit: "kickPrompt" } } },
  },
  full: {
    policy: {
      alternateCredentials: {
        ...ALT_DEFAULTS,
        forgotPassword: true,
        signup: true,
        magicLink: true,
      },
      guards: { passwordInitial: true, emailVerifiedRequired: true, passwordExpiry: true },
      enrollment: { ensureEmail: true, ensurePhone: true },
      mfaConfig: { backupCodes: true },
      deviceTrust: { enabled: true, optIn: true, skipsMfa: true },
      // Phase 5/6 reshape — the consent half moved to `DemoConsentStore.getPendingConsents`
      // (see `VARIANT_PENDING_CONSENTS['full']` in `app.ts`); `profileCompleteRequired`
      // moved onto the dedicated `profile.required` knob.
      profile: { required: true },
      multiContext: { tenantSelect: true, personaSelect: true },
      sessionPolicy: { concurrencyLimit: { max: 1, onLimit: "kickPrompt" } },
    },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["sms", "email", "totp"] },
  },
  "redirect-home": {
    policy: { finalize: { auditLogin: true, notifyNewDevice: false, redirect: "home" } },
  },
  // Like `mfa-full` but with a 1s pincode-resend cooldown so the resend-throttled
  // / resend-after-cooldown stories (WF-LOGIN-011 / -012) run inside a single e2e
  // tick rather than the 60s production default. Post-AuthOpts reshape the
  // cooldown moved off `opts.mfa` onto the shared `AuthOpts.mfa` provider —
  // declared on the variant's `authOpts` overlay (cloned per-event by
  // `DemoLoginWorkflow`'s ctor; the workflow then reads `this.authOpts.mfa.pincodeResendTimeoutMs`).
  "mfa-fast-resend": {
    authOpts: { mfa: { pincodeResendTimeoutMs: 1000 } },
    policy: { mfaConfig: { backupCodes: true } },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["sms", "email", "totp"] },
  },
  // Like `device-trust` but with `optIn: false` so the workflow does NOT render
  // the `rememberDevice` checkbox on `PincodeForm` (WF-LOGIN-019).
  "device-trust-no-optin": {
    policy: { deviceTrust: { enabled: true, optIn: false, skipsMfa: true } },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["email"] },
  },
  // Like `mfa-totp` but `backupCodes: false` so the `useBackupCode` alt-action
  // MUST be hidden on the MFA forms (WF-LOGIN-014).
  "mfa-no-backup": {
    policy: { mfaConfig: { backupCodes: false } },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["totp"] },
  },
  // 1ms TTL so the cookie minted on the first login is already past `exp`
  // by the time the second login resumes (WF-LOGIN-020). MFA email forces the
  // `device-trust` step to mint a fresh cookie on the first pass.
  "device-trust-short-ttl": {
    opts: { deviceTrust: { ttlMs: 1 } },
    policy: { deviceTrust: { enabled: true, optIn: true, skipsMfa: true } },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["email"] },
  },
  // Same as `concurrency` but rejects with HTTP 429 instead of pausing on
  // kickPrompt (WF-LOGIN-030).
  "concurrency-reject": {
    policy: { sessionPolicy: { concurrencyLimit: { max: 1, onLimit: "reject" } } },
  },
  // ── MFA-enrollment variants (PW MFA coverage PR) ──
  //
  // These pin the auto-pick + skip + useDifferentMethod + resend ergonomics
  // shipped by PR7-1/2 + PR9 end-to-end through the SPA. The vitest suite
  // (auth-moost T1-T7, e2e-demo WF-LOGIN-12/13) covers the wire layer but
  // can't see SPA-side regressions (hidden-fn button visibility, form-scope
  // re-render after action dispatch, action-envelope shape from clickAction).
  //
  // `required` + single transport → `prepareMfaSetup` auto-picks and the
  // login workflow skips EnrollPickMethodForm straight to EnrollConfirmForm
  // (WF-LOGIN-033). The 1-transport gate is what enables auto-pick — drop it
  // or widen to 2+ transports and the picker pause comes back.
  "mfa-enroll-required-totp": {
    mfaCtx: { mfaMode: "required", availableMfaTransports: ["totp"] },
  },
  // `optional` + full transport menu → EnrollPickMethodForm renders with
  // `skip` + per-method picks; EnrollAddressForm renders `useDifferentMethod`
  // (≥2 transports); EnrollConfirmForm renders `resend` + `skip` +
  // `useDifferentMethod`. Drives WF-LOGIN-034 (skip) + WF-LOGIN-035
  // (useDifferentMethod cleanup).
  "mfa-enroll-optional-full": {
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["sms", "email", "totp"] },
  },
  // Same as above but with a 1s pincode-resend cooldown so the
  // resend-throttled / resend-after-cooldown branches (WF-LOGIN-036) run
  // inside one test tick. Mirrors `mfa-fast-resend` for the enrolment side.
  // Cooldown lives on `AuthOpts.mfa` post-AuthOpts reshape — see `mfa-fast-resend`.
  "mfa-enroll-optional-fast-resend": {
    authOpts: { mfa: { pincodeResendTimeoutMs: 1000 } },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["sms", "email", "totp"] },
  },
};

/**
 * Recovery variant entry. `opts` is forms-only after the AuthOpts reshape
 * (magic-link TTL + OTP pincode timers moved). `authOpts` carries per-request
 * overlay onto the singleton `AuthOpts`. `policy` carries per-request policy
 * groups (delivery mode + otpTransports, preReset, postReset, altActions,
 * audit) applied by `DemoRecoveryWorkflow`'s `resolveXxx(ctx)` overrides.
 */
export interface RecoveryVariant {
  opts?: Partial<RecoveryWorkflowOpts>;
  authOpts?: AuthOptsVariantOverrides;
  policy?: RecoveryPolicyOverrides;
}

/**
 * Default-merged `postReset` policy — saves variants from spelling out the
 * full 3-field shape just to flip one flag. Mirrors `RecoveryWorkflow`'s
 * `resolvePostReset` defaults.
 */
const POST_RESET_DEMO_DEFAULTS: NonNullable<RecoveryPolicyOverrides["postReset"]> = {
  revokeAllSessions: true,
  freshLoginRequired: false,
  loginUrl: "/login",
};

/**
 * Recovery profiles — keys mirror `USER_STORIES.md` §4 variants R-A…R-G.
 */
export const RECOVERY_VARIANTS: Record<string, RecoveryVariant> = {
  "default-magiclink": {
    policy: { delivery: { mode: "magicLink", otpTransports: ["email"] } },
  },
  "otp-email": {
    policy: { delivery: { mode: "otp", otpTransports: ["email"] } },
  },
  "otp-sms": {
    policy: { delivery: { mode: "otp", otpTransports: ["sms"] } },
  },
  "otp-both": {
    policy: { delivery: { mode: "otp", otpTransports: ["email", "sms"] } },
  },
  choice: {
    policy: { delivery: { mode: "choice", otpTransports: ["email"] } },
  },
  "pre-factor": {
    policy: { preReset: { requireKnownFactor: true } },
  },
  "fresh-login": {
    policy: {
      postReset: { ...POST_RESET_DEMO_DEFAULTS, freshLoginRequired: true },
    },
  },
  // Fast-expire magic-link variant — WF-RECOVERY-004. The persisted state
  // strategy honours `output.expires` so 1ms guarantees the resumed `wfs`
  // hits the "Invalid or expired workflow state" branch in @wooksjs/event-wf.
  // Magic-link TTL moved off `RecoveryWorkflowOpts.delivery` onto `AuthOpts.magicLinkTtlMs`
  // post-AuthOpts reshape — declared on the variant's `authOpts` overlay.
  "recovery-short-ttl": {
    authOpts: { magicLinkTtlMs: 1 },
    policy: { delivery: { mode: "magicLink", otpTransports: ["email"] } },
  },
  // Short OTP resend cooldown — WF-RECOVERY-010/011. 1s cooldown lets the
  // first `Resend code` click trip the rate-limit branch, while a >1s wait
  // proves a second click after the cooldown sends a fresh code.
  "recovery-fast-resend": {
    authOpts: { mfa: { pincodeResendTimeoutMs: 1000 } },
    policy: { delivery: { mode: "otp", otpTransports: ["email"] } },
  },
  // Phase-5 dynamic inline-consent on recovery — `DemoConsentStore` keys its
  // per-variant pending universe so this variant returns a required-terms
  // `v2` descriptor. `AsConsentArray` renders the row on `SetPasswordForm`.
  // Drives WF-RECOVERY-CONSENT-01. Terms-bump is the headline recovery
  // scenario for inline consent ("since you last set your password we
  // updated our terms").
  "recovery-terms-bump": {
    policy: {
      delivery: { mode: "magicLink", otpTransports: ["email"] },
    },
  },
};

/**
 * Default-merged `accept` policy — saves variants from spelling out the full
 * 5-field shape just to flip one flag. Mirrors `InviteWorkflow.resolveAccept`
 * defaults, with `showConfirmation: false` swapped in to match the demo
 * default (existing demo tests assert the auto-login response payload —
 * pre-dating the BIG 3.3 confirmation pause).
 */
const ACCEPT_DEMO_DEFAULTS: NonNullable<InvitePolicyOverrides["accept"]> = {
  alreadyAcceptedRedirectUrl: "/login",
  freshLoginRequired: false,
  loginUrl: "/login",
  showConfirmation: false,
  confirmationMessage: "Your account has been created.",
};

/**
 * Invite profiles — keys mirror `USER_STORIES.md` §5 variants I-A…I-G. Each
 * entry uses the `{ opts?, policy?, mfaCtx? }` shape: `opts` carries infra
 * overrides (TTLs, pincode fields), `policy` carries `resolveXxx`-readable
 * policy groups, `mfaCtx` pushes static ctx through `invite-setup-mfa`.
 */
export const INVITE_VARIANTS: Record<string, InviteVariant> = {
  "email-no-roles": {
    policy: {
      adminForm: { collectRoles: false },
      send: { mode: "email" },
    },
  },
  "roles-profile": {
    policy: {
      adminForm: { collectRoles: true },
      send: { mode: "email" },
    },
  },
  "shareable-link": {
    policy: { send: { mode: "shareableLink" } },
  },
  "choice-freshlogin": {
    policy: {
      send: { mode: "choice" },
      accept: { ...ACCEPT_DEMO_DEFAULTS, freshLoginRequired: true },
    },
  },
  "audit-enabled": {
    policy: { audit: { enabled: true } },
  },
  "cancellation-disabled": {
    policy: { cancellation: { allowed: false } },
  },
  "short-ttl-confirmation": {
    // Invite magic-link TTL moved off `InviteWorkflowOpts.send` onto
    // `AuthOpts.magicLinkTtlMs` post-AuthOpts reshape — declared on the
    // variant's `authOpts` overlay (cloned per-event by `DemoInviteWorkflow`'s ctor).
    authOpts: { magicLinkTtlMs: 1000 },
    policy: { accept: { ...ACCEPT_DEMO_DEFAULTS, showConfirmation: true } },
  },
  // Surfaces the confirmation message in the finish envelope (WF-INVITE-020).
  // Demo's other variants leave the message blank.
  "confirmation-message": {
    policy: {
      accept: {
        ...ACCEPT_DEMO_DEFAULTS,
        showConfirmation: true,
        confirmationMessage: "Your account has been created.",
      },
    },
  },
  // Enables the secondary 'Request a new invite' button on the
  // idempotent-redirect step (WF-INVITE-010).
  "idempotent-redirect": {
    policy: { accept: { ...ACCEPT_DEMO_DEFAULTS, alreadyAcceptedRedirectUrl: "/login" } },
  },
  // ── MFA-enrollment invite variants (PW MFA coverage PR) ──
  //
  // `optional` + full transport menu on the invite tail → after the invitee
  // sets their password, the workflow pauses on EnrollPickMethodForm.
  // Drives WF-INVITE-018 (skip from EnrollPickMethodForm) and WF-INVITE-019
  // (useDifferentMethod from EnrollConfirmForm after picking totp).
  "invite-mfa-optional-full": {
    policy: {
      adminForm: { collectRoles: false },
      send: { mode: "email" },
    },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["sms", "email", "totp"] },
  },
  // Phase-5 dynamic inline-consent on invite — `DemoConsentStore` keys its
  // per-variant pending universe so the `invite-terms` variant returns a
  // required-terms `v1` descriptor. `AsConsentArray` renders the row on
  // `SetPasswordForm`. Drives WF-INVITE-CONSENT-01. `mfaMode: 'disabled'`
  // so the test stays focused on the consent path without an MFA pause.
  "invite-terms": {
    policy: {
      adminForm: { collectRoles: false },
      send: { mode: "email" },
    },
    mfaCtx: { mfaMode: "disabled" },
  },
};

/**
 * Look up a variant preset by name. Returns `undefined` when `name` is missing
 * or not registered — the caller falls back to the bare demo opts. Silent on
 * miss by design: Playwright sets the header explicitly per spec, and a
 * mistyped variant should not log-spam the dev server.
 */
export function pickVariant<T>(
  map: Record<string, T>,
  name: string | null | undefined,
): T | undefined {
  if (!name) return undefined;
  return Object.prototype.hasOwnProperty.call(map, name) ? map[name] : undefined;
}
