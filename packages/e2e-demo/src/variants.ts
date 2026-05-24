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
  RecoveryWorkflowOpts,
} from "@aooth/auth-moost";

// Re-export so consumers that import the demo's variant types keep a single
// import surface (`@e2e-demo` re-exports from "./variants" elsewhere).
export type { InvitePolicyOverrides, LoginPolicyOverrides };

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
 * Login variant entry. `opts` carries infrastructure-only overrides (pincode
 * timers, cookie name/TTL, magic-link TTL) merged into `demoLoginOpts`.
 * `policy` carries per-request policy groups (alternateCredentials, guards,
 * acceptance, …) applied by `DemoLoginWorkflow`'s `resolveXxx(ctx)` overrides.
 * `mfaCtx` carries the static MFA-ctx overrides written by the
 * `prepare-mfa-setup` step.
 */
export interface LoginVariant {
  opts?: Partial<LoginWorkflowOpts>;
  policy?: LoginPolicyOverrides;
  mfaCtx?: LoginMfaCtxOverrides;
}

/**
 * Invite variant entry — `{ opts?, policy?, mfaCtx? }`. `opts` carries
 * infrastructure overrides (magic-link TTL, pincode timers, forms) merged into
 * `demoInviteOpts`. `policy` carries per-request policy groups (adminForm,
 * send, accept, cancellation, audit, mfa) applied by `DemoInviteWorkflow`'s
 * `resolveXxx(ctx)` overrides. `mfaCtx` carries the static MFA-ctx overrides
 * written by the `invite-setup-mfa` step.
 */
export interface InviteVariant {
  opts?: Partial<InviteWorkflowOpts>;
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
  acceptance: {
    policy: {
      acceptance: {
        termsVersion: "v1",
        profileCompleteRequired: true,
        consentMarketing: true,
      },
    },
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
      acceptance: {
        termsVersion: "v1",
        profileCompleteRequired: true,
        consentMarketing: true,
      },
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
  // tick rather than the 60s production default.
  "mfa-fast-resend": {
    opts: {
      mfa: { pincodeResendTimeoutMs: 1000 },
    },
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
  "mfa-enroll-optional-fast-resend": {
    opts: { mfa: { pincodeResendTimeoutMs: 1000 } },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["sms", "email", "totp"] },
  },
};

/**
 * Recovery profiles — keys mirror `USER_STORIES.md` §4 variants R-A…R-G.
 */
export const RECOVERY_VARIANTS: Record<string, Partial<RecoveryWorkflowOpts>> = {
  "default-magiclink": {
    delivery: { mode: "magicLink" },
  },
  "otp-email": {
    delivery: { mode: "otp", otp: { transports: ["email"] } },
  },
  "otp-sms": {
    delivery: { mode: "otp", otp: { transports: ["sms"] } },
  },
  "otp-both": {
    delivery: { mode: "otp", otp: { transports: ["email", "sms"] } },
  },
  choice: {
    delivery: { mode: "choice" },
  },
  "pre-factor": {
    preReset: { requireKnownFactor: true },
  },
  "fresh-login": {
    postReset: { freshLoginRequired: true, revokeAllSessions: true },
  },
  // Fast-expire magic-link variant — WF-RECOVERY-004. The persisted state
  // strategy honours `output.expires` so 1ms guarantees the resumed `wfs`
  // hits the "Invalid or expired workflow state" branch in @wooksjs/event-wf.
  "recovery-short-ttl": {
    delivery: { mode: "magicLink", magicLinkTtlMs: 1 },
  },
  // Short OTP resend cooldown — WF-RECOVERY-010/011. 1s cooldown lets the
  // first `Resend code` click trip the rate-limit branch, while a >1s wait
  // proves a second click after the cooldown sends a fresh code.
  "recovery-fast-resend": {
    delivery: {
      mode: "otp",
      otp: { transports: ["email"], resendCooldownMs: 1000 },
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
    opts: { send: { tokenTtlMs: 1000 } },
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
