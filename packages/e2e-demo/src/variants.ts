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
  InviteWorkflowOpts,
  LoginWorkflowOpts,
  MfaTransport,
  RecoveryWorkflowOpts,
} from "@aooth/auth-moost";

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

/** Login variant entry — opts (merged into `demoLoginOpts`) + mfa ctx overrides. */
export interface LoginVariant {
  opts?: Partial<LoginWorkflowOpts>;
  mfaCtx?: LoginMfaCtxOverrides;
}

/**
 * Login profiles — keys mirror `USER_STORIES.md` §3 variants L-A…L-J plus the
 * dedicated `redirect-home` row used by WF-LOGIN-031.
 */
export const LOGIN_VARIANTS: Record<string, LoginVariant> = {
  minimal: {
    opts: {
      // Explicit false on signup/magicLink so the variant clears the demo
      // defaults (which set signup:true for the dev-UI dropdown). Tests assert
      // those alt-action buttons are hidden under `minimal`.
      alternateCredentials: { forgotPassword: true, signup: false, magicLink: false },
    },
    mfaCtx: { mfaMode: "disabled" },
  },
  "mfa-totp": {
    opts: { mfa: { backupCodes: true } },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["totp"] },
  },
  "mfa-full": {
    opts: { mfa: { backupCodes: true } },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["sms", "email", "totp"] },
  },
  enrollment: {
    opts: { enrollment: { ensureEmail: true, ensurePhone: true } },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["email", "sms", "totp"] },
  },
  "device-trust": {
    opts: { deviceTrust: { enabled: true, optIn: true, skipsMfa: true } },
    // Use email transport so the MFA pause renders `PincodeForm`, which
    // carries the `rememberDevice` checkbox (MfaCodeForm doesn't).
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["email"] },
  },
  guards: {
    opts: { guards: { passwordInitial: true, emailVerifiedRequired: true } },
    mfaCtx: { mfaMode: "disabled" },
  },
  acceptance: {
    opts: {
      acceptance: {
        termsVersion: "v1",
        profileCompleteRequired: true,
        consentMarketing: true,
      },
    },
  },
  "multi-context": {
    opts: { multiContext: { tenantSelect: true, personaSelect: true } },
  },
  concurrency: {
    opts: { sessionPolicy: { concurrencyLimit: { max: 1, onLimit: "kickPrompt" } } },
  },
  full: {
    opts: {
      alternateCredentials: { forgotPassword: true, signup: true, magicLink: true },
      guards: { passwordInitial: true, emailVerifiedRequired: true, passwordExpiry: true },
      enrollment: { ensureEmail: true, ensurePhone: true },
      mfa: { backupCodes: true },
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
    opts: { finalize: { redirect: "home" } },
  },
  // Like `mfa-full` but with a 1s pincode-resend cooldown so the resend-throttled
  // / resend-after-cooldown stories (WF-LOGIN-011 / -012) run inside a single e2e
  // tick rather than the 60s production default.
  "mfa-fast-resend": {
    opts: {
      mfa: { backupCodes: true, pincodeResendTimeoutMs: 1000 },
    },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["sms", "email", "totp"] },
  },
  // Like `device-trust` but with `optIn: false` so the workflow does NOT render
  // the `rememberDevice` checkbox on `PincodeForm` (WF-LOGIN-019).
  "device-trust-no-optin": {
    opts: { deviceTrust: { enabled: true, optIn: false, skipsMfa: true } },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["email"] },
  },
  // Like `mfa-totp` but `backupCodes: false` so the `useBackupCode` alt-action
  // MUST be hidden on the MFA forms (WF-LOGIN-014).
  "mfa-no-backup": {
    opts: { mfa: { backupCodes: false } },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["totp"] },
  },
  // 1ms TTL so the cookie minted on the first login is already past `exp`
  // by the time the second login resumes (WF-LOGIN-020). MFA email forces the
  // `device-trust` step to mint a fresh cookie on the first pass.
  "device-trust-short-ttl": {
    opts: { deviceTrust: { enabled: true, optIn: true, skipsMfa: true, ttlMs: 1 } },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["email"] },
  },
  // Same as `concurrency` but rejects with HTTP 429 instead of pausing on
  // kickPrompt (WF-LOGIN-030).
  "concurrency-reject": {
    opts: { sessionPolicy: { concurrencyLimit: { max: 1, onLimit: "reject" } } },
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
 * Invite profiles — keys mirror `USER_STORIES.md` §5 variants I-A…I-G.
 */
export const INVITE_VARIANTS: Record<string, Partial<InviteWorkflowOpts>> = {
  "email-no-roles": {
    adminForm: { collectRoles: false },
    send: { mode: "email" },
  },
  "roles-profile": {
    adminForm: { collectRoles: true },
    send: { mode: "email" },
  },
  "shareable-link": {
    send: { mode: "shareableLink" },
  },
  "choice-freshlogin": {
    send: { mode: "choice" },
    accept: { freshLoginRequired: true },
  },
  "audit-enabled": {
    audit: { enabled: true },
  },
  "cancellation-disabled": {
    cancellation: { allowed: false },
  },
  "short-ttl-confirmation": {
    send: { tokenTtlMs: 1000 },
    accept: { showConfirmation: true },
  },
  // Surfaces the confirmation message in the finish envelope (WF-INVITE-020).
  // Demo's other variants leave the message blank.
  "confirmation-message": {
    accept: { showConfirmation: true, confirmationMessage: "Your account has been created." },
  },
  // Enables the secondary 'Request a new invite' button on the
  // idempotent-redirect step (WF-INVITE-010).
  "idempotent-redirect": {
    accept: { alreadyAcceptedRedirectUrl: "/login" },
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
