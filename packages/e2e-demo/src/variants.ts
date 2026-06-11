/**
 * Named workflow-option presets selected per-request via the `x-wf-variant`
 * HTTP header. Playwright sets the header on each `<AsWfForm>` trigger so the
 * single backend can serve every variant in `USER_STORIES.md` §3/4/5 without
 * spinning a fresh process per profile.
 *
 * The maps below carry `{ opts?, authOpts?, policy?, mfaCtx? }` slots. `opts`
 * shallow-merges onto the demo's base `AuthWorkflowOpts` at workflow-ctor
 * time. `authOpts` overlays the cross-workflow infrastructure subset (pincode
 * timers) and is merged into `opts` before super(). `policy`
 * supplies per-resolver payloads consulted by `DemoAuthWorkflow`'s
 * `resolveXxx` overrides. `mfaCtx` is consumed by the unified `prepare-mfa`
 * setter override.
 *
 * The unified `AuthWorkflow` replaces the prior three workflows; the policy
 * shapes below are typed against `AuthWfCtx` fields directly.
 */
import type { AuthWfCtx, AuthWorkflowOpts, MfaTransport } from "@aooth/auth-moost";

import { RecoveryIdentifierForm } from "./models/auth-forms.as";

/**
 * Static MFA ctx overrides applied by `DemoAuthWorkflow`'s `prepare-mfa`
 * setter override. Writes onto `ctx.mfaPolicy` (mode + transports) and
 * `ctx.mfa.current` (single-transport auto-pick).
 */
export interface LoginMfaCtxOverrides {
  mfaMode?: "required" | "optional" | "disabled";
  availableMfaTransports?: MfaTransport[];
  currentMfa?: MfaTransport;
}

/**
 * Invite-side counterpart. Writes the same mfaPolicy / enroll-method picks
 * via `prepare-mfa` on the invite-accept resume.
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
 * Per-request infrastructure overlay applied by `DemoAuthWorkflow`'s ctor
 * (FOR_EVENT scope) onto the base `AuthWorkflowOpts`. The cross-workflow
 * knobs (pincode timers) live on `AuthWorkflowOpts` itself — this overlay
 * merges into the workflow opts before super().
 */
export type AuthOptsVariantOverrides = Partial<Pick<AuthWorkflowOpts, "mfa">>;

/**
 * Login-flow resolver overrides. Mirrors the shape of the matching
 * `AuthWfCtx` resolved-policy slots so variants only need to spell out the
 * fields they're overriding.
 */
export interface LoginPolicyOverrides {
  alternateCredentials?: NonNullable<AuthWfCtx["alternateCredentials"]>;
  deviceTrust?: NonNullable<AuthWfCtx["deviceTrust"]>;
  enrollment?: NonNullable<AuthWfCtx["enrollment"]>;
  finalize?: NonNullable<AuthWfCtx["finalize"]>;
  guards?: NonNullable<AuthWfCtx["guards"]>;
  lockout?: NonNullable<AuthWfCtx["lockout"]>;
  sessionPolicy?: NonNullable<AuthWfCtx["sessionPolicy"]>;
  mfaPolicy?: NonNullable<AuthWfCtx["mfaPolicy"]>;
}

/**
 * Invite-flow resolver overrides. `mfa` is unified onto `mfaPolicy` (the
 * legacy split `invite.mfa` resolver was collapsed when the three workflows
 * merged).
 */
export interface InvitePolicyOverrides {
  adminForm?: NonNullable<AuthWfCtx["adminForm"]>;
  accept?: NonNullable<AuthWfCtx["accept"]>;
  mfaPolicy?: NonNullable<AuthWfCtx["mfaPolicy"]>;
}

/**
 * Recovery-flow resolver overrides. The unified `AuthWorkflow` exposes
 * `postReset`, `mfaPolicy`, and `recoveryAltActions` as the recovery-side
 * resolved-policy surface.
 */
export interface RecoveryPolicyOverrides {
  postReset?: NonNullable<AuthWfCtx["postReset"]>;
  lockout?: NonNullable<AuthWfCtx["lockout"]>;
  mfaPolicy?: NonNullable<AuthWfCtx["mfaPolicy"]>;
  recoveryAltActions?: NonNullable<AuthWfCtx["recoveryAltActions"]>;
  /** Recovery OTP delivery model — `"registered"` arms M2 (OTP to a verified row channel). Default M1. */
  deliverySource?: "typed" | "registered";
}

/**
 * Login variant entry. `opts` overlays the demo's base `AuthWorkflowOpts`
 * (forms, device-trust cookie config). `authOpts` overlays the
 * cross-workflow infrastructure subset (pincode timers).
 * `policy` carries per-request resolver overrides. `mfaCtx` pushes static
 * MFA state through the unified `prepare-mfa` setter.
 */
export interface LoginVariant {
  opts?: Partial<AuthWorkflowOpts>;
  authOpts?: AuthOptsVariantOverrides;
  policy?: LoginPolicyOverrides;
  mfaCtx?: LoginMfaCtxOverrides;
}

/**
 * Invite variant entry. Same shape as `LoginVariant`; `policy` consults the
 * invite-flow resolver surface (admin-form, accept, mfaPolicy).
 */
export interface InviteVariant {
  opts?: Partial<AuthWorkflowOpts>;
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
 * payloads. Mirrors the base `AuthWorkflow.resolveAlternateCredentials`
 * defaults so a variant only needs to flip the flags it cares about.
 */
const ALT_DEFAULTS: NonNullable<AuthWfCtx["alternateCredentials"]> = {
  forgotPassword: true,
  signup: false,
  magicLink: false,
  magicLinkSkipsMfa: false,
  ssoProviders: [],
  recoveryUrl: "/recover",
  signupUrl: "/signup",
  embedRecovery: false,
};

/**
 * Shared trust profile for `device-trust-short-ttl` and its `-notify` clone
 * (WF-LOGIN-020 / WF-LOGIN-039) — one source so the clones can't drift.
 */
const SHORT_TTL_TRUST: LoginVariant = {
  opts: { deviceTrust: { ttlMs: 1 } },
  policy: { deviceTrust: { enabled: true, optIn: true, skipsMfa: true } },
  mfaCtx: { mfaMode: "optional", availableMfaTransports: ["email"] },
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
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["totp"] },
  },
  "mfa-full": {
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
  // Drives WF-LOGIN-EXPIRED-01. The `guards.passwordExpiry: true` default
  // (declared by `AuthWorkflow.resolveGuards`) combined with the app-wide
  // `password.maxAgeMs: 365 days` configured in `aooth.ts` causes the
  // `credentials` step to set `ctx.isPasswordExpired = true` for any user
  // whose stored `password.lastChanged` is older than the window. The
  // demo's `t1_stale` seed user is the deterministic hit (lastChanged=1,
  // i.e. epoch+1ms). MFA is disabled so the workflow lands on
  // `SetPasswordForm` immediately after credentials.
  "password-expired": {
    mfaCtx: { mfaMode: "disabled" },
  },
  // Phase 5 moved the consent half to the customer `ConsentStore`
  // (`VARIANT_PENDING_CONSENTS['acceptance']` in `app.ts`).
  acceptance: {},
  // Phase 5 dynamic consent — the customer ConsentStore (DemoConsentStore)
  // keys its `getPendingConsents` off the `x-wf-variant` header to return a
  // 2-descriptor set for this variant (required terms + optional marketing).
  // No enrollment on this profile so the workflow lands on TermsBumpForm
  // after credentials with the `AsConsentArray` rendered for the
  // `consents: string[]` field. Drives WF-CONSENT-ARRAY-01.
  "consent-array": {
    mfaCtx: { mfaMode: "disabled" },
  },
  // Standalone terms re-acceptance prompt — `termsVersion: 'v3'` (declared by
  // `DemoConsentStore.getPendingConsents` via `VARIANT_PENDING_CONSENTS` in
  // `app.ts`) with NO other carrier form (no enrollment) so the workflow
  // lands on `TermsBumpForm` after credentials. Drives WF-LOGIN-BUMP-01.
  "terms-bump": {
    mfaCtx: { mfaMode: "disabled" },
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
      deviceTrust: { enabled: true, optIn: true, skipsMfa: true },
      // Phase 5 reshape — the consent half moved to `DemoConsentStore.getPendingConsents`
      // (see `VARIANT_PENDING_CONSENTS['full']` in `app.ts`).
      sessionPolicy: { concurrencyLimit: { max: 1, onLimit: "kickPrompt" } },
    },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["sms", "email", "totp"] },
  },
  "redirect-home": {
    // `auditLogin` removed from the finalize shape — audit moved to
    // interceptors when the workflows unified.
    policy: { finalize: { notifyNewDevice: false, redirect: "home" } },
  },
  // Like `mfa-full` but with a 1s pincode-resend cooldown so the resend-throttled
  // / resend-after-cooldown stories (WF-LOGIN-011 / -012) run inside a single e2e
  // tick rather than the 60s production default. The cooldown is a
  // cross-workflow infrastructure knob on `AuthWorkflowOpts.mfa.pincodeResendTimeoutMs`;
  // declared via the variant's `authOpts` overlay (merged into the workflow
  // opts at ctor time).
  "mfa-fast-resend": {
    authOpts: { mfa: { pincodeResendTimeoutMs: 1000 } },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["sms", "email", "totp"] },
  },
  // Like `device-trust` but with `optIn: false` so the workflow does NOT render
  // the `rememberDevice` checkbox on `PincodeForm` (WF-LOGIN-019).
  "device-trust-no-optin": {
    policy: { deviceTrust: { enabled: true, optIn: false, skipsMfa: true } },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["email"] },
  },
  // 1ms TTL so the cookie minted on the first login is already past `exp`
  // by the time the second login resumes (WF-LOGIN-020). MFA email forces the
  // `device-trust` step to mint a fresh cookie on the first pass.
  "device-trust-short-ttl": SHORT_TTL_TRUST,
  // Like `device-trust`, but the login FINISHES with a server-driven redirect
  // (`finalize.redirect: "home"`) instead of the demo's default data envelope.
  // This is the path where the trusted-device cookie MUST ride the finish
  // envelope's `cookies` map: the `redirect` step rebuilds the envelope and
  // preserves only `existing.cookies`, so a response-context `setCookie` would
  // be dropped. Drives WF-LOGIN-037 (the cookie-survives-redirect regression).
  "device-trust-redirect": {
    policy: {
      deviceTrust: { enabled: true, optIn: true, skipsMfa: true },
      finalize: { notifyNewDevice: false, redirect: "home" },
    },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["email"] },
  },
  // Always-on device-RECOGNITION notification with the opt-in device-TRUST
  // machinery fully OFF (resolveDeviceTrust default `enabled:false`) and MFA
  // disabled — the leanest profile that can fire `new-device-notice`. Proves
  // recognition is independent of trust: the `device-recognition` step
  // self-gates only on `ctx.subject` + `users.hasDeviceTrustSecret()` (the
  // demo wires `deviceTrust.secret` in `aooth.ts`), and the email gate is
  // `!isFirstLogin && finalize.notifyNewDevice && !trust.recognized`.
  // Drives WF-LOGIN-038.
  "notify-new-device": {
    policy: { finalize: { notifyNewDevice: true, redirect: false } },
    mfaCtx: { mfaMode: "disabled" },
  },
  // Clone of `device-trust-short-ttl` (trust enabled + optIn + email-MFA +
  // 1ms trust-cookie TTL) with `finalize.notifyNewDevice: true` layered on.
  // Drives WF-LOGIN-039 — the headline regression: an EXPIRED trust cookie
  // re-requires MFA on the next login but must NOT re-send the new-device
  // email, because the always-on recognition cookie (180d default TTL) still
  // marks the browser as seen.
  "device-trust-short-ttl-notify": {
    ...SHORT_TTL_TRUST,
    policy: {
      ...SHORT_TTL_TRUST.policy,
      finalize: { notifyNewDevice: true, redirect: false },
    },
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
  // `required` + single transport → `prepareMfa` auto-picks and the
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
    authOpts: { mfa: { pincodeResendTimeoutMs: 1000 } },
    mfaCtx: { mfaMode: "optional", availableMfaTransports: ["sms", "email", "totp"] },
  },
  // ── Lockout posture (resolveLockout) — WF-LOGIN-LOCKOUT-* ──
  // MFA disabled so the bad-login path is pure credentials → lock trip, and a
  // post-unlock login lands straight on `issue` with no MFA noise. The lock
  // duration is forced by the MODE (permanent for admin-only/self-service),
  // overriding the demo's env LOCKOUT_DURATION_MS at lock-set time.
  "lockout-admin-only": {
    mfaCtx: { mfaMode: "disabled" },
    policy: { lockout: { mode: "admin-only" } },
  },
  "lockout-self-service": {
    mfaCtx: { mfaMode: "disabled" },
    policy: { lockout: { mode: "self-service" } },
  },
  "lockout-temporary": {
    mfaCtx: { mfaMode: "disabled" },
    policy: { lockout: { mode: "temporary" } },
  },
};

/**
 * Recovery variant entry. `opts` overlays the demo's base `AuthWorkflowOpts`
 * (forms only). `authOpts` overlays the cross-workflow infrastructure subset
 * (pincode timers). `policy` carries per-request resolver overrides on
 * `postReset` / `mfaPolicy` / `recoveryAltActions`.
 */
export interface RecoveryVariant {
  opts?: Partial<AuthWorkflowOpts>;
  authOpts?: AuthOptsVariantOverrides;
  policy?: RecoveryPolicyOverrides;
}

/**
 * Recovery profiles — keys mirror `USER_STORIES.md` §5 unified recovery
 * matrix. Variants exercise either `postReset` policy, infrastructure
 * overlays (pincode cooldown), or the customer `ConsentStore` per-variant
 * lookup.
 */
export const RECOVERY_VARIANTS: Record<string, RecoveryVariant> = {
  // Flips the static opt so the finish envelope issues tokens instead of
  // redirecting to login (WF-RECOVERY-016). The default (no variant) leaves
  // `autoLoginOnRecover=false`, exercised by WF-RECOVERY-001.
  "recovery-auto-login": {
    opts: { autoLoginOnRecover: true },
  },
  // Fast-expire recovery-state TTL — WF-RECOVERY-004. The wf engine's
  // persisted-state strategy honours `output.expires` on each pause, so 1ms
  // guarantees the next resume hits the "Invalid or expired workflow state"
  // branch.
  "recovery-short-ttl": {
    opts: { recoveryStateTtlMs: 1 },
  },
  // Short OTP resend cooldown — WF-RECOVERY-010/011. 1s cooldown lets the
  // first `Resend code` click trip the rate-limit branch, while a >1s wait
  // proves a second click after the cooldown sends a fresh code.
  "recovery-fast-resend": {
    authOpts: { mfa: { pincodeResendTimeoutMs: 1000 } },
  },
  // Phase-5 dynamic inline-consent on recovery — `DemoConsentStore` keys its
  // per-variant pending universe so this variant returns a required-terms
  // `v2` descriptor. `AsConsentArray` renders the row on `SetPasswordForm`.
  // Drives WF-RECOVERY-CONSENT-01. Terms-bump is the headline recovery
  // scenario for inline consent ("since you last set your password we
  // updated our terms").
  "recovery-terms-bump": {},
  // Recovery-via-SMS (M1) — swaps in a phone-capable identifier form. The user
  // types a phone (their `@aooth.user.phone` handle), `emailToUserId` resolves
  // the account via `findByHandle`, and `DemoAuthWorkflow.resolveRecoveryChannel`
  // infers `sms` from the value shape, so the OTP is delivered by SMS to the
  // typed phone (= the verified handle). Drives WF-RECOVERY-SMS-*.
  "recovery-via-sms": {
    opts: { forms: { recoveryEmailIdentifier: RecoveryIdentifierForm } },
  },
  // Recovery via a REGISTERED channel (M2) — `policy.deliverySource: "registered"`
  // arms `DemoAuthWorkflow.resolveRecoveryDeliverySource`. The user types only an
  // account identifier (a plain username — the `RecoveryIdentifierForm` accepts
  // it, vs the bundled email-only form), `emailToUserId` resolves the account,
  // and the OTP is delivered to a channel already verified on the row
  // (`selectRecoveryRegisteredMethod` — SMS-first), NOT to anything typed. A row
  // with no deliverable confirmed method hits the anti-enumeration generic
  // finish. Drives WF-RECOVERY-REGISTERED-*.
  "recovery-registered": {
    opts: { forms: { recoveryEmailIdentifier: RecoveryIdentifierForm } },
    policy: { deliverySource: "registered" },
  },
  // M2 + a 1s resend cooldown — lets WF-RECOVERY-REGISTERED-05 exercise the
  // request→send TOCTOU: start recovery (first OTP sent), delete the registered
  // method mid-flow, then resend after the cooldown. The resend's pincode-send
  // finds no method and degrades to the generic anti-enumeration finish (never a
  // 500) instead of delivering.
  "recovery-registered-fast-resend": {
    opts: { forms: { recoveryEmailIdentifier: RecoveryIdentifierForm } },
    authOpts: { mfa: { pincodeResendTimeoutMs: 1000 } },
    policy: { deliverySource: "registered" },
  },
  // Lockout unlock-on-reset (WF-LOGIN-LOCKOUT-*) — the recovery side of the
  // same mode chosen on login. `self-service` runs the `unlock-account` step
  // after the reset; `admin-only` does NOT (the account stays frozen).
  "lockout-self-service": {
    policy: { lockout: { mode: "self-service" } },
  },
  "lockout-admin-only": {
    policy: { lockout: { mode: "admin-only" } },
  },
  // admin-only lockout + autoLoginOnRecover — proves the auto-login finalize
  // does NOT mint tokens for an account the reset left frozen (the freeze must
  // outrank auto-login). WF-LOGIN-LOCKOUT-ADMIN-ONLY-AUTOLOGIN.
  "lockout-admin-only-autologin": {
    opts: { autoLoginOnRecover: true },
    policy: { lockout: { mode: "admin-only" } },
  },
};

/**
 * Default-merged `accept` policy — saves variants from spelling out the full
 * 4-field shape just to flip one flag. Mirrors `AuthWorkflow.resolveAccept`
 * defaults, with `showConfirmation: false` swapped in to match the demo
 * default (existing demo tests assert the auto-login response payload —
 * pre-dating the BIG 3.3 confirmation pause).
 */
const ACCEPT_DEMO_DEFAULTS: NonNullable<InvitePolicyOverrides["accept"]> = {
  alreadyAcceptedRedirectUrl: "/login",
  loginUrl: "/login",
  showConfirmation: false,
  confirmationMessage: "Your account has been created.",
};

/**
 * Invite profiles — keys mirror `USER_STORIES.md` §5 variants I-A…I-G. Each
 * entry uses the `{ opts?, policy?, mfaCtx? }` shape: `opts` carries infra
 * overrides (TTLs, pincode fields), `policy` carries `resolveXxx`-readable
 * policy groups, `mfaCtx` pushes static ctx through the unified `prepare-mfa`
 * setter on the invite resume.
 */
export const INVITE_VARIANTS: Record<string, InviteVariant> = {
  "email-no-roles": {
    policy: {
      adminForm: { collectRoles: false },
    },
  },
  "roles-profile": {
    policy: {
      adminForm: { collectRoles: true },
    },
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
