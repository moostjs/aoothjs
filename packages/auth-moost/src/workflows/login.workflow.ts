/**
 * LoginWorkflow — `wfid = 'auth/login/flow'`.
 *
 * Full step catalog per `WF_LOGIN.md`. Every advanced step is gated by the
 * matching `LoginWorkflowOpts` flag so the default-opts flow matches today's
 * "credentials → optional totp MFA → issue tokens" behaviour with no surprise
 * prompts.
 *
 * **Step routing model.** Phase 1's `credentials` step is the main happy
 * path. Alternate credential paths (`magicLink*`, `passkey`, `ssoCallback`)
 * are stubs that throw `HttpError(501)` — the brief allows ships-as-stub for
 * these. Channel-enrollment loops are split into paired `ask/<channel>` +
 * `verify/<channel>` schema entries backed by two parameterized @Step
 * handlers (`ask`, `verify`) that route both email + phone through the same
 * code path via the `:channel(email|phone)` route param.
 *
 * **Alt-action delivery.** The wire shape `<AsWfForm>` emits when an action
 * button is clicked nests the action inside the workflow input envelope:
 * `{ wfs, input: { action: "<id>" } }`. Each form-bearing step reads its
 * alt-action via `useAtscriptWf(form).resolveAction()` — the form's
 * `@ui.form.action` / `@wf.action.withData` whitelist validates the action id
 * and unknown ids throw `StepRetriableError` before the step body runs. SSO
 * provider ids (consumer-configured via
 * `opts.alternateCredentials.ssoProviders[].id`) MUST be declared as phantom
 * `ui.action` fields on the consumer's custom `LoginCredentialsForm`. Action
 * handling runs BEFORE form validation so the user can hit "Forgot password?"
 * / "Cancel" without filling the form.
 *
 * **Consumer subclass pattern (Phase 2 reshape).** Consumers subclass
 * `LoginWorkflow` to override `protected` hook methods. The subclass MUST
 * re-apply `@Inherit() @Controller("auth/login")` and re-declare the
 * constructor signature (TS emits fresh design-paramtypes per class).
 * Re-applying the prefix is load-bearing: moost shallow-merges the
 * subclass's `controller` metadata over the parent's, so a bare
 * `@Controller()` would override the inherited prefix with the empty
 * string and the wfid would lose its `auth/login` namespace.
 * `@Controller(...)` implicitly applies SINGLETON DI scope — workflow
 * controllers hold no
 * per-event mutable state on `this` (per-event state lives on ctx + wooks
 * composables), so one instance per app lifetime is correct.
 *
 * **Side-effect deps as protected methods (this reshape).** The four
 * optional sender/store/emitter DI providers (EmailSender, SmsSender,
 * DeviceTrustStore, AuditEmitter) have been DROPPED from the constructor.
 * Side-effecting hooks live as `protected` methods consumers override:
 *
 *   - `deliver(payload)` — unified email + SMS dispatch. Default throws
 *     `Error("deliver() not configured …")`; override to wire your senders.
 *   - `audit(event)` — fire audit events. Default: no-op.
 *   - `loadTrustedDevice(userId, token, ip?)` — return `true` to grant
 *     trust. Default: delegates to `UserService.verifyTrustedDevice`.
 *   - `storeTrustedDevice(userId, record)` — persist a freshly issued trust
 *     record. Default: delegates to `UserService.addTrustedDevice`.
 *   - `revokeTrustedDevice(userId, token)` — remove a trust record.
 *     Default: delegates to `UserService.revokeTrustedDevice`.
 *
 * Validation of senders is now INHERENT — the first `deliver()` invocation
 * without an override throws. Boot-time "X required when Y enabled" checks
 * are gone for sender/store/emitter; only data-validity checks remain.
 */
import { AuthCredential, type AuthEmailKind, type AuthSmsKind } from "@aooth/auth";
import {
  type MfaMethodInfo,
  type TrustedDeviceRecord,
  UserAuthError,
  UserService,
  maskEmail,
  maskPhone,
} from "@aooth/user";
import { abortWf, finishWf, useAtscriptWf, type WfFinished } from "@atscript/moost-wf";
import { HttpError } from "@moostjs/event-http";
import {
  Step,
  useWfFinished,
  useWfState,
  Workflow,
  WorkflowParam,
  WorkflowSchema,
} from "@moostjs/event-wf";
import { current } from "@wooksjs/event-core";
import { useCookies, useHeaders, useResponse } from "@wooksjs/event-http";
import { Controller, Inherit, Param } from "moost";

import type { AuditEvent } from "../audit/index";
import { AuthOpts } from "../auth.opts";
import { ConsentStore } from "../consent.store";
import { useAuth } from "../auth.composables";
import { Public } from "../auth.decorator";
import {
  type AuthWfCtxBase,
  AuthWorkflowBase,
  consentsPersistTailSchema,
  consentsPreludeSchema,
  type InlineConsentInput,
  type MfaEnrollDeps,
  passwordChangeSchema,
  stripReservedUserKeys,
} from "./auth-workflow.base";
import {
  type ConcurrencyLimitOptions,
  type LoginRedirect,
  type LoginWorkflowOpts,
  type MfaTransport,
  type ResolvedLoginWorkflowOpts,
  type SsoProvider,
  mergeLoginOpts,
} from "./login.workflow.options";

/**
 * MFA verification state — populated across `prepareMfaSetup` /
 * `loadEnrolledMfaMethods` / `selectMfaMethod` / `select2fa` /
 * `pincodeSendLogin` / `pincodeCheckLogin` / `mfaTotp`. Each field is
 * mirrored as a flat-alias on `LoginWfCtx` via dual-write in the matching
 * @Step body; the flat aliases are removed in B1.4 once forms.as migrates
 * to read this group nested.
 */
export interface LoginMfaState {
  enrolledMethods?: MfaSummary[];
  /** Pre-selected MFA transport (e.g. existing-user default, single-transport auto-pick). */
  current?: MfaTransport;
  /** Method selected for THIS verification (per-iteration). */
  method?: "sms" | "email" | "totp";
  saveAsDefault?: boolean;
  ignoreDefault?: boolean;
  checked?: boolean;
  /** Counter incremented by the `risk-step-up` step so MFA reruns for the extra factor. */
  runsRemaining?: number;
  /** Mirror of `enrolledMethods.length` for form hide-logic. */
  methodCount?: number;
  /**
   * 3-state MFA policy:
   *   - `'required'` — MFA enforced; users with 0 methods MUST enroll (no skip).
   *   - `'optional'` — MFA prompted; users with 0 methods see an enrollment
   *     form that offers a `skip` action (in-flight opt-out).
   *   - `'disabled'` — MFA loops never fire; Phase 4 is skipped entirely.
   */
  mode?: "required" | "optional" | "disabled";
  availableTransports?: MfaTransport[];
  /**
   * Per-method "next-allowed-send-at" timestamps. Written by
   * `pincode-send-login` after each send and consulted by `select2fa` to
   * reject re-picking a method while it's still in cooldown.
   */
  pincodeCooldowns?: { sms?: number; email?: number };
}

/**
 * Channel-onboarding state — populated by `ask/:channel` /
 * `verify/:channel` / `credentials` (existing-user channel sync).
 */
export interface LoginChannelState {
  emailConfirmed?: boolean;
  phone?: string;
  phoneConfirmed?: boolean;
  /**
   * Disclosure text rendered beneath the channel input field on
   * `AskEmailForm` / `AskPhoneForm` at ask-time (BEFORE the user submits
   * their email/phone — typing + submitting constitutes implied consent).
   * Forwarded to `consentStore.recordOtpChannelConsent` at `verify/:channel`
   * AFTER the channel is confirmed as an MFA method.
   */
  otpDisclosure?: string;
}

/**
 * Device-trust state — populated by `checkTrustedDevice` / `deviceTrust` /
 * `pincodeCheckLogin` / `mfaTotp` (rememberDevice opt-in).
 */
export interface LoginTrustState {
  deviceTrustToken?: string;
  /** Set true at MFA gate when no trust cookie matched → trigger `notify-new-device`. */
  newDevice?: boolean;
  /** Captured from the OTP/pincode form when `opts.deviceTrust.optIn`. */
  rememberDevice?: boolean;
  /** Mirror of `opts.deviceTrust.optIn`. Passed to `PincodeForm` so the `rememberDevice` checkbox can hide when the consumer's device-trust is off-by-default (no user choice to make). */
  optIn?: boolean;
}

/**
 * Session-policy state — populated by `loadActiveSessions` / `riskStepUp`.
 */
export interface LoginSessionState {
  riskStepUpReason?: string;
  activeSessions?: number;
  /** Tracks whether `risk-step-up` has already been evaluated this iteration. */
  riskStepUpEvaluated?: boolean;
}

/**
 * Alt-credential mirror flags — populated by `credentials` from the
 * resolved `alternateCredentials` policy so `@ui.form.fn.hidden` can hide
 * disabled action buttons. `usedMagicLink` is reserved for the magic-link
 * branch (currently a stub).
 */
export interface LoginAltActionsState {
  forgotPassword?: boolean;
  signup?: boolean;
  magicLink?: boolean;
  usedMagicLink?: boolean;
}

export interface LoginWfCtx extends AuthWfCtxBase {
  // ── Policy (populated by prepare-* steps; reads via resolveXxx() getters) ──
  /**
   * Whether the user must complete profile fields BEFORE token issuance.
   * Populated by `prepare-profile` from `resolveProfile(ctx).required`.
   * Default-false matches the prior behavior (most consumers don't gate logins
   * on profile completion). Read by the `profile-complete` schema condition.
   */
  profileCompleteRequired?: boolean;
  alternateCredentials?: {
    forgotPassword: boolean;
    signup: boolean;
    magicLink: boolean;
    magicLinkSkipsMfa: boolean;
    ssoProviders: SsoProvider[];
    recoveryUrl: string;
    signupUrl: string;
    embedRecovery: boolean;
  };
  deviceTrust?: {
    enabled: boolean;
    optIn: boolean;
    skipsMfa: boolean;
  };
  enrollment?: {
    ensureEmail: boolean;
    ensurePhone: boolean;
  };
  finalize?: {
    auditLogin: boolean;
    notifyNewDevice: boolean;
    redirect: LoginRedirect;
  };
  guards?: {
    passwordInitial: boolean;
    passwordExpiry: boolean;
    emailVerifiedRequired: boolean;
  };
  sessionPolicy?: {
    concurrencyLimit?: ConcurrencyLimitOptions;
  };

  // ── Login-local state groups ──
  mfa?: LoginMfaState;
  channel?: LoginChannelState;
  trust?: LoginTrustState;
  session?: LoginSessionState;
  altActions?: LoginAltActionsState;

  // ── Low-cardinality top-level flags (don't fit any group) ──
  /** Legacy alias for `pwReset`; kept until tests migrate. */
  mfaRequired?: boolean;
  /** Per-event guards STATE flag paired with `guards.passwordInitial` policy. */
  isPasswordInitial?: boolean;
  /**
   * Per-event guards STATE flag paired with `guards.passwordExpiry` policy.
   * Set in `credentials` when `guards.passwordExpiry` is true AND
   * `UserService.isPasswordExpired(user)` returns true. Combined with
   * `isPasswordInitial` in the forced-change schema condition — either
   * being truthy routes the user through `prepare-password-rules` +
   * `create-password-form`. Reset after `create-password-form` commits.
   */
  isPasswordExpired?: boolean;
  /** Resume-from-pause idempotency flag for the profile-complete step. */
  profileApplied?: boolean;
  /** Injected by consumer subclass / credentials override to surface missing profile fields. */
  profileMissingFields?: string[];

  // ── Flat aliases (compat) — removed in B1.4 once forms.as migrates to nested ──
  //
  // Each one mirrors a `ctx.<group>.<field>` on `LoginWfCtx` (login-local
  // groups above) or on `AuthWfCtxBase` (shared groups) via dual-write in
  // the step bodies below; kept here for forms.as `@wf.context.pass 'flatKey'`
  // compat. Type-safe consumers should read the nested form.

  // MFA verification (mirrors `ctx.mfa.*`):
  /** Flat alias for `ctx.mfa.enrolledMethods`. */
  mfaEnrolledMethods?: MfaSummary[];
  /** Flat alias for `ctx.mfa.current`. */
  currentMfa?: MfaTransport;
  /** Flat alias for `ctx.mfa.method`. */
  mfaMethod?: "sms" | "email" | "totp";
  /** Flat alias for `ctx.mfa.saveAsDefault`. */
  mfaSaveAsDefault?: boolean;
  /** Flat alias for `ctx.mfa.ignoreDefault`. */
  ignoreMfaDefault?: boolean;
  /** Flat alias for `ctx.mfa.checked`. */
  mfaChecked?: boolean;
  /** Flat alias for `ctx.mfa.runsRemaining`. */
  mfaRunsRemaining?: number;
  /** Flat alias for `ctx.mfa.methodCount`. */
  mfaMethodCount?: number;
  /** Flat alias for `ctx.mfa.mode`. */
  mfaMode?: "required" | "optional" | "disabled";
  /** Flat alias for `ctx.mfa.availableTransports`. */
  availableMfaTransports?: MfaTransport[];
  /** Flat alias for `ctx.mfa.pincodeCooldowns`. */
  pincodeCooldowns?: { sms?: number; email?: number };

  // Channel (mirrors `ctx.channel.*`; `ctx.email` stays on AuthWfCtxBase):
  /** Flat alias for `ctx.channel.emailConfirmed`. */
  emailConfirmed?: boolean;
  /** Flat alias for `ctx.channel.phone`. */
  phone?: string;
  /** Flat alias for `ctx.channel.phoneConfirmed`. */
  phoneConfirmed?: boolean;
  /** Flat alias for `ctx.channel.otpDisclosure`. */
  otpDisclosure?: string;

  // Device trust (mirrors `ctx.trust.*`):
  /** Flat alias for `ctx.trust.deviceTrustToken`. */
  deviceTrustToken?: string;
  /** Flat alias for `ctx.trust.newDevice`. */
  newDevice?: boolean;
  /** Flat alias for `ctx.trust.rememberDevice`. */
  rememberDevice?: boolean;
  /** Flat alias for `ctx.trust.optIn`. */
  deviceTrustOptIn?: boolean;

  // Session (mirrors `ctx.session.*`):
  /** Flat alias for `ctx.session.riskStepUpReason`. */
  riskStepUpReason?: string;
  /** Flat alias for `ctx.session.activeSessions`. */
  activeSessions?: number;
  /** Flat alias for `ctx.session.riskStepUpEvaluated`. */
  riskStepUpEvaluated?: boolean;

  // Alt-credential mirrors (mirrors `ctx.altActions.*`):
  /** Flat alias for `ctx.altActions.forgotPassword`. */
  altForgotPassword?: boolean;
  /** Flat alias for `ctx.altActions.signup`. */
  altSignup?: boolean;
  /** Flat alias for `ctx.altActions.magicLink`. */
  altMagicLink?: boolean;
  /** Flat alias for `ctx.altActions.usedMagicLink`. */
  usedMagicLink?: boolean;

  // ── Flat aliases (compat) for AuthWfCtxBase groups — removed in B1.4 ──
  // Each one mirrors a `ctx.<group>.<field>` on `AuthWfCtxBase` via dual-write
  // in the step bodies below; kept here for forms.as `@wf.context.pass 'flatKey'`
  // compat. Type-safe consumers should read the nested form.

  // Password-change UI (mirrors `ctx.password.*`):
  /** Flat alias for `ctx.password.changeReason`. */
  passwordChangeReason?: "initial" | "expired";
  /** Flat alias for `ctx.password.heading`. */
  passwordFormHeading?: string;
  /** Flat alias for `ctx.password.intro`. */
  passwordFormIntro?: string;
}

/**
 * Per-group policy override shape consumed by `resolveXxx(ctx)` subclass
 * overrides. Mirrors the `ctx.<group>` fields that the `prepare-<group>`
 * @Step methods populate — one entry per resolver. Library users typically
 * accept a payload of this shape on their `LoginWorkflow` subclass ctor /
 * test harness and have each `resolveXxx` return its matching key (falling
 * back to `super.resolveXxx(ctx)` for unset groups).
 */
export interface LoginPolicyOverrides {
  /**
   * Override the profile-completion policy (`{ required: boolean }`) — the
   * boolean is mirrored onto `ctx.profileCompleteRequired` by `prepare-profile`
   * and read by the `profile-complete` schema condition.
   */
  profile?: { required: boolean };
  alternateCredentials?: NonNullable<LoginWfCtx["alternateCredentials"]>;
  deviceTrust?: NonNullable<LoginWfCtx["deviceTrust"]>;
  enrollment?: NonNullable<LoginWfCtx["enrollment"]>;
  finalize?: NonNullable<LoginWfCtx["finalize"]>;
  guards?: NonNullable<LoginWfCtx["guards"]>;
  sessionPolicy?: NonNullable<LoginWfCtx["sessionPolicy"]>;
}

export interface MfaSummary {
  kind: "sms" | "email" | "totp";
  /** Underlying `MfaMethod.name` so the workflow can call into UserService. */
  methodName: string;
  masked: string;
  isDefault: boolean;
}

function mfaKindOf(methodName: string): "sms" | "email" | "totp" | null {
  if (methodName === "sms" || methodName === "email" || methodName === "totp") return methodName;
  return null;
}

/**
 * Sentinel returned by alt-action handlers that have already short-circuited
 * the step (via `useWfFinished().set(...)` or by mutating ctx to drive the
 * next iteration). The step body re-returns `undefined` after seeing this so
 * the schema advances without running form validation against the alt-action
 * payload (which lacks the form's required fields).
 */
const ALT_HANDLED: unique symbol = Symbol("ALT_HANDLED");
type AltHandled = typeof ALT_HANDLED;

/**
 * Read a single field from the raw wf input envelope (`wfState.input().formData`)
 * without validating against any form schema. Used by alt-action handlers that
 * carry a payload field outside the current step's form (e.g. the typed
 * `username` read on a `forgotPassword` click before the password is filled
 * in).
 */
function getInputField<T = string>(name: string): T | undefined {
  return useWfState().input<{ formData?: Record<string, T> }>()?.formData?.[name];
}

/**
 * Construction-time invariants for DATA validity only. Sender/store/emitter
 * absence is no longer checked — those default to fail-loud (`deliver()`) or
 * no-op (`audit()`, `loadTrustedDevice()`) protected methods that consumers
 * override.
 */
function validateOpts(_opts: ResolvedLoginWorkflowOpts): void {
  // No cross-field invariants today — mfa mode/transports are now set at
  // runtime via the `prepareMfaSetup` @Step so their emptiness can't be
  // checked at construct time.
}

/**
 * Unified payload for `deliver()` — discriminated by `channel`. `kind`
 * narrows further to the template the consumer should render. The two
 * channels do not share a fields set (email carries `url` for magic links
 * and `expiresAt`; SMS always carries a pincode + `ttlMs`).
 */
export interface DeliverEmail {
  channel: "email";
  /** Template kind — discriminator the consumer uses to pick which email template to render. */
  kind: AuthEmailKind;
  recipient: string;
  /** Numeric pincode (set for `*.pincode` kinds). */
  code?: string;
  /** Magic-link URL (set for `*.magicLink` kinds). */
  url?: string;
  /** Absolute expiry timestamp for the link/code (ms epoch). */
  expiresAt?: number;
  /** Associated user id, when known. */
  userId?: string;
  /** Extra context (e.g. `roles` for invite emails, IP/UA for notifyNewDevice). */
  metadata?: Record<string, unknown>;
}

export interface DeliverSms {
  channel: "sms";
  kind: AuthSmsKind;
  recipient: string;
  /** SMS always carries a pincode — that's the only thing SMS gets used for in this lib. */
  code: string;
  ttlMs?: number;
  userId?: string;
}

export type DeliverPayload = DeliverEmail | DeliverSms;

// `@Public()` marks `arbacPublic` AND `authPublic` on the controller — the
// global `arbacAuthorizeInterceptor` running on WF events bypasses this
// class. Anonymous login is supposed to be reachable without authn, and the
// `/auth/trigger` HTTP route is already `@Public()`; without this marker the
// arbac interceptor would resolve resource→`LoginWorkflow` / action→step
// name on workflow events and either deny (no matching role) or require a
// configured grant.
@Inherit()
@Public()
@Controller("auth/login")
export class LoginWorkflow extends AuthWorkflowBase {
  protected readonly opts: ResolvedLoginWorkflowOpts;
  protected readonly users: UserService;
  protected readonly auth: AuthCredential;
  protected readonly authOpts: AuthOpts;
  protected readonly consentStore: ConsentStore;

  constructor(
    opts: LoginWorkflowOpts,
    users: UserService,
    auth: AuthCredential,
    authOpts: AuthOpts,
    consentStore: ConsentStore,
  ) {
    super();
    this.opts = mergeLoginOpts(opts);
    this.users = users;
    this.auth = auth;
    this.authOpts = authOpts;
    this.consentStore = consentStore;
    validateOpts(this.opts);
  }

  protected get consentsWorkflowId(): string {
    return "auth/login/flow";
  }

  // ── Protected extension surface ───────────────────────────────────────
  /**
   * Dispatch an email or SMS event. Default throws — consumers MUST override
   * if any feature that emits is enabled (MFA pincode, ask/verify channel OTP,
   * notifyNewDevice). The throw surfaces at the HTTP layer as 500 on the
   * first event that triggers a send, which is the fail-loud signal.
   */
  protected async deliver(_payload: DeliverPayload): Promise<void> {
    throw new Error(
      "LoginWorkflow.deliver() not configured — override to wire your email/sms sender",
    );
  }

  /**
   * Emit an audit event. Default: no-op. Consumers override to fan out to
   * their audit sink (DB table, log file, Kafka topic, …).
   */
  protected async audit(_event: AuditEvent): Promise<void> {
    // No-op default.
  }

  /**
   * Verify whether a presented trust-cookie token belongs to `userId` and is
   * still valid. Default: delegates to `UserService.verifyTrustedDevice`
   * (HMAC + persisted record + expiry + IP-binding). Override to use a
   * different trust backend.
   */
  protected async loadTrustedDevice(userId: string, token: string, ip?: string): Promise<boolean> {
    return this.users.verifyTrustedDevice(userId, token, ip);
  }

  /**
   * Persist a freshly-issued trust record. Default: delegates to
   * `UserService.addTrustedDevice` — the record is appended to the user's
   * `trustedDevices` array on the user store. `userId` is the username the
   * record belongs to (passed alongside since `TrustedDeviceRecord` itself
   * carries no user identifier).
   */
  protected async storeTrustedDevice(userId: string, record: TrustedDeviceRecord): Promise<void> {
    await this.withStoreErrorTranslation(() => this.users.addTrustedDevice(userId, record));
  }

  /**
   * Revoke a trust record. Default: delegates to
   * `UserService.revokeTrustedDevice`. Currently unused by the workflow's own
   * happy path but exposed so consumers can call it from their own "sign out
   * everywhere" flows for symmetry with `storeTrustedDevice`.
   */
  protected async revokeTrustedDevice(userId: string, token: string): Promise<void> {
    await this.users.revokeTrustedDevice(userId, token);
  }

  /**
   * Mint a new device-trust record + cookie value. Default: delegates to
   * `UserService.issueTrustedDevice` — produces an HMAC-signed token bound to
   * `userId` (+ `ip` when `bindsTo === 'cookie+ip'`). Consumers running
   * multiple instances typically override `loadTrustedDevice`/
   * `storeTrustedDevice` against Redis but keep this default.
   */
  protected async issueTrustedDevice(
    userId: string,
    ip: string | undefined,
    ttlMs: number,
  ): Promise<TrustedDeviceRecord> {
    return this.users.issueTrustedDevice(userId, {
      ttlMs,
      ...(ip !== undefined && { ip }),
    });
  }

  // ── Resolved policy surface (override these to customize per-tenant/per-request behavior) ──
  /**
   * Resolve the profile-completion policy. Returns `{ required: boolean }` —
   * whether the user must complete profile fields (e.g. `firstName` /
   * `lastName`) BEFORE token issuance. Override per-tenant or per-user to
   * gate logins on missing profile fields; the boolean is mirrored onto
   * `ctx.profileCompleteRequired` by `prepare-profile` and read by the
   * `profile-complete` schema condition (which AND-s the gate with
   * `ctx.profileMissingFields.length > 0` so the step only fires when the
   * consumer has surfaced fields to collect — typically populated by a
   * `credentials` override that hydrates `ctx.profileMissingFields` from
   * the user row).
   *
   * Default-false matches the prior behavior — most consumers don't gate
   * logins on profile completion. Async-friendly via the union return type —
   * sync defaults stay sync (engine fast path).
   */
  protected resolveProfile(
    _ctx: LoginWfCtx,
  ): { required: boolean } | Promise<{ required: boolean }> {
    return { required: false };
  }

  /**
   * Resolve the alternate-credentials policy (forgot-password / signup /
   * magic-link / SSO providers + their URLs). Override to enable/disable per
   * tenant. Sync default; async overrides supported.
   */
  protected resolveAlternateCredentials(
    _ctx: LoginWfCtx,
  ):
    | NonNullable<LoginWfCtx["alternateCredentials"]>
    | Promise<NonNullable<LoginWfCtx["alternateCredentials"]>> {
    return {
      forgotPassword: true,
      signup: false,
      magicLink: false,
      magicLinkSkipsMfa: false,
      ssoProviders: [],
      recoveryUrl: "/recover",
      signupUrl: "/signup",
      embedRecovery: false,
    };
  }

  /**
   * Resolve the device-trust policy (enabled / opt-in / skipsMfa). Infrastructure
   * (cookieName / ttlMs / bindsTo) still lives on `this.opts.deviceTrust` since
   * those are app-wide constants, not per-request policy. Sync/async friendly.
   */
  protected resolveDeviceTrust(
    _ctx: LoginWfCtx,
  ): NonNullable<LoginWfCtx["deviceTrust"]> | Promise<NonNullable<LoginWfCtx["deviceTrust"]>> {
    return {
      enabled: false,
      optIn: true,
      skipsMfa: true,
    };
  }

  /**
   * Resolve the channel-enrollment policy (ensureEmail / ensurePhone gates).
   * Override to force email/phone capture per user segment. Sync/async friendly.
   */
  protected resolveEnrollment(
    _ctx: LoginWfCtx,
  ): NonNullable<LoginWfCtx["enrollment"]> | Promise<NonNullable<LoginWfCtx["enrollment"]>> {
    return {
      ensureEmail: false,
      ensurePhone: false,
    };
  }

  /**
   * Resolve the finalize policy (audit emission / new-device notification /
   * redirect target). Override to drive per-tenant audit-log routing or
   * per-app redirect targets. Sync/async friendly.
   */
  protected resolveFinalize(
    _ctx: LoginWfCtx,
  ): NonNullable<LoginWfCtx["finalize"]> | Promise<NonNullable<LoginWfCtx["finalize"]>> {
    return {
      auditLogin: true,
      notifyNewDevice: false,
      redirect: false,
    };
  }

  /**
   * Resolve the guards policy (passwordInitial / passwordExpiry /
   * emailVerifiedRequired). Override per-tenant to tighten or loosen the
   * post-credentials gates. Sync/async friendly.
   *
   * The `passwordExpiry` flag (default `true`) is the per-tenant escape
   * hatch for rotation policy: flip to `false` for SSO-only tenants
   * where the IdP owns rotation, or for service accounts where forced
   * change would break automation. When `true`, the `credentials` step
   * consults `UserService.isPasswordExpired(user)` — which is itself
   * gated on `config.password.maxAgeMs`, so an unset `maxAgeMs` already
   * disables expiry independent of this flag.
   */
  protected resolveGuards(
    _ctx: LoginWfCtx,
  ): NonNullable<LoginWfCtx["guards"]> | Promise<NonNullable<LoginWfCtx["guards"]>> {
    return {
      passwordInitial: true,
      passwordExpiry: true,
      emailVerifiedRequired: false,
    };
  }

  /**
   * Resolve the disclosure text rendered beneath the channel input field on
   * `AskEmailForm` / `AskPhoneForm` at ask-time — BEFORE the user submits
   * their email/phone. Default returns a TCPA / PECR / CASL / GDPR-safe
   * English paragraph that is GENERIC per channel (no target templated in,
   * since the user hasn't submitted it yet). Override per-tenant or per-
   * locale to swap copy (e.g. i18n catalog lookup). The resolved string is
   * mirrored onto `ctx.otpDisclosure`, transported to the SPA via
   * `@wf.context.pass`, and forwarded to
   * `consentStore.recordOtpChannelConsent` at `verify/:channel` AFTER the
   * pincode validates AND the channel is confirmed as an MFA method — the
   * persisted audit record pins BOTH the literal disclosure copy the user
   * saw AND the verified target as a separate field.
   *
   * Disclosure-only is sufficient for transactional security codes by default;
   * customers wanting affirmative consent capture override
   * `ConsentStore.recordOtpChannelConsent` instead. Sync/async friendly.
   */
  protected resolveOtpDisclosure(
    _ctx: LoginWfCtx,
    channel: "email" | "phone",
  ): string | Promise<string> {
    return channel === "phone"
      ? "By providing your phone number, you consent to receive one-time security codes from us via SMS. Message and data rates may apply."
      : "By providing your email address, you consent to receive one-time security codes from us via email. Standard email delivery may apply.";
  }

  /**
   * Resolve the session policy (concurrency limit). Override to enforce a
   * per-tenant or per-user max-concurrent-sessions cap with reject / kickPrompt
   * behaviour. Sync/async friendly.
   */
  protected resolveSessionPolicy(
    _ctx: LoginWfCtx,
  ): NonNullable<LoginWfCtx["sessionPolicy"]> | Promise<NonNullable<LoginWfCtx["sessionPolicy"]>> {
    return {};
  }

  // ── Prepare steps (call resolveXxx getters; populate ctx for schema conditions) ──
  /**
   * Call `resolveProfile(ctx)` and mirror `result.required` onto
   * `ctx.profileCompleteRequired`. Promise-branched body preserves the engine's
   * sync fast path: a sync `resolveProfile` override skips the microtask
   * allocation, while an `async` override is awaited via `.then` before the
   * `profile-complete` schema condition reads the boolean. The resolved POJO
   * is intentionally NOT stashed on ctx as a group — `profileCompleteRequired`
   * is the only field, so a top-level boolean keeps the ctx shape flat.
   */
  @Step("prepare-profile")
  prepareProfile(@WorkflowParam("context") ctx: LoginWfCtx): undefined | Promise<undefined> {
    const result = this.resolveProfile(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.profileCompleteRequired = resolved.required;
        return undefined;
      });
    }
    ctx.profileCompleteRequired = result.required;
    return undefined;
  }

  @Step("prepare-alternate-credentials")
  prepareAlternateCredentials(
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): undefined | Promise<undefined> {
    const result = this.resolveAlternateCredentials(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.alternateCredentials = resolved;
        return undefined;
      });
    }
    ctx.alternateCredentials = result;
    return undefined;
  }

  @Step("prepare-device-trust")
  prepareDeviceTrust(@WorkflowParam("context") ctx: LoginWfCtx): undefined | Promise<undefined> {
    const result = this.resolveDeviceTrust(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.deviceTrust = resolved;
        return undefined;
      });
    }
    ctx.deviceTrust = result;
    return undefined;
  }

  @Step("prepare-enrollment")
  prepareEnrollment(@WorkflowParam("context") ctx: LoginWfCtx): undefined | Promise<undefined> {
    const result = this.resolveEnrollment(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.enrollment = resolved;
        return undefined;
      });
    }
    ctx.enrollment = result;
    return undefined;
  }

  @Step("prepare-finalize")
  prepareFinalize(@WorkflowParam("context") ctx: LoginWfCtx): undefined | Promise<undefined> {
    const result = this.resolveFinalize(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.finalize = resolved;
        return undefined;
      });
    }
    ctx.finalize = result;
    return undefined;
  }

  @Step("prepare-guards")
  prepareGuards(@WorkflowParam("context") ctx: LoginWfCtx): undefined | Promise<undefined> {
    const result = this.resolveGuards(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.guards = resolved;
        return undefined;
      });
    }
    ctx.guards = result;
    return undefined;
  }

  @Step("prepare-session-policy")
  prepareSessionPolicy(@WorkflowParam("context") ctx: LoginWfCtx): undefined | Promise<undefined> {
    const result = this.resolveSessionPolicy(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.sessionPolicy = resolved;
        return undefined;
      });
    }
    ctx.sessionPolicy = result;
    return undefined;
  }

  @Workflow("flow")
  @WorkflowSchema<LoginWfCtx>([
    { id: "init" },
    { id: "credentials" },
    // Alt-action gate — credentials' forgotPassword/signup/sso alt-actions
    // emit a finishWf envelope without setting ctx.username. Halt the schema
    // before downstream steps' `requireUsername` defense throws 500.
    { break: (ctx) => !ctx.username },

    // Resolve all policy groups before any step reads them.
    { id: "prepare-profile" },
    ...consentsPreludeSchema,
    { id: "prepare-alternate-credentials" },
    { id: "prepare-device-trust" },
    { id: "prepare-enrollment" },
    { id: "prepare-finalize" },
    { id: "prepare-guards" },
    { id: "prepare-session-policy" },

    // Phase 1 alt-cred paths — stubs registered for override; never executed.
    {
      condition: () => false,
      steps: [
        { id: "magic-link-request" },
        { id: "magic-link-send" },
        { id: "magic-link-verified" },
        { id: "passkey" },
        { id: "sso-callback" },
      ],
    },

    // Phase 3 enrollment loops — paired ask/verify per channel. The `ask`
    // half collects the address + mints+sends the OTP (pauses on PincodeForm);
    // the `verify` half consumes the pincode submission. Both halves share a
    // single parameterized @Step handler keyed by `:channel(email|phone)`.
    {
      id: "ask/email",
      condition: (ctx) =>
        (!!ctx.enrollment?.ensureEmail || !!ctx.guards?.emailVerifiedRequired) && !ctx.email,
    },
    {
      id: "verify/email",
      condition: (ctx) =>
        (!!ctx.enrollment?.ensureEmail || !!ctx.guards?.emailVerifiedRequired) &&
        !!ctx.email &&
        !ctx.emailConfirmed,
    },
    {
      id: "ask/phone",
      condition: (ctx) => !!ctx.enrollment?.ensurePhone && !ctx.phone,
    },
    {
      id: "verify/phone",
      condition: (ctx) => !!ctx.enrollment?.ensurePhone && !!ctx.phone && !ctx.phoneConfirmed,
    },

    // Phase 4 MFA setup + verification loop:
    { id: "prepare-mfa-setup" },
    {
      while: (ctx) => ctx.mfaMode !== "disabled" && !ctx.mfaChecked,
      steps: [
        {
          id: "check-trusted-device",
          condition: (ctx) =>
            !ctx.mfaChecked && !!ctx.deviceTrust?.enabled && !!ctx.deviceTrust?.skipsMfa,
        },
        { id: "load-enrolled-mfa-methods", condition: (ctx) => !ctx.mfaChecked },
        { id: "select-mfa-method", condition: (ctx) => !ctx.mfaChecked },
        {
          id: "select-2fa",
          condition: (ctx) =>
            !ctx.mfaChecked && !ctx.mfaMethod && (ctx.mfaEnrolledMethods?.length ?? 0) > 1,
        },
        // Pincode pair (sms/email):
        {
          condition: (ctx) =>
            !ctx.mfaChecked && (ctx.mfaMethod === "sms" || ctx.mfaMethod === "email"),
          steps: [
            { id: "pincode-send-login", condition: (ctx) => !ctx.pin },
            { id: "pincode-check-login" },
          ],
        },
        // TOTP branch:
        { id: "mfa-totp", condition: (ctx) => !ctx.mfaChecked && ctx.mfaMethod === "totp" },
        // Forced enrollment trio — `mfaMode !== "disabled"` already enforced by the while-guard.
        // Also gated on `availableMfaTransports.length > 0`: with zero transports
        // there's nothing to enrol into, so optional mode should be treated like
        // disabled (skip the trio entirely). `enrollPickPhase` still defends
        // against the 0-transport case in optional mode (auto-skip) and throws
        // in required mode if a consumer reaches it via a different path.
        {
          condition: (ctx) =>
            !ctx.mfaChecked &&
            (ctx.mfaEnrolledMethods?.length ?? 0) === 0 &&
            (ctx.availableMfaTransports?.length ?? 0) > 0,
          steps: [
            {
              id: "enroll-pick-method",
              condition: (ctx) => !ctx.mfaEnroll?.method,
            },
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
        // Risk step-up — may clear mfaChecked to rearm MFA for another iteration.
        { id: "risk-step-up", condition: (ctx) => !!ctx.mfaChecked && !ctx.riskStepUpEvaluated },
      ],
    },

    // Phase 4 tail — device-trust issuance after a successful MFA:
    {
      id: "device-trust",
      condition: (ctx) =>
        !!ctx.deviceTrust?.enabled &&
        !!ctx.mfaChecked &&
        !!ctx.newDevice &&
        (!ctx.deviceTrust?.optIn || !!ctx.rememberDevice),
    },

    // Phase 5 forced password change:
    {
      condition: (ctx) =>
        (!!ctx.isPasswordInitial || !!ctx.isPasswordExpired) && !ctx.completion?.passwordChanged,
      steps: [...passwordChangeSchema],
    },
    // No abort path from create-password-form anymore — the SetPasswordForm
    // has no alt-actions. The `{ break }` gate is retained for the wrapping
    // schema's `ctx.aborted` propagation contract: any prior step that flips
    // `ctx.aborted` (e.g. concurrency-limit `cancel`) still short-circuits
    // the post-Phase-5 tail without re-checking on each downstream step.
    { break: (ctx) => !!ctx.aborted },

    // Phase 6 acceptance / onboarding — dynamic consents (customer-defined
    // via `ConsentStore.getPendingConsents`, transported on
    // `ctx.consents.pending`) are captured via the inherited `consents:
    // string[]` field from `WithInlineConsentForm` on whichever carrier
    // onboarding form fires first (AskEmailForm / AskPhoneForm /
    // SetPasswordForm / ProfileCompleteForm). When no such carrier form
    // runs but pending consents exist, the standalone `terms-bump-prompt`
    // step fires to render the `AsConsentArray` on `TermsBumpForm`.
    // `persist-consents` then fans one event per pending descriptor
    // (accepted=true|false) out via `ConsentStore.save` in one batched
    // call once `ctx.username` is bound.
    {
      id: "profile-complete",
      condition: (ctx) =>
        !!ctx.profileCompleteRequired &&
        !ctx.profileApplied &&
        (ctx.profileMissingFields?.length ?? 0) > 0,
    },
    // Returning user with pending consents but no onboarding carrier form
    // ran to collect them. Standalone prompt rendering the dynamic
    // `AsConsentArray` on `TermsBumpForm`. Skips when an earlier carrier
    // form already collected (consents.decidedAt set) or when there are no
    // pending consents. `!ctx.aborted` is handled by the upstream
    // `{ break }` gate.
    {
      id: "terms-bump-prompt",
      condition: (ctx) =>
        (ctx.consents?.pending?.length ?? 0) > 0 &&
        !ctx.consents?.decidedAt &&
        !ctx.consents?.persisted,
    },
    // Batched consent persistence — see `consentsPersistTailSchema` for rationale.
    ...consentsPersistTailSchema,

    // Phase 8 session policy:
    {
      condition: (ctx) => !!ctx.sessionPolicy?.concurrencyLimit,
      steps: [
        { id: "load-active-sessions" },
        {
          id: "concurrency-limit",
          condition: (ctx) => (ctx.activeSessions ?? 0) >= ctx.sessionPolicy!.concurrencyLimit!.max,
        },
      ],
    },
    // Abort gate — concurrency-limit 'cancel' alt-action sets ctx.aborted = true.
    { break: (ctx) => !!ctx.aborted },

    // Phase 9 finalize:
    { id: "issue", condition: (ctx) => !ctx.completion?.tokensIssued },
    {
      condition: (ctx) => !!ctx.completion?.tokensIssued,
      steps: [
        { id: "audit-login", condition: (ctx) => !!ctx.finalize?.auditLogin },
        {
          id: "notify-new-device",
          condition: (ctx) => !!ctx.finalize?.notifyNewDevice && !!ctx.newDevice,
        },
        { id: "redirect" },
      ],
    },
  ])
  flow(): void {}

  // ── Phase 0 ───────────────────────────────────────────────────────────
  /**
   * First step of the workflow; remains as a no-op override hook for
   * consumers (e.g. seeding pre-flight ctx fields, capturing request metadata).
   * The pre-PR policy-pojo-on-ctx stash was dropped — policy now lives on
   * `ctx.<group>` populated by the dedicated `prepare-<group>` steps.
   *
   * Return type is `undefined | Promise<undefined>` so consumers can override
   * with `async init(...)` without the default fast-path paying a Promise
   * allocation (the wf engine awaits only when the return value is a Promise).
   */
  @Step("init")
  init(@WorkflowParam("context") _ctx: LoginWfCtx): undefined | Promise<undefined> {
    return undefined;
  }

  /**
   * Prepare MFA setup: writes `ctx.mfaMode`, `ctx.availableMfaTransports`, and
   * (when the user is resolvable) pre-selects `ctx.currentMfa` from the
   * existing-user `defaultMethod` or the single-available-transport auto-pick.
   * Override to compute any of the three from tenant policy / user attrs /
   * request context. Return type allows a sync override (skip the promise
   * round-trip) when no async work is needed — the default body is async only
   * because of the `users.getUser` lookup for `currentMfa`.
   */
  @Step("prepare-mfa-setup")
  prepareMfaSetup(@WorkflowParam("context") ctx: LoginWfCtx): undefined | Promise<undefined> {
    // dual-write — flat alias removed in B1.4
    const mfa = (ctx.mfa ??= {});
    mfa.mode = "optional";
    mfa.availableTransports = ["sms", "email", "totp"];
    ctx.mfaMode = "optional";
    ctx.availableMfaTransports = ["sms", "email", "totp"];
    if (!ctx.username) return undefined;
    return this.users.getUser(ctx.username).then(
      (user) => {
        const confirmed = (user?.mfa?.methods ?? []).filter((m) => m.confirmed);
        if (confirmed.length > 0 && user?.mfa?.defaultMethod) {
          mfa.current = user.mfa.defaultMethod as MfaTransport;
          ctx.currentMfa = user.mfa.defaultMethod as MfaTransport;
          return undefined;
        }
        if ((ctx.availableMfaTransports?.length ?? 0) === 1) {
          mfa.current = ctx.availableMfaTransports![0];
          ctx.currentMfa = ctx.availableMfaTransports![0];
        }
        return undefined;
      },
      (err) => {
        if (err instanceof UserAuthError && err.type === "NOT_FOUND") return undefined;
        throw err;
      },
    );
  }

  // ── Phase 1 ───────────────────────────────────────────────────────────
  @Step("credentials")
  async credentials(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    // `credentials` runs BEFORE the `!ctx.username` gate and the prepare-*
    // steps, but it needs `alternateCredentials` (for alt-action routing)
    // and `guards` (for the passwordInitial flag) in scope. Call the
    // resolvers inline and stash the result on ctx — the prepare-* steps
    // that run later will overwrite with the same value (idempotent) once
    // username is set.
    const altResult = this.resolveAlternateCredentials(ctx);
    const alt = altResult instanceof Promise ? await altResult : altResult;
    ctx.alternateCredentials = alt;
    const guardsResult = this.resolveGuards(ctx);
    const guards = guardsResult instanceof Promise ? await guardsResult : guardsResult;
    ctx.guards = guards;
    // Mirror alt-credentials config into ctx so the form can hide each alt-action
    // button when its corresponding feature is disabled (`@ui.form.fn.hidden`).
    // dual-write — flat alias removed in B1.4
    const altActions = (ctx.altActions ??= {});
    altActions.forgotPassword = alt.forgotPassword;
    altActions.signup = alt.signup;
    altActions.magicLink = alt.magicLink;
    ctx.altForgotPassword = alt.forgotPassword;
    ctx.altSignup = alt.signup;
    ctx.altMagicLink = alt.magicLink;
    const wf = useAtscriptWf(this.opts.forms.loginCredentials);

    // Alt-action routing — handled BEFORE the form-input pause so the user
    // can hit "Forgot password?" without filling in the form at all. The
    // handler returns `ALT_HANDLED` (sentinel) when it has already
    // short-circuited via `finishWf(...)` or by throwing.
    //
    // `wf.resolveAction()` validates the incoming action against the form's
    // static `@ui.form.action` / `@wf.action.withData` whitelist and throws
    // `StepRetriableError` for anything else. The bundled default
    // `LoginCredentialsForm` declares `forgotPassword`, `signup`, and
    // `magicLink` — SSO provider ids (from
    // `opts.alternateCredentials.ssoProviders[].id`) are dynamic per consumer
    // and MUST be declared on the consumer's custom `LoginCredentialsForm` as
    // phantom `ui.action` fields with matching `@ui.form.action 'providerId'`
    // annotations. Without that, `resolveAction()` rejects unknown ids — that
    // is correct and desired (fail-loud).
    const action = wf.resolveAction();
    if (action) {
      // `forgotPassword` needs the typed username to pre-fill recovery. Peek
      // at the raw envelope (no validation) — password is intentionally
      // absent on alt-action submits.
      const typedUsername = getInputField("username");
      const handled = this.handleCredentialsAlt(action, typedUsername, alt);
      if (handled === ALT_HANDLED) return undefined;
    }

    const input = wf.resolveInput() as { username: string; password: string };

    try {
      const result = await this.users.login(input.username, input.password);
      ctx.username = result.user.username;
      // Preserve legacy `mfaRequired` for tests / consumer subclasses; the
      // step catalog decides MFA inclusion via `ctx.mfaMode` + enrolled
      // methods, not this flag.
      ctx.mfaRequired = result.mfaRequired;
      // Phase 2 inline guards:
      if (ctx.guards?.passwordInitial && result.user.password.isInitial) {
        ctx.isPasswordInitial = true;
      }
      // `isPasswordExpired` is independent of `isPasswordInitial` — the user
      // store can carry both flags on a fresh account whose generated
      // password also crossed `maxAgeMs` between createUser and first login.
      // `passwordChangeReason` picks `'initial'` over `'expired'` because a
      // never-used password being "expired" is semantically still its
      // initial set; downstream SPA banner copy keys on this discriminator.
      if (ctx.guards?.passwordExpiry && this.users.isPasswordExpired(result.user)) {
        ctx.isPasswordExpired = true;
      }
      // dual-write — flat alias removed in B1.4
      if (ctx.isPasswordInitial) {
        ctx.passwordChangeReason = "initial";
        (ctx.password ??= {}).changeReason = "initial";
      } else if (ctx.isPasswordExpired) {
        ctx.passwordChangeReason = "expired";
        (ctx.password ??= {}).changeReason = "expired";
      }
      // Sync existing channel state so `ensureEmail`/`ensurePhone` skip
      // when the user already has a confirmed channel.
      // dual-write — flat alias removed in B1.4
      const email = result.user.mfa.methods.find((m) => m.name === "email" && m.confirmed);
      if (email) {
        ctx.email = email.value;
        (ctx.channel ??= {}).emailConfirmed = true;
        ctx.emailConfirmed = true;
      }
      const phone = result.user.mfa.methods.find((m) => m.name === "sms" && m.confirmed);
      if (phone) {
        const channel = (ctx.channel ??= {});
        channel.phone = phone.value;
        channel.phoneConfirmed = true;
        ctx.phone = phone.value;
        ctx.phoneConfirmed = true;
      }
    } catch (err) {
      if (err instanceof UserAuthError) {
        if (err.type === "LOCKED") {
          throw wf.requireInput({ formMessage: "Account locked, please try again later" });
        }
        throw wf.requireInput({ formMessage: "Invalid credentials" });
      }
      throw err;
    }
    return undefined;
  }

  private handleCredentialsAlt(
    action: string,
    typedUsername: string | undefined,
    alt: NonNullable<LoginWfCtx["alternateCredentials"]>,
  ): AltHandled | undefined {
    if (action === "forgotPassword" && alt.forgotPassword) {
      const url = this.resolveRecoveryUrl(typedUsername, alt);
      finishWf({
        next: {
          trigger: "immediate",
          action: { type: "redirect", target: url, reason: "forgot-password" },
        },
      });
      return ALT_HANDLED;
    }
    if (action === "signup" && alt.signup) {
      finishWf({
        next: {
          trigger: "immediate",
          action: { type: "redirect", target: alt.signupUrl, reason: "signup" },
        },
      });
      return ALT_HANDLED;
    }
    if (action === "magicLink" && alt.magicLink) {
      // Magic-link alternate path is a stub. See class doc.
      throw new HttpError(501, "Magic-link login path not implemented in this version");
    }
    const sso = alt.ssoProviders.find((p) => p.id === action);
    if (sso) {
      // Per-provider discriminator so consumer analytics can distinguish which
      // IdP the user picked without parsing the URL.
      finishWf({
        next: {
          trigger: "immediate",
          action: { type: "redirect", target: sso.url, reason: `sso-${sso.id}` },
        },
      });
      return ALT_HANDLED;
    }
    return undefined;
  }

  /**
   * Resolves the redirect URL the `forgotPassword` alt-action navigates to.
   * Receives whatever the user typed into the username field so the recovery
   * page can pre-fill it. Default:
   * `${alternateCredentials.recoveryUrl}?username=${encodeURIComponent(username ?? '')}`.
   * Sync return type only — the caller (`credentials` step's alt-action
   * handler) uses the URL inline; consumers needing async URL construction
   * should override the `credentials` @Step instead. The resolved
   * `alternateCredentials` policy is supplied by the caller so the base impl
   * doesn't have to re-call `resolveAlternateCredentials`.
   */
  protected resolveRecoveryUrl(
    username: string | undefined,
    alt: NonNullable<LoginWfCtx["alternateCredentials"]>,
  ): string {
    return `${alt.recoveryUrl}?username=${encodeURIComponent(username ?? "")}`;
  }

  @Step("magic-link-request")
  magicLinkRequest(): void | Promise<void> {
    throw new HttpError(501, "magic-link-request step not implemented");
  }

  @Step("magic-link-send")
  magicLinkSend(): void | Promise<void> {
    throw new HttpError(501, "magic-link-send step not implemented");
  }

  @Step("magic-link-verified")
  magicLinkVerified(): void | Promise<void> {
    throw new HttpError(501, "magic-link-verified step not implemented");
  }

  @Step("passkey")
  passkey(): void | Promise<void> {
    throw new HttpError(501, "passkey step not implemented");
  }

  @Step("sso-callback")
  ssoCallback(): void | Promise<void> {
    throw new HttpError(501, "sso-callback step not implemented");
  }

  // ── Phase 3: enrollment loops (ask/verify pair per channel) ───────────
  // Split into two parameterized @Step handlers so each schema entry pauses
  // at exactly one form: `ask/<ch>` collects the address + mints the OTP,
  // `verify/<ch>` validates the pincode submission. Both channels (email,
  // phone) route through the SAME handler — the route-param picks the form
  // slot, MFA method name ("email" | "sms"), and deliver-payload shape.
  @Step("ask/:channel(email|phone)")
  async ask(
    @WorkflowParam("context") ctx: LoginWfCtx,
    @Param("channel") channel: "email" | "phone",
  ): Promise<unknown> {
    this.requireUsername(ctx);
    const isEmail = channel === "email";
    // Stash the disclosure BEFORE `useAtscriptWf` / `resolveInput` throws
    // `requireInput` for the AskEmail/AskPhone pause — the wf engine snapshots
    // ctx at the throw site, so setting `otpDisclosure` here is what makes
    // `@wf.context.pass 'otpDisclosure'` ride on the carrier-form pause
    // descriptor (rendered adjacent to the email/phone input → submission =
    // implied consent). Forwarded to `recordOtpChannelConsent` at verify-time.
    const disclosure = await this.resolveOtpDisclosure(ctx, channel);
    // dual-write — flat alias removed in B1.4
    (ctx.channel ??= {}).otpDisclosure = disclosure;
    ctx.otpDisclosure = disclosure;
    const askWf = useAtscriptWf(isEmail ? this.opts.forms.askEmail : this.opts.forms.askPhone);
    const input = askWf.resolveInput() as { email?: string; phone?: string } & InlineConsentInput;
    this.processInlineConsent(ctx, input, askWf);
    const value = (isEmail ? input.email : input.phone) as string;
    const methodName = isEmail ? "email" : "sms";
    const username = ctx.username;
    await this.withStoreErrorTranslation(() =>
      this.users.addMfaMethod(username, { name: methodName, value, confirmed: false }),
    );
    // dual-write — flat alias removed in B1.4
    if (isEmail) ctx.email = value;
    else {
      (ctx.channel ??= {}).phone = value;
      ctx.phone = value;
    }
    const code = this.mintPin(ctx, this.authOpts.mfa.pincodeLength, this.authOpts.mfa.pincodeTtlMs);
    if (isEmail) {
      await this.deliver({
        channel: "email",
        kind: "login.pincode",
        recipient: value,
        code,
        expiresAt: ctx.pinExpire as number,
      });
    } else {
      await this.deliver({
        channel: "sms",
        kind: "login.pincode",
        recipient: value,
        code,
        ttlMs: this.authOpts.mfa.pincodeTtlMs,
        userId: ctx.username,
      });
    }
    const pincodeWf = useAtscriptWf(this.opts.forms.pincode);
    throw pincodeWf.requireInput();
  }

  @Step("verify/:channel(email|phone)")
  async verify(
    @WorkflowParam("context") ctx: LoginWfCtx,
    @Param("channel") channel: "email" | "phone",
  ): Promise<unknown> {
    this.requireUsername(ctx);
    const pincodeWf = useAtscriptWf(this.opts.forms.pincode);
    const input = pincodeWf.resolveInput() as { code: string };
    const pinErr = this.verifyPin(ctx, input.code);
    if (pinErr) throw pincodeWf.requireInput({ errors: pinErr });
    const isEmail = channel === "email";
    await this.withStoreErrorTranslation(() =>
      this.users.confirmMfaMethod(ctx.username, isEmail ? "email" : "sms"),
    );
    // dual-write — flat alias removed in B1.4
    if (isEmail) {
      (ctx.channel ??= {}).emailConfirmed = true;
      ctx.emailConfirmed = true;
    } else {
      (ctx.channel ??= {}).phoneConfirmed = true;
      ctx.phoneConfirmed = true;
    }
    // Record the OTP-channel disclosure AFTER channel ownership is confirmed
    // (pincode validated + MFA method flipped to `confirmed: true`). Default
    // ConsentStore.recordOtpChannelConsent is a no-op — customers override
    // to persist an audit-grade record. The `if (ctx.otpDisclosure)` guard is
    // defensive: any path that lands here without having traversed
    // ask/:channel (cleanup retry, manual harness invocation) skips the hook
    // rather than recording an empty-target consent.
    if (ctx.otpDisclosure) {
      const channelArg: "email" | "sms" = isEmail ? "email" : "sms";
      const target = (isEmail ? ctx.email : ctx.phone) as string;
      await this.consentStore.recordOtpChannelConsent(
        ctx.username,
        channelArg,
        target,
        ctx.otpDisclosure,
      );
    }
    delete ctx.pin;
    delete ctx.pinExpire;
    return undefined;
  }

  // ── Phase 4: MFA ──────────────────────────────────────────────────────
  @Step("check-trusted-device")
  async checkTrustedDevice(@WorkflowParam("context") ctx: LoginWfCtx): Promise<undefined> {
    if (!ctx.username) return undefined;
    const cookieValue = useCookies(current()).getCookie(this.opts.deviceTrust.cookieName);
    if (!cookieValue) {
      // dual-write — flat alias removed in B1.4
      (ctx.trust ??= {}).newDevice = true;
      ctx.newDevice = true;
      return undefined;
    }
    const ip = this.opts.deviceTrust.bindsTo === "cookie+ip" ? this.resolveClientIp() : undefined;
    const ok = await this.loadTrustedDevice(ctx.username, cookieValue, ip);
    // dual-write — flat alias removed in B1.4
    if (ok) {
      (ctx.mfa ??= {}).checked = true;
      (ctx.trust ??= {}).deviceTrustToken = cookieValue;
      ctx.mfaChecked = true;
      ctx.deviceTrustToken = cookieValue;
    } else {
      (ctx.trust ??= {}).newDevice = true;
      ctx.newDevice = true;
    }
    return undefined;
  }

  /**
   * Load + summarise the user's enrolled MFA methods (filtered against
   * `ctx.availableMfaTransports`) and mirror the form-gating flags
   * (`mfaMethodCount`, `deviceTrustOptIn`) onto ctx. Pure data-load — no
   * selection decision. Split out of the old `prepare-mfa-options` step so
   * consumers can override the load/summary shape (custom MFA inventory
   * source) without copying the selection heuristics in `selectMfaMethod`.
   */
  @Step("load-enrolled-mfa-methods")
  async loadEnrolledMfaMethods(@WorkflowParam("context") ctx: LoginWfCtx): Promise<undefined> {
    if (!ctx.username) return undefined;
    const user = await this.users.getUser(ctx.username);
    const allowed = new Set(ctx.availableMfaTransports ?? []);
    const methods = this.users.getAvailableMfaMethods(user.mfa);
    const summary: MfaSummary[] = methods
      .filter((m: MfaMethodInfo) => {
        const kind = mfaKindOf(m.name);
        return kind !== null && allowed.has(kind);
      })
      .map((m: MfaMethodInfo) => {
        const kind = mfaKindOf(m.name) as "sms" | "email" | "totp";
        return {
          kind,
          methodName: m.name,
          masked: m.masked,
          isDefault: m.isDefault,
        };
      });
    // dual-write — flat alias removed in B1.4
    const mfa = (ctx.mfa ??= {});
    mfa.enrolledMethods = summary;
    // Mirror count into ctx so MFA forms can hide `useDifferentMethod` when
    // only one method exists.
    mfa.methodCount = summary.length;
    ctx.mfaEnrolledMethods = summary;
    ctx.mfaMethodCount = summary.length;
    // Mirror so `PincodeForm` can hide `rememberDevice` when the consumer
    // doesn't ask the user to opt in (skipsMfa auto-trusts the device).
    const trustOptIn = !!(ctx.deviceTrust?.enabled && ctx.deviceTrust?.optIn);
    (ctx.trust ??= {}).optIn = trustOptIn;
    ctx.deviceTrustOptIn = trustOptIn;
    return undefined;
  }

  /**
   * Pick which MFA method to use from the already-loaded
   * `ctx.mfaEnrolledMethods` summary. Decision-only — no IO. Honors
   * `ctx.currentMfa` (pre-selected by `prepareMfaSetup` from the user's
   * `defaultMethod` or single-transport auto-pick), auto-picks when only one
   * method is enrolled, falls back to the `isDefault` method. All paths are
   * gated on `!ctx.ignoreMfaDefault` so the `useDifferentMethod` re-pick flow
   * (which sets the flag) skips straight to the `select2fa` picker. Split out
   * of the old `prepare-mfa-options` step so consumers can override selection
   * heuristics (e.g. risk-based per-tenant defaults) without re-implementing
   * the load/summary.
   */
  @Step("select-mfa-method")
  selectMfaMethod(@WorkflowParam("context") ctx: LoginWfCtx): undefined | Promise<undefined> {
    const summary = ctx.mfaEnrolledMethods ?? [];
    // `prepareMfaSetup` setter may have pre-selected a transport (existing-user
    // defaultMethod / single-transport auto-pick / consumer override). Honor
    // it if it matches an enrolled method. Gated on `!ctx.ignoreMfaDefault` so
    // the `useDifferentMethod` re-pick flow can clear the auto-selection and
    // route the user back to the picker instead of looping straight back to
    // the same method.
    // dual-write — flat alias removed in B1.4
    if (!ctx.ignoreMfaDefault && ctx.currentMfa && summary.some((m) => m.kind === ctx.currentMfa)) {
      (ctx.mfa ??= {}).method = ctx.currentMfa;
      ctx.mfaMethod = ctx.currentMfa;
      return undefined;
    }
    // Short-circuit: no methods → let `mfa-enroll-required` handle it.
    // `mode === 'required'` blocks until enrolment; `mode === 'optional'` lets
    // the user `skip`; `mode === 'disabled'` never reaches this step (the
    // while-loop guard filters it out).
    if (summary.length === 0) return undefined;
    if (summary.length === 1) {
      (ctx.mfa ??= {}).method = summary[0].kind;
      ctx.mfaMethod = summary[0].kind;
      return undefined;
    }
    if (!ctx.ignoreMfaDefault) {
      const def = summary.find((m) => m.isDefault);
      if (def) {
        (ctx.mfa ??= {}).method = def.kind;
        ctx.mfaMethod = def.kind;
      }
    }
    return undefined;
  }

  @Step("select-2fa")
  async select2fa(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    const wf = useAtscriptWf(this.opts.forms.select2fa);
    const input = wf.resolveInput() as { methodName: string; saveAsDefault?: boolean };
    const picked = (ctx.mfaEnrolledMethods ?? []).find((m) => m.methodName === input.methodName);
    if (!picked) {
      throw wf.requireInput({ errors: { methodName: "Unknown MFA method" } });
    }
    if (picked.kind === "sms" || picked.kind === "email") {
      const cooldownUntil = ctx.pincodeCooldowns?.[picked.kind];
      if (cooldownUntil && Date.now() < cooldownUntil) {
        const waitSec = Math.ceil((cooldownUntil - Date.now()) / 1000);
        const channel = picked.kind === "sms" ? "SMS" : "email";
        throw wf.requireInput({
          errors: {
            methodName: `Please wait ${waitSec}s before requesting another ${channel} code`,
          },
        });
      }
    }
    // dual-write — flat alias removed in B1.4
    const mfa = (ctx.mfa ??= {});
    mfa.method = picked.kind;
    mfa.saveAsDefault = Boolean(input.saveAsDefault);
    ctx.mfaMethod = picked.kind;
    ctx.mfaSaveAsDefault = Boolean(input.saveAsDefault);
    if (ctx.mfaSaveAsDefault && ctx.username) {
      await this.users.setDefaultMfaMethod(ctx.username, picked.methodName);
    }
    return undefined;
  }

  @Step("pincode-send-login")
  async pincodeSendLogin(@WorkflowParam("context") ctx: LoginWfCtx): Promise<undefined> {
    if (!ctx.username || !ctx.mfaMethod) return undefined;
    const summary = (ctx.mfaEnrolledMethods ?? []).find((m) => m.kind === ctx.mfaMethod);
    if (!summary) throw new HttpError(500, "Workflow state corrupted: missing mfa method");
    const user = await this.users.getUser(ctx.username);
    const method = user.mfa.methods.find((m) => m.name === summary.methodName && m.confirmed);
    if (!method) throw new HttpError(500, "MFA method no longer present");
    const code = this.mintPin(ctx, this.authOpts.mfa.pincodeLength, this.authOpts.mfa.pincodeTtlMs);
    const pincode = (ctx.pincode ??= {});
    pincode.timeout = Date.now() + this.authOpts.mfa.pincodeResendTimeoutMs;
    if (ctx.mfaMethod === "email") {
      pincode.sentTo = maskEmail(method.value);
      await this.deliver({
        channel: "email",
        kind: "login.pincode",
        recipient: method.value,
        code,
        expiresAt: ctx.pinExpire as number,
        userId: ctx.username,
      });
    } else if (ctx.mfaMethod === "sms") {
      pincode.sentTo = maskPhone(method.value);
      await this.deliver({
        channel: "sms",
        kind: "login.pincode",
        recipient: method.value,
        code,
        ttlMs: this.authOpts.mfa.pincodeTtlMs,
        userId: ctx.username,
      });
    }
    if (ctx.mfaMethod === "sms" || ctx.mfaMethod === "email") {
      // dual-write — flat alias removed in B1.4
      const cooldownAt = Date.now() + this.authOpts.mfa.pincodeResendTimeoutMs;
      (ctx.mfa ??= {}).pincodeCooldowns ??= {};
      ctx.mfa.pincodeCooldowns[ctx.mfaMethod] = cooldownAt;
      ctx.pincodeCooldowns ??= {};
      ctx.pincodeCooldowns[ctx.mfaMethod] = cooldownAt;
    }
    return undefined;
  }

  @Step("pincode-check-login")
  async pincodeCheckLogin(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    const wf = useAtscriptWf(this.opts.forms.pincode);
    const action = wf.resolveAction();
    if (action === "resend") {
      const timeout = ctx.pincode?.timeout;
      if (timeout && Date.now() < timeout) {
        const waitSec = Math.ceil((timeout - Date.now()) / 1000);
        throw wf.requireInput({ formMessage: `Please wait ${waitSec}s` });
      }
      delete ctx.pin;
      delete ctx.pinExpire;
      // Returning lets the MFA while-loop re-iterate; `pincode-send-login`
      // fires again because `!ctx.pin`, emits a fresh code, and the next
      // `pincode-check-login` pause renders `PincodeForm` with the new code.
      // (Previously this threw `requireInput`, which paused HERE and never
      // re-ran the send step — the user got a "Code resent" toast but no
      // new code was actually delivered.)
      return undefined;
    }
    if (action === "useDifferentMethod") {
      // dual-write — flat alias removed in B1.4
      const mfa = (ctx.mfa ??= {});
      mfa.ignoreDefault = true;
      delete mfa.method;
      ctx.ignoreMfaDefault = true;
      delete ctx.mfaMethod;
      delete ctx.pin;
      delete ctx.pinExpire;
      return undefined;
    }
    const input = wf.resolveInput() as { code: string; rememberDevice?: boolean };
    const pinErr = this.verifyPin(ctx, input.code);
    if (pinErr) throw wf.requireInput({ errors: pinErr });
    // dual-write — flat alias removed in B1.4
    const mfa = (ctx.mfa ??= {});
    mfa.checked = true;
    ctx.mfaChecked = true;
    // Allow the risk-step-up gate to re-evaluate after this re-verification.
    (ctx.session ??= {}).riskStepUpEvaluated = false;
    ctx.riskStepUpEvaluated = false;
    if (ctx.deviceTrust?.enabled && ctx.deviceTrust?.optIn) {
      (ctx.trust ??= {}).rememberDevice = Boolean(input.rememberDevice);
      ctx.rememberDevice = Boolean(input.rememberDevice);
    }
    return undefined;
  }

  @Step("mfa-totp")
  async mfaTotp(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    const wf = useAtscriptWf(this.opts.forms.mfaCode);
    const action = wf.resolveAction();
    if (action === "useDifferentMethod") {
      // dual-write — flat alias removed in B1.4
      const mfa = (ctx.mfa ??= {});
      mfa.ignoreDefault = true;
      delete mfa.method;
      ctx.ignoreMfaDefault = true;
      delete ctx.mfaMethod;
      return undefined;
    }
    const input = wf.resolveInput() as { code: string; rememberDevice?: boolean };
    this.requireUsername(ctx);
    try {
      await this.users.verifyMfa(ctx.username, input.code);
      // dual-write — flat alias removed in B1.4
      (ctx.mfa ??= {}).checked = true;
      ctx.mfaChecked = true;
      (ctx.session ??= {}).riskStepUpEvaluated = false;
      ctx.riskStepUpEvaluated = false;
      if (ctx.deviceTrust?.enabled && ctx.deviceTrust?.optIn) {
        (ctx.trust ??= {}).rememberDevice = Boolean(input.rememberDevice);
        ctx.rememberDevice = Boolean(input.rememberDevice);
      }
    } catch (err) {
      if (err instanceof UserAuthError) {
        if (err.type === "LOCKED") {
          throw wf.requireInput({ formMessage: "Account locked, please try again later" });
        }
        if (err.type === "INACTIVE") {
          throw wf.requireInput({ errors: { code: "Invalid code" } });
        }
        if (err.type === "MFA_NOT_CONFIGURED") throw new HttpError(400, "No TOTP MFA configured");
        if (err.type === "MFA_INVALID") {
          if (err.details?.lockEnds !== undefined) {
            throw wf.requireInput({ formMessage: "Account locked, please try again later" });
          }
          throw wf.requireInput({ errors: { code: "Invalid code" } });
        }
        // `verifyMfa` writes `lastUsedWindow` via `withCas` for replay defense
        // (audit #1) — exhausted CAS budget surfaces as 409 Conflict.
        if (err.type === "CAS_EXHAUSTED") throw new HttpError(409, err.message);
      }
      throw err;
    }
    return undefined;
  }

  /**
   * Forced MFA enrollment — Phase 1 (pick method). Auto-picks a single
   * transport, otherwise pauses for the picker form. When TOTP is picked, the
   * secret is provisioned in the same step body (see `enrollPickPhase`).
   * Sync-friendly return: the auto-pick branch and the picker-form branch are
   * both synchronous; only the TOTP-provisioning tail is async.
   */
  @Step("enroll-pick-method")
  loginEnrollPickMethod(@WorkflowParam("context") ctx: LoginWfCtx): undefined | Promise<undefined> {
    return this.enrollPickPhase(this.buildLoginEnrollDeps(ctx));
  }

  /**
   * Forced MFA enrollment — Phase 2 (collect sms/email address + send
   * pincode). Gated out for totp by the schema condition.
   */
  @Step("enroll-address")
  loginEnrollAddress(@WorkflowParam("context") ctx: LoginWfCtx): undefined | Promise<undefined> {
    return this.enrollAddressPhase(this.buildLoginEnrollDeps(ctx));
  }

  /**
   * Forced MFA enrollment — Phase 3 (verify code + activate method). Fires
   * `onComplete` to bridge `ctx.mfaEnroll.done` → `mfaChecked` so login's
   * outer MFA while-loop (gated on `!mfaChecked`) exits.
   */
  @Step("enroll-confirm")
  loginEnrollConfirm(@WorkflowParam("context") ctx: LoginWfCtx): undefined | Promise<undefined> {
    return this.enrollConfirmPhase(this.buildLoginEnrollDeps(ctx));
  }

  /**
   * Build the `MfaEnrollDeps` payload shared by all three login enrollment
   * step bodies. Sets `ctx.mfaEnroll.mode` so `EnrollPickMethodForm` can hide
   * the `skip` action unless mode is `'optional'`, and supplies `onComplete`
   * to mirror `ctx.mfaEnroll.done` → `mfaChecked` for login's loop-exit
   * signal.
   */
  private buildLoginEnrollDeps(ctx: LoginWfCtx): MfaEnrollDeps {
    this.requireUsername(ctx);
    // `'disabled'` is filtered at each step's schema condition, so the cast is safe.
    const mode = (ctx.mfaMode ?? "optional") as "required" | "optional";
    (ctx.mfaEnroll ??= {}).mode = mode;
    return {
      ctx,
      username: ctx.username,
      users: this.users,
      deliver: (p) => this.deliver(p as DeliverPayload),
      forms: {
        pickMethod: this.opts.forms.enrollPickMethod,
        address: this.opts.forms.enrollAddress,
        confirm: this.opts.forms.enrollConfirm,
      },
      transports: ctx.availableMfaTransports ?? [],
      pincodeLength: this.authOpts.mfa.pincodeLength,
      pincodeTtlMs: this.authOpts.mfa.pincodeTtlMs,
      pincodeResendTimeoutMs: this.authOpts.mfa.pincodeResendTimeoutMs,
      issuer: this.authOpts.totpIssuer,
      mode,
      onComplete: (c) => {
        (c as LoginWfCtx).mfaChecked = true;
      },
    };
  }

  @Step("device-trust")
  async deviceTrust(@WorkflowParam("context") ctx: LoginWfCtx): Promise<undefined> {
    if (!ctx.username) return undefined;
    const ip = this.opts.deviceTrust.bindsTo === "cookie+ip" ? this.resolveClientIp() : undefined;
    const record = await this.issueTrustedDevice(ctx.username, ip, this.opts.deviceTrust.ttlMs);
    await this.storeTrustedDevice(ctx.username, record);
    // dual-write — flat alias removed in B1.4
    (ctx.trust ??= {}).deviceTrustToken = record.token;
    ctx.deviceTrustToken = record.token;
    useResponse(current()).setCookie(
      this.opts.deviceTrust.cookieName,
      record.token,
      useAuth().cookieAttrs({ maxAge: this.opts.deviceTrust.ttlMs / 1000 }),
    );
    return undefined;
  }

  // ── Phase 5: forced password change ───────────────────────────────────
  @Step("prepare-password-rules")
  preparePasswordRules(@WorkflowParam("context") ctx: LoginWfCtx): undefined | Promise<undefined> {
    // Stash transferable policies onto ctx so the front-end can render rule
    // hints next to the form. Pure read; no behavior change.
    const policies = this.users.getTransferablePolicies();
    // dual-write — flat alias removed in B1.4
    (ctx as Record<string, unknown>).passwordPolicies = policies;
    (ctx.password ??= {}).policies = policies;
    return undefined;
  }

  @Step("create-password-form")
  async createPasswordForm(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    // Stage context-aware copy BEFORE the pause so the inputRequired envelope
    // carries the rendered heading/intro alongside the form schema. The
    // SetPasswordForm declares matching `@wf.context.pass` annotations; the
    // form's phantom `heading` / `intro` paragraphs read these values via
    // `@ui.form.fn.value`. Defaults to the 'initial' copy when the
    // credentials step somehow didn't write a reason — neutral safe copy
    // beats no copy.
    // dual-write — flat alias removed in B1.4
    if (ctx.passwordChangeReason === "expired") {
      ctx.passwordFormHeading = "Your password has expired";
      ctx.passwordFormIntro =
        "Choose a new password to continue. The previous one is no longer valid.";
    } else {
      ctx.passwordFormHeading = "Set your initial password";
      ctx.passwordFormIntro =
        "Your account was created without a password. Choose one to continue.";
    }
    (ctx.password ??= {}).heading = ctx.passwordFormHeading;
    (ctx.password ??= {}).intro = ctx.passwordFormIntro;
    const wf = useAtscriptWf(this.opts.forms.setPassword);
    const input = wf.resolveInput() as {
      newPassword: string;
      confirmPassword: string;
    } & InlineConsentInput;
    if (input.newPassword !== input.confirmPassword) {
      throw wf.requireInput({ errors: { confirmPassword: "Passwords do not match" } });
    }
    this.requireUsername(ctx);
    try {
      await this.users.setPassword(ctx.username, input.newPassword);
    } catch (err) {
      if (err instanceof UserAuthError) {
        throw wf.requireInput({ errors: { newPassword: err.message } });
      }
      throw err;
    }
    this.processInlineConsent(ctx, input, wf);
    (ctx.completion ??= {}).passwordChanged = true;
    ctx.isPasswordInitial = false;
    ctx.isPasswordExpired = false;
    // `delete` rather than `= undefined`: the wf state-token persistence
    // layer JSON-schema-validates the ctx and rejects `undefined` (allowed
    // types are string/number/boolean/null/array/object). Deleting the
    // key drops it from the serialized payload cleanly.
    delete ctx.passwordChangeReason;
    delete ctx.passwordFormHeading;
    delete ctx.passwordFormIntro;
    if (ctx.password) {
      delete ctx.password.changeReason;
      delete ctx.password.heading;
      delete ctx.password.intro;
    }
    return undefined;
  }

  // ── Phase 6: acceptance / onboarding ──────────────────────────────────
  @Step("profile-complete")
  async profileComplete(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    const wf = useAtscriptWf(this.opts.forms.profileComplete);
    const input = wf.resolveInput({ partial: "deep" }) as Record<string, unknown> &
      InlineConsentInput;
    this.requireUsername(ctx);
    this.processInlineConsent(ctx, input, wf);
    // Defense (audit hole #15 Sink A): strip privileged top-level
    // `UserCredentials` keys before handing off to `applyProfile`. The
    // form parser preserves unknown extras (`partial: "deep"`), and a
    // consumer's `.as` profile form may legitimize keys like `roles` /
    // `account` / `password`. Without this strip, a default `applyProfile`
    // override that deep-merges the payload onto the user row would let
    // any logged-in user self-promote / overwrite their password hash via
    // the post-login profile-complete prompt. Strip lives at the step so
    // consumer overrides of `applyProfile` (external CRM, etc.) still
    // receive a sanitized payload — see `auth-workflow.base.ts`.
    const sanitized = stripReservedUserKeys(input);
    await this.applyProfile(ctx.username, sanitized);
    ctx.profileApplied = true;
    return undefined;
  }

  /**
   * Persists the profile-complete payload onto the user record. Default:
   * no-op (the workflow records the form was submitted but writes nothing).
   * Consumers override to write into their user store.
   */
  protected async applyProfile(
    _username: string,
    _payload: Record<string, unknown>,
  ): Promise<void> {
    // No-op default.
  }

  /**
   * Standalone terms re-acceptance prompt for returning users whose accepted
   * terms version is stale — the consumer's `ConsentStore.getPendingConsents`
   * returned a non-empty descriptor list (typically a bumped terms version)
   * and no onboarding carrier form (ask-email/ask-phone/set-password/
   * profile-complete) ran to capture them via the dynamic `consents: string[]`
   * carrier field. The body delegates to `processInlineConsent`, which
   * handles validation + ctx writes identically to the inline path.
   */
  @Step("terms-bump-prompt")
  termsBumpPrompt(@WorkflowParam("context") ctx: LoginWfCtx): undefined {
    const wf = useAtscriptWf(this.opts.forms.termsBump);
    const input = wf.resolveInput() as InlineConsentInput;
    this.processInlineConsent(ctx, input, wf);
    return undefined;
  }

  // ── Phase 8: session policy ───────────────────────────────────────────
  @Step("load-active-sessions")
  async loadActiveSessionsStep(@WorkflowParam("context") ctx: LoginWfCtx): Promise<undefined> {
    if (!ctx.username) return undefined;
    const n = await this.loadActiveSessions(ctx.username);
    // dual-write — flat alias removed in B1.4
    (ctx.session ??= {}).activeSessions = n;
    ctx.activeSessions = n;
    return undefined;
  }

  /**
   * Return the number of active (non-revoked, non-expired) sessions for the
   * user — consulted by `concurrency-limit` to decide whether the kickPrompt
   * branch fires. Default returns `0` (no enforcement). Override with a real
   * count from your credential store or session table.
   */
  protected async loadActiveSessions(_username: string): Promise<number> {
    return 0;
  }

  @Step("concurrency-limit")
  async concurrencyLimit(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    const cfg = ctx.sessionPolicy?.concurrencyLimit;
    if (!cfg) return undefined;
    const wf = useAtscriptWf(this.opts.forms.concurrencyLimit);
    if (cfg.onLimit === "reject") {
      throw wf.requireInput({ formMessage: "Session limit reached" });
    }
    const action = wf.resolveAction();
    if (action === "cancel") {
      abortWf("sessionLimit", {
        message: { level: "warn", text: "Concurrent session limit reached." },
      });
      // BUG-LOGIN-5: stop the schema progressing into `issue` etc.
      ctx.aborted = true;
      return undefined;
    }
    if (action === "logoutOthers" && ctx.username) {
      await this.logoutOtherSessions(ctx.username);
      return undefined;
    }
    throw wf.requireInput();
  }

  /**
   * Implements the "log out other sessions" branch of `sessionPolicy.concurrencyLimit`.
   * Default: no-op. Consumers override to revoke sessions in their auth store.
   */
  protected async logoutOtherSessions(_username: string): Promise<void> {
    // No-op default.
  }

  @Step("risk-step-up")
  async riskStepUp(@WorkflowParam("context") ctx: LoginWfCtx): Promise<undefined> {
    // Runs INSIDE the Phase 4 `while: !mfaChecked` loop (see schema above).
    // `assessRiskStepUp({require: true})` re-arms MFA for another round by
    // clearing `mfaChecked`. `riskStepUpEvaluated` is flipped true so this
    // step does not fire twice within one MFA round — the MFA steps reset it
    // on next successful verification.
    // dual-write — flat alias removed in B1.4
    (ctx.session ??= {}).riskStepUpEvaluated = true;
    ctx.riskStepUpEvaluated = true;
    const res = await this.resolveRiskStepUp(ctx);
    if (res.require) {
      const reason = res.reason ?? "additional verification required";
      (ctx.session ??= {}).riskStepUpReason = reason;
      (ctx.mfa ??= {}).checked = false;
      ctx.riskStepUpReason = reason;
      ctx.mfaChecked = false;
      // delete (not `= undefined`) so the persisted ctx remains JSON-clean
      // — AsWfStore validates state.context against a JSON-anyOf schema and
      // chokes on explicit `undefined` entries.
      delete ctx.pin;
      delete ctx.pinExpire;
    } else {
      if (ctx.session) delete ctx.session.riskStepUpReason;
      delete ctx.riskStepUpReason;
    }
    return undefined;
  }

  /**
   * Resolves whether to require an additional MFA round (risk step-up).
   * Default: never requires an extra factor. Consumers override to inspect ctx
   * (IP, geo, time since last login, etc.) and return `{require: true, reason: '…'}`
   * to force an additional MFA round.
   */
  protected async resolveRiskStepUp(
    _ctx: LoginWfCtx,
  ): Promise<{ require: boolean; reason?: string }> {
    return { require: false };
  }

  // ── Phase 9: finalize ─────────────────────────────────────────────────
  @Step("issue")
  async issue(@WorkflowParam("context") ctx: LoginWfCtx): Promise<void> {
    this.requireUsername(ctx);
    const issue = await this.auth.issue(ctx.username);
    (ctx.completion ??= {}).tokensIssued = true;
    // Build response payload + cookies and stash on the finished response.
    // The `redirect` step (terminal) overrides with a redirect envelope when
    // `resolveRedirect` returns a URL; otherwise the data envelope sticks.
    // Raw `useWfFinished` path: cookies are wooks-level, helpers don't expose them.
    const auth = useAuth();
    const envelope: WfFinished = {
      finished: true,
      data: auth.buildLoginResponse(ctx.username, issue),
    };
    useWfFinished().set({
      type: "data",
      value: envelope,
      cookies: auth.buildFinishedCookies(issue),
    });
  }

  @Step("audit-login")
  async auditLogin(@WorkflowParam("context") ctx: LoginWfCtx): Promise<undefined> {
    await this.audit({
      kind: "login.success",
      userId: ctx.username,
      workflow: "auth/login/flow",
      method: ctx.mfaMethod ?? (ctx.mfaChecked ? "mfa.skipped" : "password"),
      ip: this.resolveClientIp(),
    });
    return undefined;
  }

  @Step("notify-new-device")
  async notifyNewDevice(@WorkflowParam("context") ctx: LoginWfCtx): Promise<undefined> {
    if (!ctx.email) return undefined;
    await this.deliver({
      channel: "email",
      kind: "notifyNewDevice",
      recipient: ctx.email,
      expiresAt: Date.now(),
      userId: ctx.username,
      metadata: { ip: this.resolveClientIp() ?? "" },
    });
    return undefined;
  }

  @Step("redirect")
  redirect(@WorkflowParam("context") ctx: LoginWfCtx): undefined | Promise<undefined> {
    // Compute the target URL — when set, overrides the issue step's data
    // envelope with an immediate-redirect envelope; otherwise keep the data
    // response from `issue`.
    const url = this.resolveRedirect(ctx);
    if (!url) return undefined;
    // Raw envelope path: cookies from `issue` must be preserved, and
    // `finishWf` doesn't accept cookies — that's a wooks concern.
    const existing = useWfFinished().get();
    const envelope: WfFinished = {
      finished: true,
      next: {
        trigger: "immediate",
        action: { type: "redirect", target: url, reason: "finalize-redirect" },
      },
    };
    useWfFinished().set({
      type: "data",
      value: envelope,
      ...(existing?.cookies && { cookies: existing.cookies }),
    });
    (ctx.completion ??= {}).redirectUrl = url;
    return undefined;
  }

  /**
   * Resolves the post-login redirect URL. Default reads
   * `finalize.redirect`: `false` / `null` (the default) → no redirect, the
   * `issue` step's data response stands (typical for SPAs/API clients);
   * `'home'` → `/`; `'referer'` → request `Referer` header (undefined when
   * absent, falling back to the data response).
   *
   * Sync return type only — the caller (`redirect` @Step's default body)
   * uses the URL inline; consumers needing async redirect resolution should
   * override the `redirect` @Step instead.
   */
  protected resolveRedirect(ctx: LoginWfCtx): string | undefined {
    const r = ctx.finalize?.redirect;
    if (!r) return undefined;
    if (r === "home") return "/";
    if (r === "referer") {
      const { referer, referrer } = useHeaders(current());
      const ref = referer ?? referrer;
      const first = Array.isArray(ref) ? ref[0] : ref;
      return typeof first === "string" && first.length > 0 ? first : undefined;
    }
    return undefined;
  }
}
