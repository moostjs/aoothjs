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
 * these. Channel-enrollment loops (`ensureEmail` / `ensurePhone`) are a
 * single-pass ask-and-verify per the brief, since moost-wf does not provide
 * a clean "loop while" primitive at the @WorkflowSchema level.
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
import { Controller } from "moost";

import type { AuditEvent } from "../audit/index";
import { AuthOpts } from "../auth.opts";
import { useAuth } from "../auth.composables";
import { Public } from "../auth.decorator";
import {
  AuthWorkflowBase,
  type ConsentEvent,
  type InlineConsentInput,
  type MfaEnrollDeps,
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

export interface LoginWfCtx {
  // Resolved policy (populated by prepare-* steps; reads via resolveXxx() getters):
  acceptance?: {
    termsVersion?: string;
    profileCompleteRequired: boolean;
    consentMarketing: boolean;
  };
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
  mfaConfig?: {
    backupCodes: boolean;
  };
  multiContext?: {
    tenantSelect: boolean;
    personaSelect: boolean;
  };
  sessionPolicy?: {
    concurrencyLimit?: ConcurrencyLimitOptions;
  };

  // Populated by `credentials`:
  username?: string;
  /** Legacy alias for `pwReset`; kept until tests migrate. */
  mfaRequired?: boolean;
  isPasswordInitial?: boolean;
  usedMagicLink?: boolean;

  // MFA policy (populated by the single `prepareMfaSetup` setter — overridable per consumer):
  /**
   * 3-state MFA policy:
   *   - `'required'` — MFA enforced; users with 0 methods MUST enroll (no skip).
   *   - `'optional'` — MFA prompted; users with 0 methods see an enrollment
   *     form that offers a `skip` action (in-flight opt-out).
   *   - `'disabled'` — MFA loops never fire; Phase 4 is skipped entirely.
   */
  mfaMode?: "required" | "optional" | "disabled";
  availableMfaTransports?: MfaTransport[];
  /** Pre-selected MFA transport (e.g. existing-user default, single-transport auto-pick). */
  currentMfa?: MfaTransport;

  // Channel state:
  email?: string;
  emailConfirmed?: boolean;
  phone?: string;
  phoneConfirmed?: boolean;

  // MFA state:
  mfaEnrolledMethods?: MfaSummary[];
  mfaMethod?: "sms" | "email" | "totp";
  mfaSaveAsDefault?: boolean;
  ignoreMfaDefault?: boolean;
  mfaChecked?: boolean;
  /**
   * Set true the first time the user picks `useBackupCode` on the MFA step,
   * so the workflow remembers to route the subsequent `BackupCodeForm`
   * submission (which carries no `action`) through `handleBackupCode` instead
   * of falling through to `verifyMfa` / pincode-verify.
   */
  usingBackupCode?: boolean;
  /** Counter incremented by the `risk-step-up` step so MFA reruns for the extra factor. */
  mfaRunsRemaining?: number;
  /** Mirror of `mfaEnrolledMethods.length`. Passed to client forms via `@wf.context.pass` so action buttons (`useDifferentMethod`) can hide when only one method exists. */
  mfaMethodCount?: number;
  /** Mirror of `opts.mfa.backupCodes`. Passed to client forms so `useBackupCode` can hide when backup codes are disabled. */
  mfaBackupCodes?: boolean;

  // Alternate-credentials flags mirrored from `opts.alternateCredentials` for `@ui.form.fn.hidden`:
  altForgotPassword?: boolean;
  altSignup?: boolean;
  altMagicLink?: boolean;

  // MFA forced-enrollment state (Phase 4 `mfa-enroll-required` sub-flow):
  enrollMethod?: MfaTransport;
  enrollAddress?: string;
  /** TOTP secret in flight (passed to UI via `@wf.context.pass` for QR rendering). */
  enrollSecret?: string;
  /** Provisioning URI for TOTP QR rendering. */
  enrollUri?: string;
  /** Mirror of `ctx.availableMfaTransports`, surfaced to `EnrollPickMethodForm` via `@wf.context.pass`. */
  enrollAvailableTransports?: MfaTransport[];
  /**
   * Mirror of `ctx.mfaMode` (only set when not `'disabled'`). Surfaced to
   * `EnrollPickMethodForm` via `@wf.context.pass` so the `skip` action can
   * hide unless mode is `'optional'`.
   */
  enrollMode?: "required" | "optional";
  /** Set true by `enrollConfirmPhase` (or `enrollPickPhase`/`enrollAddressPhase` on `skip` in `'optional'` mode); mirrored to `mfaChecked` via `buildLoginEnrollDeps` `onComplete`. */
  enrollDone?: boolean;
  /** Phase 3 confirm-pincode resend cooldown (sms/email). See `MfaEnrollCtx.enrollPincodeCooldown`. */
  enrollPincodeCooldown?: number;

  // Pincode state:
  pin?: string;
  pinExpire?: number;
  pinTimeout?: number;
  pinSentTo?: string;
  /**
   * Per-method "next-allowed-send-at" timestamp. Written by
   * `pincode-send-login` after each send and consulted by `select2fa` to
   * reject re-picking a method while it's still in cooldown. Closes the
   * `useDifferentMethod → same method → fresh SMS` abuse loop: without this
   * an attacker (or an impatient user) can spam SMS/email by alternating
   * methods. Persists across `delete ctx.pin` (resend/useDifferentMethod)
   * so the throttle survives a method switch.
   */
  pincodeCooldowns?: { sms?: number; email?: number };

  // Device trust:
  deviceTrustToken?: string;
  /** Set true at MFA gate when no trust cookie matched → trigger `notify-new-device`. */
  newDevice?: boolean;
  /** Captured from the OTP/pincode form when `opts.deviceTrust.optIn`. */
  rememberDevice?: boolean;
  /** Mirror of `opts.deviceTrust.optIn`. Passed to `PincodeForm` so the `rememberDevice` checkbox can hide when the consumer's device-trust is off-by-default (no user choice to make). */
  deviceTrustOptIn?: boolean;

  // Terms / profile:
  termsAcceptedVersion?: string;
  /**
   * Wall-clock ms at the moment `processInlineConsent` accepted the terms
   * gate (NOT the moment the batched `persist-consents` step ran). Captured
   * here so the consent event emitted to consumers reflects user-action
   * time, not write-time — surviving a paused workflow's resume gap.
   */
  termsAcceptedAt?: number;
  /**
   * Wall-clock ms at the moment `processInlineConsent` staged the marketing
   * opt-in/out. Same rationale as `termsAcceptedAt` — preserves user-action
   * time across the gap between carrier-form submit and the batched
   * `persist-consents` write.
   */
  marketingDecidedAt?: number;
  profileMissingFields?: string[];

  // Tenant / persona:
  availableTenants?: Array<{ id: string; name: string }>;
  selectedTenantId?: string;
  availablePersonas?: Array<{ id: string; label: string }>;
  selectedPersonaId?: string;

  // Session policy:
  riskStepUpReason?: string;
  activeSessions?: number;

  // Internal flags (resume-from-pause idempotency):
  passwordChanged?: boolean;
  termsAcceptedDone?: boolean;
  profileApplied?: boolean;
  /**
   * Set true by `persist-consents` after the batched `persistConsents`
   * consumer hook fires (or after the step short-circuits with no events to
   * persist). Gates `processInlineConsent` from staging further marketing
   * opt-ins, and the `persist-consents` schema condition from re-firing.
   * Replaces the pre-refactor singular `consentApplied` (which gated only
   * marketing — the new flag is batch-write-completion).
   */
  consentsPersisted?: boolean;
  /**
   * Marketing opt-in value captured inline (via `WithInlineConsentForm` on a
   * carrier form's payload). Stashed here by `processInlineConsent` so the
   * later `persist-consents` step can persist it once `ctx.username` is set —
   * the inline capture commonly happens BEFORE the credentials step finishes
   * (e.g. `AskEmailForm`), where the user-store write would have nothing
   * to bind to.
   */
  pendingMarketingOptIn?: boolean;
  tokensIssued?: boolean;
  redirectUrl?: string;
  /**
   * Set true by abort alt-actions (`logout`, `decline`, `cancel`). All terminal
   * steps (`issue`, `audit-login`, `notify-new-device`, `redirect`) gate on
   * `!ctx.aborted` so the abort response set via `useWfFinished()` stays.
   */
  aborted?: boolean;
  /** Tracks whether `risk-step-up` has already been evaluated this iteration. */
  riskStepUpEvaluated?: boolean;
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
  acceptance?: NonNullable<LoginWfCtx["acceptance"]>;
  alternateCredentials?: NonNullable<LoginWfCtx["alternateCredentials"]>;
  deviceTrust?: NonNullable<LoginWfCtx["deviceTrust"]>;
  enrollment?: NonNullable<LoginWfCtx["enrollment"]>;
  finalize?: NonNullable<LoginWfCtx["finalize"]>;
  guards?: NonNullable<LoginWfCtx["guards"]>;
  mfaConfig?: NonNullable<LoginWfCtx["mfaConfig"]>;
  multiContext?: NonNullable<LoginWfCtx["multiContext"]>;
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
 * carry a payload field outside the current step's form (e.g. a backup `code`
 * posted alongside `select2fa`, or the typed `username` read on a
 * `forgotPassword` click before the password is filled in).
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
@Public()
@Controller("auth/login")
export class LoginWorkflow extends AuthWorkflowBase {
  protected readonly opts: ResolvedLoginWorkflowOpts;
  protected readonly users: UserService;
  protected readonly auth: AuthCredential;
  protected readonly authOpts: AuthOpts;

  constructor(
    opts: LoginWorkflowOpts,
    users: UserService,
    auth: AuthCredential,
    authOpts: AuthOpts,
  ) {
    super();
    this.opts = mergeLoginOpts(opts);
    this.users = users;
    this.auth = auth;
    this.authOpts = authOpts;
    validateOpts(this.opts);
  }

  // ── Protected extension surface ───────────────────────────────────────
  /**
   * Dispatch an email or SMS event. Default throws — consumers MUST override
   * if any feature that emits is enabled (MFA pincode, ensureEmail/Phone OTP,
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
   * Resolve the acceptance / onboarding policy (terms version, profile-complete
   * gating, marketing consent). Override per-tenant or per-user. Async-friendly
   * via the union return type — sync defaults stay sync (engine fast path).
   */
  protected resolveAcceptance(
    _ctx: LoginWfCtx,
  ): NonNullable<LoginWfCtx["acceptance"]> | Promise<NonNullable<LoginWfCtx["acceptance"]>> {
    return {
      profileCompleteRequired: false,
      consentMarketing: false,
    };
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
   * Resolve the MFA config (currently only backup-codes availability — pincode
   * timings stay on `this.opts.mfa` as infrastructure). Override to enable or
   * disable backup-code redemption per tenant. Sync/async friendly.
   */
  protected resolveMfaConfig(
    _ctx: LoginWfCtx,
  ): NonNullable<LoginWfCtx["mfaConfig"]> | Promise<NonNullable<LoginWfCtx["mfaConfig"]>> {
    return {
      backupCodes: true,
    };
  }

  /**
   * Resolve the multi-context policy (tenantSelect / personaSelect prompts).
   * Override to require a tenant/persona pick when the user has more than one.
   * Sync/async friendly.
   */
  protected resolveMultiContext(
    _ctx: LoginWfCtx,
  ): NonNullable<LoginWfCtx["multiContext"]> | Promise<NonNullable<LoginWfCtx["multiContext"]>> {
    return {
      tenantSelect: false,
      personaSelect: false,
    };
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
  @Step("prepare-acceptance")
  prepareAcceptance(@WorkflowParam("context") ctx: LoginWfCtx): undefined | Promise<undefined> {
    const result = this.resolveAcceptance(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.acceptance = resolved;
        return undefined;
      });
    }
    ctx.acceptance = result;
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

  @Step("prepare-mfa-config")
  prepareMfaConfig(@WorkflowParam("context") ctx: LoginWfCtx): undefined | Promise<undefined> {
    const result = this.resolveMfaConfig(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.mfaConfig = resolved;
        return undefined;
      });
    }
    ctx.mfaConfig = result;
    return undefined;
  }

  @Step("prepare-multi-context")
  prepareMultiContext(@WorkflowParam("context") ctx: LoginWfCtx): undefined | Promise<undefined> {
    const result = this.resolveMultiContext(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.multiContext = resolved;
        return undefined;
      });
    }
    ctx.multiContext = result;
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
    { id: "prepare-acceptance" },
    { id: "prepare-alternate-credentials" },
    { id: "prepare-device-trust" },
    { id: "prepare-enrollment" },
    { id: "prepare-finalize" },
    { id: "prepare-guards" },
    { id: "prepare-mfa-config" },
    { id: "prepare-multi-context" },
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

    // Phase 3 enrollment loops (single-pass per brief):
    {
      id: "ensure-email",
      condition: (ctx) =>
        (!!ctx.enrollment?.ensureEmail || !!ctx.guards?.emailVerifiedRequired) &&
        !ctx.emailConfirmed,
    },
    {
      id: "ensure-phone",
      condition: (ctx) => !!ctx.enrollment?.ensurePhone && !ctx.phoneConfirmed,
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
        {
          condition: (ctx) => !ctx.mfaChecked && (ctx.mfaEnrolledMethods?.length ?? 0) === 0,
          steps: [
            {
              id: "enroll-pick-method",
              condition: (ctx) => !ctx.enrollMethod,
            },
            {
              id: "enroll-address",
              condition: (ctx) =>
                !!ctx.enrollMethod &&
                (ctx.enrollMethod === "sms" || ctx.enrollMethod === "email") &&
                !ctx.enrollAddress,
            },
            {
              id: "enroll-confirm",
              condition: (ctx) =>
                !!ctx.enrollMethod &&
                (ctx.enrollMethod === "totp" || !!ctx.enrollAddress) &&
                !ctx.enrollDone,
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
      condition: (ctx) => !!ctx.isPasswordInitial && !ctx.passwordChanged,
      steps: [{ id: "prepare-password-rules" }, { id: "create-password-form" }],
    },
    // Abort gate — create-password-form 'logout' alt-action sets ctx.aborted = true.
    { break: (ctx) => !!ctx.aborted },

    // Phase 6 acceptance / onboarding — terms acceptance + marketing consent
    // are now captured inline via `WithInlineConsentForm` on whichever carrier
    // onboarding form fires first (AskEmailForm / AskPhoneForm /
    // SetPasswordForm / ProfileCompleteForm). When no such carrier form runs
    // and `acceptance.termsVersion` is set (returning user, terms-bump-only
    // login), the standalone `terms-bump-prompt` step fires to collect terms
    // re-acceptance. `persist-consents` then fans every collected consent
    // event (terms + marketing) out via the consumer's `persistConsents`
    // batched hook once `ctx.username` is bound.
    {
      id: "profile-complete",
      condition: (ctx) =>
        !!ctx.acceptance?.profileCompleteRequired &&
        !ctx.profileApplied &&
        (ctx.profileMissingFields?.length ?? 0) > 0,
    },
    // Returning user with a stale terms version + no onboarding carrier form
    // ran to capture acceptance inline. Standalone prompt to re-accept the
    // current terms. Skips when an earlier carrier form already collected.
    // `!ctx.aborted` is handled by the upstream `{ break }` gate.
    {
      id: "terms-bump-prompt",
      condition: (ctx) => !!ctx.acceptance?.termsVersion && !ctx.termsAcceptedDone,
    },
    {
      // Batched consent persistence. Fires once per workflow run after any
      // consent capture (terms acceptance via `processInlineConsent` or the
      // `terms-bump-prompt` step; marketing opt-in stashed by
      // `processInlineConsent`). Condition AND-s `!consentsPersisted` to
      // guarantee single fire, and OR-s the two capture sources so a
      // terms-only or marketing-only run still hits the step.
      id: "persist-consents",
      condition: (ctx) =>
        !ctx.consentsPersisted &&
        (ctx.termsAcceptedDone === true || ctx.pendingMarketingOptIn !== undefined),
    },

    // Phase 7 tenant / persona selection:
    {
      id: "tenant-select",
      condition: (ctx) =>
        !!ctx.multiContext?.tenantSelect &&
        !ctx.selectedTenantId &&
        (ctx.availableTenants?.length ?? 0) > 1,
    },
    {
      id: "persona-select",
      condition: (ctx) =>
        !!ctx.multiContext?.personaSelect &&
        !ctx.selectedPersonaId &&
        (ctx.availablePersonas?.length ?? 0) > 1,
    },

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
    { id: "issue", condition: (ctx) => !ctx.tokensIssued },
    {
      condition: (ctx) => !!ctx.tokensIssued,
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
    ctx.mfaMode = "optional";
    ctx.availableMfaTransports = ["sms", "email", "totp"];
    if (!ctx.username) return undefined;
    return this.users.getUser(ctx.username).then(
      (user) => {
        const confirmed = (user?.mfa?.methods ?? []).filter((m) => m.confirmed);
        if (confirmed.length > 0 && user?.mfa?.defaultMethod) {
          ctx.currentMfa = user.mfa.defaultMethod as MfaTransport;
          return undefined;
        }
        if ((ctx.availableMfaTransports?.length ?? 0) === 1) {
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
    ctx.altForgotPassword = !!alt.forgotPassword;
    ctx.altSignup = !!alt.signup;
    ctx.altMagicLink = !!alt.magicLink;
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
      // Sync existing channel state so `ensureEmail`/`ensurePhone` skip
      // when the user already has a confirmed channel.
      const email = result.user.mfa.methods.find((m) => m.name === "email" && m.confirmed);
      if (email) {
        ctx.email = email.value;
        ctx.emailConfirmed = true;
      }
      const phone = result.user.mfa.methods.find((m) => m.name === "sms" && m.confirmed);
      if (phone) {
        ctx.phone = phone.value;
        ctx.phoneConfirmed = true;
      }
    } catch (err) {
      if (err instanceof UserAuthError) {
        if (err.type === "LOCKED") throw new HttpError(423, "Account locked");
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

  // ── Phase 3: enrollment loops (single-pass per brief) ─────────────────
  @Step("ensure-email")
  async ensureEmail(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    this.requireUsername(ctx);
    const pincodeWf = useAtscriptWf(this.opts.forms.pincode);
    // Step 1: collect the email if we don't have one.
    if (!ctx.email) {
      const askEmailWf = useAtscriptWf(this.opts.forms.askEmail);
      const input = askEmailWf.resolveInput() as { email: string } & InlineConsentInput;
      this.processInlineConsent(ctx, input, askEmailWf);
      const username = ctx.username;
      await this.withStoreErrorTranslation(() =>
        this.users.addMfaMethod(username, {
          name: "email",
          value: input.email,
          confirmed: false,
        }),
      );
      ctx.email = input.email;
      // Generate + send the OTP, then ask for it next round.
      const code = this.mintPin(
        ctx,
        this.authOpts.mfa.pincodeLength,
        this.authOpts.mfa.pincodeTtlMs,
      );
      await this.deliver({
        channel: "email",
        kind: "login.pincode",
        recipient: input.email,
        code,
        expiresAt: ctx.pinExpire as number,
      });
      throw pincodeWf.requireInput();
    }
    // Step 2: verify the OTP.
    const input = pincodeWf.resolveInput() as { code: string };
    const pinErr = this.verifyPin(ctx, input.code);
    if (pinErr) throw pincodeWf.requireInput({ errors: pinErr });
    await this.withStoreErrorTranslation(() => this.users.confirmMfaMethod(ctx.username, "email"));
    ctx.emailConfirmed = true;
    delete ctx.pin;
    delete ctx.pinExpire;
    return undefined;
  }

  @Step("ensure-phone")
  async ensurePhone(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    this.requireUsername(ctx);
    const pincodeWf = useAtscriptWf(this.opts.forms.pincode);
    if (!ctx.phone) {
      const askPhoneWf = useAtscriptWf(this.opts.forms.askPhone);
      const input = askPhoneWf.resolveInput() as { phone: string } & InlineConsentInput;
      this.processInlineConsent(ctx, input, askPhoneWf);
      const username = ctx.username;
      await this.withStoreErrorTranslation(() =>
        this.users.addMfaMethod(username, {
          name: "sms",
          value: input.phone,
          confirmed: false,
        }),
      );
      ctx.phone = input.phone;
      const code = this.mintPin(
        ctx,
        this.authOpts.mfa.pincodeLength,
        this.authOpts.mfa.pincodeTtlMs,
      );
      await this.deliver({
        channel: "sms",
        kind: "login.pincode",
        recipient: input.phone,
        code,
        ttlMs: this.authOpts.mfa.pincodeTtlMs,
        userId: ctx.username,
      });
      throw pincodeWf.requireInput();
    }
    const input = pincodeWf.resolveInput() as { code: string };
    const pinErr = this.verifyPin(ctx, input.code);
    if (pinErr) throw pincodeWf.requireInput({ errors: pinErr });
    await this.withStoreErrorTranslation(() => this.users.confirmMfaMethod(ctx.username, "sms"));
    ctx.phoneConfirmed = true;
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
      ctx.newDevice = true;
      return undefined;
    }
    const ip = this.opts.deviceTrust.bindsTo === "cookie+ip" ? this.resolveClientIp() : undefined;
    const ok = await this.loadTrustedDevice(ctx.username, cookieValue, ip);
    if (ok) {
      ctx.mfaChecked = true;
      ctx.deviceTrustToken = cookieValue;
    } else {
      ctx.newDevice = true;
    }
    return undefined;
  }

  /**
   * Load + summarise the user's enrolled MFA methods (filtered against
   * `ctx.availableMfaTransports`) and mirror the form-gating flags
   * (`mfaMethodCount`, `mfaBackupCodes`, `deviceTrustOptIn`) onto ctx. Pure
   * data-load — no selection decision. Split out of the old
   * `prepare-mfa-options` step so consumers can override the load/summary
   * shape (custom MFA inventory source) without copying the selection
   * heuristics in `selectMfaMethod`.
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
    ctx.mfaEnrolledMethods = summary;
    // Mirror count + backup-code flag into ctx so MFA forms can hide
    // `useDifferentMethod` / `useBackupCode` buttons when not applicable.
    ctx.mfaMethodCount = summary.length;
    ctx.mfaBackupCodes = !!ctx.mfaConfig?.backupCodes;
    // Mirror so `PincodeForm` can hide `rememberDevice` when the consumer
    // doesn't ask the user to opt in (skipsMfa auto-trusts the device).
    ctx.deviceTrustOptIn = !!(ctx.deviceTrust?.enabled && ctx.deviceTrust?.optIn);
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
    if (!ctx.ignoreMfaDefault && ctx.currentMfa && summary.some((m) => m.kind === ctx.currentMfa)) {
      ctx.mfaMethod = ctx.currentMfa;
      return undefined;
    }
    // Short-circuit: no methods → let `mfa-enroll-required` handle it.
    // `mode === 'required'` blocks until enrolment; `mode === 'optional'` lets
    // the user `skip`; `mode === 'disabled'` never reaches this step (the
    // while-loop guard filters it out).
    if (summary.length === 0) return undefined;
    if (summary.length === 1) {
      ctx.mfaMethod = summary[0].kind;
      return undefined;
    }
    if (!ctx.ignoreMfaDefault) {
      const def = summary.find((m) => m.isDefault);
      if (def) ctx.mfaMethod = def.kind;
    }
    return undefined;
  }

  @Step("select-2fa")
  async select2fa(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    const wf = useAtscriptWf(this.opts.forms.select2fa);
    const action = wf.resolveAction();
    if (ctx.usingBackupCode && ctx.mfaConfig?.backupCodes) {
      const code = getInputField("code");
      return this.handleBackupCode(code ? { code } : undefined, ctx);
    }
    if (action === "useBackupCode" && ctx.mfaConfig?.backupCodes) {
      // Peek raw input for the backup `code` field — it lives outside the
      // select2fa form schema, so we read the envelope directly.
      ctx.usingBackupCode = true;
      const code = getInputField("code");
      return this.handleBackupCode(code ? { code } : undefined, ctx);
    }
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
    ctx.pinTimeout = Date.now() + this.authOpts.mfa.pincodeResendTimeoutMs;
    if (ctx.mfaMethod === "email") {
      ctx.pinSentTo = maskEmail(method.value);
      await this.deliver({
        channel: "email",
        kind: "login.pincode",
        recipient: method.value,
        code,
        expiresAt: ctx.pinExpire as number,
        userId: ctx.username,
      });
    } else if (ctx.mfaMethod === "sms") {
      ctx.pinSentTo = maskPhone(method.value);
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
      ctx.pincodeCooldowns ??= {};
      ctx.pincodeCooldowns[ctx.mfaMethod] = Date.now() + this.authOpts.mfa.pincodeResendTimeoutMs;
    }
    return undefined;
  }

  @Step("pincode-check-login")
  async pincodeCheckLogin(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    const wf = useAtscriptWf(this.opts.forms.pincode);
    const action = wf.resolveAction();
    if (action === "resend") {
      if (ctx.pinTimeout && Date.now() < ctx.pinTimeout) {
        const waitSec = Math.ceil((ctx.pinTimeout - Date.now()) / 1000);
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
      ctx.ignoreMfaDefault = true;
      delete ctx.mfaMethod;
      delete ctx.pin;
      delete ctx.pinExpire;
      return undefined;
    }
    if (ctx.usingBackupCode && ctx.mfaConfig?.backupCodes) {
      const code = getInputField("code");
      return this.handleBackupCode(code ? { code } : undefined, ctx);
    }
    if (action === "useBackupCode" && ctx.mfaConfig?.backupCodes) {
      // First click → no `code` field → handleBackupCode pauses for the form.
      // Resume with the backup code populated → handleBackupCode validates and
      // consumes. The presence of `code` is the toggle.
      ctx.usingBackupCode = true;
      const code = getInputField("code");
      return this.handleBackupCode(code ? { code } : undefined, ctx);
    }
    const input = wf.resolveInput() as { code: string; rememberDevice?: boolean };
    const pinErr = this.verifyPin(ctx, input.code);
    if (pinErr) throw wf.requireInput({ errors: pinErr });
    ctx.mfaChecked = true;
    // Allow the risk-step-up gate to re-evaluate after this re-verification.
    ctx.riskStepUpEvaluated = false;
    if (ctx.deviceTrust?.enabled && ctx.deviceTrust?.optIn) {
      ctx.rememberDevice = Boolean(input.rememberDevice);
    }
    return undefined;
  }

  @Step("mfa-totp")
  async mfaTotp(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    const wf = useAtscriptWf(this.opts.forms.mfaCode);
    const action = wf.resolveAction();
    if (action === "useDifferentMethod") {
      ctx.ignoreMfaDefault = true;
      delete ctx.mfaMethod;
      return undefined;
    }
    if (ctx.usingBackupCode && ctx.mfaConfig?.backupCodes) {
      const code = getInputField("code");
      return this.handleBackupCode(code ? { code } : undefined, ctx);
    }
    if (action === "useBackupCode" && ctx.mfaConfig?.backupCodes) {
      ctx.usingBackupCode = true;
      const code = getInputField("code");
      return this.handleBackupCode(code ? { code } : undefined, ctx);
    }
    const input = wf.resolveInput() as { code: string; rememberDevice?: boolean };
    this.requireUsername(ctx);
    try {
      await this.users.verifyMfa(ctx.username, input.code);
      ctx.mfaChecked = true;
      ctx.riskStepUpEvaluated = false;
      if (ctx.deviceTrust?.enabled && ctx.deviceTrust?.optIn) {
        ctx.rememberDevice = Boolean(input.rememberDevice);
      }
    } catch (err) {
      if (err instanceof UserAuthError) {
        if (err.type === "LOCKED") throw new HttpError(423, "Account locked");
        if (err.type === "INACTIVE") throw new HttpError(401, "Invalid credentials");
        if (err.type === "MFA_NOT_CONFIGURED") throw new HttpError(400, "No TOTP MFA configured");
        if (err.type === "MFA_INVALID") {
          if (err.details?.lockEnds !== undefined) throw new HttpError(423, "Account locked");
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
   * Backup-code alt-action handler shared by `select2fa`, `pincode-check-login`,
   * and `mfa-totp`. Validates against `BackupCodeForm` (alphanumeric +
   * hyphen-grouped — `MfaCodeForm` is digits-only and rejects backup codes
   * produced by `UserService.generateBackupCodes`).
   */
  private async handleBackupCode(
    input: { code?: string } | undefined,
    ctx: LoginWfCtx,
  ): Promise<unknown> {
    const wf = useAtscriptWf(this.opts.forms.backupCode);
    // First click → caller passes `undefined` → pause for the form.
    if (!input) throw wf.requireInput();
    // Resume click — re-validate against BackupCodeForm's pattern. The caller
    // already extracted `code` from the raw envelope; resolveInput re-reads
    // it from the same envelope and enforces the alphanumeric+hyphen rule.
    const validated = wf.resolveInput() as { code: string };
    this.requireUsername(ctx);
    const ok = await this.withStoreErrorTranslation(() =>
      this.users.consumeBackupCode(ctx.username, validated.code),
    );
    if (!ok) throw wf.requireInput({ errors: { code: "Invalid backup code" } });
    ctx.mfaChecked = true;
    ctx.riskStepUpEvaluated = false;
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
   * `onComplete` to bridge `enrollDone` → `mfaChecked` so login's outer MFA
   * while-loop (gated on `!mfaChecked`) exits.
   */
  @Step("enroll-confirm")
  loginEnrollConfirm(@WorkflowParam("context") ctx: LoginWfCtx): undefined | Promise<undefined> {
    return this.enrollConfirmPhase(this.buildLoginEnrollDeps(ctx));
  }

  /**
   * Build the `MfaEnrollDeps` payload shared by all three login enrollment
   * step bodies. Sets `ctx.enrollMode` (mirrored onto ctx so
   * `EnrollPickMethodForm` can hide the `skip` action unless mode is
   * `'optional'`) and supplies `onComplete` to mirror `enrollDone` →
   * `mfaChecked` for login's loop-exit signal.
   */
  private buildLoginEnrollDeps(ctx: LoginWfCtx): MfaEnrollDeps {
    this.requireUsername(ctx);
    // `'disabled'` is filtered at each step's schema condition, so the cast is safe.
    const mode = (ctx.mfaMode ?? "optional") as "required" | "optional";
    ctx.enrollMode = mode;
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
    (ctx as Record<string, unknown>).passwordPolicies = this.users.getTransferablePolicies();
    return undefined;
  }

  @Step("create-password-form")
  async createPasswordForm(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    const wf = useAtscriptWf(this.opts.forms.setPassword);
    const action = wf.resolveAction();
    if (action === "logout") {
      abortWf("logout", { message: { level: "info", text: "Signed out." } });
      // Gate downstream steps (issue/audit/notify/redirect) — without this
      // the schema continues and the `issue` step overwrites the abort
      // response with tokens. See BUG-LOGIN-5.
      ctx.aborted = true;
      return undefined;
    }
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
      this.translatePasswordSetError(err);
    }
    this.processInlineConsent(ctx, input, wf);
    ctx.passwordChanged = true;
    ctx.isPasswordInitial = false;
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
   * terms version is stale (consumer's `resolveAcceptance` returned a newer
   * `termsVersion` than what's recorded in their consent history). Fires only
   * when no onboarding carrier form (ask-email/ask-phone/set-password/
   * profile-complete) has already captured terms acceptance via
   * `WithInlineConsentForm`. The body delegates to `processInlineConsent`,
   * which handles validation + ctx writes identically to the inline path.
   */
  @Step("terms-bump-prompt")
  termsBumpPrompt(@WorkflowParam("context") ctx: LoginWfCtx): undefined {
    const wf = useAtscriptWf(this.opts.forms.termsBump);
    const input = wf.resolveInput() as InlineConsentInput;
    this.processInlineConsent(ctx, input, wf);
    return undefined;
  }

  /**
   * Batched consent persistence — fans every consent event captured during
   * this workflow run (terms acceptance + marketing opt-in/out) out to the
   * consumer's `persistConsents(username, events)` hook in one call.
   * Idempotent via `ctx.consentsPersisted`; short-circuits with no events
   * when neither gate fired but the schema still routed here (defensive —
   * the schema condition normally filters this case).
   */
  @Step("persist-consents")
  async persistConsentsStep(@WorkflowParam("context") ctx: LoginWfCtx): Promise<undefined> {
    this.requireUsername(ctx);
    if (ctx.consentsPersisted) return undefined;
    const events: ConsentEvent[] = [];
    if (ctx.termsAcceptedDone && ctx.termsAcceptedVersion && ctx.termsAcceptedAt) {
      events.push({
        kind: "terms",
        version: ctx.termsAcceptedVersion,
        at: ctx.termsAcceptedAt,
      });
    }
    if (ctx.pendingMarketingOptIn !== undefined && ctx.marketingDecidedAt) {
      events.push({
        kind: "marketing",
        optIn: ctx.pendingMarketingOptIn,
        at: ctx.marketingDecidedAt,
      });
    }
    if (events.length === 0) {
      ctx.consentsPersisted = true;
      return undefined;
    }
    await this.persistConsents(ctx.username, events);
    ctx.consentsPersisted = true;
    return undefined;
  }

  /**
   * Persist consent events collected during this workflow run. Default: no-op.
   * Override to write to your DB of choice — MongoDB users typically push the
   * events onto an embedded array on the user document, SQL users insert into
   * an audit table. Storage shape is intentionally the consumer's call.
   */
  protected async persistConsents(_username: string, _events: ConsentEvent[]): Promise<void> {
    // No-op default.
  }

  // ── Phase 7: tenant / persona ─────────────────────────────────────────
  @Step("tenant-select")
  async tenantSelect(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    if (!ctx.availableTenants && ctx.username) {
      ctx.availableTenants = await this.loadTenants(ctx.username);
    }
    const wf = useAtscriptWf(this.opts.forms.tenantSelect);
    const input = wf.resolveInput() as { tenantId: string };
    const ok = (ctx.availableTenants ?? []).some((t) => t.id === input.tenantId);
    if (!ok) {
      throw wf.requireInput({ errors: { tenantId: "Unknown tenant" } });
    }
    ctx.selectedTenantId = input.tenantId;
    return undefined;
  }

  /**
   * Resolves the user's available tenants. Default: empty array. Consumers
   * who enable `multiContext.tenantSelect` must override this to return the
   * tenants the user belongs to.
   */
  protected async loadTenants(_username: string): Promise<Array<{ id: string; name: string }>> {
    return [];
  }

  @Step("persona-select")
  async personaSelect(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    if (!ctx.availablePersonas && ctx.username) {
      ctx.availablePersonas = await this.loadPersonas(ctx.username);
    }
    const wf = useAtscriptWf(this.opts.forms.personaSelect);
    const input = wf.resolveInput() as { personaId: string };
    const ok = (ctx.availablePersonas ?? []).some((p) => p.id === input.personaId);
    if (!ok) {
      throw wf.requireInput({ errors: { personaId: "Unknown persona" } });
    }
    ctx.selectedPersonaId = input.personaId;
    return undefined;
  }

  /**
   * Resolves the user's available personas. Default: empty array. Consumers
   * who enable `multiContext.personaSelect` must override this.
   */
  protected async loadPersonas(_username: string): Promise<Array<{ id: string; label: string }>> {
    return [];
  }

  // ── Phase 8: session policy ───────────────────────────────────────────
  @Step("load-active-sessions")
  async loadActiveSessionsStep(@WorkflowParam("context") ctx: LoginWfCtx): Promise<undefined> {
    if (!ctx.username) return undefined;
    ctx.activeSessions = await this.loadActiveSessions(ctx.username);
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
    if (cfg.onLimit === "reject") {
      throw new HttpError(429, "Session limit reached");
    }
    const wf = useAtscriptWf(this.opts.forms.concurrencyLimit);
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
    ctx.riskStepUpEvaluated = true;
    const res = await this.resolveRiskStepUp(ctx);
    if (res.require) {
      ctx.riskStepUpReason = res.reason ?? "additional verification required";
      ctx.mfaChecked = false;
      // delete (not `= undefined`) so the persisted ctx remains JSON-clean
      // — AsWfStore validates state.context against a JSON-anyOf schema and
      // chokes on explicit `undefined` entries.
      delete ctx.pin;
      delete ctx.pinExpire;
    } else {
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
    ctx.tokensIssued = true;
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
      ...(ctx.selectedTenantId && { tenantId: ctx.selectedTenantId }),
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
    ctx.redirectUrl = url;
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
