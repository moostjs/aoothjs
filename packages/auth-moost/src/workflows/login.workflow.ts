/**
 * LoginWorkflow — `wfid = 'auth.login'`.
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
 * re-apply `@Inherit() @Injectable('FOR_EVENT') @Controller()` and re-declare
 * the constructor signature (TS emits fresh design-paramtypes per class).
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
import { useCookies, useRequest, useResponse } from "@wooksjs/event-http";
import { Controller, Injectable } from "moost";

import type { AuditEvent } from "../audit/index";
import { useAuth } from "../auth.composables";
import { Public } from "../auth.decorator";
import { AuthWorkflowBase } from "./auth-workflow.base";
import {
  type LoginWorkflowOpts,
  type ResolvedLoginWorkflowOpts,
  mergeLoginOpts,
} from "./login.workflow.options";

export interface LoginWfCtx {
  // Populated by `init`:
  opts?: ResolvedLoginWorkflowOpts;

  // Populated by `credentials`:
  username?: string;
  /** Legacy alias for `pwReset`; kept until tests migrate. */
  mfaRequired?: boolean;
  isPasswordInitial?: boolean;
  usedMagicLink?: boolean;

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

  // Pincode state:
  pin?: string;
  pinExpire?: number;
  pinTimeout?: number;
  pinSentTo?: string;

  // Device trust:
  deviceTrustToken?: string;
  /** Set true at MFA gate when no trust cookie matched → trigger `notify-new-device`. */
  newDevice?: boolean;
  /** Captured from the OTP/pincode form when `opts.deviceTrust.optIn`. */
  rememberDevice?: boolean;

  // Terms / profile:
  termsAcceptedVersion?: string;
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
  consentApplied?: boolean;
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
function validateOpts(opts: ResolvedLoginWorkflowOpts): void {
  if (opts.mfa.enabled && opts.mfa.transports.length === 0) {
    throw new Error("LoginWorkflow: mfa.transports cannot be empty when mfa.enabled is true");
  }
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
@Injectable("FOR_EVENT")
@Controller()
export class LoginWorkflow extends AuthWorkflowBase {
  protected readonly opts: ResolvedLoginWorkflowOpts;
  protected readonly users: UserService;
  protected readonly auth: AuthCredential;

  constructor(opts: LoginWorkflowOpts, users: UserService, auth: AuthCredential) {
    super();
    this.opts = mergeLoginOpts(opts);
    this.users = users;
    this.auth = auth;
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
    await this.users.addTrustedDevice(userId, record);
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

  @Workflow("auth.login")
  @WorkflowSchema<LoginWfCtx>([
    { id: "init" },
    { id: "credentials" },
    // Phase 1 alternate paths (stubs — never reachable via condition).
    { id: "magicLinkRequest", condition: () => false },
    { id: "magicLinkSend", condition: () => false },
    { id: "magicLinkVerified", condition: () => false },
    { id: "passkey", condition: () => false },
    { id: "ssoCallback", condition: () => false },
    // Phase 3 enrollment loops (single-pass):
    {
      id: "ensureEmail",
      condition: (ctx) =>
        !!ctx.username &&
        (ctx.opts!.enrollment.ensureEmail || ctx.opts!.guards.emailVerifiedRequired) &&
        !ctx.emailConfirmed &&
        !ctx.aborted,
    },
    {
      id: "ensurePhone",
      condition: (ctx) =>
        !!ctx.username && ctx.opts!.enrollment.ensurePhone && !ctx.phoneConfirmed && !ctx.aborted,
    },
    // Phase 4 MFA + Phase 8 risk-step-up wrapped in a while-loop so:
    //   - `select2fa.useDifferentMethod` (BUG-LOGIN-3/4) can clear `mfaMethod`
    //     and loop back to method picking + re-verification,
    //   - `risk-step-up` can clear `mfaChecked` to force an additional factor.
    // The loop exits the moment `mfaChecked` flips true with no pending risk
    // step-up — at which point linear execution resumes.
    {
      while: (ctx) => !!(ctx.username && ctx.opts!.mfa.enabled && !ctx.mfaChecked && !ctx.aborted),
      steps: [
        {
          id: "check-trusted-device",
          condition: (ctx) =>
            ctx.opts!.deviceTrust.enabled && ctx.opts!.deviceTrust.skipsMfa && !ctx.mfaChecked,
        },
        {
          id: "prepare-mfa-options",
          condition: (ctx) => !ctx.mfaChecked,
        },
        {
          id: "select2fa",
          condition: (ctx) =>
            !ctx.mfaChecked && !ctx.mfaMethod && (ctx.mfaEnrolledMethods?.length ?? 0) > 1,
        },
        {
          id: "pincode-send-login",
          condition: (ctx) =>
            !ctx.mfaChecked && (ctx.mfaMethod === "sms" || ctx.mfaMethod === "email") && !ctx.pin,
        },
        {
          id: "pincode-check-login",
          condition: (ctx) =>
            !ctx.mfaChecked && (ctx.mfaMethod === "sms" || ctx.mfaMethod === "email"),
        },
        {
          id: "mfa-totp",
          condition: (ctx) => !ctx.mfaChecked && ctx.mfaMethod === "totp",
        },
        {
          id: "mfa-enroll-required",
          condition: (ctx) =>
            ctx.opts!.mfa.enrollRequired &&
            !ctx.mfaChecked &&
            (ctx.mfaEnrolledMethods?.length ?? 0) === 0,
        },
        {
          // Inside the loop so a `require: true` result can clear `mfaChecked`
          // and force another MFA round. `riskStepUpEvaluated` is the one-shot
          // guard: it flips true on each call and is only reset when the loop
          // re-enters MFA, so a `require: false` outcome lets the loop exit.
          id: "risk-step-up",
          condition: (ctx) => !!(ctx.mfaChecked && !ctx.riskStepUpEvaluated),
        },
      ],
    },
    {
      id: "device-trust",
      condition: (ctx) =>
        !!ctx.username &&
        ctx.opts!.deviceTrust.enabled &&
        !!ctx.mfaChecked &&
        !!ctx.newDevice &&
        (!ctx.opts!.deviceTrust.optIn || !!ctx.rememberDevice) &&
        !ctx.aborted,
    },
    // Phase 5 forced password change:
    {
      id: "prepare-password-rules",
      condition: (ctx) => !!ctx.isPasswordInitial && !ctx.passwordChanged && !ctx.aborted,
    },
    {
      id: "create-password-form",
      condition: (ctx) => !!ctx.isPasswordInitial && !ctx.passwordChanged && !ctx.aborted,
    },
    // Phase 6 acceptance / onboarding:
    {
      id: "terms-accept",
      condition: (ctx) =>
        !!ctx.username &&
        !!ctx.opts!.acceptance.termsVersion &&
        ctx.termsAcceptedVersion !== ctx.opts!.acceptance.termsVersion &&
        !ctx.termsAcceptedDone &&
        !ctx.aborted,
    },
    {
      id: "profile-complete",
      condition: (ctx) =>
        !!ctx.username &&
        ctx.opts!.acceptance.profileCompleteRequired &&
        !ctx.profileApplied &&
        (ctx.profileMissingFields?.length ?? 0) > 0 &&
        !ctx.aborted,
    },
    {
      id: "consent-marketing",
      condition: (ctx) =>
        !!ctx.username &&
        ctx.opts!.acceptance.consentMarketing &&
        !ctx.consentApplied &&
        !ctx.aborted,
    },
    // Phase 7 tenant / persona:
    {
      id: "tenant-select",
      condition: (ctx) =>
        !!ctx.username &&
        ctx.opts!.multiContext.tenantSelect &&
        !ctx.selectedTenantId &&
        (ctx.availableTenants?.length ?? 0) > 1 &&
        !ctx.aborted,
    },
    {
      id: "persona-select",
      condition: (ctx) =>
        !!ctx.username &&
        ctx.opts!.multiContext.personaSelect &&
        !ctx.selectedPersonaId &&
        (ctx.availablePersonas?.length ?? 0) > 1 &&
        !ctx.aborted,
    },
    // Phase 8 session policy:
    {
      id: "concurrency-limit",
      condition: (ctx) =>
        !!ctx.username &&
        !!ctx.opts!.sessionPolicy.concurrencyLimit &&
        (ctx.activeSessions ?? 0) >= ctx.opts!.sessionPolicy.concurrencyLimit.max &&
        !ctx.aborted,
    },
    // Phase 9 finalize. All gate on `!ctx.aborted` so the abort response set
    // via `useWfFinished()` by an abort alt-action (BUG-LOGIN-5) is not
    // overwritten by token issuance further down.
    {
      id: "issue",
      condition: (ctx) => !!ctx.username && !ctx.tokensIssued && !ctx.aborted,
    },
    {
      id: "audit-login",
      condition: (ctx) =>
        !!ctx.username && ctx.opts!.finalize.auditLogin && !!ctx.tokensIssued && !ctx.aborted,
    },
    {
      id: "notify-new-device",
      condition: (ctx) =>
        !!ctx.username &&
        ctx.opts!.finalize.notifyNewDevice &&
        !!ctx.newDevice &&
        !!ctx.tokensIssued &&
        !ctx.aborted,
    },
    {
      id: "redirect",
      condition: (ctx) => !!ctx.username && !!ctx.tokensIssued && !ctx.aborted,
    },
  ])
  flow(): void {}

  // ── Phase 0 ───────────────────────────────────────────────────────────
  @Step("init")
  init(@WorkflowParam("context") ctx: LoginWfCtx): undefined {
    // `snapshotOpts` returns a JSON-safe projection (drops the `forms` group of
    // atscript classes) so it persists into `AsWfStore`. Step bodies still
    // consult `this.opts.forms.*` via `this.opts`, not `ctx.opts`.
    ctx.opts = this.snapshotOpts(this.opts);
    return undefined;
  }

  /**
   * Returns the JSON-safe projection of `opts` stashed onto `ctx` for schema
   * conditions to read. Default: drop the `forms` group (atscript form classes
   * are not plain JSON) so `AsWfStore`'s plain-JSON persistence doesn't choke.
   * Step bodies still consult the form classes via `this.opts.forms.*`.
   *
   * Consumers who put non-JSON values on `opts` (e.g. by extending the type)
   * can override this to strip them.
   */
  protected snapshotOpts(opts: ResolvedLoginWorkflowOpts): ResolvedLoginWorkflowOpts {
    const { forms: _forms, ...rest } = opts;
    return rest as ResolvedLoginWorkflowOpts;
  }

  // ── Phase 1 ───────────────────────────────────────────────────────────
  @Step("credentials")
  async credentials(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    // Mirror alt-credentials config into ctx so the form can hide each alt-action
    // button when its corresponding feature is disabled (`@ui.form.fn.hidden`).
    const alt = this.opts.alternateCredentials;
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
      const handled = this.handleCredentialsAlt(action, typedUsername);
      if (handled === ALT_HANDLED) return undefined;
    }

    const input = wf.resolveInput() as { username: string; password: string };

    try {
      const result = await this.users.login(input.username, input.password);
      ctx.username = result.user.username;
      // Preserve legacy `mfaRequired` for tests / consumer subclasses; the
      // step catalog decides MFA inclusion via `mfa.enabled` + enrolled
      // methods, not this flag.
      ctx.mfaRequired = result.mfaRequired;
      // Phase 2 inline guards:
      if (this.opts.guards.passwordInitial && result.user.password.isInitial) {
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
  ): AltHandled | undefined {
    const alt = this.opts.alternateCredentials;
    if (action === "forgotPassword" && alt.forgotPassword) {
      const url = this.buildRecoveryUrl(typedUsername);
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
   * Builds the redirect URL the `forgotPassword` alt-action navigates to.
   * Receives whatever the user typed into the username field so the recovery
   * page can pre-fill it. Default:
   * `${alternateCredentials.recoveryUrl}?username=${encodeURIComponent(username ?? '')}`.
   */
  protected buildRecoveryUrl(username?: string): string {
    const base = this.opts.alternateCredentials.recoveryUrl;
    return `${base}?username=${encodeURIComponent(username ?? "")}`;
  }

  @Step("magicLinkRequest")
  magicLinkRequest(): never {
    throw new HttpError(501, "magicLinkRequest step not implemented");
  }

  @Step("magicLinkSend")
  magicLinkSend(): never {
    throw new HttpError(501, "magicLinkSend step not implemented");
  }

  @Step("magicLinkVerified")
  magicLinkVerified(): never {
    throw new HttpError(501, "magicLinkVerified step not implemented");
  }

  @Step("passkey")
  passkey(): never {
    throw new HttpError(501, "passkey step not implemented");
  }

  @Step("ssoCallback")
  ssoCallback(): never {
    throw new HttpError(501, "ssoCallback step not implemented");
  }

  // ── Phase 3: enrollment loops (single-pass per brief) ─────────────────
  @Step("ensureEmail")
  async ensureEmail(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    this.requireUsername(ctx);
    const pincodeWf = useAtscriptWf(this.opts.forms.pincode);
    // Step 1: collect the email if we don't have one.
    if (!ctx.email) {
      const askEmailWf = useAtscriptWf(this.opts.forms.askEmail);
      const input = askEmailWf.resolveInput() as { email: string };
      await this.users.addMfaMethod(ctx.username, {
        name: "email",
        value: input.email,
        confirmed: false,
      });
      ctx.email = input.email;
      // Generate + send the OTP, then ask for it next round.
      const code = this.mintPin(ctx, this.opts.mfa.pincodeLength, this.opts.mfa.pincodeTtlMs);
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
    await this.users.confirmMfaMethod(ctx.username, "email");
    ctx.emailConfirmed = true;
    ctx.pin = undefined;
    ctx.pinExpire = undefined;
    return undefined;
  }

  @Step("ensurePhone")
  async ensurePhone(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    this.requireUsername(ctx);
    const pincodeWf = useAtscriptWf(this.opts.forms.pincode);
    if (!ctx.phone) {
      const askPhoneWf = useAtscriptWf(this.opts.forms.askPhone);
      const input = askPhoneWf.resolveInput() as { phone: string };
      await this.users.addMfaMethod(ctx.username, {
        name: "sms",
        value: input.phone,
        confirmed: false,
      });
      ctx.phone = input.phone;
      const code = this.mintPin(ctx, this.opts.mfa.pincodeLength, this.opts.mfa.pincodeTtlMs);
      await this.deliver({
        channel: "sms",
        kind: "login.pincode",
        recipient: input.phone,
        code,
        ttlMs: this.opts.mfa.pincodeTtlMs,
        userId: ctx.username,
      });
      throw pincodeWf.requireInput();
    }
    const input = pincodeWf.resolveInput() as { code: string };
    const pinErr = this.verifyPin(ctx, input.code);
    if (pinErr) throw pincodeWf.requireInput({ errors: pinErr });
    await this.users.confirmMfaMethod(ctx.username, "sms");
    ctx.phoneConfirmed = true;
    ctx.pin = undefined;
    ctx.pinExpire = undefined;
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

  @Step("prepare-mfa-options")
  async prepareMfaOptions(@WorkflowParam("context") ctx: LoginWfCtx): Promise<undefined> {
    if (!ctx.username) return undefined;
    const user = await this.users.getUser(ctx.username);
    const allowed = new Set(this.opts.mfa.transports);
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
    ctx.mfaBackupCodes = !!this.opts.mfa.backupCodes;
    // Short-circuit: no methods → MFA is skipped (covered by mfa-enroll-required
    // when policy demands enrolment; otherwise we let the user through).
    if (summary.length === 0) {
      ctx.mfaChecked = true;
      return undefined;
    }
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

  @Step("select2fa")
  async select2fa(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    const wf = useAtscriptWf(this.opts.forms.select2fa);
    const action = wf.resolveAction();
    if (action === "useBackupCode" && this.opts.mfa.backupCodes) {
      // Peek raw input for the backup `code` field — it lives outside the
      // select2fa form schema, so we read the envelope directly.
      const code = getInputField("code");
      return this.handleBackupCode(code ? { code } : undefined, ctx);
    }
    const input = wf.resolveInput() as { methodName: string; saveAsDefault?: boolean };
    const picked = (ctx.mfaEnrolledMethods ?? []).find((m) => m.methodName === input.methodName);
    if (!picked) {
      throw wf.requireInput({ errors: { methodName: "Unknown MFA method" } });
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
    const code = this.mintPin(ctx, this.opts.mfa.pincodeLength, this.opts.mfa.pincodeTtlMs);
    ctx.pinTimeout = Date.now() + this.opts.mfa.pincodeResendTimeoutMs;
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
        ttlMs: this.opts.mfa.pincodeTtlMs,
        userId: ctx.username,
      });
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
      ctx.pin = undefined;
      ctx.pinExpire = undefined;
      // Re-runs `pincode-send-login` on the next iteration because `!ctx.pin`.
      // Throwing a paused form would short-circuit the schema; instead, fall
      // through to the resend by clearing and re-invoking via the schema.
      // moost-wf re-evaluates conditions on resume — clearing `pin` causes
      // `pincode-send-login` to be re-included next pass.
      throw wf.requireInput({ formMessage: "Code resent" });
    }
    if (action === "useDifferentMethod") {
      ctx.ignoreMfaDefault = true;
      ctx.mfaMethod = undefined;
      ctx.pin = undefined;
      ctx.pinExpire = undefined;
      return undefined;
    }
    if (action === "useBackupCode" && this.opts.mfa.backupCodes) {
      // First click → no `code` field → handleBackupCode pauses for the form.
      // Resume with the backup code populated → handleBackupCode validates and
      // consumes. The presence of `code` is the toggle.
      const code = getInputField("code");
      return this.handleBackupCode(code ? { code } : undefined, ctx);
    }
    const input = wf.resolveInput() as { code: string; rememberDevice?: boolean };
    const pinErr = this.verifyPin(ctx, input.code);
    if (pinErr) throw wf.requireInput({ errors: pinErr });
    ctx.mfaChecked = true;
    // Allow the risk-step-up gate to re-evaluate after this re-verification.
    ctx.riskStepUpEvaluated = false;
    if (this.opts.deviceTrust.enabled && this.opts.deviceTrust.optIn) {
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
      ctx.mfaMethod = undefined;
      return undefined;
    }
    if (action === "useBackupCode" && this.opts.mfa.backupCodes) {
      const code = getInputField("code");
      return this.handleBackupCode(code ? { code } : undefined, ctx);
    }
    const input = wf.resolveInput() as { code: string; rememberDevice?: boolean };
    this.requireUsername(ctx);
    try {
      await this.users.verifyMfa(ctx.username, input.code);
      ctx.mfaChecked = true;
      ctx.riskStepUpEvaluated = false;
      if (this.opts.deviceTrust.enabled && this.opts.deviceTrust.optIn) {
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
    const ok = await this.users.consumeBackupCode(ctx.username, validated.code);
    if (!ok) throw wf.requireInput({ errors: { code: "Invalid backup code" } });
    ctx.mfaChecked = true;
    ctx.riskStepUpEvaluated = false;
    return undefined;
  }

  @Step("mfa-enroll-required")
  mfaEnrollRequired(): never {
    throw new HttpError(501, "mfa-enroll-required step not implemented");
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
  preparePasswordRules(@WorkflowParam("context") ctx: LoginWfCtx): undefined {
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
    const input = wf.resolveInput() as { newPassword: string; confirmPassword: string };
    if (input.newPassword !== input.confirmPassword) {
      throw wf.requireInput({ errors: { confirmPassword: "Passwords do not match" } });
    }
    this.requireUsername(ctx);
    try {
      await this.users.setPassword(ctx.username, input.newPassword);
    } catch (err) {
      this.translatePasswordSetError(err);
    }
    ctx.passwordChanged = true;
    ctx.isPasswordInitial = false;
    return undefined;
  }

  // ── Phase 6: acceptance / onboarding ──────────────────────────────────
  @Step("terms-accept")
  async termsAccept(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    const wf = useAtscriptWf(this.opts.forms.termsAccept);
    const action = wf.resolveAction();
    if (action === "decline") {
      abortWf("termsDeclined", {
        message: { level: "info", text: "You must accept to continue" },
      });
      // BUG-LOGIN-5: stop the schema progressing into `issue` etc.
      ctx.aborted = true;
      return undefined;
    }
    const input = wf.resolveInput() as { acceptedVersion: string; accepted: boolean };
    if (!input.accepted) {
      throw wf.requireInput({ errors: { accepted: "You must accept the terms" } });
    }
    if (input.acceptedVersion !== this.opts.acceptance.termsVersion) {
      throw wf.requireInput({ errors: { acceptedVersion: "Version mismatch — please retry" } });
    }
    ctx.termsAcceptedVersion = input.acceptedVersion;
    ctx.termsAcceptedDone = true;
    return undefined;
  }

  @Step("profile-complete")
  async profileComplete(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    const wf = useAtscriptWf(this.opts.forms.profileComplete);
    const input = wf.resolveInput({ partial: "deep" });
    this.requireUsername(ctx);
    await this.applyProfile(ctx.username, input as Record<string, unknown>);
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

  @Step("consent-marketing")
  async consentMarketing(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    const wf = useAtscriptWf(this.opts.forms.consentMarketing);
    const input = wf.resolveInput() as { optIn?: boolean };
    this.requireUsername(ctx);
    await this.applyConsentMarketing(ctx.username, Boolean(input.optIn));
    ctx.consentApplied = true;
    return undefined;
  }

  /**
   * Persists the marketing consent decision. Default: no-op.
   */
  protected async applyConsentMarketing(_username: string, _optIn: boolean): Promise<void> {
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
  @Step("concurrency-limit")
  async concurrencyLimit(@WorkflowParam("context") ctx: LoginWfCtx): Promise<unknown> {
    const cfg = this.opts.sessionPolicy.concurrencyLimit;
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
    const res = await this.assessRiskStepUp(ctx);
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
   * Risk-step-up assessor. Default: never requires an extra factor. Consumers
   * override to inspect ctx (IP, geo, time since last login, etc.) and return
   * `{require: true, reason: '…'}` to force an additional MFA round.
   */
  protected async assessRiskStepUp(
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
      workflow: "auth.login",
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
  redirect(@WorkflowParam("context") ctx: LoginWfCtx): undefined {
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
   * Consumers who want a computed redirect override this method.
   */
  protected resolveRedirect(_ctx: LoginWfCtx): string | undefined {
    const r = this.opts.finalize.redirect;
    if (r === false || r === null) return undefined;
    if (r === "home") return "/";
    if (r === "referer") {
      try {
        const req = useRequest(current());
        const headers = (
          req as unknown as { headers?: Record<string, string | string[] | undefined> }
        ).headers;
        const ref = headers?.referer ?? headers?.referrer;
        const first = Array.isArray(ref) ? ref[0] : ref;
        return typeof first === "string" && first.length > 0 ? first : undefined;
      } catch {
        return undefined;
      }
    }
    return undefined;
  }
}
