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
 * **Alt-action delivery.** Form payloads carry `action?: string` alongside
 * the regular form fields. Each form-bearing step inspects `input.action`
 * for routing rather than wiring `@AltAction()` (the existing trigger
 * controller does not call `useWfAction().setAction()`).
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
import { AuthCredential, type AuthEmailKind, type AuthSmsKind } from "@aoothjs/auth";
import {
  type MfaMethodInfo,
  type TrustedDeviceRecord,
  UserAuthError,
  UserService,
  maskEmail,
  maskPhone,
} from "@aoothjs/user";
import { HttpError } from "@moostjs/event-http";
import { Step, useWfFinished, Workflow, WorkflowParam, WorkflowSchema } from "@moostjs/event-wf";
import { current } from "@wooksjs/event-core";
import { useCookies, useRequest, useResponse } from "@wooksjs/event-http";
import { Controller, Injectable } from "moost";

import type { AuditEvent } from "../audit/index";
import { MoostAuthConfig } from "../auth.config";
import { buildLoginResponse, cookieAttrs } from "../auth.cookies";
import {
  type LoginWorkflowOpts,
  type ResolvedLoginWorkflowOpts,
  mergeLoginOpts,
} from "./login.workflow.options";
import {
  buildFinishedCookies,
  httpInputRequired,
  requireUsername,
  translatePasswordSetError,
  validateFormInput,
} from "./wf-helpers";

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

/** Mint a numeric pincode of the requested length using Math.random — fine for OTPs. */
function generatePincode(length: number): string {
  let out = "";
  for (let i = 0; i < length; i++) out += Math.floor(Math.random() * 10).toString();
  return out;
}

/**
 * Mint and stash a fresh pincode + its expiry on `ctx`. Returns the code so
 * the caller can hand it to the delivery transport.
 */
function mintPin(ctx: LoginWfCtx, length: number, ttlMs: number): string {
  const code = generatePincode(length);
  ctx.pin = code;
  ctx.pinExpire = Date.now() + ttlMs;
  return code;
}

/**
 * Verify a submitted pincode against the one stashed on `ctx`. Returns a
 * `{ code: '…' }` error map when expired/invalid, or `null` on success.
 * Callers wrap with `httpInputRequired(PincodeForm, ctx, …)` to render.
 */
function verifyPin(ctx: LoginWfCtx, submitted: string | undefined): { code: string } | null {
  if (!ctx.pin || !ctx.pinExpire || Date.now() > ctx.pinExpire) return { code: "Code expired" };
  if (submitted !== ctx.pin) return { code: "Invalid code" };
  return null;
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

@Injectable("FOR_EVENT")
@Controller()
export class LoginWorkflow {
  protected readonly opts: ResolvedLoginWorkflowOpts;
  protected readonly users: UserService;
  protected readonly auth: AuthCredential;
  protected readonly authConfig: MoostAuthConfig;

  constructor(
    opts: LoginWorkflowOpts,
    users: UserService,
    auth: AuthCredential,
    authConfig: MoostAuthConfig,
  ) {
    this.opts = mergeLoginOpts(opts);
    this.users = users;
    this.auth = auth;
    this.authConfig = authConfig;
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
  async credentials(
    @WorkflowParam("input") input:
      | { username?: string; password?: string; action?: string }
      | undefined,
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(this.opts.forms.loginCredentials, ctx);

    // Alt-action routing — handled BEFORE form validation so the user can
    // hit "Forgot password?" without filling in the password field. The
    // handler returns `ALT_HANDLED` (sentinel) when it has already
    // short-circuited via `useWfFinished().set(...)` or by throwing — the
    // caller then returns `undefined` so the step finishes cleanly without
    // running validation on a payload that lacks the form's required fields.
    if (input.action) {
      const handled = this.handleCredentialsAlt(input.action, input.username);
      if (handled === ALT_HANDLED) return undefined;
    }

    const errors = validateFormInput(this.opts.forms.loginCredentials, input);
    if (errors) return httpInputRequired(this.opts.forms.loginCredentials, ctx, errors);

    try {
      const result = await this.users.login(input.username as string, input.password as string);
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
        return httpInputRequired(this.opts.forms.loginCredentials, ctx, {
          __form: "Invalid credentials",
        });
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
      useWfFinished().set({ type: "redirect", value: url });
      return ALT_HANDLED;
    }
    if (action === "signup" && alt.signup) {
      useWfFinished().set({ type: "redirect", value: alt.signupUrl });
      return ALT_HANDLED;
    }
    if (action === "magicLink" && alt.magicLink) {
      // Magic-link alternate path is a stub. See class doc.
      throw new HttpError(501, "Magic-link login path not implemented in this version");
    }
    const sso = alt.ssoProviders.find((p) => p.id === action);
    if (sso) {
      useWfFinished().set({ type: "redirect", value: sso.url });
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
  async ensureEmail(
    @WorkflowParam("input") input: { email?: string; code?: string } | undefined,
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): Promise<unknown> {
    requireUsername(ctx);
    // Step 1: collect the email if we don't have one.
    if (!ctx.email) {
      if (!input?.email) return httpInputRequired(this.opts.forms.askEmail, ctx);
      const errors = validateFormInput(this.opts.forms.askEmail, input);
      if (errors) return httpInputRequired(this.opts.forms.askEmail, ctx, errors);
      await this.users.addMfaMethod(ctx.username, {
        name: "email",
        value: input.email,
        confirmed: false,
      });
      ctx.email = input.email;
      // Generate + send the OTP, then ask for it next round.
      const code = mintPin(ctx, this.opts.mfa.pincodeLength, this.opts.mfa.pincodeTtlMs);
      await this.deliver({
        channel: "email",
        kind: "login.pincode",
        recipient: input.email,
        code,
        expiresAt: ctx.pinExpire as number,
      });
      return httpInputRequired(this.opts.forms.pincode, ctx);
    }
    // Step 2: verify the OTP.
    if (!input?.code) return httpInputRequired(this.opts.forms.pincode, ctx);
    const errors = validateFormInput(this.opts.forms.pincode, input);
    if (errors) return httpInputRequired(this.opts.forms.pincode, ctx, errors);
    const pinErr = verifyPin(ctx, input.code);
    if (pinErr) return httpInputRequired(this.opts.forms.pincode, ctx, pinErr);
    await this.users.confirmMfaMethod(ctx.username, "email");
    ctx.emailConfirmed = true;
    ctx.pin = undefined;
    ctx.pinExpire = undefined;
    return undefined;
  }

  @Step("ensurePhone")
  async ensurePhone(
    @WorkflowParam("input") input: { phone?: string; code?: string } | undefined,
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): Promise<unknown> {
    requireUsername(ctx);
    if (!ctx.phone) {
      if (!input?.phone) return httpInputRequired(this.opts.forms.askPhone, ctx);
      const errors = validateFormInput(this.opts.forms.askPhone, input);
      if (errors) return httpInputRequired(this.opts.forms.askPhone, ctx, errors);
      await this.users.addMfaMethod(ctx.username, {
        name: "sms",
        value: input.phone,
        confirmed: false,
      });
      ctx.phone = input.phone;
      const code = mintPin(ctx, this.opts.mfa.pincodeLength, this.opts.mfa.pincodeTtlMs);
      await this.deliver({
        channel: "sms",
        kind: "login.pincode",
        recipient: input.phone,
        code,
        ttlMs: this.opts.mfa.pincodeTtlMs,
        userId: ctx.username,
      });
      return httpInputRequired(this.opts.forms.pincode, ctx);
    }
    if (!input?.code) return httpInputRequired(this.opts.forms.pincode, ctx);
    const errors = validateFormInput(this.opts.forms.pincode, input);
    if (errors) return httpInputRequired(this.opts.forms.pincode, ctx, errors);
    const pinErr = verifyPin(ctx, input.code);
    if (pinErr) return httpInputRequired(this.opts.forms.pincode, ctx, pinErr);
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
  async select2fa(
    @WorkflowParam("input") input:
      | { methodName?: string; saveAsDefault?: boolean; action?: string }
      | undefined,
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(this.opts.forms.select2fa, ctx);
    if (input.action === "useBackupCode" && this.opts.mfa.backupCodes) {
      return this.handleBackupCode(
        (input as { code?: string }).code ? { code: (input as { code?: string }).code } : undefined,
        ctx,
      );
    }
    const errors = validateFormInput(this.opts.forms.select2fa, input);
    if (errors) return httpInputRequired(this.opts.forms.select2fa, ctx, errors);
    const picked = (ctx.mfaEnrolledMethods ?? []).find((m) => m.methodName === input.methodName);
    if (!picked) {
      return httpInputRequired(this.opts.forms.select2fa, ctx, {
        methodName: "Unknown MFA method",
      });
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
    const code = mintPin(ctx, this.opts.mfa.pincodeLength, this.opts.mfa.pincodeTtlMs);
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
  async pincodeCheckLogin(
    @WorkflowParam("input") input:
      | { code?: string; action?: string; rememberDevice?: boolean }
      | undefined,
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(this.opts.forms.pincode, ctx);
    if (input.action === "resend") {
      if (ctx.pinTimeout && Date.now() < ctx.pinTimeout) {
        const waitSec = Math.ceil((ctx.pinTimeout - Date.now()) / 1000);
        return httpInputRequired(this.opts.forms.pincode, ctx, {
          __form: `Please wait ${waitSec}s`,
        });
      }
      ctx.pin = undefined;
      ctx.pinExpire = undefined;
      // Re-runs `pincode-send-login` on the next iteration because `!ctx.pin`.
      // Returning a paused form would short-circuit the schema; instead, fall
      // through to the resend by clearing and re-invoking via the schema.
      // moost-wf re-evaluates conditions on resume — clearing `pin` causes
      // `pincode-send-login` to be re-included next pass.
      return httpInputRequired(this.opts.forms.pincode, ctx, { __form: "Code resent" });
    }
    if (input.action === "useDifferentMethod") {
      ctx.ignoreMfaDefault = true;
      ctx.mfaMethod = undefined;
      ctx.pin = undefined;
      ctx.pinExpire = undefined;
      return undefined;
    }
    if (input.action === "useBackupCode" && this.opts.mfa.backupCodes) {
      // First click → no `code` field → handleBackupCode pauses for the form.
      // Resume with the backup code populated → handleBackupCode validates and
      // consumes. The presence of `code` is the toggle.
      return this.handleBackupCode(input.code ? { code: input.code } : undefined, ctx);
    }
    const errors = validateFormInput(this.opts.forms.pincode, input);
    if (errors) return httpInputRequired(this.opts.forms.pincode, ctx, errors);
    const pinErr = verifyPin(ctx, input.code);
    if (pinErr) return httpInputRequired(this.opts.forms.pincode, ctx, pinErr);
    ctx.mfaChecked = true;
    // Allow the risk-step-up gate to re-evaluate after this re-verification.
    ctx.riskStepUpEvaluated = false;
    if (this.opts.deviceTrust.enabled && this.opts.deviceTrust.optIn) {
      ctx.rememberDevice = Boolean(input.rememberDevice);
    }
    return undefined;
  }

  @Step("mfa-totp")
  async mfaTotp(
    @WorkflowParam("input") input:
      | { code?: string; action?: string; rememberDevice?: boolean }
      | undefined,
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(this.opts.forms.mfaCode, ctx);
    if (input.action === "useDifferentMethod") {
      ctx.ignoreMfaDefault = true;
      ctx.mfaMethod = undefined;
      return undefined;
    }
    if (input.action === "useBackupCode" && this.opts.mfa.backupCodes) {
      return this.handleBackupCode(input.code ? { code: input.code } : undefined, ctx);
    }
    const errors = validateFormInput(this.opts.forms.mfaCode, input);
    if (errors) return httpInputRequired(this.opts.forms.mfaCode, ctx, errors);
    requireUsername(ctx);
    try {
      await this.users.verifyMfa(ctx.username, input.code as string);
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
          return httpInputRequired(this.opts.forms.mfaCode, ctx, { code: "Invalid code" });
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
    if (!input) return httpInputRequired(this.opts.forms.backupCode, ctx);
    const errors = validateFormInput(this.opts.forms.backupCode, input);
    if (errors) return httpInputRequired(this.opts.forms.backupCode, ctx, errors);
    requireUsername(ctx);
    const ok = await this.users.consumeBackupCode(ctx.username, input.code as string);
    if (!ok)
      return httpInputRequired(this.opts.forms.backupCode, ctx, { code: "Invalid backup code" });
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
      cookieAttrs(this.authConfig.cookie, { maxAge: this.opts.deviceTrust.ttlMs / 1000 }),
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
  async createPasswordForm(
    @WorkflowParam("input") input:
      | { newPassword?: string; confirmPassword?: string; action?: string }
      | undefined,
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(this.opts.forms.setPassword, ctx);
    if (input.action === "logout") {
      useWfFinished().set({ type: "data", value: { aborted: true, reason: "logout" } });
      // Gate downstream steps (issue/audit/notify/redirect) — without this
      // the schema continues and the `issue` step overwrites the abort
      // response with tokens. See BUG-LOGIN-5.
      ctx.aborted = true;
      return undefined;
    }
    const errors = validateFormInput(this.opts.forms.setPassword, input);
    if (errors) return httpInputRequired(this.opts.forms.setPassword, ctx, errors);
    if (input.newPassword !== input.confirmPassword) {
      return httpInputRequired(this.opts.forms.setPassword, ctx, {
        confirmPassword: "Passwords do not match",
      });
    }
    requireUsername(ctx);
    try {
      await this.users.setPassword(ctx.username, input.newPassword as string);
    } catch (err) {
      translatePasswordSetError(err);
    }
    ctx.passwordChanged = true;
    ctx.isPasswordInitial = false;
    return undefined;
  }

  // ── Phase 6: acceptance / onboarding ──────────────────────────────────
  @Step("terms-accept")
  async termsAccept(
    @WorkflowParam("input") input:
      | { acceptedVersion?: string; accepted?: boolean; action?: string }
      | undefined,
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(this.opts.forms.termsAccept, ctx);
    if (input.action === "decline") {
      useWfFinished().set({
        type: "data",
        value: { aborted: true, reason: "termsDeclined", message: "You must accept to continue" },
      });
      // BUG-LOGIN-5: stop the schema progressing into `issue` etc.
      ctx.aborted = true;
      return undefined;
    }
    const errors = validateFormInput(this.opts.forms.termsAccept, input);
    if (errors) return httpInputRequired(this.opts.forms.termsAccept, ctx, errors);
    if (input.accepted !== true) {
      return httpInputRequired(this.opts.forms.termsAccept, ctx, {
        accepted: "You must accept the terms",
      });
    }
    if (input.acceptedVersion !== this.opts.acceptance.termsVersion) {
      return httpInputRequired(this.opts.forms.termsAccept, ctx, {
        acceptedVersion: "Version mismatch — please retry",
      });
    }
    ctx.termsAcceptedVersion = input.acceptedVersion;
    ctx.termsAcceptedDone = true;
    return undefined;
  }

  @Step("profile-complete")
  async profileComplete(
    @WorkflowParam("input") input: Record<string, unknown> | undefined,
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): Promise<unknown> {
    const form = this.opts.forms.profileComplete;
    if (!input) return httpInputRequired(form, ctx);
    const errors = validateFormInput(form, input, { partial: "deep" });
    if (errors) return httpInputRequired(form, ctx, errors);
    requireUsername(ctx);
    await this.applyProfile(ctx.username, input);
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
  async consentMarketing(
    @WorkflowParam("input") input: { optIn?: boolean; action?: string } | undefined,
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(this.opts.forms.consentMarketing, ctx);
    requireUsername(ctx);
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
  async tenantSelect(
    @WorkflowParam("input") input: { tenantId?: string } | undefined,
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): Promise<unknown> {
    if (!ctx.availableTenants && ctx.username) {
      ctx.availableTenants = await this.loadTenants(ctx.username);
    }
    if (!input) return httpInputRequired(this.opts.forms.tenantSelect, ctx);
    const errors = validateFormInput(this.opts.forms.tenantSelect, input);
    if (errors) return httpInputRequired(this.opts.forms.tenantSelect, ctx, errors);
    const ok = (ctx.availableTenants ?? []).some((t) => t.id === input.tenantId);
    if (!ok) {
      return httpInputRequired(this.opts.forms.tenantSelect, ctx, { tenantId: "Unknown tenant" });
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
  async personaSelect(
    @WorkflowParam("input") input: { personaId?: string } | undefined,
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): Promise<unknown> {
    if (!ctx.availablePersonas && ctx.username) {
      ctx.availablePersonas = await this.loadPersonas(ctx.username);
    }
    if (!input) return httpInputRequired(this.opts.forms.personaSelect, ctx);
    const errors = validateFormInput(this.opts.forms.personaSelect, input);
    if (errors) return httpInputRequired(this.opts.forms.personaSelect, ctx, errors);
    const ok = (ctx.availablePersonas ?? []).some((p) => p.id === input.personaId);
    if (!ok) {
      return httpInputRequired(this.opts.forms.personaSelect, ctx, {
        personaId: "Unknown persona",
      });
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
  async concurrencyLimit(
    @WorkflowParam("input") input: { action?: string } | undefined,
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): Promise<unknown> {
    const cfg = this.opts.sessionPolicy.concurrencyLimit;
    if (!cfg) return undefined;
    if (cfg.onLimit === "reject") {
      throw new HttpError(429, "Session limit reached");
    }
    if (!input) return httpInputRequired(this.opts.forms.concurrencyLimit, ctx);
    if (input.action === "cancel") {
      useWfFinished().set({ type: "data", value: { aborted: true, reason: "sessionLimit" } });
      // BUG-LOGIN-5: stop the schema progressing into `issue` etc.
      ctx.aborted = true;
      return undefined;
    }
    const errors = validateFormInput(this.opts.forms.concurrencyLimit, input);
    if (errors) return httpInputRequired(this.opts.forms.concurrencyLimit, ctx, errors);
    if (input.action === "logoutOthers" && ctx.username) {
      await this.logoutOtherSessions(ctx.username);
    }
    return undefined;
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
    requireUsername(ctx);
    const issue = await this.auth.issue(ctx.username);
    ctx.tokensIssued = true;
    // Build response payload + cookies and stash on the finished response.
    // The `redirect` step (terminal) overrides with a redirect type when
    // `resolveRedirect` returns a URL; otherwise the data response sticks.
    useWfFinished().set({
      type: "data",
      value: buildLoginResponse(this.authConfig, ctx.username, issue),
      cookies: buildFinishedCookies(this.authConfig, issue),
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
    // finish with a redirect; otherwise keep the data response from `issue`.
    const url = this.resolveRedirect(ctx);
    if (!url) return undefined;
    const existing = useWfFinished().get();
    useWfFinished().set({
      type: "redirect",
      value: url,
      ...(existing?.cookies && { cookies: existing.cookies }),
    });
    ctx.redirectUrl = url;
    return undefined;
  }

  /**
   * Resolves the post-login redirect URL. Default reads
   * `finalize.redirect`: `'home'` → `/`; `'referer'` → request `Referer`
   * header (returns undefined when absent so the `issue` step's data
   * response stands — typical for SPAs/API clients).
   *
   * Consumers who want a computed redirect override this method.
   */
  protected resolveRedirect(_ctx: LoginWfCtx): string | undefined {
    const r = this.opts.finalize.redirect;
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

  // ── Helpers ───────────────────────────────────────────────────────────
  private resolveClientIp(): string | undefined {
    try {
      const req = useRequest(current());
      // wooks getIp(): some adapters return null for tests; cast loosely.
      const ip = (req as unknown as { getIp?: () => string | undefined }).getIp?.();
      return ip || undefined;
    } catch {
      return undefined;
    }
  }
}
