/**
 * LoginWorkflow — `wfid = 'auth.login'`.
 *
 * Full step catalog per `WF_LOGIN.md`. Every advanced step is gated by the
 * matching `LoginWorkflowOptions` flag so the default-opts flow matches
 * today's "credentials → optional totp MFA → issue tokens" behaviour with no
 * surprise prompts.
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
 */
import { AuthCredential, type EmailSender, type SmsSender } from "@aoothjs/auth";
import {
  type MfaMethodInfo,
  UserAuthError,
  UserService,
  maskEmail,
  maskPhone,
} from "@aoothjs/user";
import { HttpError } from "@moostjs/event-http";
import { Step, useWfFinished, Workflow, WorkflowParam, WorkflowSchema } from "@moostjs/event-wf";
import { current } from "@wooksjs/event-core";
import { useCookies, useRequest, useResponse } from "@wooksjs/event-http";
import { Controller, Inject, Injectable, Optional } from "moost";

import {
  AskEmailForm,
  AskPhoneForm,
  BackupCodeForm,
  ConcurrencyLimitForm,
  ConsentMarketingForm,
  LoginCredentialsForm,
  MfaCodeForm,
  PersonaSelectForm,
  PincodeForm,
  Select2faForm,
  SetPasswordForm,
  TenantSelectForm,
  TermsAcceptForm,
} from "../atscript/models/forms.as.js";
import { type AuditEmitter, NoopAuditEmitter } from "../audit/index";
import { MoostAuthConfig } from "../auth.config";
import { buildLoginResponse, cookieAttrs } from "../auth.cookies";
import type { DeviceTrustStore } from "../device-trust/index";
import { LoginWorkflowOptions } from "./login.workflow.options";
import {
  buildFinishedCookies,
  httpInputRequired,
  requireUsername,
  translatePasswordSetError,
  validateFormInput,
} from "./wf-helpers";

export interface LoginWfCtx {
  // Populated by `init`:
  opts?: LoginWorkflowOptions;

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
  /** Captured from the OTP/pincode form when `opts.deviceTrustOptIn`. */
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
 * Strip non-JSON values (functions, class instances) from the options object
 * so the resulting snapshot persists cleanly into `AsWfStore`. Step bodies
 * still consult `this.opts` directly for the callbacks/forms we drop here.
 */
function snapshotOpts(opts: LoginWorkflowOptions): LoginWorkflowOptions {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(opts)) {
    if (v === undefined) continue;
    if (typeof v === "function") continue;
    if (v && typeof v === "object" && !Array.isArray(v)) {
      // Drop atscript form classes (they expose `__is_atscript_annotated_type`).
      if ((v as Record<string, unknown>).__is_atscript_annotated_type) continue;
    }
    out[k] = v;
  }
  // Boolean projections of callback fields — schema `condition`/`while`
  // predicates consult `ctx.opts` (the JSON-safe snapshot) and can't see the
  // original callback. Expose presence-as-bool so conditions can gate on them.
  out.riskStepUpEnabled = typeof opts.riskStepUp === "function";
  return out as unknown as LoginWorkflowOptions;
}

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
 * Boot-time invariants. Called once per options instance via the
 * `validatedOpts` WeakSet guard inside `init` — running here per-event would
 * be wasteful since the options instance is the same across all requests.
 */
function validateOpts(
  opts: LoginWorkflowOptions,
  smsSender?: SmsSender,
  deviceTrustStore?: DeviceTrustStore,
): void {
  if (opts.mfaEnabled && opts.mfaTransports.includes("sms") && !smsSender) {
    throw new Error(
      'LoginWorkflow: SmsSender required when mfaTransports includes "sms" and mfaEnabled is true',
    );
  }
  if (opts.deviceTrust && !deviceTrustStore) {
    throw new Error("LoginWorkflow: DeviceTrustStore required when opts.deviceTrust is true");
  }
  if (opts.mfaTransports.length === 0 && opts.mfaEnabled) {
    throw new Error("LoginWorkflow: mfaTransports cannot be empty when mfaEnabled is true");
  }
}

const validatedOpts = new WeakSet<LoginWorkflowOptions>();

@Injectable("FOR_EVENT")
@Controller()
export class LoginWorkflow {
  constructor(
    private readonly opts: LoginWorkflowOptions,
    private readonly users: UserService,
    private readonly auth: AuthCredential,
    private readonly authConfig: MoostAuthConfig,
    @Optional() @Inject("EmailSender") private readonly mailer?: EmailSender,
    @Optional() @Inject("SmsSender") private readonly smsSender?: SmsSender,
    @Optional() @Inject("DeviceTrustStore") private readonly deviceTrustStore?: DeviceTrustStore,
    @Optional() @Inject("AuditEmitter") private readonly audit?: AuditEmitter,
  ) {}

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
        Boolean(
          ctx.username &&
          ctx.opts &&
          (ctx.opts.ensureEmail || ctx.opts.emailVerifiedRequired) &&
          !ctx.emailConfirmed &&
          !ctx.aborted,
        ),
    },
    {
      id: "ensurePhone",
      condition: (ctx) =>
        Boolean(ctx.username && ctx.opts?.ensurePhone && !ctx.phoneConfirmed && !ctx.aborted),
    },
    // Phase 4 MFA + Phase 8 risk-step-up wrapped in a while-loop so:
    //   - `select2fa.useDifferentMethod` (BUG-LOGIN-3/4) can clear `mfaMethod`
    //     and loop back to method picking + re-verification,
    //   - `risk-step-up` can clear `mfaChecked` to force an additional factor.
    // The loop exits the moment `mfaChecked` flips true with no pending risk
    // step-up — at which point linear execution resumes.
    {
      while: (ctx) =>
        Boolean(ctx.username && ctx.opts?.mfaEnabled && !ctx.mfaChecked && !ctx.aborted),
      steps: [
        {
          id: "check-trusted-device",
          condition: (ctx) =>
            Boolean(ctx.opts?.deviceTrust && ctx.opts?.deviceTrustSkipsMfa && !ctx.mfaChecked),
        },
        {
          id: "prepare-mfa-options",
          condition: (ctx) => Boolean(!ctx.mfaChecked),
        },
        {
          id: "select2fa",
          condition: (ctx) =>
            Boolean(!ctx.mfaChecked && !ctx.mfaMethod && (ctx.mfaEnrolledMethods?.length ?? 0) > 1),
        },
        {
          id: "pincode-send-login",
          condition: (ctx) =>
            Boolean(
              !ctx.mfaChecked && (ctx.mfaMethod === "sms" || ctx.mfaMethod === "email") && !ctx.pin,
            ),
        },
        {
          id: "pincode-check-login",
          condition: (ctx) =>
            Boolean(!ctx.mfaChecked && (ctx.mfaMethod === "sms" || ctx.mfaMethod === "email")),
        },
        {
          id: "mfa-totp",
          condition: (ctx) => Boolean(!ctx.mfaChecked && ctx.mfaMethod === "totp"),
        },
        {
          id: "mfa-enroll-required",
          condition: (ctx) =>
            Boolean(
              ctx.opts?.mfaEnrollRequired &&
              !ctx.mfaChecked &&
              (ctx.mfaEnrolledMethods?.length ?? 0) === 0,
            ),
        },
        {
          // Inside the loop so a `require: true` result can clear `mfaChecked`
          // and force another MFA round. `riskStepUpEvaluated` is the one-shot
          // guard: it flips true on each call and is only reset when the loop
          // re-enters MFA, so a `require: false` outcome lets the loop exit.
          id: "risk-step-up",
          condition: (ctx) =>
            Boolean(ctx.opts?.riskStepUpEnabled && ctx.mfaChecked && !ctx.riskStepUpEvaluated),
        },
      ],
    },
    {
      id: "device-trust",
      condition: (ctx) =>
        Boolean(
          ctx.username &&
          ctx.opts?.deviceTrust &&
          ctx.mfaChecked &&
          ctx.newDevice &&
          (!ctx.opts.deviceTrustOptIn || ctx.rememberDevice) &&
          !ctx.aborted,
        ),
    },
    // Phase 5 forced password change:
    {
      id: "prepare-password-rules",
      condition: (ctx) => Boolean(ctx.isPasswordInitial && !ctx.passwordChanged && !ctx.aborted),
    },
    {
      id: "create-password-form",
      condition: (ctx) => Boolean(ctx.isPasswordInitial && !ctx.passwordChanged && !ctx.aborted),
    },
    // Phase 6 acceptance / onboarding:
    {
      id: "terms-accept",
      condition: (ctx) =>
        Boolean(
          ctx.username &&
          ctx.opts?.termsAcceptVersion &&
          ctx.termsAcceptedVersion !== ctx.opts.termsAcceptVersion &&
          !ctx.termsAcceptedDone &&
          !ctx.aborted,
        ),
    },
    {
      id: "profile-complete",
      condition: (ctx) =>
        Boolean(
          ctx.username &&
          ctx.opts?.profileCompleteRequired &&
          !ctx.profileApplied &&
          (ctx.profileMissingFields?.length ?? 0) > 0 &&
          !ctx.aborted,
        ),
    },
    {
      id: "consent-marketing",
      condition: (ctx) =>
        Boolean(ctx.username && ctx.opts?.consentMarketing && !ctx.consentApplied && !ctx.aborted),
    },
    // Phase 7 tenant / persona:
    {
      id: "tenant-select",
      condition: (ctx) =>
        Boolean(
          ctx.username &&
          ctx.opts?.tenantSelect &&
          !ctx.selectedTenantId &&
          (ctx.availableTenants?.length ?? 0) > 1 &&
          !ctx.aborted,
        ),
    },
    {
      id: "persona-select",
      condition: (ctx) =>
        Boolean(
          ctx.username &&
          ctx.opts?.personaSelect &&
          !ctx.selectedPersonaId &&
          (ctx.availablePersonas?.length ?? 0) > 1 &&
          !ctx.aborted,
        ),
    },
    // Phase 8 session policy:
    {
      id: "concurrency-limit",
      condition: (ctx) =>
        Boolean(
          ctx.username &&
          ctx.opts?.concurrencyLimit &&
          (ctx.activeSessions ?? 0) >= ctx.opts.concurrencyLimit.max &&
          !ctx.aborted,
        ),
    },
    // Phase 9 finalize. All gate on `!ctx.aborted` so the abort response set
    // via `useWfFinished()` by an abort alt-action (BUG-LOGIN-5) is not
    // overwritten by token issuance further down.
    {
      id: "issue",
      condition: (ctx) => Boolean(ctx.username && !ctx.tokensIssued && !ctx.aborted),
    },
    {
      id: "audit-login",
      condition: (ctx) =>
        Boolean(ctx.username && ctx.opts?.auditLogin && ctx.tokensIssued && !ctx.aborted),
    },
    {
      id: "notify-new-device",
      condition: (ctx) =>
        Boolean(
          ctx.username &&
          ctx.opts?.notifyNewDevice &&
          ctx.newDevice &&
          ctx.tokensIssued &&
          !ctx.aborted,
        ),
    },
    {
      id: "redirect",
      condition: (ctx) => Boolean(ctx.username && ctx.tokensIssued && !ctx.aborted),
    },
  ])
  flow(): void {}

  // ── Phase 0 ───────────────────────────────────────────────────────────
  @Step("init")
  init(@WorkflowParam("context") ctx: LoginWfCtx): undefined {
    if (!validatedOpts.has(this.opts)) {
      validateOpts(this.opts, this.smsSender, this.deviceTrustStore);
      validatedOpts.add(this.opts);
    }
    // Snapshot only JSON-serializable feature flags onto ctx — class
    // instances / atscript form classes / callbacks break AsWfStore's plain-
    // JSON schema for `state.context`. Step bodies still read non-serializable
    // callbacks (`recoveryUrlBuilder`, `loadTenants`, ...) via `this.opts`.
    ctx.opts = snapshotOpts(this.opts);
    return undefined;
  }

  // ── Phase 1 ───────────────────────────────────────────────────────────
  @Step("credentials")
  async credentials(
    @WorkflowParam("input") input:
      | { username?: string; password?: string; action?: string }
      | undefined,
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(LoginCredentialsForm, ctx);

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

    const errors = validateFormInput(LoginCredentialsForm, input);
    if (errors) return httpInputRequired(LoginCredentialsForm, ctx, errors);

    try {
      const result = await this.users.login(input.username as string, input.password as string);
      ctx.username = result.user.username;
      // Preserve legacy `mfaRequired` for tests / consumer subclasses; the
      // step catalog decides MFA inclusion via `mfaEnabled` + enrolled
      // methods, not this flag.
      ctx.mfaRequired = result.mfaRequired;
      // Phase 2 inline guards:
      if (this.opts.passwordInitialGuard && result.user.password.isInitial) {
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
        return httpInputRequired(LoginCredentialsForm, ctx, { __form: "Invalid credentials" });
      }
      throw err;
    }
    return undefined;
  }

  private handleCredentialsAlt(
    action: string,
    typedUsername: string | undefined,
  ): AltHandled | undefined {
    if (action === "forgotPassword" && this.opts.forgotPasswordAction) {
      const url = this.opts.recoveryUrlBuilder
        ? this.opts.recoveryUrlBuilder(typedUsername)
        : `${this.opts.recoveryUrl}?username=${encodeURIComponent(typedUsername ?? "")}`;
      useWfFinished().set({ type: "redirect", value: url });
      return ALT_HANDLED;
    }
    if (action === "signup" && this.opts.signupAction) {
      useWfFinished().set({ type: "redirect", value: this.opts.signupUrl });
      return ALT_HANDLED;
    }
    if (action === "magicLink" && this.opts.magicLinkAction) {
      // Magic-link alternate path is a stub. See class doc.
      throw new HttpError(501, "Magic-link login path not implemented in this version");
    }
    const sso = this.opts.ssoActions.find((p) => p.id === action);
    if (sso) {
      useWfFinished().set({ type: "redirect", value: sso.url });
      return ALT_HANDLED;
    }
    return undefined;
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
      if (!input?.email) return httpInputRequired(AskEmailForm, ctx);
      const errors = validateFormInput(AskEmailForm, input);
      if (errors) return httpInputRequired(AskEmailForm, ctx, errors);
      await this.users.addMfaMethod(ctx.username, {
        name: "email",
        value: input.email,
        confirmed: false,
      });
      ctx.email = input.email;
      // Generate + send the OTP, then ask for it next round.
      const code = mintPin(ctx, this.opts.pincodeLength, this.opts.pincodeTtlMs);
      if (!this.mailer) throw new HttpError(500, "EmailSender not registered");
      await this.mailer.send({
        kind: "login.pincode",
        recipient: input.email,
        code,
        expiresAt: ctx.pinExpire as number,
      });
      return httpInputRequired(PincodeForm, ctx);
    }
    // Step 2: verify the OTP.
    if (!input?.code) return httpInputRequired(PincodeForm, ctx);
    const errors = validateFormInput(PincodeForm, input);
    if (errors) return httpInputRequired(PincodeForm, ctx, errors);
    const pinErr = verifyPin(ctx, input.code);
    if (pinErr) return httpInputRequired(PincodeForm, ctx, pinErr);
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
    if (!this.smsSender) {
      throw new HttpError(501, "ensurePhone requires SmsSender to be registered");
    }
    if (!ctx.phone) {
      if (!input?.phone) return httpInputRequired(AskPhoneForm, ctx);
      const errors = validateFormInput(AskPhoneForm, input);
      if (errors) return httpInputRequired(AskPhoneForm, ctx, errors);
      await this.users.addMfaMethod(ctx.username, {
        name: "sms",
        value: input.phone,
        confirmed: false,
      });
      ctx.phone = input.phone;
      const code = mintPin(ctx, this.opts.pincodeLength, this.opts.pincodeTtlMs);
      await this.smsSender.send({
        kind: "login.pincode",
        recipient: input.phone,
        code,
        ttlMs: this.opts.pincodeTtlMs,
        userId: ctx.username,
      });
      return httpInputRequired(PincodeForm, ctx);
    }
    if (!input?.code) return httpInputRequired(PincodeForm, ctx);
    const errors = validateFormInput(PincodeForm, input);
    if (errors) return httpInputRequired(PincodeForm, ctx, errors);
    const pinErr = verifyPin(ctx, input.code);
    if (pinErr) return httpInputRequired(PincodeForm, ctx, pinErr);
    await this.users.confirmMfaMethod(ctx.username, "sms");
    ctx.phoneConfirmed = true;
    ctx.pin = undefined;
    ctx.pinExpire = undefined;
    return undefined;
  }

  // ── Phase 4: MFA ──────────────────────────────────────────────────────
  @Step("check-trusted-device")
  async checkTrustedDevice(@WorkflowParam("context") ctx: LoginWfCtx): Promise<undefined> {
    if (!ctx.username || !this.deviceTrustStore) return undefined;
    const cookieValue = useCookies(current()).getCookie(this.opts.deviceTrustCookieName);
    if (!cookieValue) {
      ctx.newDevice = true;
      return undefined;
    }
    const ip = this.opts.deviceTrustBindsTo === "cookie+ip" ? this.resolveClientIp() : undefined;
    const ok = await this.deviceTrustStore.verify(ctx.username, cookieValue, ip);
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
    const allowed = new Set(this.opts.mfaTransports);
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
    if (!input) return httpInputRequired(Select2faForm, ctx);
    if (input.action === "useBackupCode" && this.opts.mfaBackupCodes) {
      return this.handleBackupCode(
        (input as { code?: string }).code ? { code: (input as { code?: string }).code } : undefined,
        ctx,
      );
    }
    const errors = validateFormInput(Select2faForm, input);
    if (errors) return httpInputRequired(Select2faForm, ctx, errors);
    const picked = (ctx.mfaEnrolledMethods ?? []).find((m) => m.methodName === input.methodName);
    if (!picked) {
      return httpInputRequired(Select2faForm, ctx, { methodName: "Unknown MFA method" });
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
    const code = mintPin(ctx, this.opts.pincodeLength, this.opts.pincodeTtlMs);
    ctx.pinTimeout = Date.now() + this.opts.pincodeResendTimeoutMs;
    if (ctx.mfaMethod === "email") {
      ctx.pinSentTo = maskEmail(method.value);
      if (!this.mailer) throw new HttpError(500, "EmailSender not registered");
      await this.mailer.send({
        kind: "login.pincode",
        recipient: method.value,
        code,
        expiresAt: ctx.pinExpire as number,
        username: ctx.username,
      });
    } else if (ctx.mfaMethod === "sms") {
      if (!this.smsSender) throw new HttpError(500, "SmsSender not registered");
      ctx.pinSentTo = maskPhone(method.value);
      await this.smsSender.send({
        kind: "login.pincode",
        recipient: method.value,
        code,
        ttlMs: this.opts.pincodeTtlMs,
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
    if (!input) return httpInputRequired(PincodeForm, ctx);
    if (input.action === "resend") {
      if (ctx.pinTimeout && Date.now() < ctx.pinTimeout) {
        const waitSec = Math.ceil((ctx.pinTimeout - Date.now()) / 1000);
        return httpInputRequired(PincodeForm, ctx, { __form: `Please wait ${waitSec}s` });
      }
      ctx.pin = undefined;
      ctx.pinExpire = undefined;
      // Re-runs `pincode-send-login` on the next iteration because `!ctx.pin`.
      // Returning a paused form would short-circuit the schema; instead, fall
      // through to the resend by clearing and re-invoking via the schema.
      // moost-wf re-evaluates conditions on resume — clearing `pin` causes
      // `pincode-send-login` to be re-included next pass.
      return httpInputRequired(PincodeForm, ctx, { __form: "Code resent" });
    }
    if (input.action === "useDifferentMethod") {
      ctx.ignoreMfaDefault = true;
      ctx.mfaMethod = undefined;
      ctx.pin = undefined;
      ctx.pinExpire = undefined;
      return undefined;
    }
    if (input.action === "useBackupCode" && this.opts.mfaBackupCodes) {
      // First click → no `code` field → handleBackupCode pauses for the form.
      // Resume with the backup code populated → handleBackupCode validates and
      // consumes. The presence of `code` is the toggle.
      return this.handleBackupCode(input.code ? { code: input.code } : undefined, ctx);
    }
    const errors = validateFormInput(PincodeForm, input);
    if (errors) return httpInputRequired(PincodeForm, ctx, errors);
    const pinErr = verifyPin(ctx, input.code);
    if (pinErr) return httpInputRequired(PincodeForm, ctx, pinErr);
    ctx.mfaChecked = true;
    // Allow the risk-step-up gate to re-evaluate after this re-verification.
    ctx.riskStepUpEvaluated = false;
    if (this.opts.deviceTrust && this.opts.deviceTrustOptIn) {
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
    if (!input) return httpInputRequired(MfaCodeForm, ctx);
    if (input.action === "useDifferentMethod") {
      ctx.ignoreMfaDefault = true;
      ctx.mfaMethod = undefined;
      return undefined;
    }
    if (input.action === "useBackupCode" && this.opts.mfaBackupCodes) {
      return this.handleBackupCode(input.code ? { code: input.code } : undefined, ctx);
    }
    const errors = validateFormInput(MfaCodeForm, input);
    if (errors) return httpInputRequired(MfaCodeForm, ctx, errors);
    requireUsername(ctx);
    try {
      await this.users.verifyMfa(ctx.username, input.code as string);
      ctx.mfaChecked = true;
      ctx.riskStepUpEvaluated = false;
      if (this.opts.deviceTrust && this.opts.deviceTrustOptIn) {
        ctx.rememberDevice = Boolean(input.rememberDevice);
      }
    } catch (err) {
      if (err instanceof UserAuthError) {
        if (err.type === "LOCKED") throw new HttpError(423, "Account locked");
        if (err.type === "INACTIVE") throw new HttpError(401, "Invalid credentials");
        if (err.type === "MFA_NOT_CONFIGURED") throw new HttpError(400, "No TOTP MFA configured");
        if (err.type === "MFA_INVALID") {
          if (err.details?.lockEnds !== undefined) throw new HttpError(423, "Account locked");
          return httpInputRequired(MfaCodeForm, ctx, { code: "Invalid code" });
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
    if (!input) return httpInputRequired(BackupCodeForm, ctx);
    const errors = validateFormInput(BackupCodeForm, input);
    if (errors) return httpInputRequired(BackupCodeForm, ctx, errors);
    requireUsername(ctx);
    const ok = await this.users.consumeBackupCode(ctx.username, input.code as string);
    if (!ok) return httpInputRequired(BackupCodeForm, ctx, { code: "Invalid backup code" });
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
    if (!ctx.username || !this.deviceTrustStore) return undefined;
    const ip = this.opts.deviceTrustBindsTo === "cookie+ip" ? this.resolveClientIp() : undefined;
    const record = this.deviceTrustStore.issue(ctx.username, ip, this.opts.deviceTrustTtlMs);
    await this.deviceTrustStore.add(record);
    ctx.deviceTrustToken = record.token;
    useResponse(current()).setCookie(
      this.opts.deviceTrustCookieName,
      record.token,
      cookieAttrs(this.authConfig.cookie, { maxAge: this.opts.deviceTrustTtlMs / 1000 }),
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
    if (!input) return httpInputRequired(SetPasswordForm, ctx);
    if (input.action === "logout") {
      useWfFinished().set({ type: "data", value: { aborted: true, reason: "logout" } });
      // Gate downstream steps (issue/audit/notify/redirect) — without this
      // the schema continues and the `issue` step overwrites the abort
      // response with tokens. See BUG-LOGIN-5.
      ctx.aborted = true;
      return undefined;
    }
    const errors = validateFormInput(SetPasswordForm, input);
    if (errors) return httpInputRequired(SetPasswordForm, ctx, errors);
    if (input.newPassword !== input.confirmPassword) {
      return httpInputRequired(SetPasswordForm, ctx, {
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
    if (!input) return httpInputRequired(TermsAcceptForm, ctx);
    if (input.action === "decline") {
      useWfFinished().set({
        type: "data",
        value: { aborted: true, reason: "termsDeclined", message: "You must accept to continue" },
      });
      // BUG-LOGIN-5: stop the schema progressing into `issue` etc.
      ctx.aborted = true;
      return undefined;
    }
    const errors = validateFormInput(TermsAcceptForm, input);
    if (errors) return httpInputRequired(TermsAcceptForm, ctx, errors);
    if (input.accepted !== true) {
      return httpInputRequired(TermsAcceptForm, ctx, { accepted: "You must accept the terms" });
    }
    if (input.acceptedVersion !== this.opts.termsAcceptVersion) {
      return httpInputRequired(TermsAcceptForm, ctx, {
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
    const form = this.opts.profileCompleteForm;
    if (!input) return httpInputRequired(form, ctx);
    const errors = validateFormInput(form, input, { partial: "deep" });
    if (errors) return httpInputRequired(form, ctx, errors);
    requireUsername(ctx);
    if (this.opts.profileApply) {
      await this.opts.profileApply(ctx.username, input);
    }
    ctx.profileApplied = true;
    return undefined;
  }

  @Step("consent-marketing")
  async consentMarketing(
    @WorkflowParam("input") input: { optIn?: boolean; action?: string } | undefined,
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(ConsentMarketingForm, ctx);
    requireUsername(ctx);
    if (this.opts.consentMarketingApply) {
      await this.opts.consentMarketingApply(ctx.username, Boolean(input.optIn));
    }
    ctx.consentApplied = true;
    return undefined;
  }

  // ── Phase 7: tenant / persona ─────────────────────────────────────────
  @Step("tenant-select")
  async tenantSelect(
    @WorkflowParam("input") input: { tenantId?: string } | undefined,
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): Promise<unknown> {
    if (!ctx.availableTenants && ctx.username && this.opts.loadTenants) {
      ctx.availableTenants = await this.opts.loadTenants(ctx.username);
    }
    if (!input) return httpInputRequired(TenantSelectForm, ctx);
    const errors = validateFormInput(TenantSelectForm, input);
    if (errors) return httpInputRequired(TenantSelectForm, ctx, errors);
    const ok = (ctx.availableTenants ?? []).some((t) => t.id === input.tenantId);
    if (!ok) {
      return httpInputRequired(TenantSelectForm, ctx, { tenantId: "Unknown tenant" });
    }
    ctx.selectedTenantId = input.tenantId;
    return undefined;
  }

  @Step("persona-select")
  async personaSelect(
    @WorkflowParam("input") input: { personaId?: string } | undefined,
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): Promise<unknown> {
    if (!ctx.availablePersonas && ctx.username && this.opts.loadPersonas) {
      ctx.availablePersonas = await this.opts.loadPersonas(ctx.username);
    }
    if (!input) return httpInputRequired(PersonaSelectForm, ctx);
    const errors = validateFormInput(PersonaSelectForm, input);
    if (errors) return httpInputRequired(PersonaSelectForm, ctx, errors);
    const ok = (ctx.availablePersonas ?? []).some((p) => p.id === input.personaId);
    if (!ok) {
      return httpInputRequired(PersonaSelectForm, ctx, { personaId: "Unknown persona" });
    }
    ctx.selectedPersonaId = input.personaId;
    return undefined;
  }

  // ── Phase 8: session policy ───────────────────────────────────────────
  @Step("concurrency-limit")
  async concurrencyLimit(
    @WorkflowParam("input") input: { action?: string } | undefined,
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): Promise<unknown> {
    const cfg = this.opts.concurrencyLimit;
    if (!cfg) return undefined;
    if (cfg.onLimit === "reject") {
      throw new HttpError(429, "Session limit reached");
    }
    if (!input) return httpInputRequired(ConcurrencyLimitForm, ctx);
    if (input.action === "cancel") {
      useWfFinished().set({ type: "data", value: { aborted: true, reason: "sessionLimit" } });
      // BUG-LOGIN-5: stop the schema progressing into `issue` etc.
      ctx.aborted = true;
      return undefined;
    }
    const errors = validateFormInput(ConcurrencyLimitForm, input);
    if (errors) return httpInputRequired(ConcurrencyLimitForm, ctx, errors);
    if (input.action === "logoutOthers" && ctx.username && this.opts.logoutOtherSessions) {
      await this.opts.logoutOtherSessions(ctx.username);
    }
    return undefined;
  }

  @Step("risk-step-up")
  async riskStepUp(@WorkflowParam("context") ctx: LoginWfCtx): Promise<undefined> {
    // Runs INSIDE the Phase 4 `while: !mfaChecked` loop (see schema above).
    // Consumers gate via `opts.riskStepUp(ctx)`; `{require: true}` re-arms MFA
    // for another round by clearing `mfaChecked`. `riskStepUpEvaluated` is
    // flipped true so this step does not fire twice within one MFA round —
    // the MFA steps reset it on next successful verification.
    if (!this.opts.riskStepUp) return undefined;
    ctx.riskStepUpEvaluated = true;
    const res = await this.opts.riskStepUp(ctx);
    if (res.require) {
      ctx.riskStepUpReason = res.reason ?? "additional verification required";
      ctx.mfaChecked = false;
      ctx.pin = undefined;
      ctx.pinExpire = undefined;
    } else {
      ctx.riskStepUpReason = undefined;
    }
    return undefined;
  }

  // ── Phase 9: finalize ─────────────────────────────────────────────────
  @Step("issue")
  async issue(@WorkflowParam("context") ctx: LoginWfCtx): Promise<void> {
    requireUsername(ctx);
    const issue = await this.auth.issue(ctx.username);
    ctx.tokensIssued = true;
    // Build response payload + cookies and stash on the finished response.
    // The `redirect` step (terminal) overrides with a redirect type when
    // `opts.redirect` is set; otherwise the data response sticks.
    useWfFinished().set({
      type: "data",
      value: buildLoginResponse(this.authConfig, ctx.username, issue),
      cookies: buildFinishedCookies(this.authConfig, issue),
    });
  }

  @Step("audit-login")
  async auditLogin(@WorkflowParam("context") ctx: LoginWfCtx): Promise<undefined> {
    const emitter = this.audit ?? NoopAuditEmitter;
    await emitter.emit({
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
    if (!ctx.email || !this.mailer) return undefined;
    await this.mailer.send({
      kind: "notifyNewDevice",
      recipient: ctx.email,
      expiresAt: Date.now(),
      username: ctx.username,
      metadata: { ip: this.resolveClientIp() ?? "" },
    });
    return undefined;
  }

  @Step("redirect")
  redirect(@WorkflowParam("context") ctx: LoginWfCtx): undefined {
    // Compute the target URL — when 'referer' or 'home', overrides the issue
    // step's data finish with a redirect; when a function returns falsy, keep
    // the data response from `issue`.
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

  private resolveRedirect(ctx: LoginWfCtx): string | undefined {
    const r = this.opts.redirect;
    if (typeof r === "function") return r(ctx) || undefined;
    if (r === "home") return "/";
    if (r === "referer") {
      // Only override to a redirect when a real Referer header is present;
      // otherwise let the `issue` step's data response stand (the typical
      // happy path for SPAs / API clients with no Referer).
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
