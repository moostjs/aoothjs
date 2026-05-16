/**
 * RecoveryWorkflow — `wfid = 'auth.recovery'`.
 *
 * Full step catalog per `WF_RECOVERY.md`. Defaults give today's 3-step
 * magic-link flow (`request` → `sendMagicLink` → `setPassword`); consumers
 * turn on OTP delivery, pre-reset factor verification, fresh-login redirect
 * etc. via `RecoveryWorkflowOptions`.
 *
 * **Step routing model.** Mirrors `LoginWorkflow`: alt-action handlers run
 * BEFORE form validation (so `backToLogin` works without filling fields) and
 * return the `ALT_HANDLED` sentinel after short-circuiting via
 * `useWfFinished().set(...)`. The step body then returns `undefined` so the
 * schema advances cleanly, with terminal steps gated on `!ctx.aborted` so the
 * abort response set via `useWfFinished()` is not overwritten.
 */
import { AuthCredential, type EmailSender, type SmsSender } from "@aoothjs/auth";
import { UserAuthError, UserService, verifyTotpCode } from "@aoothjs/user";
import {
  outletEmail,
  Step,
  useWfFinished,
  Workflow,
  WorkflowParam,
  WorkflowSchema,
} from "@moostjs/event-wf";
import { current } from "@wooksjs/event-core";
import { useUrlParams } from "@wooksjs/event-http";
import { Controller, Inject, Injectable, Optional } from "moost";

import {
  EmailIdentifierForm,
  PincodeForm,
  RecoveryFactorForm,
  RecoveryModeSelectForm,
  SetPasswordForm,
} from "../atscript/models/forms.as.js";
import { type AuditEmitter, NoopAuditEmitter } from "../audit/index";
import { MoostAuthConfig } from "../auth.config";
import { buildLoginResponse } from "../auth.cookies";
import type { WorkflowRateLimitStore } from "../rate-limit/index";
import { RecoveryWorkflowOptions } from "./recovery.workflow.options";
import {
  buildFinishedCookies,
  httpInputRequired,
  mintPin,
  requireUsername,
  resolveClientIp,
  translatePasswordSetError,
  validateFormInput,
  verifyPin,
} from "./wf-helpers";

export interface RecoveryWfCtx {
  opts?: RecoveryWorkflowOptions;

  // Phase 1 — request:
  email?: string;
  username?: string;
  rateLimited?: boolean;

  // Mode (when deliveryMode === 'choice'):
  selectedMode?: "magicLink" | "otp";
  /** Resolved delivery mode the workflow committed to (populated by `selectMode` or `init`). */
  resolvedMode?: "magicLink" | "otp";

  // OTP-mode state:
  otpTransport?: "sms" | "email";
  otpCodeLength?: number;
  pin?: string;
  pinExpire?: number;
  pinResendAllowedAt?: number;
  pinVerified?: boolean;

  // Magic-link state:
  linkSent?: boolean;

  // Pre-reset factor:
  factorVerified?: boolean;

  // Post-reset:
  passwordChanged?: boolean;
  sessionsRevoked?: boolean;
  tokensIssued?: boolean;
  /** Set by abort alt-actions (`backToLogin`). Gates all terminal steps. */
  aborted?: boolean;
}

/**
 * Sentinel returned by alt-action handlers that have already short-circuited
 * via `useWfFinished().set(...)`. The step body returns `undefined` after
 * seeing this so the schema advances without running form validation on the
 * alt-action payload (which lacks the form's required fields).
 */
const ALT_HANDLED: unique symbol = Symbol("ALT_HANDLED");
type AltHandled = typeof ALT_HANDLED;

/**
 * Strip non-JSON values (functions, atscript form classes) from the options
 * object so the snapshot persists cleanly into `AsWfStore`. Adds presence
 * booleans for callback fields so schema `condition` predicates can gate on
 * them without holding the original reference.
 */
function snapshotOpts(opts: RecoveryWorkflowOptions): RecoveryWorkflowOptions {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(opts)) {
    if (v === undefined) continue;
    if (typeof v === "function") continue;
    if (v && typeof v === "object" && !Array.isArray(v)) {
      if ((v as Record<string, unknown>).__is_atscript_annotated_type) continue;
    }
    out[k] = v;
  }
  out.emailToUserIdEnabled = typeof opts.emailToUserId === "function";
  return out as unknown as RecoveryWorkflowOptions;
}

/**
 * Boot-time invariants. Called once per options instance via the
 * `validatedOpts` WeakSet inside `init`.
 */
function validateOpts(
  opts: RecoveryWorkflowOptions,
  emailSender?: EmailSender,
  smsSender?: SmsSender,
  rateLimitStore?: WorkflowRateLimitStore,
): void {
  if (opts.rateLimit !== null) {
    if (!rateLimitStore) {
      throw new Error(
        "RecoveryWorkflow: WorkflowRateLimitStore required when opts.rateLimit is non-null",
      );
    }
    if (opts.rateLimit.count <= 0 || opts.rateLimit.windowMs <= 0) {
      throw new Error(
        "RecoveryWorkflow: opts.rateLimit.count and opts.rateLimit.windowMs must be > 0 (set rateLimit: null to disable)",
      );
    }
  }
  const otpEnabled = opts.deliveryMode !== "magicLink";
  if (otpEnabled && opts.otpTransports.length === 0) {
    throw new Error(
      "RecoveryWorkflow: otpTransports cannot be empty when deliveryMode includes OTP",
    );
  }
  if (otpEnabled && opts.otpTransports.includes("sms") && !smsSender) {
    throw new Error(
      'RecoveryWorkflow: SmsSender required when otpTransports includes "sms" and deliveryMode allows OTP',
    );
  }
  if (otpEnabled && opts.otpTransports.includes("email") && !emailSender) {
    throw new Error(
      'RecoveryWorkflow: EmailSender required when otpTransports includes "email" and deliveryMode allows OTP',
    );
  }
  if (opts.deliveryMode !== "otp" && !emailSender) {
    // magicLink and choice modes both depend on the email outlet.
    throw new Error(
      'RecoveryWorkflow: EmailSender required when deliveryMode is "magicLink" or "choice"',
    );
  }
}

const validatedOpts = new WeakSet<RecoveryWorkflowOptions>();

@Injectable("FOR_EVENT")
@Controller()
export class RecoveryWorkflow {
  constructor(
    private readonly opts: RecoveryWorkflowOptions,
    private readonly users: UserService,
    private readonly auth: AuthCredential,
    private readonly authConfig: MoostAuthConfig,
    @Optional() @Inject("EmailSender") private readonly mailer?: EmailSender,
    @Optional() @Inject("SmsSender") private readonly sms?: SmsSender,
    @Optional()
    @Inject("WorkflowRateLimitStore")
    private readonly rateLimitStore?: WorkflowRateLimitStore,
    @Optional() @Inject("AuditEmitter") private readonly audit?: AuditEmitter,
  ) {}

  @Workflow("auth.recovery")
  @WorkflowSchema<RecoveryWfCtx>([
    // Step IDs are globally registered by @moostjs/event-wf — keep them
    // workflow-scoped so the three auth workflows (login/recovery/invite)
    // don't collide on a shared `init` name and silently overwrite each
    // other's handlers.
    { id: "recoveryInit" },
    { id: "recoveryRequest" },
    // Mode picker — only when deliveryMode === 'choice' AND not already chosen.
    {
      id: "recoverySelectMode",
      condition: (ctx) =>
        Boolean(
          ctx.username && ctx.opts?.deliveryMode === "choice" && !ctx.selectedMode && !ctx.aborted,
        ),
    },
    // Magic-link branch.
    {
      id: "recoverySendMagicLink",
      condition: (ctx) => Boolean(ctx.username && ctx.resolvedMode === "magicLink" && !ctx.aborted),
    },
    // OTP branch — sendOtp + checkOtp wrapped in a while-loop so the
    // `useDifferentTransport` and `resend` alt-actions can reset
    // `pin` + `otpTransport` and loop back through `sendOtp` on the new
    // channel. The loop exits when `pinVerified` flips true.
    {
      while: (ctx) =>
        Boolean(ctx.username && ctx.resolvedMode === "otp" && !ctx.pinVerified && !ctx.aborted),
      steps: [
        {
          id: "recoverySendOtp",
          condition: (ctx) => !ctx.pin,
        },
        { id: "recoveryCheckOtp" },
      ],
    },
    // Pre-reset factor check.
    {
      id: "recoveryVerifyFactor",
      condition: (ctx) =>
        Boolean(
          ctx.username &&
          ctx.opts?.requireKnownRecoveryFactor &&
          !ctx.factorVerified &&
          (ctx.linkSent || ctx.pinVerified) &&
          !ctx.aborted,
        ),
    },
    // Set password — gated on the chosen branch having completed.
    {
      id: "recoverySetPassword",
      condition: (ctx) =>
        Boolean(
          ctx.username &&
          (ctx.linkSent || ctx.pinVerified) &&
          (!ctx.opts?.requireKnownRecoveryFactor || ctx.factorVerified) &&
          !ctx.aborted,
        ),
    },
    {
      id: "recoveryRevokeSessions",
      condition: (ctx) =>
        Boolean(ctx.opts?.revokeAllSessions && ctx.passwordChanged && !ctx.aborted),
    },
    {
      id: "recoveryAudit",
      condition: (ctx) => Boolean(ctx.opts?.auditEvents && ctx.passwordChanged && !ctx.aborted),
    },
    // Finalize: one of fresh-login or auto-login, never both.
    {
      id: "recoveryFreshLoginFinish",
      condition: (ctx) =>
        Boolean(ctx.opts?.freshLoginRequired && ctx.passwordChanged && !ctx.aborted),
    },
    {
      id: "recoveryAutoLoginFinish",
      condition: (ctx) =>
        Boolean(
          !ctx.opts?.freshLoginRequired && ctx.passwordChanged && !ctx.tokensIssued && !ctx.aborted,
        ),
    },
  ])
  flow(): void {}

  // ── Phase 0 ───────────────────────────────────────────────────────────
  @Step("recoveryInit")
  init(@WorkflowParam("context") ctx: RecoveryWfCtx): undefined {
    if (!validatedOpts.has(this.opts)) {
      validateOpts(this.opts, this.mailer, this.sms, this.rateLimitStore);
      validatedOpts.add(this.opts);
    }
    ctx.opts = snapshotOpts(this.opts);
    // Resolve the mode up-front when fixed; `'choice'` defers to `selectMode`.
    if (this.opts.deliveryMode !== "choice") {
      ctx.resolvedMode = this.opts.deliveryMode;
    }
    return undefined;
  }

  // ── request ──────────────────────────────────────────────────────────
  @Step("recoveryRequest")
  async request(
    @WorkflowParam("input") input: { email?: string; action?: string } | undefined,
    @WorkflowParam("context") ctx: RecoveryWfCtx,
  ): Promise<unknown> {
    // First entry: read `?username=` from the resume URL (carried in by the
    // login workflow's `forgotPassword` alt-action) to pre-fill the form.
    if (!input) {
      const prefilled = readUsernameQueryParam();
      const formCtx: Record<string, unknown> = { ...(ctx as Record<string, unknown>) };
      if (prefilled) {
        formCtx.defaults = { email: prefilled };
      }
      return httpInputRequired(EmailIdentifierForm, formCtx);
    }

    if (input.action === "backToLogin" && this.opts.backToLoginAction) {
      this.abortToLogin(ctx);
      return undefined;
    }

    const errors = validateFormInput(EmailIdentifierForm, input);
    if (errors) return httpInputRequired(EmailIdentifierForm, ctx, errors);

    const email = input.email as string;
    ctx.email = email;

    // Rate-limit check BEFORE the user lookup — a positive rate-limit hit
    // intentionally short-circuits to the same generic response as an unknown
    // email (anti-enumeration: indistinguishable from non-existent).
    if (this.opts.rateLimit && this.rateLimitStore) {
      const res = await this.rateLimitStore.consume(
        email.toLowerCase(),
        this.opts.rateLimit.windowMs,
        this.opts.rateLimit.count,
      );
      if (!res.allowed) {
        ctx.rateLimited = true;
        await this.emitRequested(ctx);
        this.finishGeneric();
        return undefined;
      }
    }

    let username: string | undefined;
    try {
      const userId = this.opts.emailToUserId ? await this.opts.emailToUserId(email) : email;
      if (userId) {
        const user = await this.users.getUser(userId);
        username = user.username;
      }
    } catch (err) {
      if (!(err instanceof UserAuthError) || err.type !== "NOT_FOUND") throw err;
    }

    await this.emitRequested(ctx, username);

    if (!username) {
      // Unknown email — same generic response. Downstream steps skip via the
      // `ctx.username` guard.
      this.finishGeneric();
      return undefined;
    }

    ctx.username = username;
    // Pick the default OTP transport so `sendOtp` knows the channel.
    if (ctx.resolvedMode === "otp" && !ctx.otpTransport) {
      ctx.otpTransport = this.opts.otpTransports[0];
    }
    return undefined;
  }

  // ── selectMode ───────────────────────────────────────────────────────
  @Step("recoverySelectMode")
  selectMode(
    @WorkflowParam("input") input: { mode?: string; action?: string } | undefined,
    @WorkflowParam("context") ctx: RecoveryWfCtx,
  ): unknown {
    if (!input) return httpInputRequired(RecoveryModeSelectForm, ctx);
    if (input.action === "backToLogin" && this.opts.backToLoginAction) {
      this.abortToLogin(ctx);
      return undefined;
    }
    const errors = validateFormInput(RecoveryModeSelectForm, input);
    if (errors) return httpInputRequired(RecoveryModeSelectForm, ctx, errors);
    const mode = input.mode as "magicLink" | "otp";
    ctx.selectedMode = mode;
    ctx.resolvedMode = mode;
    if (mode === "otp" && !ctx.otpTransport) {
      ctx.otpTransport = this.opts.otpTransports[0];
    }
    return undefined;
  }

  // ── sendMagicLink ────────────────────────────────────────────────────
  @Step("recoverySendMagicLink")
  sendMagicLink(@WorkflowParam("context") ctx: RecoveryWfCtx): unknown {
    // First run: emit outletEmail; engine persists state, our email outlet
    // ships the magic link. Resume run (link clicked): `linkSent` is set so
    // we advance to `setPassword` without re-sending.
    if (ctx.linkSent) return undefined;
    ctx.linkSent = true;
    return {
      ...outletEmail(ctx.email as string, "recovery.magicLink", {
        username: ctx.username,
        expiresAtMs: this.opts.magicLinkTtlMs,
      }),
      expires: Date.now() + this.opts.magicLinkTtlMs,
    };
  }

  // ── sendOtp ──────────────────────────────────────────────────────────
  @Step("recoverySendOtp")
  async sendOtp(@WorkflowParam("context") ctx: RecoveryWfCtx): Promise<undefined> {
    requireUsername(ctx);
    const transport: "sms" | "email" = ctx.otpTransport ?? this.opts.otpTransports[0] ?? "email";
    ctx.otpTransport = transport;
    ctx.otpCodeLength = this.opts.otpCodeLength;
    const code = mintPin(ctx, this.opts.otpCodeLength, this.opts.otpTtlMs);
    ctx.pinResendAllowedAt = Date.now() + this.opts.otpResendCooldownMs;

    if (transport === "email") {
      if (!this.mailer) {
        throw new Error("RecoveryWorkflow.sendOtp: EmailSender not registered");
      }
      await this.mailer.send({
        kind: "recovery.pincode",
        recipient: ctx.email as string,
        code,
        expiresAt: ctx.pinExpire as number,
        username: ctx.username,
      });
    } else {
      if (!this.sms) {
        throw new Error("RecoveryWorkflow.sendOtp: SmsSender not registered");
      }
      // The user's recorded phone wins over `ctx.email` (which is what the
      // user typed at `request` time — could be an email even when delivering
      // SMS). Fall back to the typed value if there is no recorded phone.
      const phone = await this.resolveUserPhone(ctx.username);
      await this.sms.send({
        kind: "recovery.pincode",
        recipient: phone ?? (ctx.email as string),
        code,
        ttlMs: this.opts.otpTtlMs,
        userId: ctx.username,
      });
    }
    return undefined;
  }

  // ── checkOtp ─────────────────────────────────────────────────────────
  @Step("recoveryCheckOtp")
  async checkOtp(
    @WorkflowParam("input") input: { code?: string; action?: string } | undefined,
    @WorkflowParam("context") ctx: RecoveryWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(PincodeForm, ctx);

    if (input.action === "backToLogin" && this.opts.backToLoginAction) {
      this.abortToLogin(ctx);
      return undefined;
    }
    if (input.action === "resend") {
      if (ctx.pinResendAllowedAt && Date.now() < ctx.pinResendAllowedAt) {
        const waitSec = Math.ceil((ctx.pinResendAllowedAt - Date.now()) / 1000);
        return httpInputRequired(PincodeForm, ctx, { __form: `Please wait ${waitSec}s` });
      }
      // Clear pin so the while-loop's `sendOtp` condition re-fires.
      ctx.pin = undefined;
      ctx.pinExpire = undefined;
      return undefined;
    }
    if (input.action === "useDifferentTransport") {
      const transports = this.opts.otpTransports;
      if (transports.length < 2) {
        return httpInputRequired(PincodeForm, ctx, {
          __form: "Only one transport configured",
        });
      }
      const current = ctx.otpTransport ?? transports[0];
      const next = transports.find((t) => t !== current) ?? transports[0];
      ctx.otpTransport = next;
      ctx.pin = undefined;
      ctx.pinExpire = undefined;
      return undefined;
    }

    const errors = validateFormInput(PincodeForm, input);
    if (errors) return httpInputRequired(PincodeForm, ctx, errors);
    const pinErr = verifyPin(ctx, input.code);
    if (pinErr) return httpInputRequired(PincodeForm, ctx, pinErr);
    ctx.pinVerified = true;
    ctx.pin = undefined;
    ctx.pinExpire = undefined;
    return undefined;
  }

  // ── verifyFactor ─────────────────────────────────────────────────────
  @Step("recoveryVerifyFactor")
  async verifyFactor(
    @WorkflowParam("input") input: { factor?: string; value?: string; action?: string } | undefined,
    @WorkflowParam("context") ctx: RecoveryWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(RecoveryFactorForm, ctx);
    if (input.action === "backToLogin" && this.opts.backToLoginAction) {
      this.abortToLogin(ctx);
      return undefined;
    }
    const errors = validateFormInput(RecoveryFactorForm, input);
    if (errors) return httpInputRequired(RecoveryFactorForm, ctx, errors);
    requireUsername(ctx);
    const factor = input.factor as "phone" | "totp";
    const value = input.value as string;

    const user = await this.users.getUser(ctx.username);
    if (factor === "phone") {
      const phoneMethod = user.mfa.methods.find((m) => m.name === "sms" && m.confirmed);
      if (!phoneMethod) {
        // Opaque error — never reveal which factor is enrolled.
        return httpInputRequired(RecoveryFactorForm, ctx, { value: "Invalid factor" });
      }
      const last4 = phoneMethod.value.slice(-4);
      if (value !== last4) {
        return httpInputRequired(RecoveryFactorForm, ctx, { value: "Invalid factor" });
      }
    } else if (factor === "totp") {
      const totpMethod = user.mfa.methods.find((m) => m.name === "totp" && m.confirmed);
      if (!totpMethod || !verifyTotpCode(totpMethod.value, value)) {
        return httpInputRequired(RecoveryFactorForm, ctx, { value: "Invalid factor" });
      }
    }
    ctx.factorVerified = true;
    return undefined;
  }

  // ── setPassword ──────────────────────────────────────────────────────
  @Step("recoverySetPassword")
  async setPassword(
    @WorkflowParam("input") input:
      | { newPassword?: string; confirmPassword?: string; action?: string }
      | undefined,
    @WorkflowParam("context") ctx: RecoveryWfCtx,
  ): Promise<unknown> {
    if (!input) {
      // Surface policy rules into the form context so the front-end can
      // render hints alongside the inputs.
      const formCtx: Record<string, unknown> = { ...(ctx as Record<string, unknown>) };
      formCtx.passwordPolicies = this.users.getTransferablePolicies();
      return httpInputRequired(SetPasswordForm, formCtx);
    }

    if (input.action === "backToLogin" && this.opts.backToLoginAction) {
      this.abortToLogin(ctx);
      return undefined;
    }

    const errors = validateFormInput(SetPasswordForm, input);
    if (errors) return httpInputRequired(SetPasswordForm, ctx, errors);
    if (input.newPassword !== input.confirmPassword) {
      return httpInputRequired(SetPasswordForm, ctx, {
        confirmPassword: "Passwords do not match",
      });
    }
    if (!ctx.username) {
      return httpInputRequired(SetPasswordForm, ctx, { __form: "Recovery session expired" });
    }
    try {
      await this.users.setPassword(ctx.username, input.newPassword as string);
    } catch (err) {
      translatePasswordSetError(err);
    }
    ctx.passwordChanged = true;
    return undefined;
  }

  // ── revokeSessions ───────────────────────────────────────────────────
  @Step("recoveryRevokeSessions")
  async revokeSessions(@WorkflowParam("context") ctx: RecoveryWfCtx): Promise<undefined> {
    if (!ctx.username) return undefined;
    await this.auth.revokeAllForUser(ctx.username);
    ctx.sessionsRevoked = true;
    return undefined;
  }

  // ── audit ────────────────────────────────────────────────────────────
  @Step("recoveryAudit")
  async auditStep(@WorkflowParam("context") ctx: RecoveryWfCtx): Promise<undefined> {
    const emitter = this.audit ?? NoopAuditEmitter;
    await emitter.emit({
      kind: "recovery.completed",
      userId: ctx.username,
      workflow: "auth.recovery",
      deliveryMode: ctx.resolvedMode ?? this.opts.deliveryMode,
      ip: resolveClientIp(),
      ...(ctx.sessionsRevoked && { sessionsRevoked: true }),
    });
    return undefined;
  }

  // ── freshLoginFinish ─────────────────────────────────────────────────
  @Step("recoveryFreshLoginFinish")
  freshLoginFinish(@WorkflowParam("context") _ctx: RecoveryWfCtx): undefined {
    useWfFinished().set({ type: "redirect", value: this.opts.loginUrl });
    return undefined;
  }

  // ── autoLoginFinish ──────────────────────────────────────────────────
  @Step("recoveryAutoLoginFinish")
  async autoLoginFinish(@WorkflowParam("context") ctx: RecoveryWfCtx): Promise<undefined> {
    requireUsername(ctx);
    const issue = await this.auth.issue(ctx.username);
    ctx.tokensIssued = true;
    useWfFinished().set({
      type: "data",
      value: buildLoginResponse(this.authConfig, ctx.username, issue),
      cookies: buildFinishedCookies(this.authConfig, issue),
    });
    return undefined;
  }

  // ── Helpers ──────────────────────────────────────────────────────────
  /**
   * Send the generic "if an account exists, you'll receive instructions"
   * finished response. Used for unknown emails and rate-limited known ones
   * so the two are indistinguishable to the client.
   */
  private finishGeneric(): void {
    useWfFinished().set({
      type: "data",
      value: { sent: true, message: "If an account exists, you will receive instructions." },
    });
  }

  private abortToLogin(ctx: RecoveryWfCtx): AltHandled {
    useWfFinished().set({ type: "redirect", value: this.opts.loginUrl });
    ctx.aborted = true;
    return ALT_HANDLED;
  }

  private async emitRequested(ctx: RecoveryWfCtx, username?: string): Promise<void> {
    if (!this.opts.auditEvents) return;
    const emitter = this.audit ?? NoopAuditEmitter;
    await emitter.emit({
      kind: "recovery.requested",
      workflow: "auth.recovery",
      userId: username,
      email: ctx.email,
      ip: resolveClientIp(),
      ...(ctx.rateLimited && { rateLimited: true }),
    });
  }

  private async resolveUserPhone(username: string): Promise<string | undefined> {
    try {
      const user = await this.users.getUser(username);
      const sms = user.mfa.methods.find((m) => m.name === "sms" && m.confirmed);
      return sms?.value;
    } catch {
      return undefined;
    }
  }
}

/**
 * Reads the `?username=` query parameter when the workflow is triggered (e.g.
 * via the login workflow's `forgotPassword` alt-action). Returns undefined
 * outside of an HTTP event context (e.g. unit tests that hand-roll the wf
 * runtime). Used purely for form pre-fill.
 */
function readUsernameQueryParam(): string | undefined {
  try {
    const { params } = useUrlParams(current());
    const raw = params().get("username");
    return raw ?? undefined;
  } catch {
    return undefined;
  }
}
