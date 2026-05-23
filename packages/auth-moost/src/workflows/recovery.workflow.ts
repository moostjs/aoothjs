/**
 * RecoveryWorkflow — `wfid = 'auth.recovery'`.
 *
 * Full step catalog per `WF_RECOVERY.md`. Defaults give today's 3-step
 * magic-link flow (`request` → `sendMagicLink` → `setPassword`); consumers
 * turn on OTP delivery, pre-reset factor verification, fresh-login redirect
 * etc. via `RecoveryWorkflowOpts`.
 *
 * **Step routing model.** Mirrors `LoginWorkflow`: alt-action handlers run
 * BEFORE form validation so `backToLogin` works without filling fields, and
 * return the `ALT_HANDLED` sentinel after short-circuiting via
 * `useWfFinished().set(...)`. Actions are read via
 * `useAtscriptWf(form).resolveAction()` — the form's static `@ui.form.action`
 * whitelist validates the action id; unknown ids throw `StepRetriableError`
 * before the step body runs. The step body then returns `undefined` so the
 * schema advances cleanly, with terminal steps gated on `!ctx.aborted` so the
 * abort response set via `useWfFinished()` is not overwritten.
 *
 * **Consumer subclass pattern (Phase 3 reshape).** Consumers subclass
 * `RecoveryWorkflow` to override `protected` hook methods. The subclass MUST
 * re-apply `@Inherit() @Injectable('FOR_EVENT') @Controller()` and re-declare
 * the constructor signature (TS emits fresh design-paramtypes per class).
 *
 * **Side-effect deps as protected methods.** The optional sender/emitter DI
 * providers have been DROPPED from the constructor. The hooks live as
 * `protected` methods consumers override:
 *
 *   - `deliver(payload)` — unified email + SMS dispatch (see `DeliverPayload`).
 *     Default throws; override to wire your senders.
 *   - `audit(event)` — fire audit events. Default: no-op.
 *   - `emailToUserId(email)` — resolve recovery email to canonical username.
 *   - `verifyRecoveryFactor(...)` — phone last-4 / TOTP / custom factors.
 *
 * Rate-limiting is intentionally NOT part of this workflow — consumers who
 * want a cap wire it themselves at the HTTP / trigger layer.
 */
import { AuthCredential } from "@aooth/auth";
import { UserAuthError, UserService, verifyTotpCode } from "@aooth/user";
import { finishWf, useAtscriptWf, type WfFinished } from "@atscript/moost-wf";
import {
  outletEmail,
  Step,
  useWfFinished,
  useWfState,
  Workflow,
  WorkflowParam,
  WorkflowSchema,
} from "@moostjs/event-wf";
import { current } from "@wooksjs/event-core";
import { useUrlParams } from "@wooksjs/event-http";
import { Controller, Injectable } from "moost";

import type { AuditEvent } from "../audit/index";
import { useAuth } from "../auth.composables";
import { Public } from "../auth.decorator";
import { AuthWorkflowBase } from "./auth-workflow.base";
import type { DeliverPayload } from "./login.workflow";
import {
  mergeRecoveryOpts,
  type RecoveryWorkflowOpts,
  type ResolvedRecoveryWorkflowOpts,
} from "./recovery.workflow.options";

export interface RecoveryWfCtx {
  opts?: ResolvedRecoveryWorkflowOpts;

  // Phase 1 — request:
  email?: string;
  username?: string;

  // Mode (when delivery.mode === 'choice'):
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
  /** Mirror of `opts.delivery.otp.transports.length`. Passed to `PincodeForm` so the `useDifferentTransport` action hides when only one transport is configured. */
  recoveryTransportCount?: number;

  // Magic-link state:
  linkSent?: boolean;

  // Pre-reset factor:
  factorVerified?: boolean;
  /**
   * Recovery factors the user is actually able to verify on this attempt —
   * intersection of `opts.preReset.allowedFactors` (workflow whitelist) and
   * what the user has enrolled (e.g. phone only if a confirmed SMS method
   * exists). Populated by `recoveryVerifyFactor` before its form pauses and
   * consumed by `RecoveryFactorForm` via `@wf.context.pass` to render only
   * the available radio options.
   */
  availableRecoveryFactors?: Array<{ key: string; label: string }>;

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
 * Construction-time invariants for DATA validity only. Sender/emitter absence
 * is no longer checked — those default to fail-loud (`deliver()`) or safe
 * (`audit()` no-op) protected methods that consumers override.
 */
function validateOpts(opts: ResolvedRecoveryWorkflowOpts): void {
  const otpReachable = opts.delivery.mode !== "magicLink";
  if (otpReachable && opts.delivery.otp.transports.length === 0) {
    throw new Error(
      "RecoveryWorkflow: delivery.otp.transports cannot be empty when delivery.mode includes OTP",
    );
  }
}

// `@Public()` — recovery is by definition reachable without authn (the user
// can't authenticate yet). The global `arbacAuthorizeInterceptor` running on
// workflow events bypasses this controller. See `LoginWorkflow` for the
// rationale on why the marker has to live on the workflow class itself, not
// just the `/auth/trigger` HTTP route.
@Public()
@Injectable("FOR_EVENT")
@Controller()
export class RecoveryWorkflow extends AuthWorkflowBase {
  protected readonly opts: ResolvedRecoveryWorkflowOpts;
  protected readonly users: UserService;
  protected readonly auth: AuthCredential;

  constructor(opts: RecoveryWorkflowOpts, users: UserService, auth: AuthCredential) {
    super();
    this.opts = mergeRecoveryOpts(opts);
    this.users = users;
    this.auth = auth;
    validateOpts(this.opts);
  }

  // ── Protected extension surface ───────────────────────────────────────
  /**
   * Dispatch an email or SMS event. Default throws — consumers MUST override
   * if `delivery.mode` ever drives email/SMS (i.e. for any non-`magicLink`
   * mode AND for `magicLink` mode the `outletEmail` outlet still runs the
   * email through `createAuthEmailOutlet`'s `EmailSender` — see the trigger
   * controller wiring; this method covers OTP code dispatch).
   */
  protected async deliver(_payload: DeliverPayload): Promise<void> {
    throw new Error(
      "RecoveryWorkflow.deliver() not configured — override to wire your email/sms sender",
    );
  }

  /**
   * Emit an audit event. Default: no-op. Consumers override to fan out to
   * their audit sink.
   */
  protected async audit(_event: AuditEvent): Promise<void> {
    // No-op default.
  }

  @Workflow("auth.recovery")
  @WorkflowSchema<RecoveryWfCtx>([
    // Step IDs are globally registered by @moostjs/event-wf — keep them
    // workflow-scoped so the three auth workflows (login/recovery/invite)
    // don't collide on a shared `init` name and silently overwrite each
    // other's handlers.
    { id: "recoveryInit" },
    { id: "recoveryRequest" },
    // Mode picker — only when delivery.mode === 'choice' AND not already chosen.
    {
      id: "recoverySelectMode",
      condition: (ctx) =>
        !!(
          ctx.username &&
          ctx.opts!.delivery.mode === "choice" &&
          !ctx.selectedMode &&
          !ctx.aborted
        ),
    },
    // Magic-link branch.
    {
      id: "recoverySendMagicLink",
      condition: (ctx) => !!(ctx.username && ctx.resolvedMode === "magicLink" && !ctx.aborted),
    },
    // OTP branch — sendOtp + checkOtp wrapped in a while-loop so the
    // `useDifferentTransport` and `resend` alt-actions can reset
    // `pin` + `otpTransport` and loop back through `sendOtp` on the new
    // channel. The loop exits when `pinVerified` flips true.
    {
      while: (ctx) =>
        !!(ctx.username && ctx.resolvedMode === "otp" && !ctx.pinVerified && !ctx.aborted),
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
        !!(
          ctx.username &&
          ctx.opts!.preReset.requireKnownFactor &&
          !ctx.factorVerified &&
          (ctx.linkSent || ctx.pinVerified) &&
          !ctx.aborted
        ),
    },
    // Set password — gated on the chosen branch having completed.
    {
      id: "recoverySetPassword",
      condition: (ctx) =>
        !!(
          ctx.username &&
          (ctx.linkSent || ctx.pinVerified) &&
          (!ctx.opts!.preReset.requireKnownFactor || ctx.factorVerified) &&
          !ctx.aborted
        ),
    },
    {
      id: "recoveryRevokeSessions",
      condition: (ctx) =>
        !!(ctx.opts!.postReset.revokeAllSessions && ctx.passwordChanged && !ctx.aborted),
    },
    {
      id: "recoveryAudit",
      condition: (ctx) => !!(ctx.opts!.audit.enabled && ctx.passwordChanged && !ctx.aborted),
    },
    // Finalize: one of fresh-login or auto-login, never both.
    {
      id: "recoveryFreshLoginFinish",
      condition: (ctx) =>
        !!(ctx.opts!.postReset.freshLoginRequired && ctx.passwordChanged && !ctx.aborted),
    },
    {
      id: "recoveryAutoLoginFinish",
      condition: (ctx) =>
        !!(
          !ctx.opts!.postReset.freshLoginRequired &&
          ctx.passwordChanged &&
          !ctx.tokensIssued &&
          !ctx.aborted
        ),
    },
  ])
  flow(): void {}

  // ── Phase 0 ───────────────────────────────────────────────────────────
  @Step("recoveryInit")
  init(@WorkflowParam("context") ctx: RecoveryWfCtx): undefined {
    ctx.opts = this.snapshotOpts(this.opts);
    // Resolve the mode up-front when fixed; `'choice'` defers to `selectMode`.
    if (this.opts.delivery.mode !== "choice") {
      ctx.resolvedMode = this.opts.delivery.mode;
    }
    ctx.recoveryTransportCount = this.opts.delivery.otp.transports.length;
    return undefined;
  }

  /**
   * Returns the JSON-safe projection of `opts` stashed onto `ctx` for schema
   * conditions to read. Default: drop the `forms` group (atscript form classes
   * are not plain JSON) so `AsWfStore`'s plain-JSON persistence doesn't choke.
   * Step bodies still consult the form classes via `this.opts.forms.*`.
   *
   * Consumers who extend the opts type with non-JSON values can override this
   * to strip them so `AsWfStore`'s plain-JSON persistence doesn't choke.
   */
  protected snapshotOpts(opts: ResolvedRecoveryWorkflowOpts): ResolvedRecoveryWorkflowOpts {
    const { forms: _forms, ...rest } = opts;
    return rest as ResolvedRecoveryWorkflowOpts;
  }

  // ── request ──────────────────────────────────────────────────────────
  @Step("recoveryRequest")
  async request(@WorkflowParam("context") ctx: RecoveryWfCtx): Promise<unknown> {
    const emailWf = useAtscriptWf(this.opts.forms.emailIdentifier);
    const action = emailWf.resolveAction();
    if (action === "backToLogin" && this.opts.altActions.backToLogin) {
      this.abortToLogin(ctx);
      return undefined;
    }

    // First entry: read `?username=` from the resume URL (carried in by the
    // login workflow's `forgotPassword` alt-action) to pre-fill the form.
    // `requireInput()` SNAPSHOTS `wfState.ctx()` at call time (it builds the
    // pass-context payload from the ctx-as-it-stands), so we must seed
    // `ctx.defaults` BEFORE building the requireInput sentinel — otherwise
    // the snapshot carries the pre-mutation ctx and the prefill is lost.
    // `EmailIdentifierForm` declares `@wf.context.pass 'defaults'` so the
    // engine surfaces the key to the client when it is present.
    const rawFormData = useWfState().input<{ formData?: unknown }>()?.formData;
    if (rawFormData === undefined) {
      const prefilled = readUsernameQueryParam();
      if (prefilled) {
        (ctx as Record<string, unknown>).defaults = { email: prefilled };
      }
      throw emailWf.requireInput();
    }

    const input = emailWf.resolveInput() as { email: string };

    const email = input.email;
    ctx.email = email;

    let username: string | undefined;
    try {
      const userId = await this.emailToUserId(email);
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
      ctx.otpTransport = this.opts.delivery.otp.transports[0];
    }
    return undefined;
  }

  /**
   * Resolves the recovery-step `email` input to the `username` (user-id) that
   * `UserService.getUser` expects. Default: returns the email unchanged (treats
   * email as username). Apps whose user model separates `username` from
   * `email` MUST override this; return `null` when no user matches.
   */
  protected async emailToUserId(email: string): Promise<string | null> {
    return email;
  }

  // ── selectMode ───────────────────────────────────────────────────────
  @Step("recoverySelectMode")
  selectMode(@WorkflowParam("context") ctx: RecoveryWfCtx): unknown {
    const wf = useAtscriptWf(this.opts.forms.recoveryModeSelect);
    const action = wf.resolveAction();
    if (action === "backToLogin" && this.opts.altActions.backToLogin) {
      this.abortToLogin(ctx);
      return undefined;
    }
    const input = wf.resolveInput() as { mode: string };
    const mode = input.mode as "magicLink" | "otp";
    ctx.selectedMode = mode;
    ctx.resolvedMode = mode;
    if (mode === "otp" && !ctx.otpTransport) {
      ctx.otpTransport = this.opts.delivery.otp.transports[0];
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
        expiresAtMs: this.opts.delivery.magicLinkTtlMs,
      }),
      expires: Date.now() + this.opts.delivery.magicLinkTtlMs,
    };
  }

  // ── sendOtp ──────────────────────────────────────────────────────────
  @Step("recoverySendOtp")
  async sendOtp(@WorkflowParam("context") ctx: RecoveryWfCtx): Promise<undefined> {
    this.requireUsername(ctx);
    const transport: "sms" | "email" =
      ctx.otpTransport ?? this.opts.delivery.otp.transports[0] ?? "email";
    ctx.otpTransport = transport;
    ctx.otpCodeLength = this.opts.delivery.otp.codeLength;
    const code = this.mintPin(ctx, this.opts.delivery.otp.codeLength, this.opts.delivery.otp.ttlMs);
    ctx.pinResendAllowedAt = Date.now() + this.opts.delivery.otp.resendCooldownMs;

    if (transport === "email") {
      await this.deliver({
        channel: "email",
        kind: "recovery.pincode",
        recipient: ctx.email as string,
        code,
        expiresAt: ctx.pinExpire as number,
        userId: ctx.username,
      });
    } else {
      // The user's recorded phone wins over `ctx.email` (which is what the
      // user typed at `request` time — could be an email even when delivering
      // SMS). Fall back to the typed value if there is no recorded phone.
      const phone = await this.resolveUserPhone(ctx.username);
      await this.deliver({
        channel: "sms",
        kind: "recovery.pincode",
        recipient: phone ?? (ctx.email as string),
        code,
        ttlMs: this.opts.delivery.otp.ttlMs,
        userId: ctx.username,
      });
    }
    return undefined;
  }

  // ── checkOtp ─────────────────────────────────────────────────────────
  @Step("recoveryCheckOtp")
  async checkOtp(@WorkflowParam("context") ctx: RecoveryWfCtx): Promise<unknown> {
    const wf = useAtscriptWf(this.opts.forms.pincode);
    const action = wf.resolveAction();
    if (action === "backToLogin" && this.opts.altActions.backToLogin) {
      this.abortToLogin(ctx);
      return undefined;
    }
    if (action === "resend") {
      if (ctx.pinResendAllowedAt && Date.now() < ctx.pinResendAllowedAt) {
        const waitSec = Math.ceil((ctx.pinResendAllowedAt - Date.now()) / 1000);
        throw wf.requireInput({ formMessage: `Please wait ${waitSec}s` });
      }
      // Clear pin so the while-loop's `sendOtp` condition re-fires.
      // `delete` (not `= undefined`) so the persisted ctx remains JSON-clean
      // — AsWfStore validates state.context against a JSON-anyOf schema and
      // chokes on explicit `undefined` entries.
      delete ctx.pin;
      delete ctx.pinExpire;
      return undefined;
    }
    if (action === "useDifferentTransport") {
      const transports = this.opts.delivery.otp.transports;
      if (transports.length < 2) {
        throw wf.requireInput({ formMessage: "Only one transport configured" });
      }
      const current = ctx.otpTransport ?? transports[0];
      const next = transports.find((t) => t !== current) ?? transports[0];
      ctx.otpTransport = next;
      delete ctx.pin;
      delete ctx.pinExpire;
      return undefined;
    }
    const input = wf.resolveInput() as { code: string };
    const pinErr = this.verifyPin(ctx, input.code);
    if (pinErr) throw wf.requireInput({ errors: pinErr });
    ctx.pinVerified = true;
    delete ctx.pin;
    delete ctx.pinExpire;
    return undefined;
  }

  // ── verifyFactor ─────────────────────────────────────────────────────
  @Step("recoveryVerifyFactor")
  async verifyFactor(@WorkflowParam("context") ctx: RecoveryWfCtx): Promise<unknown> {
    const wf = useAtscriptWf(this.opts.forms.recoveryFactor);
    // Populate the radio options BEFORE `resolveInput()` — `requireInput`
    // (the implicit pause when no input is present) embeds the current ctx
    // into the form envelope, so the client needs the list ready on first
    // render. Filtered down to factors the user is actually able to verify
    // (workflow whitelist ∩ user enrollment).
    if (!ctx.availableRecoveryFactors) {
      ctx.availableRecoveryFactors = await this.loadAvailableRecoveryFactors(ctx);
    }
    const action = wf.resolveAction();
    if (action === "backToLogin" && this.opts.altActions.backToLogin) {
      this.abortToLogin(ctx);
      return undefined;
    }
    const input = wf.resolveInput() as { factor: string; value: string };
    this.requireUsername(ctx);
    const factor = input.factor;
    const value = input.value;

    const ok = await this.verifyRecoveryFactor({ factor, value, ctx });
    if (!ok) {
      // Opaque error — never reveal which factor is enrolled.
      throw wf.requireInput({ errors: { value: "Invalid factor" } });
    }
    ctx.factorVerified = true;
    return undefined;
  }

  /**
   * Returns the factor options to show on `RecoveryFactorForm`. Default:
   * intersection of `opts.preReset.allowedFactors` (workflow whitelist —
   * `undefined` means both `phone` and `totp` are eligible) and the kinds
   * the user has actually enrolled (`phone` if a confirmed SMS method
   * exists, `totp` if a confirmed TOTP method exists). Override to add
   * custom factors (e.g. security questions) — call `super` to keep the
   * built-in pair.
   */
  protected async loadAvailableRecoveryFactors(
    ctx: RecoveryWfCtx,
  ): Promise<Array<{ key: string; label: string }>> {
    if (!ctx.username) return [];
    const user = await this.users.getUser(ctx.username);
    const allowed = this.opts.preReset.allowedFactors ?? ["phone", "totp"];
    const has = {
      phone: user.mfa.methods.some((m) => m.name === "sms" && m.confirmed),
      totp: user.mfa.methods.some((m) => m.name === "totp" && m.confirmed),
    };
    const out: Array<{ key: string; label: string }> = [];
    if (allowed.includes("phone") && has.phone) out.push({ key: "phone", label: "Phone number" });
    if (allowed.includes("totp") && has.totp) {
      out.push({ key: "totp", label: "Authenticator app" });
    }
    return out;
  }

  /**
   * Verifies a recovery factor against the user's enrolled MFA methods.
   * Default: supports `'phone'` (phone last-4 match) and `'totp'` (current
   * TOTP code). Returns `true` when the factor matches.
   *
   * Consumers extend by overriding to support additional factors (e.g.
   * security questions); call `super.verifyRecoveryFactor(...)` to keep
   * the built-in checks.
   */
  protected async verifyRecoveryFactor(input: {
    factor: string;
    value: string;
    ctx: RecoveryWfCtx;
  }): Promise<boolean> {
    const { factor, value, ctx } = input;
    if (!ctx.username) return false;
    const user = await this.users.getUser(ctx.username);
    if (factor === "phone") {
      const phoneMethod = user.mfa.methods.find((m) => m.name === "sms" && m.confirmed);
      if (!phoneMethod) return false;
      return value === phoneMethod.value.slice(-4);
    }
    if (factor === "totp") {
      const totpMethod = user.mfa.methods.find((m) => m.name === "totp" && m.confirmed);
      if (!totpMethod) return false;
      return verifyTotpCode(totpMethod.value, value) !== null;
    }
    return false;
  }

  // ── setPassword ──────────────────────────────────────────────────────
  @Step("recoverySetPassword")
  async setPassword(@WorkflowParam("context") ctx: RecoveryWfCtx): Promise<unknown> {
    const wf = useAtscriptWf(this.opts.forms.setPassword);
    const action = wf.resolveAction();
    if (action === "backToLogin" && this.opts.altActions.backToLogin) {
      this.abortToLogin(ctx);
      return undefined;
    }

    const rawFormData = useWfState().input<{ formData?: unknown }>()?.formData;
    if (rawFormData === undefined) {
      // First entry: seed policy rules onto ctx BEFORE building requireInput
      // so the wfState.ctx() snapshot the engine sends with the
      // inputRequired envelope includes them. SetPasswordForm declares
      // `@wf.context.pass 'passwordPolicies'` so the engine surfaces the
      // key to the client. Mirrors the peek-then-throw-fresh pattern used
      // in `recoveryRequest` — the previous catch-and-rethrow snapshotted
      // ctx PRE-mutation, so the policies never reached the client.
      (ctx as Record<string, unknown>).passwordPolicies = this.users.getTransferablePolicies();
      throw wf.requireInput();
    }
    const input = wf.resolveInput() as { newPassword: string; confirmPassword: string };
    if (input.newPassword !== input.confirmPassword) {
      throw wf.requireInput({ errors: { confirmPassword: "Passwords do not match" } });
    }
    if (!ctx.username) {
      throw wf.requireInput({ formMessage: "Recovery session expired" });
    }
    try {
      await this.users.setPassword(ctx.username, input.newPassword);
    } catch (err) {
      this.translatePasswordSetError(err);
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
    await this.audit({
      kind: "recovery.completed",
      userId: ctx.username,
      workflow: "auth.recovery",
      deliveryMode: ctx.resolvedMode ?? this.opts.delivery.mode,
      ip: this.resolveClientIp(),
      ...(ctx.sessionsRevoked && { sessionsRevoked: true }),
    });
    return undefined;
  }

  // ── freshLoginFinish ─────────────────────────────────────────────────
  @Step("recoveryFreshLoginFinish")
  freshLoginFinish(@WorkflowParam("context") _ctx: RecoveryWfCtx): undefined {
    // Auto-mode countdown: user reads the success confirmation before redirect.
    finishWf({
      message: {
        level: "success",
        text: "Password updated. Redirecting to sign-in…",
      },
      next: {
        trigger: "auto",
        timeoutMs: 5000,
        action: {
          type: "redirect",
          target: this.opts.postReset.loginUrl,
          reason: "reset-success",
        },
        skipButton: { label: "Go now" },
      },
    });
    return undefined;
  }

  // ── autoLoginFinish ──────────────────────────────────────────────────
  @Step("recoveryAutoLoginFinish")
  async autoLoginFinish(@WorkflowParam("context") ctx: RecoveryWfCtx): Promise<undefined> {
    this.requireUsername(ctx);
    const issue = await this.auth.issue(ctx.username);
    ctx.tokensIssued = true;
    const auth = useAuth();
    // Raw envelope path — helpers don't expose cookies; wooks-level Set-Cookie.
    const envelope: WfFinished = {
      finished: true,
      data: auth.buildLoginResponse(ctx.username, issue),
    };
    useWfFinished().set({
      type: "data",
      value: envelope,
      cookies: auth.buildFinishedCookies(issue),
    });
    return undefined;
  }

  // ── Helpers ──────────────────────────────────────────────────────────
  /**
   * Send the generic "if an account exists, you'll receive instructions"
   * finished response. Used for unknown emails so a known/unknown lookup is
   * indistinguishable to the client (anti-enumeration).
   */
  private finishGeneric(): void {
    finishWf({
      data: { sent: true },
      message: { level: "info", text: "If an account exists, you will receive instructions." },
    });
  }

  private abortToLogin(ctx: RecoveryWfCtx): AltHandled {
    finishWf({
      next: {
        trigger: "immediate",
        action: {
          type: "redirect",
          target: this.opts.postReset.loginUrl,
          reason: "user-cancelled",
        },
      },
    });
    ctx.aborted = true;
    return ALT_HANDLED;
  }

  private async emitRequested(ctx: RecoveryWfCtx, username?: string): Promise<void> {
    if (!this.opts.audit.enabled) return;
    await this.audit({
      kind: "recovery.requested",
      workflow: "auth.recovery",
      userId: username,
      email: ctx.email,
      ip: this.resolveClientIp(),
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
