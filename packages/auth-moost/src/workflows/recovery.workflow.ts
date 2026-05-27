/**
 * RecoveryWorkflow — `wfid = 'auth/recovery/flow'`.
 *
 * Full step catalog per `WF_RECOVERY.md`. Defaults give today's 3-step
 * magic-link flow (`request` → `send-magic-link` → `set-password`);
 * consumers turn on OTP delivery, pre-reset factor
 * verification, fresh-login redirect etc. via `resolveXxx(ctx)` overrides
 * (delivery / preReset / postReset / altActions / audit).
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
 * **Consumer subclass pattern.** Consumers subclass `RecoveryWorkflow` to
 * override `protected` hook methods (`resolveXxx`, `deliver`, `audit`,
 * `emailToUserId`, `verifyRecoveryFactor`). The subclass MUST re-apply
 * `@Inherit() @Controller("auth/recovery")` and re-declare the constructor
 * signature (TS emits fresh design-paramtypes per class). Re-applying the
 * prefix is load-bearing: moost shallow-merges the subclass's `controller`
 * metadata over the parent's, so a bare `@Controller()` would override the
 * inherited prefix with the empty string and the wfid would lose its
 * `auth/recovery` namespace. `@Controller(...)` implicitly applies SINGLETON
 * DI scope — workflow controllers hold no per-event mutable state on `this`
 * (per-event state lives on ctx + wooks composables), so one instance per
 * app lifetime is correct.
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
import { Controller, Inherit } from "moost";

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
} from "./auth-workflow.base";
import type { DeliverPayload } from "./login.workflow";
import {
  mergeRecoveryOpts,
  type RecoveryDeliveryMode,
  type RecoveryOtpTransport,
  type RecoveryWorkflowOpts,
  type ResolvedRecoveryWorkflowOpts,
} from "./recovery.workflow.options";

/**
 * OTP-delivery state — populated across `prepare-delivery` / `select-mode` /
 * `send-otp` / `check-otp`. Step bodies write here and `PincodeForm` reads it
 * nested via `@wf.context.pass 'otp'` (mirrors login's `'mfa'` group).
 */
export interface RecoveryOtpState {
  /** Active transport for the current OTP attempt (set by `select-mode` for fixed-otp; flipped by `useDifferentTransport` action). */
  transport?: RecoveryOtpTransport;
  /** Pincode digit count mirrored from `authOpts.mfa.pincodeLength` for the form to render the input width. */
  codeLength?: number;
  /** Epoch-ms timestamp; `check-otp` rejects `resend` action before this. */
  resendAllowedAt?: number;
  /** Latches true after `check-otp` validates the submitted code — exits the otp while-loop. */
  verified?: boolean;
  /** Mirror of `delivery.otpTransports.length`; passed to `PincodeForm` so the `useDifferentTransport` action hides when only one transport is configured. */
  transportCount?: number;
}

export interface RecoveryWfCtx extends AuthWfCtxBase {
  // Resolved policy + per-event state (populated by prepare-* steps + step bodies;
  // policy reads via resolveXxx() getters, state writes from step bodies). All
  // fields are optional so init-time pre-writes (and `request`'s inline policy
  // resolution before `prepare-*`) merge cleanly.
  delivery?: {
    mode?: RecoveryDeliveryMode;
    otpTransports?: RecoveryOtpTransport[];
    /** User's choice from `select-mode` form (only when `mode === 'choice'`). */
    selectedMode?: "magicLink" | "otp";
    /** Mode the workflow committed to (set by `prepare-delivery` for fixed modes; by `select-mode` for `'choice'`). */
    resolvedMode?: "magicLink" | "otp";
    /** `send-magic-link` idempotency — resume → advance. */
    linkSent?: boolean;
  };
  preReset?: {
    requireKnownFactor?: boolean;
    allowedFactors?: Array<"phone" | "totp">;
    /** Set by `verify-factor` after the user proves a recovery factor (phone code / TOTP). */
    factorVerified?: boolean;
    /**
     * Recovery factors the user can actually verify on this attempt —
     * intersection of `allowedFactors` and what the user has enrolled.
     * Populated by `verify-factor`, surfaced to `RecoveryFactorForm` via
     * `@wf.context.pass 'preReset'`.
     */
    availableRecoveryFactors?: Array<{ key: string; label: string }>;
  };
  postReset?: {
    revokeAllSessions?: boolean;
    freshLoginRequired?: boolean;
    loginUrl?: string;
    /** Set by `revoke-sessions`; emitted into the auto-login finish envelope. */
    sessionsRevoked?: boolean;
  };
  altActions?: {
    backToLogin: boolean;
  };
  audit?: {
    enabled: boolean;
  };

  // OTP-mode state (grouped — passed to PincodeForm via `@wf.context.pass 'otp'`):
  otp?: RecoveryOtpState;
}

/**
 * Per-group policy override shape consumed by `resolveXxx(ctx)` subclass
 * overrides. Mirrors the `ctx.<group>` fields that the `prepare-<group>`
 * @Step methods populate — one entry per resolver. Library users typically
 * accept a payload of this shape on their `RecoveryWorkflow` subclass ctor /
 * test harness and have each `resolveXxx` return its matching key (falling
 * back to `super.resolveXxx(ctx)` for unset groups).
 *
 * Picked down to policy keys only — `ctx.<group>` also carries per-event
 * state (e.g. `delivery.linkSent`, `preReset.factorVerified`,
 * `postReset.sessionsRevoked`) that step bodies write at runtime; those must
 * not be settable via the override surface.
 */
export interface RecoveryPolicyOverrides {
  delivery?: Pick<NonNullable<RecoveryWfCtx["delivery"]>, "mode" | "otpTransports">;
  preReset?: Pick<NonNullable<RecoveryWfCtx["preReset"]>, "requireKnownFactor" | "allowedFactors">;
  postReset?: Pick<
    NonNullable<RecoveryWfCtx["postReset"]>,
    "revokeAllSessions" | "freshLoginRequired" | "loginUrl"
  >;
  altActions?: NonNullable<RecoveryWfCtx["altActions"]>;
  audit?: NonNullable<RecoveryWfCtx["audit"]>;
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
 * (`audit()` no-op) protected methods that consumers override. Policy moved
 * to `resolveXxx(ctx)` so empty-transports-while-otp checks now fire at
 * `prepare-delivery` step time, not construction time.
 */
function validateOpts(_opts: ResolvedRecoveryWorkflowOpts): void {
  // No cross-field invariants today.
}

// `@Public()` — recovery is by definition reachable without authn (the user
// can't authenticate yet). The global `arbacAuthorizeInterceptor` running on
// workflow events bypasses this controller. See `LoginWorkflow` for the
// rationale on why the marker has to live on the workflow class itself, not
// just the `/auth/trigger` HTTP route.
@Inherit()
@Public()
@Controller("auth/recovery")
export class RecoveryWorkflow extends AuthWorkflowBase {
  protected readonly opts: ResolvedRecoveryWorkflowOpts;
  protected readonly users: UserService;
  protected readonly auth: AuthCredential;
  protected readonly authOpts: AuthOpts;
  protected readonly consentStore: ConsentStore;

  constructor(
    opts: RecoveryWorkflowOpts,
    users: UserService,
    auth: AuthCredential,
    authOpts: AuthOpts,
    consentStore: ConsentStore,
  ) {
    super();
    this.opts = mergeRecoveryOpts(opts);
    this.users = users;
    this.auth = auth;
    this.authOpts = authOpts;
    this.consentStore = consentStore;
    validateOpts(this.opts);
  }

  protected get consentsWorkflowId(): string {
    return "auth/recovery/flow";
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

  // ── Resolved policy surface (override these to customize per-tenant/per-request behavior) ──
  /**
   * Resolve the delivery policy (mode + OTP transports). Override per-tenant
   * to drive magic-link vs OTP delivery preferences. Sync/async friendly.
   */
  protected resolveDelivery(
    _ctx: RecoveryWfCtx,
  ): NonNullable<RecoveryWfCtx["delivery"]> | Promise<NonNullable<RecoveryWfCtx["delivery"]>> {
    return { mode: "magicLink", otpTransports: ["email"] };
  }

  /**
   * Resolve the pre-reset policy (requireKnownFactor + allowedFactors whitelist).
   * Override to enforce a factor check between the magic-link / OTP step and
   * the new-password form. `allowedFactors` omitted means both phone and TOTP
   * are eligible. Sync/async friendly.
   */
  protected resolvePreReset(
    _ctx: RecoveryWfCtx,
  ): NonNullable<RecoveryWfCtx["preReset"]> | Promise<NonNullable<RecoveryWfCtx["preReset"]>> {
    return { requireKnownFactor: false };
  }

  /**
   * Resolve the post-reset policy (session revocation / fresh-login redirect /
   * loginUrl). Override per-tenant. `loginUrl` defaults to
   * `this.authOpts.loginUrl` (the cross-workflow shared login URL); customers
   * can still override per-tenant by overriding this resolver — the field
   * stays on the policy surface. Sync/async friendly.
   */
  protected resolvePostReset(
    _ctx: RecoveryWfCtx,
  ): NonNullable<RecoveryWfCtx["postReset"]> | Promise<NonNullable<RecoveryWfCtx["postReset"]>> {
    return {
      // safe to default-on since CredentialStoreJwt.passesEpoch uses >= (no race with issue in same tick)
      revokeAllSessions: true,
      // SPA-friendly default; server-rendered apps opt in via freshLoginRequired: true
      freshLoginRequired: false,
      loginUrl: this.authOpts.loginUrl,
    };
  }

  /**
   * Resolve the alt-actions policy (whether `backToLogin` is offered on the
   * recovery forms). Override to hide the escape hatch per-tenant. Sync/async
   * friendly.
   */
  protected resolveAltActions(
    _ctx: RecoveryWfCtx,
  ): NonNullable<RecoveryWfCtx["altActions"]> | Promise<NonNullable<RecoveryWfCtx["altActions"]>> {
    return { backToLogin: true };
  }

  /**
   * Resolve the audit policy (whether recovery.* audit events fire). Override
   * to route audit-log emission per-tenant. Sync/async friendly.
   */
  protected resolveAudit(
    _ctx: RecoveryWfCtx,
  ): NonNullable<RecoveryWfCtx["audit"]> | Promise<NonNullable<RecoveryWfCtx["audit"]>> {
    return { enabled: true };
  }

  // ── Prepare steps (call resolveXxx getters; populate ctx for schema conditions) ──
  //
  // Step IDs are bare (`prepare-delivery`, `prepare-audit`, …) because the
  // class-level `@Controller("auth/recovery")` prefix namespaces them at
  // registration time — `@moostjs/event-wf` prepends `auth/recovery/` to each
  // `@Step('id')` so the engine sees `auth/recovery/prepare-delivery` and
  // sibling workflows can keep their own `prepare-delivery` without collision.
  @Step("prepare-delivery")
  prepareDelivery(@WorkflowParam("context") ctx: RecoveryWfCtx): undefined | Promise<undefined> {
    const result = this.resolveDelivery(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        this.applyResolvedDelivery(ctx, resolved);
        return undefined;
      });
    }
    this.applyResolvedDelivery(ctx, result);
    return undefined;
  }

  /**
   * Apply resolved delivery to ctx — also auto-resolves derived ctx fields:
   *   - `delivery.resolvedMode` (when mode !== 'choice' — `'choice'` defers to `select-mode`)
   *   - `otp.transportCount` (mirrored to ctx for the `useDifferentTransport` form gate)
   *
   * Validates the otpTransports-not-empty invariant at step time (replacing
   * the old construction-time `validateOpts` check; the value is now
   * ctx-driven so the check has to fire at step time). Merges into
   * `ctx.delivery` rather than overwriting — `select-mode` may have already
   * stamped `selectedMode` / `resolvedMode` on resume.
   */
  private applyResolvedDelivery(
    ctx: RecoveryWfCtx,
    resolved: NonNullable<RecoveryWfCtx["delivery"]>,
  ): void {
    const transports = resolved.otpTransports ?? [];
    if (resolved.mode !== "magicLink" && transports.length === 0) {
      throw new Error(
        "RecoveryWorkflow: delivery.otpTransports cannot be empty when delivery.mode includes OTP",
      );
    }
    const d = (ctx.delivery ??= {});
    Object.assign(d, resolved);
    if (resolved.mode !== "choice" && !d.resolvedMode) {
      d.resolvedMode = resolved.mode;
    }
    (ctx.otp ??= {}).transportCount = transports.length;
  }

  @Step("prepare-pre-reset")
  preparePreReset(@WorkflowParam("context") ctx: RecoveryWfCtx): undefined | Promise<undefined> {
    const result = this.resolvePreReset(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.preReset = resolved;
        return undefined;
      });
    }
    ctx.preReset = result;
    return undefined;
  }

  @Step("prepare-post-reset")
  preparePostReset(@WorkflowParam("context") ctx: RecoveryWfCtx): undefined | Promise<undefined> {
    const result = this.resolvePostReset(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.postReset = resolved;
        return undefined;
      });
    }
    ctx.postReset = result;
    return undefined;
  }

  @Step("prepare-alt-actions")
  prepareAltActions(@WorkflowParam("context") ctx: RecoveryWfCtx): undefined | Promise<undefined> {
    const result = this.resolveAltActions(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.altActions = resolved;
        return undefined;
      });
    }
    ctx.altActions = result;
    return undefined;
  }

  @Step("prepare-audit")
  prepareAudit(@WorkflowParam("context") ctx: RecoveryWfCtx): undefined | Promise<undefined> {
    const result = this.resolveAudit(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.audit = resolved;
        return undefined;
      });
    }
    ctx.audit = result;
    return undefined;
  }

  @Workflow("flow")
  @WorkflowSchema<RecoveryWfCtx>([
    // Step IDs are bare; the class-level `@Controller("auth/recovery")` prefix
    // namespaces them globally (auth/recovery/init etc.) so sibling workflows
    // can keep their own `init` without collision.
    { id: "init" },
    { id: "request" },
    // Username gate — `request` finishes anonymously on unknown email
    // (anti-enumeration short-circuit) without setting ctx.username. Halt the
    // schema before downstream steps run.
    { break: (ctx) => !ctx.username },

    // Resolve remaining policy groups now that username is set.
    // `prepare-alt-actions` + `prepare-audit` are also
    // called INLINE by `request` (since that step needs them BEFORE
    // the username gate); these re-runs are idempotent — they re-write the
    // same values.
    { id: "prepare-delivery" },
    { id: "prepare-pre-reset" },
    { id: "prepare-post-reset" },
    { id: "prepare-alt-actions" },
    { id: "prepare-audit" },
    ...consentsPreludeSchema,

    // Mode picker — only when delivery.mode === 'choice' AND not already chosen.
    {
      id: "select-mode",
      condition: (ctx) => ctx.delivery?.mode === "choice" && !ctx.delivery?.selectedMode,
    },
    // Abort gate — select-mode 'backToLogin' alt-action sets ctx.aborted.
    { break: (ctx) => !!ctx.aborted },

    // Magic-link branch.
    {
      id: "send-magic-link",
      condition: (ctx) => ctx.delivery?.resolvedMode === "magicLink",
    },
    // OTP branch — sendOtp + checkOtp wrapped in a while-loop so the
    // `useDifferentTransport` and `resend` alt-actions can reset
    // `pin` + `otp.transport` and loop back through `sendOtp` on the new
    // channel. The loop exits when `otp.verified` flips true.
    {
      while: (ctx) => ctx.delivery?.resolvedMode === "otp" && !ctx.otp?.verified && !ctx.aborted,
      steps: [
        {
          id: "send-otp",
          condition: (ctx) => !ctx.pin,
        },
        { id: "check-otp" },
      ],
    },
    // Abort gate — check-otp 'backToLogin' alt-action sets ctx.aborted.
    { break: (ctx) => !!ctx.aborted },

    // Pre-reset factor check.
    {
      id: "verify-factor",
      condition: (ctx) =>
        !!ctx.preReset?.requireKnownFactor &&
        !ctx.preReset?.factorVerified &&
        (!!ctx.delivery?.linkSent || !!ctx.otp?.verified),
    },
    // Abort gate — verify-factor 'backToLogin' alt-action sets ctx.aborted.
    { break: (ctx) => !!ctx.aborted },

    // Set password — gated on the chosen branch having completed.
    {
      id: "set-password",
      condition: (ctx) =>
        (!!ctx.delivery?.linkSent || !!ctx.otp?.verified) &&
        (!ctx.preReset?.requireKnownFactor || !!ctx.preReset?.factorVerified),
    },
    // No abort path from set-password anymore — SetPasswordForm has no
    // alt-actions. The `{ break }` gate is retained so any prior step that
    // flipped `ctx.aborted` (e.g. `request` / `select-mode` / `verify-factor`
    // backToLogin) still short-circuits the post-reset tail.
    { break: (ctx) => !!ctx.aborted },

    // Post-password subflow — `completion.passwordChanged` flips ONCE in
    // `set-password` and stays true; safe to hoist as a subflow
    // condition (evaluated once when the engine reaches it).
    {
      condition: (ctx) => !!ctx.completion?.passwordChanged,
      steps: [
        {
          id: "revoke-sessions",
          condition: (ctx) => !!ctx.postReset?.revokeAllSessions,
        },
        // Batched consent persistence — see `consentsPersistTailSchema`.
        // No recovery-specific terms-bump-prompt: recovery always reaches
        // `SetPasswordForm` as a guaranteed carrier form, so the inline
        // `AsConsentArray` path is sufficient.
        ...consentsPersistTailSchema,
        {
          id: "audit",
          condition: (ctx) => !!ctx.audit?.enabled,
        },
        // Finalize: one of fresh-login or auto-login, never both.
        {
          id: "fresh-login-finish",
          condition: (ctx) => !!ctx.postReset?.freshLoginRequired,
        },
        {
          id: "auto-login-finish",
          condition: (ctx) => !ctx.postReset?.freshLoginRequired && !ctx.completion?.tokensIssued,
        },
      ],
    },
  ])
  flow(): void {}

  // ── Phase 0 ───────────────────────────────────────────────────────────
  /**
   * First step of the workflow; remains as a no-op override hook for
   * consumers. Policy populated by the dedicated `prepare-<group>` steps.
   *
   * Return type is `undefined | Promise<undefined>` so consumers can override
   * with `async init(...)` without the default fast-path paying a Promise
   * allocation (the wf engine awaits only when the return value is a Promise).
   */
  @Step("init")
  init(@WorkflowParam("context") _ctx: RecoveryWfCtx): undefined | Promise<undefined> {
    return undefined;
  }

  // ── request ──────────────────────────────────────────────────────────
  @Step("request")
  async request(@WorkflowParam("context") ctx: RecoveryWfCtx): Promise<unknown> {
    // `request` runs BEFORE the `!ctx.username` gate and the prepare-*
    // steps, but it needs `altActions` (for the backToLogin alt-action) and
    // `audit` (for `emitRequested`) in scope. Call the resolvers inline and
    // stash the result on ctx — the prepare-* steps that run later will
    // overwrite with the same value (idempotent) once username is set.
    const altResult = this.resolveAltActions(ctx);
    const alt = altResult instanceof Promise ? await altResult : altResult;
    ctx.altActions = alt;
    const auditResult = this.resolveAudit(ctx);
    ctx.audit = auditResult instanceof Promise ? await auditResult : auditResult;

    const emailWf = useAtscriptWf(this.opts.forms.emailIdentifier);
    const action = emailWf.resolveAction();
    if (action === "backToLogin" && alt.backToLogin) {
      // postReset is not yet resolved at this point — call the resolver inline
      // (mirrors altActions + audit above). Idempotent w.r.t. the later
      // `prepare-post-reset` step. `abortToLogin` reads `ctx.postReset!.loginUrl`.
      const postResetResult = this.resolvePostReset(ctx);
      ctx.postReset = postResetResult instanceof Promise ? await postResetResult : postResetResult;
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
      // `ctx.username` gate.
      this.finishGeneric();
      return undefined;
    }

    ctx.username = username;
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
  @Step("select-mode")
  selectMode(@WorkflowParam("context") ctx: RecoveryWfCtx): unknown {
    const wf = useAtscriptWf(this.opts.forms.recoveryModeSelect);
    const action = wf.resolveAction();
    if (action === "backToLogin" && ctx.altActions!.backToLogin) {
      this.abortToLogin(ctx);
      return undefined;
    }
    const input = wf.resolveInput() as { mode: string };
    const mode = input.mode as "magicLink" | "otp";
    const d = (ctx.delivery ??= {});
    d.selectedMode = mode;
    d.resolvedMode = mode;
    if (mode === "otp" && !ctx.otp?.transport) {
      (ctx.otp ??= {}).transport = d.otpTransports?.[0];
    }
    return undefined;
  }

  // ── sendMagicLink ────────────────────────────────────────────────────
  @Step("send-magic-link")
  sendMagicLink(@WorkflowParam("context") ctx: RecoveryWfCtx): unknown {
    // First run: emit outletEmail; engine persists state, our email outlet
    // ships the magic link. Resume run (link clicked): `delivery.linkSent` is
    // set so we advance to `set-password` without re-sending.
    if (ctx.delivery?.linkSent) return undefined;
    (ctx.delivery ??= {}).linkSent = true;
    return {
      ...outletEmail(ctx.email as string, "recovery.magicLink", {
        username: ctx.username,
        expiresAtMs: this.authOpts.magicLinkTtlMs,
      }),
      expires: Date.now() + this.authOpts.magicLinkTtlMs,
    };
  }

  // ── sendOtp ──────────────────────────────────────────────────────────
  @Step("send-otp")
  async sendOtp(@WorkflowParam("context") ctx: RecoveryWfCtx): Promise<undefined> {
    this.requireUsername(ctx);
    const transports = ctx.delivery!.otpTransports!;
    const transport: RecoveryOtpTransport = ctx.otp?.transport ?? transports[0] ?? "email";
    const otp = (ctx.otp ??= {});
    otp.transport = transport;
    otp.codeLength = this.authOpts.mfa.pincodeLength;
    const code = this.mintPin(ctx, this.authOpts.mfa.pincodeLength, this.authOpts.mfa.pincodeTtlMs);
    otp.resendAllowedAt = Date.now() + this.authOpts.mfa.pincodeResendTimeoutMs;

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
      // user typed at `request` time — could be an email even when
      // delivering SMS). Fall back to the typed value if there is no recorded
      // phone.
      const phone = await this.resolveUserPhone(ctx.username);
      await this.deliver({
        channel: "sms",
        kind: "recovery.pincode",
        recipient: phone ?? (ctx.email as string),
        code,
        ttlMs: this.authOpts.mfa.pincodeTtlMs,
        userId: ctx.username,
      });
    }
    return undefined;
  }

  // ── checkOtp ─────────────────────────────────────────────────────────
  @Step("check-otp")
  async checkOtp(@WorkflowParam("context") ctx: RecoveryWfCtx): Promise<unknown> {
    const wf = useAtscriptWf(this.opts.forms.pincode);
    const action = wf.resolveAction();
    if (action === "backToLogin" && ctx.altActions!.backToLogin) {
      this.abortToLogin(ctx);
      return undefined;
    }
    if (action === "resend") {
      if (ctx.otp?.resendAllowedAt && Date.now() < ctx.otp.resendAllowedAt) {
        const waitSec = Math.ceil((ctx.otp.resendAllowedAt - Date.now()) / 1000);
        throw wf.requireInput({ formMessage: `Please wait ${waitSec}s` });
      }
      // Clear pin so the while-loop's `send-otp` condition re-fires.
      // `delete` (not `= undefined`) so the persisted ctx remains JSON-clean
      // — AsWfStore validates state.context against a JSON-anyOf schema and
      // chokes on explicit `undefined` entries.
      delete ctx.pin;
      delete ctx.pinExpire;
      return undefined;
    }
    if (action === "useDifferentTransport") {
      const transports = ctx.delivery!.otpTransports!;
      if (transports.length < 2) {
        throw wf.requireInput({ formMessage: "Only one transport configured" });
      }
      const current = ctx.otp?.transport ?? transports[0];
      const next = transports.find((t) => t !== current) ?? transports[0];
      (ctx.otp ??= {}).transport = next;
      delete ctx.pin;
      delete ctx.pinExpire;
      return undefined;
    }
    const input = wf.resolveInput() as { code: string };
    const pinErr = this.verifyPin(ctx, input.code);
    if (pinErr) throw wf.requireInput({ errors: pinErr });
    (ctx.otp ??= {}).verified = true;
    delete ctx.pin;
    delete ctx.pinExpire;
    return undefined;
  }

  // ── verifyFactor ─────────────────────────────────────────────────────
  @Step("verify-factor")
  async verifyFactor(@WorkflowParam("context") ctx: RecoveryWfCtx): Promise<unknown> {
    const wf = useAtscriptWf(this.opts.forms.recoveryFactor);
    // Populate the radio options BEFORE `resolveInput()` — `requireInput`
    // (the implicit pause when no input is present) embeds the current ctx
    // into the form envelope, so the client needs the list ready on first
    // render. Filtered down to factors the user is actually able to verify
    // (workflow whitelist ∩ user enrollment).
    const p = (ctx.preReset ??= {});
    if (!p.availableRecoveryFactors) {
      p.availableRecoveryFactors = await this.loadAvailableRecoveryFactors(ctx);
    }
    const action = wf.resolveAction();
    if (action === "backToLogin" && ctx.altActions!.backToLogin) {
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
    p.factorVerified = true;
    return undefined;
  }

  /**
   * Returns the factor options to show on `RecoveryFactorForm`. Default:
   * intersection of `preReset.allowedFactors` (workflow whitelist —
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
    const allowed = ctx.preReset?.allowedFactors ?? ["phone", "totp"];
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
  @Step("set-password")
  async setPassword(@WorkflowParam("context") ctx: RecoveryWfCtx): Promise<unknown> {
    // Stage context-aware copy BEFORE any pause so the inputRequired wire
    // envelope carries the heading/intro alongside the form schema.
    // Recovery's set-password is always "Reset your password" — no
    // discriminator branching (cf. login's initial-vs-expired split).
    const password = (ctx.password ??= {});
    password.heading = "Reset your password";
    password.intro = "Choose a new password for your account.";
    const wf = useAtscriptWf(this.opts.forms.setPassword);

    const rawFormData = useWfState().input<{ formData?: unknown }>()?.formData;
    if (rawFormData === undefined) {
      // First entry: seed policy rules onto ctx BEFORE building requireInput
      // so the wfState.ctx() snapshot the engine sends with the
      // inputRequired envelope includes them. SetPasswordForm declares
      // `@wf.context.pass 'password'` so the engine surfaces the
      // group to the client. Mirrors the peek-then-throw-fresh pattern used
      // in `request` — the previous catch-and-rethrow snapshotted
      // ctx PRE-mutation, so the policies never reached the client.
      password.policies = this.users.getTransferablePolicies();
      throw wf.requireInput();
    }
    const input = wf.resolveInput() as {
      newPassword: string;
      confirmPassword: string;
    } & InlineConsentInput;
    if (input.newPassword !== input.confirmPassword) {
      throw wf.requireInput({ errors: { confirmPassword: "Passwords do not match" } });
    }
    if (!ctx.username) {
      throw wf.requireInput({ formMessage: "Recovery session expired" });
    }
    try {
      await this.users.setPassword(ctx.username, input.newPassword);
    } catch (err) {
      if (err instanceof UserAuthError) {
        throw wf.requireInput({ errors: { newPassword: err.message } });
      }
      throw err;
    }
    // SetPasswordForm `extends WithInlineConsentForm` — capture the dynamic
    // `consents: string[]` array inline. `processInlineConsent` is a no-op
    // when `ctx.consents.pending` is empty (default), so the call is safe
    // to make on every recovery run; unknown ids are silently dropped per
    // its SECURITY contract.
    this.processInlineConsent(ctx, input, wf);
    (ctx.completion ??= {}).passwordChanged = true;
    return undefined;
  }

  // ── revokeSessions ───────────────────────────────────────────────────
  @Step("revoke-sessions")
  async revokeSessions(@WorkflowParam("context") ctx: RecoveryWfCtx): Promise<undefined> {
    if (!ctx.username) return undefined;
    await this.auth.revokeAllForUser(ctx.username);
    (ctx.postReset ??= {}).sessionsRevoked = true;
    return undefined;
  }

  // ── audit ────────────────────────────────────────────────────────────
  @Step("audit")
  async auditStep(@WorkflowParam("context") ctx: RecoveryWfCtx): Promise<undefined> {
    await this.audit({
      kind: "recovery.completed",
      userId: ctx.username,
      workflow: "auth/recovery/flow",
      deliveryMode: ctx.delivery?.resolvedMode ?? ctx.delivery!.mode!,
      ip: this.resolveClientIp(),
      ...(ctx.postReset?.sessionsRevoked && { sessionsRevoked: true }),
    });
    return undefined;
  }

  // ── freshLoginFinish ─────────────────────────────────────────────────
  @Step("fresh-login-finish")
  freshLoginFinish(@WorkflowParam("context") ctx: RecoveryWfCtx): undefined | Promise<undefined> {
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
          target: ctx.postReset!.loginUrl!,
          reason: "reset-success",
        },
        skipButton: { label: "Go now" },
      },
    });
    return undefined;
  }

  // ── autoLoginFinish ──────────────────────────────────────────────────
  @Step("auto-login-finish")
  async autoLoginFinish(@WorkflowParam("context") ctx: RecoveryWfCtx): Promise<undefined> {
    this.requireUsername(ctx);
    const issue = await this.auth.issue(ctx.username);
    (ctx.completion ??= {}).tokensIssued = true;
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
          target: ctx.postReset!.loginUrl!,
          reason: "user-cancelled",
        },
      },
    });
    ctx.aborted = true;
    return ALT_HANDLED;
  }

  private async emitRequested(ctx: RecoveryWfCtx, username?: string): Promise<void> {
    if (!ctx.audit?.enabled) return;
    await this.audit({
      kind: "recovery.requested",
      workflow: "auth/recovery/flow",
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
