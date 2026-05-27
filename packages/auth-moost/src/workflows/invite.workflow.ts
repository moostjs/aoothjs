/**
 * InviteWorkflow — registers a single workflow id `auth/invite/start`.
 *
 * Single email-only path: admin enters recipient email + roles → invitee
 * receives an emailed magic link → invitee resumes anonymously on the link
 * to set password, optionally enroll MFA, optionally complete a profile,
 * and gets activated + auto-logged-in.
 *
 * Resend / cancel are deliberately NOT workflows here. Both are atomic
 * admin-side actions and belong on consumer-supplied controller routes
 * (resend = mint a new magic-link + re-emit; cancel = delete the pending
 * row). Wrapping atomic actions in workflow machinery added no value.
 *
 * SMS invites and shareable-link return modes are NOT supported: this
 * workflow ships exactly one delivery path — emailed magic link.
 *
 * Audit emission is NOT in the workflow either. Consumers who want audit
 * wire it through standard moost interceptors against the workflow's step
 * events.
 *
 * Step IDs are namespaced via the class-level `@Controller("auth/invite")`
 * prefix — `@moostjs/event-wf` prepends it before registering with the
 * @prostojs/wf engine, so bare step IDs (`init`, `setup-mfa`, …) become
 * `auth/invite/init` etc. at registration time.
 *
 * **Consumer subclass pattern.** Consumers subclass `InviteWorkflow` to
 * override `protected` hook methods. The subclass MUST re-apply
 * `@Inherit() @Controller("auth/invite")` and re-declare the constructor
 * signature (TS emits fresh design-paramtypes per class).
 *
 * **Side-effect dep as a protected method.**
 *
 *   - `deliver(payload)` — email-only dispatch (see `DeliverPayload`).
 *     Default throws; override to wire your sender. The default invite send
 *     uses `outletEmail` (handled by `createAuthEmailOutlet` at the trigger
 *     route) so `deliver()` is only invoked if a consumer's accept-tail
 *     steps drive a manual send.
 *
 * **Replaceable behaviour as protected methods.**
 *
 *   - `prepareUser(input)` — extras merged into the freshly-created user row.
 *   - `getAvailableRoles()` — multi-select source for the admin invite form.
 *   - `inferRoles(input)` — derive roles server-side (e.g. AD lookup).
 *   - `applyProfile({username, profile})` — persist the accept-time profile.
 *   - `duplicateCheck({email, existingUser})` — override the structural
 *     duplicate rule (multi-tenant escape hatch).
 *   - `getProfileForm()` — return the consumer's `.as` profile form schema;
 *     `undefined` skips the profile-collection step.
 *
 * Rate-limiting is intentionally NOT part of this workflow — consumers who
 * want a cap wire it themselves at the HTTP / trigger layer.
 */
import { ArbacAction, ArbacResource } from "@aooth/arbac-moost";
import { AuthCredential } from "@aooth/auth";
import { UserAuthError, type UserCredentials, UserService } from "@aooth/user";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { finishWf, type FinishWfOpts, useAtscriptWf, type WfFinished } from "@atscript/moost-wf";
import { HttpError } from "@moostjs/event-http";
import {
  outletEmail,
  Step,
  useWfFinished,
  Workflow,
  WorkflowParam,
  WorkflowSchema,
} from "@moostjs/event-wf";
import { Controller, Inherit } from "moost";

import { AuthOpts } from "../auth.opts";
import { ConsentStore } from "../consent.store";
import { useAuth } from "../auth.composables";
import { Public } from "../auth.decorator";
import {
  type DuplicateAction,
  type InviteWorkflowOpts,
  mergeInviteOpts,
  type PreparedUserInput,
  type ResolvedInviteWorkflowOpts,
} from "./invite.workflow.options";
import {
  type AuthWfCtxBase,
  AuthWorkflowBase,
  consentsPersistTailSchema,
  consentsPreludeSchema,
  type InlineConsentInput,
  type MfaEnrollDeps,
  stripReservedUserKeys,
} from "./auth-workflow.base";
import type { DeliverPayload } from "./login.workflow";

/**
 * Admin-side (Phase A) state — populated across `prepare-available-roles` /
 * `admin-form` / `infer-roles` / `build-user-extras` / `send-email`. Step
 * bodies write here and forms.as reads it nested via `@wf.context.pass 'admin'`.
 */
export interface InviteAdminState {
  /**
   * Admin policy — whitelist of role keys the admin may pick. Populated by
   * `prepare-available-roles` when the `getAvailableRoles()` override returns
   * a list. Surfaced into the `InviteForm` via `@wf.context.pass 'admin'` so
   * the role multi-select renders the whitelisted choices; also used by
   * `admin-form` to reject admin-submitted roles outside the list.
   */
  availableRoles?: string[];
  /**
   * Admin form input — role keys the admin actually picked (or set-unioned by
   * `infer-roles`). Validated against `availableRoles` when that whitelist is
   * set; persisted onto the user row by `create-user` / `send-email`.
   */
  roles?: string[];
  /**
   * Extras dict built by `build-user-extras` (calls `prepareUser`) and
   * consumed by `create-user` to populate the user-row fields beyond the
   * base credential shape. Split apart so consumers can inject e.g. a
   * tenant-validation step between extras-build and create-user without
   * copying either body.
   */
  userExtras?: Record<string, unknown>;
  /**
   * `send-email` idempotency — marks that the invite outlet already emitted,
   * so re-entry into the step on resume short-circuits. The @prostojs/wf
   * runtime re-enters the saved step on resume (the loop restarts at
   * `indexes[level]`, not after it), so the step body guards on this flag.
   */
  linkSent?: boolean;
}

export interface InviteWfCtx extends AuthWfCtxBase {
  // Resolved policy (populated by prepare-* steps; reads via resolveXxx() getters):
  adminForm?: { collectRoles: boolean };
  /**
   * Accept-tail policy AND state. The 5 leading fields are the policy
   * resolved by `resolveAccept`/`prepare-accept`; the 3 trailing fields are
   * Phase-B state filled in by `init` / `check-pending-invitation` /
   * `collect-profile`. All fields are optional because `init` writes
   * `profileFormPresent` BEFORE `prepare-accept` runs.
   */
  accept?: {
    alreadyAcceptedRedirectUrl?: string;
    freshLoginRequired?: boolean;
    loginUrl?: string;
    showConfirmation?: boolean;
    confirmationMessage?: string;
    /** Derived projection from `init`: `this.getProfileForm() !== undefined`. Read by accept-tail schema gates. */
    profileFormPresent?: boolean;
    /** Set by `check-pending-invitation` when the invite was already accepted; triggers `idempotent-redirect`. */
    alreadyAccepted?: boolean;
    /** Set by `collect-profile` — raw profile-form input awaiting `apply-profile`. */
    profile?: Record<string, unknown>;
  };
  mfa?: {
    issuer: string;
    /**
     * 3-state MFA policy:
     *   - `'required'` — invitee MUST enroll a second factor BEFORE activation.
     *   - `'optional'` — invitee is prompted but may `skip` the enrollment form.
     *   - `'disabled'` — enrollment loop is skipped entirely.
     */
    mode?: "required" | "optional" | "disabled";
    /** Available MFA transports (set by `inviteSetupMfa` setter — overridable per consumer). */
    availableTransports?: Array<"sms" | "email" | "totp">;
  };

  // ── Admin-side (Phase A) ────────────────────────────────────────────────
  admin?: InviteAdminState;
}

/**
 * Per-group policy override shape consumed by `resolveXxx(ctx)` subclass
 * overrides. Mirrors the `ctx.<group>` fields that the `prepare-<group>`
 * @Step methods populate — one entry per resolver. Library users typically
 * accept a payload of this shape on their `InviteWorkflow` subclass ctor /
 * test harness and have each `resolveXxx` return its matching key (falling
 * back to `super.resolveXxx(ctx)` for unset groups).
 */
export interface InvitePolicyOverrides {
  adminForm?: NonNullable<InviteWfCtx["adminForm"]>;
  accept?: NonNullable<InviteWfCtx["accept"]>;
  mfa?: NonNullable<InviteWfCtx["mfa"]>;
}

/**
 * Construction-time invariants for DATA validity only. Currently no
 * cross-field invariants survive — the function stays as a future hook for
 * opts validation without re-plumbing the ctor.
 */
function validateOpts(_opts: ResolvedInviteWorkflowOpts): void {
  // No cross-field invariants today.
}

/** Trim + de-duplicate role identifiers submitted via the admin invite form. */
export function parseInviteRoles(input?: string[]): string[] {
  if (!Array.isArray(input)) return [];
  const seen = new Set<string>();
  for (const v of input) {
    const trimmed = typeof v === "string" ? v.trim() : "";
    if (trimmed) seen.add(trimmed);
  }
  return [...seen];
}

/**
 * Single source of truth for the "this invite was already accepted" finish
 * envelope. Used by both `idempotent-redirect` (in-workflow) and by
 * `AuthController.invitePostRedemption` (side route reached when the wf
 * state store has evicted the finished row and re-resume hits 410).
 *
 * Secondary "Request a new invite" option is gated on `alreadyAcceptedRedirectUrl`
 * being non-empty — mirrors how `mergeInviteOpts` defaults it to `/login`,
 * but lets consumers blank it to suppress the secondary button.
 */
export function buildInviteAlreadyAcceptedEnvelope(opts: {
  loginUrl: string;
  alreadyAcceptedRedirectUrl: string;
}): FinishWfOpts {
  const altUrl = opts.alreadyAcceptedRedirectUrl;
  return {
    message: { level: "info", text: "This invite was already accepted." },
    next: {
      trigger: "manual",
      primary: {
        label: "Go to sign-in",
        action: { type: "redirect", target: opts.loginUrl, reason: "already-accepted" },
      },
      ...(altUrl && {
        options: [
          {
            label: "Request a new invite",
            action: { type: "redirect", target: altUrl, reason: "request-new-invite" },
          },
        ],
      }),
    },
  };
}

/**
 * **Per-step ARBAC model.** Phase-A steps (admin-side, pre magic-link send)
 * inherit the class-level `@ArbacResource('auth.invite') @ArbacAction('start')`
 * so every admin-side step event is gated. Apps that wire
 * `arbacAuthorizeInterceptor` globally grant admin a single rule:
 * `allow('auth.invite', 'start')`. The ARBAC resource name is intentionally
 * distinct from the wfid path (`auth/invite/start`) — RBAC policy ids and
 * wfid namespacing are separate naming schemes.
 *
 * The `inviteFlow` body method is `@Public()` because the wf adapter
 * dispatches the flow body on EVERY `start()` / `resume()` call — gating
 * it would 401 the anonymous magic-link resume before any step runs. The
 * real gate is the step methods themselves, which the wf runtime invokes
 * through the same interceptor chain.
 *
 * Phase-B steps (post `ctx.admin.linkSent`, accept tail) are method-level
 * `@Public()` because they fire on the anonymous magic-link resume.
 * `send-email` is the boundary: also `@Public()` because the @prostojs/wf
 * runtime re-enters the saved step on resume (the loop restarts at
 * `indexes[level]`, not after it). Its body is idempotent via
 * `if (admin.linkSent) return`.
 */
@Inherit()
@ArbacResource("auth.invite")
@ArbacAction("start")
@Controller("auth/invite")
export class InviteWorkflow extends AuthWorkflowBase {
  protected readonly opts: ResolvedInviteWorkflowOpts;
  protected readonly users: UserService;
  protected readonly auth: AuthCredential;
  protected readonly authOpts: AuthOpts;
  protected readonly consentStore: ConsentStore;

  constructor(
    opts: InviteWorkflowOpts,
    users: UserService,
    auth: AuthCredential,
    authOpts: AuthOpts,
    consentStore: ConsentStore,
  ) {
    super();
    this.opts = mergeInviteOpts(opts);
    this.users = users;
    this.auth = auth;
    this.authOpts = authOpts;
    this.consentStore = consentStore;
    validateOpts(this.opts);
  }

  protected get consentsWorkflowId(): string {
    return "auth/invite/start";
  }

  // ── Protected extension surface ───────────────────────────────────────
  /**
   * Dispatch the invite email. Default throws — the default invite send
   * uses `outletEmail` (handled by `createAuthEmailOutlet`) so this method
   * is only invoked when a consumer's accept-tail steps drive a manual
   * send. Override to wire your sender.
   */
  protected async deliver(_payload: DeliverPayload): Promise<void> {
    throw new Error("InviteWorkflow.deliver() not configured — override to wire your email sender");
  }

  /**
   * Build the extras dictionary merged into the freshly-created user row in
   * `invitePreCreateUser`. Default: `{}`. Override to populate e.g. a
   * required `tenantId`.
   */
  protected async prepareUser(_input: PreparedUserInput): Promise<Record<string, unknown>> {
    return {};
  }

  /**
   * Return the list of selectable role identifiers for the admin invite form.
   * When defined AND `adminForm.collectRoles` is true → form ships
   * `ctx.admin.availableRoles` so the UI renders a multi-select AND the
   * `admin-form` step rejects admin-submitted roles outside the
   * list. When `undefined` (default) → no whitelist is enforced and any role
   * value the admin form supplies is accepted.
   */
  protected async getAvailableRoles(): Promise<string[] | undefined> {
    return undefined;
  }

  /**
   * Derive roles server-side from the admin-form payload (e.g. email domain
   * → tenant role, AD lookup). Result is set-unioned with admin-supplied
   * roles when `adminForm.collectRoles` is true. Default: `[]` (no inference).
   */
  protected async inferRoles(_input: { email: string }): Promise<string[]> {
    return [];
  }

  /**
   * Persist the accept-time profile payload. Default: deep-merge into the
   * user record via `UserService.update(username, profile)`. Override to
   * route into a separate profile table / external CRM.
   */
  protected async applyProfile(input: {
    username: string;
    profile: Record<string, unknown>;
  }): Promise<void> {
    await this.users.update(input.username, input.profile as Partial<UserCredentials>);
  }

  /**
   * Override the structural duplicate rule for `admin-form`.
   * Default: any existing row → `'reject'`; nothing → `'allow'`. Multi-tenant
   * apps that allow re-inviting the same email into a different tenant
   * override to return `'allow'` for those cases.
   */
  protected async duplicateCheck(input: {
    email: string;
    existingUser: UserCredentials | null;
  }): Promise<DuplicateAction> {
    return input.existingUser ? "reject" : "allow";
  }

  /**
   * Return the consumer-supplied `.as` form schema rendered in the
   * `collect-profile` step. `undefined` (default) skips the step
   * entirely (just password collection).
   */
  protected getProfileForm(): TAtscriptAnnotatedType | undefined {
    return undefined;
  }

  // ── Resolved policy surface (override these to customize per-tenant/per-request behavior) ──
  /**
   * Resolve the admin-form policy (whether to collect roles on the admin
   * invite form). Override per-tenant. Sync/async friendly.
   */
  protected resolveAdminForm(
    _ctx: InviteWfCtx,
  ): NonNullable<InviteWfCtx["adminForm"]> | Promise<NonNullable<InviteWfCtx["adminForm"]>> {
    return { collectRoles: true };
  }

  /**
   * Resolve the accept-tail policy (idempotent-redirect URL, fresh-login gate,
   * loginUrl, confirmation message). Override per-tenant. Sync/async friendly.
   * `loginUrl` defaults to `this.authOpts.loginUrl` (the cross-workflow shared
   * login URL); customers can still override per-tenant by overriding this
   * resolver — the field stays on the policy surface.
   */
  protected resolveAccept(
    _ctx: InviteWfCtx,
  ): NonNullable<InviteWfCtx["accept"]> | Promise<NonNullable<InviteWfCtx["accept"]>> {
    return {
      alreadyAcceptedRedirectUrl: this.authOpts.loginUrl,
      freshLoginRequired: false,
      loginUrl: this.authOpts.loginUrl,
      showConfirmation: true,
      confirmationMessage: "Your account has been created.",
    };
  }

  /**
   * Resolve the MFA-issuer policy (TOTP provisioning issuer string rendered
   * in the authenticator app). Default tracks `this.authOpts.totpIssuer` —
   * customers override the resolver for per-tenant issuers. Pincode timers/
   * length live on `AuthOpts.mfa`. Sync/async friendly.
   */
  protected resolveMfa(
    _ctx: InviteWfCtx,
  ): NonNullable<InviteWfCtx["mfa"]> | Promise<NonNullable<InviteWfCtx["mfa"]>> {
    return { issuer: this.authOpts.totpIssuer };
  }

  // ── Prepare steps (call resolveXxx getters; populate ctx for schema conditions) ──
  @Step("prepare-admin-form")
  prepareAdminForm(@WorkflowParam("context") ctx: InviteWfCtx): undefined | Promise<undefined> {
    const result = this.resolveAdminForm(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.adminForm = resolved;
        return undefined;
      });
    }
    ctx.adminForm = result;
    return undefined;
  }

  @Step("prepare-accept")
  @Public()
  prepareAccept(@WorkflowParam("context") ctx: InviteWfCtx): undefined | Promise<undefined> {
    const result = this.resolveAccept(ctx);
    // Merge into `ctx.accept` rather than overwrite — `init` may have already
    // stamped `profileFormPresent` (and `check-pending-invitation` /
    // `collect-profile` may add `alreadyAccepted` / `profile` on resume).
    if (result instanceof Promise) {
      return result.then((resolved) => {
        Object.assign((ctx.accept ??= {}), resolved);
        return undefined;
      });
    }
    Object.assign((ctx.accept ??= {}), result);
    return undefined;
  }

  @Step("prepare-mfa")
  @Public()
  prepareMfa(@WorkflowParam("context") ctx: InviteWfCtx): undefined | Promise<undefined> {
    const result = this.resolveMfa(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.mfa = resolved;
        return undefined;
      });
    }
    ctx.mfa = result;
    return undefined;
  }

  // ╔═══════════════════════════════════════════════════════════════════════╗
  // ║ Workflow definitions                                                  ║
  // ╚═══════════════════════════════════════════════════════════════════════╝

  @Workflow("start")
  @WorkflowSchema<InviteWfCtx>([
    { id: "init" },
    { id: "prepare-admin-form" },
    {
      id: "prepare-available-roles",
      condition: (ctx) => !!ctx.adminForm?.collectRoles,
    },
    { id: "admin-form", condition: (ctx) => !ctx.email },
    {
      id: "infer-roles",
      condition: (ctx) => !!ctx.email,
    },
    {
      id: "build-user-extras",
      condition: (ctx) => !!(ctx.email && !ctx.username && !ctx.admin?.userExtras),
    },
    {
      id: "create-user",
      condition: (ctx) => !!(ctx.email && !ctx.username && !!ctx.admin?.userExtras),
    },
    {
      id: "send-email",
      condition: (ctx) => !!ctx.username,
    },
    // ── Phase B (accept tail): runs only after the magic link resumes here.
    // `ctx.admin.linkSent` flips ONCE in `send-email` and stays true — safe
    // to hoist as a subflow condition (evaluated once when the engine reaches
    // the subflow).
    {
      condition: (ctx) => !!ctx.admin?.linkSent,
      steps: [
        // Resolve accept + mfa policies on the anonymous resume side — the
        // admin-side `prepare-*` runs (above) don't survive across the
        // magic-link boundary in all cases; re-resolve here so accept-tail
        // step bodies + schema conditions read populated ctx slots.
        { id: "prepare-accept" },
        { id: "check-pending-invitation" },
        {
          id: "idempotent-redirect",
          condition: (ctx) => !!ctx.accept?.alreadyAccepted,
        },
        { id: "prepare-password-rules" },
        ...consentsPreludeSchema,
        {
          id: "create-password-form",
          condition: (ctx) => !ctx.completion?.passwordSet,
        },
        // MFA policy setters — fire once before the enrolment loop so consumer
        // overrides can compute mode/transports/enrollMethod from request context.
        { id: "prepare-mfa" },
        { id: "setup-mfa" },
        // ── Forced MFA enrollment (3 entries — pick / address / confirm). The
        // invite schema is linear and can't loop a single step like login does,
        // so each phase is a distinct entry; each step body calls the matching
        // `enrollPickPhase` / `enrollAddressPhase` / `enrollConfirmPhase` helper
        // on `AuthWorkflowBase` directly — no internal routing-by-ctx-state.
        {
          // Wrap the 3 enrolment entries in a while-loop so `useDifferentMethod`
          // (which clears `ctx.mfaEnroll.method` via `cleanupEnrollment`) causes
          // the schema to re-evaluate from the picker instead of falling through
          // to activation with no method enrolled. Mirrors login's MFA loop. Loop
          // exits when `ctx.mfaEnroll.done` flips true (Phase-3 confirm OR user-
          // skip in optional mode). `passwordSet` + `mode !== 'disabled'` live on
          // the while-gate so each inner step condition only checks the ctx
          // fields that distinguish ITS phase.
          while: (ctx) =>
            !!(ctx.completion?.passwordSet && ctx.mfa?.mode !== "disabled" && !ctx.mfaEnroll?.done),
          steps: [
            {
              id: "enroll-pick-method",
              condition: (ctx) =>
                !!((ctx.mfa?.availableTransports?.length ?? 0) > 1 && !ctx.mfaEnroll?.method),
            },
            {
              id: "enroll-address",
              condition: (ctx) =>
                !!(
                  ctx.mfaEnroll?.method &&
                  (ctx.mfaEnroll.method === "sms" || ctx.mfaEnroll.method === "email") &&
                  !ctx.mfaEnroll.address
                ),
            },
            {
              id: "enroll-confirm",
              condition: (ctx) =>
                !!(
                  ctx.mfaEnroll?.method &&
                  (ctx.mfaEnroll.method === "totp" || !!ctx.mfaEnroll.address)
                ),
            },
          ],
        },
        {
          id: "collect-profile",
          condition: (ctx) =>
            !!(
              ctx.completion?.passwordSet &&
              ctx.accept?.profileFormPresent &&
              !ctx.accept?.profile
            ),
        },
        {
          id: "apply-profile",
          condition: (ctx) =>
            !!(
              ctx.completion?.passwordSet &&
              ctx.accept?.profileFormPresent &&
              ctx.accept?.profile &&
              !ctx.completion?.profileApplied
            ),
        },
        // Consumer extension point — see `inviteExtraStep()` method.
        { id: "extra-step" },
        // Batched consent persistence — see `consentsPersistTailSchema`.
        // Placed before the tail that issues tokens. No invite-specific
        // terms-bump-prompt: invite always has `SetPasswordForm` as a
        // guaranteed carrier form, so the inline `AsConsentArray` path is
        // sufficient.
        ...consentsPersistTailSchema,
        {
          id: "unset-pending-invitation",
          condition: (ctx) =>
            !!(ctx.completion?.passwordSet && !ctx.completion?.pendingInvitationCleared),
        },
        {
          id: "activate-user",
          condition: (ctx) =>
            !!(ctx.completion?.pendingInvitationCleared && !ctx.completion?.activated),
        },
        {
          id: "confirmation",
          condition: (ctx) =>
            !!(
              ctx.completion?.activated &&
              ctx.accept?.showConfirmation &&
              !ctx.completion?.confirmationShown
            ),
        },
        {
          id: "fresh-login-finish",
          condition: (ctx) => !!(ctx.completion?.activated && ctx.accept?.freshLoginRequired),
        },
        {
          id: "auto-login-finish",
          condition: (ctx) =>
            !!(
              ctx.completion?.activated &&
              !ctx.accept?.freshLoginRequired &&
              !ctx.completion?.tokensIssued
            ),
        },
      ],
    },
  ])
  @Public()
  inviteFlow(): void {}

  // ╔═══════════════════════════════════════════════════════════════════════╗
  // ║ Steps                                                                 ║
  // ╚═══════════════════════════════════════════════════════════════════════╝

  // ── Phase 0 ────────────────────────────────────────────────────────────
  @Step("init")
  init(@WorkflowParam("context") ctx: InviteWfCtx): undefined | Promise<undefined> {
    // `init` writes BEFORE `prepare-accept` runs, so `ctx.accept` is partially
    // populated here — `prepare-accept` later spreads the resolved policy in.
    (ctx.accept ??= {}).profileFormPresent = this.getProfileForm() !== undefined;
    return undefined;
  }

  // ── Phase A: prepareAvailableRoles ────────────────────────────────────
  @Step("prepare-available-roles")
  async prepareAvailableRoles(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    const roles = await this.getAvailableRoles();
    if (roles) (ctx.admin ??= {}).availableRoles = roles;
    return undefined;
  }

  // ── Phase A: adminInviteForm ──────────────────────────────────────────
  @Step("admin-form")
  async adminInviteForm(@WorkflowParam("context") ctx: InviteWfCtx): Promise<unknown> {
    const wf = useAtscriptWf(this.opts.forms.invite);
    const input = wf.resolveInput() as {
      email: string;
      roles: string[];
    };

    const email = input.email;
    const parsed = parseInviteRoles(input.roles);

    // Server-side whitelist enforcement: when `getAvailableRoles()` returned a
    // list (surfaced as `ctx.admin.availableRoles` by `prepare-available-roles`),
    // reject any admin-submitted role outside the whitelist. Skipped when no
    // whitelist is configured — see `getAvailableRoles` doc.
    if (Array.isArray(ctx.admin?.availableRoles)) {
      const allowed = new Set(ctx.admin.availableRoles);
      const bad = parsed.find((r) => !allowed.has(r));
      if (bad !== undefined) {
        throw wf.requireInput({ errors: { roles: "Invalid role" } });
      }
    }

    // Duplicate check — override-friendly. Default structural rule: any
    // existing row → reject (with a different message per pending / accepted).
    const existing = await this.loadUserOrNull(email);
    const action: DuplicateAction = await this.duplicateCheck({ email, existingUser: existing });
    if (action === "reject") {
      if (existing?.account?.pendingInvitation) {
        throw wf.requireInput({
          errors: { email: "Invite already pending" },
        });
      }
      if (existing) throw wf.requireInput({ errors: { email: "User already exists" } });
      throw wf.requireInput({ errors: { email: "Duplicate invite rejected" } });
    }

    ctx.email = email;
    if (parsed.length > 0) (ctx.admin ??= {}).roles = parsed;
    return undefined;
  }

  // ── Phase A: inferRolesStep ───────────────────────────────────────────
  @Step("infer-roles")
  async inferRolesStep(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    if (!ctx.email) return undefined;
    const inferred = await this.inferRoles({ email: ctx.email });
    if (inferred.length === 0) return undefined;
    const admin = (ctx.admin ??= {});
    const merged = new Set<string>([...(admin.roles ?? []), ...inferred]);
    admin.roles = Array.from(merged);
    return undefined;
  }

  // ── Phase A: buildUserExtras ──────────────────────────────────────────
  /**
   * Build the extras dict that `create-user` merges into the new user
   * row. Calls `prepareUser({email, roles, invitedBy})` and writes the
   * result onto `ctx.admin.userExtras`.
   */
  @Step("build-user-extras")
  async buildUserExtras(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    if (!ctx.email) throw new HttpError(500, "Workflow state corrupted: missing email");

    const invitedBy = useAuth().getAuthContext()?.userId;
    const preparedInput: PreparedUserInput = {
      email: ctx.email,
      roles: ctx.admin?.roles ?? [],
      ...(invitedBy && { invitedBy }),
    };

    (ctx.admin ??= {}).userExtras = await this.prepareUser(preparedInput);
    return undefined;
  }

  // ── Phase A: createUser ───────────────────────────────────────────────
  /**
   * Create the user row from `ctx.admin.userExtras` (plus the admin-supplied
   * `ctx.admin.roles`), translate store-level CONFLICT into HTTP 409, then stamp
   * `pendingInvitation = true` via a deep-merge update so the
   * `createUser`-applied account defaults (`active: false`, `locked: false`)
   * survive. Split out of the old `invitePreCreateUser` step so consumers can
   * override extras-build (`build-user-extras`) without touching the
   * store-write transaction.
   */
  @Step("create-user")
  async createUserStep(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    if (!ctx.email) throw new HttpError(500, "Workflow state corrupted: missing email");

    // `UserService.createUser` shallow-merges `extras` over `base`, so passing
    // an `account` key would wipe out the base's `active: false` / `locked:
    // false` defaults (and atscript-db validation would reject the row). Set
    // `pendingInvitation` via a follow-up `update` instead — preserves the
    // base defaults AND uses the same `@db.patch.strategy 'merge'` path the
    // rest of the workflow relies on.
    //
    // `firstName` / `lastName` are intentionally NOT injected here — they're
    // not in the base credential shape, and a strict-schema store would 500
    // on unknown columns. They reach the consumer only via `prepareUser`.
    const adminRoles = ctx.admin?.roles;
    const fields: Record<string, unknown> = {
      ...ctx.admin?.userExtras,
      ...(adminRoles && adminRoles.length > 0 && { roles: adminRoles }),
    };

    try {
      await this.users.createUser(ctx.email, undefined, fields);
    } catch (err) {
      if (err instanceof UserAuthError && err.type === "ALREADY_EXISTS") {
        // duplicateCheck returned 'allow' but the store still rejected — surface
        // the 409 cleanly.
        throw new HttpError(409, "User already exists");
      }
      throw err;
    }
    // Flip the structural pending-invitation flag via the deep-merge update
    // path so account-shape defaults persisted by `createUser` survive.
    await this.users.update(ctx.email, {
      account: { pendingInvitation: true },
    } as Partial<UserCredentials>);
    ctx.username = ctx.email;
    return undefined;
  }

  // ── Boundary: sendInviteEmail (fires on admin send AND on anonymous resume) ─
  @Step("send-email")
  @Public()
  sendInviteEmail(@WorkflowParam("context") ctx: InviteWfCtx): unknown {
    const admin = (ctx.admin ??= {});
    if (admin.linkSent) return undefined;
    admin.linkSent = true;
    return {
      ...outletEmail(ctx.email as string, "invite.magicLink", {
        username: ctx.username,
        // userId travels in the outlet context so `buildMagicLinkUrl` can embed
        // `&uid=…` in the URL. The SPA uses it to fall through to the
        // post-redemption side route when a second click hits a 410. In this
        // workflow `username` IS the user-id (see `autoLoginFinish` → `auth.issue(ctx.username)`).
        ...(ctx.username && { userId: ctx.username }),
        ...(admin.roles && { roles: admin.roles }),
        expiresAtMs: this.authOpts.magicLinkTtlMs,
      }),
      expires: Date.now() + this.authOpts.magicLinkTtlMs,
    };
  }

  // ── Phase B: checkPendingInvitation ───────────────────────────────────
  @Step("check-pending-invitation")
  @Public()
  async checkPendingInvitation(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    if (!ctx.username) {
      // No username on ctx means we're in a corrupted state — the admin-side
      // flow ALWAYS sets it before sending the email. Bail loud.
      throw new HttpError(500, "Workflow state corrupted: missing username at accept");
    }
    const existing = await this.loadUserOrNull(ctx.username);
    if (!existing) {
      // Admin cancelled between send and click — hard delete removed the row.
      throw new HttpError(410, "This invite has been cancelled");
    }
    if (!existing.account?.pendingInvitation) {
      (ctx.accept ??= {}).alreadyAccepted = true;
    }
    return undefined;
  }

  // ── Phase B: idempotentRedirect ───────────────────────────────────────
  @Step("idempotent-redirect")
  @Public()
  idempotentRedirect(@WorkflowParam("context") ctx: InviteWfCtx): undefined | Promise<undefined> {
    // Labels are hardcoded English (consistent with login/recovery finishers);
    // localization is a cross-workflow concern not yet wired.
    finishWf(
      buildInviteAlreadyAcceptedEnvelope({
        loginUrl: ctx.accept!.loginUrl!,
        alreadyAcceptedRedirectUrl: ctx.accept!.alreadyAcceptedRedirectUrl!,
      }),
    );
    return undefined;
  }

  // ── Phase B: preparePasswordRules ─────────────────────────────────────
  @Step("prepare-password-rules")
  @Public()
  preparePasswordRules(@WorkflowParam("context") ctx: InviteWfCtx): undefined | Promise<undefined> {
    const policies = this.users.getTransferablePolicies();
    (ctx.password ??= {}).policies = policies;
    return undefined;
  }

  // ── Phase B: createPasswordForm ───────────────────────────────────────
  @Step("create-password-form")
  @Public()
  async createPasswordForm(@WorkflowParam("context") ctx: InviteWfCtx): Promise<unknown> {
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
    // SetPasswordForm `extends WithInlineConsentForm` — capture the dynamic
    // `consents: string[]` array inline. `processInlineConsent` is a no-op
    // when `ctx.consents.pending` is empty (default), so the call is safe
    // to make on every accept-tail invite run; unknown ids are silently
    // dropped per its SECURITY contract.
    this.processInlineConsent(ctx, input, wf);
    (ctx.completion ??= {}).passwordSet = true;
    return undefined;
  }

  // ── Phase B: forced MFA enrollment ────────────────────────────────────
  // Three @Step methods (pick / address / confirm) each call the matching
  // phase helper on `AuthWorkflowBase` directly — one step = one phase, no
  // internal routing-by-ctx-state. The schema's per-phase conditions ensure
  // only one fires per workflow tick. Three steps (vs one) is required
  // because the invite schema is linear; a single step couldn't pause between
  // phases.
  /**
   * Build the `MfaEnrollDeps` payload shared by all three invite enrollment
   * step bodies. Sets `ctx.mfaEnroll.mode` so `EnrollPickMethodForm` can hide
   * the `skip` action unless mode is `'optional'`. Omits `onComplete` because
   * invite's enrollment while-loop is gated on `!ctx.mfaEnroll?.done`
   * directly.
   */
  private buildInviteEnrollDeps(ctx: InviteWfCtx): MfaEnrollDeps {
    this.requireUsername(ctx);
    // `'disabled'` is filtered at each step's schema condition, so the cast is safe.
    const mode = (ctx.mfa?.mode ?? "optional") as "required" | "optional";
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
      transports: ctx.mfa?.availableTransports ?? [],
      pincodeLength: this.authOpts.mfa.pincodeLength,
      pincodeTtlMs: this.authOpts.mfa.pincodeTtlMs,
      pincodeResendTimeoutMs: this.authOpts.mfa.pincodeResendTimeoutMs,
      issuer: ctx.mfa?.issuer ?? this.authOpts.totpIssuer,
      mode,
    };
  }

  /**
   * Prepare MFA enrolment setup: writes `ctx.mfa.mode`,
   * `ctx.mfa.availableTransports`, and pre-picks `ctx.mfaEnroll.method` when
   * only one transport is available. Override to compute any of the three
   * from tenant policy / invitee role / request context in a single hook.
   * Return type allows a sync override (skip the promise round-trip) when no
   * async work is needed.
   *
   * `ctx.mfa` is guaranteed populated here — the `prepare-mfa` @Step runs
   * BEFORE `setup-mfa` in the schema and seeds `ctx.mfa = { issuer }`.
   */
  @Step("setup-mfa")
  @Public()
  inviteSetupMfa(@WorkflowParam("context") ctx: InviteWfCtx): undefined | Promise<undefined> {
    const mfa = ctx.mfa!;
    mfa.mode = "optional";
    mfa.availableTransports = ["sms", "email", "totp"];
    if (!ctx.mfaEnroll?.method && mfa.availableTransports.length === 1) {
      (ctx.mfaEnroll ??= {}).method = mfa.availableTransports[0];
    }
    return undefined;
  }

  /**
   * Forced MFA enrollment — Phase 1 (pick method). Auto-picks a single
   * transport, otherwise pauses for the picker form. When TOTP is picked, the
   * secret is provisioned in the same step body (see `enrollPickPhase`).
   */
  @Step("enroll-pick-method")
  @Public()
  inviteEnrollPickMethod(
    @WorkflowParam("context") ctx: InviteWfCtx,
  ): undefined | Promise<undefined> {
    return this.enrollPickPhase(this.buildInviteEnrollDeps(ctx));
  }

  /**
   * Forced MFA enrollment — Phase 2 (collect sms/email address + send
   * pincode). Gated out for totp by the schema condition.
   */
  @Step("enroll-address")
  @Public()
  inviteEnrollAddress(@WorkflowParam("context") ctx: InviteWfCtx): undefined | Promise<undefined> {
    return this.enrollAddressPhase(this.buildInviteEnrollDeps(ctx));
  }

  /**
   * Forced MFA enrollment — Phase 3 (verify code + activate method). Sets
   * `ctx.mfaEnroll.done` on success, which the schema's enrollment while-loop
   * reads as the exit signal directly.
   */
  @Step("enroll-confirm")
  @Public()
  inviteEnrollConfirm(@WorkflowParam("context") ctx: InviteWfCtx): undefined | Promise<undefined> {
    return this.enrollConfirmPhase(this.buildInviteEnrollDeps(ctx));
  }

  // ── Phase B: collectProfile ───────────────────────────────────────────
  @Step("collect-profile")
  @Public()
  async collectProfile(@WorkflowParam("context") ctx: InviteWfCtx): Promise<unknown> {
    const form = this.getProfileForm();
    if (!form) return undefined; // Defensive — condition gates on `acceptProfileFormPresent`.
    const wf = useAtscriptWf(form);
    // Consumer contract: the profile form supplied via `getProfileForm()`
    // MUST declare a `'skip'` action (phantom `ui.action` field annotated
    // `@ui.form.action 'skip', 'Skip'`) for this step to accept skip clicks.
    // Without the declaration, `wf.resolveAction()` rejects the action and
    // throws `StepRetriableError` — that is correct and fail-loud.
    if (wf.resolveAction() === "skip") {
      // 'skip' alt-action — record an empty profile and let `applyProfile` no-op.
      (ctx.accept ??= {}).profile = {};
      return undefined;
    }
    const input = wf.resolveInput({ partial: "deep" });
    (ctx.accept ??= {}).profile = input as Record<string, unknown>;
    return undefined;
  }

  // ── Phase B: applyProfile ─────────────────────────────────────────────
  @Step("apply-profile")
  @Public()
  async applyProfileStep(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    this.requireUsername(ctx);
    const c = (ctx.completion ??= {});
    const sanitized = stripReservedUserKeys(ctx.accept?.profile ?? {});
    if (Object.keys(sanitized).length === 0) {
      c.profileApplied = true;
      return undefined;
    }
    await this.applyProfile({ username: ctx.username, profile: sanitized });
    c.profileApplied = true;
    return undefined;
  }

  // ── Phase B: consumer extension point ──────────────────────────────────
  /**
   * Consumer extension point — override in your subclass to inject extra
   * accept-tail logic (input pauses, alt actions, persistence). Default:
   * no-op. Runs AFTER profile collection, BEFORE activation. Signature is
   * intentionally arg-less; read ctx + form input via composables
   * (`useWfState`, `useAtscriptWf`) in the override body.
   */
  @Step("extra-step")
  @Public()
  inviteExtraStep(): unknown {
    return undefined;
  }

  // ── Phase B: unsetPendingInvitation ───────────────────────────────────
  @Step("unset-pending-invitation")
  @Public()
  async unsetPendingInvitation(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    this.requireUsername(ctx);
    await this.users.update(ctx.username, {
      account: { pendingInvitation: false },
    } as Partial<UserCredentials>);
    (ctx.completion ??= {}).pendingInvitationCleared = true;
    return undefined;
  }

  // ── Phase B: activateUser ─────────────────────────────────────────────
  @Step("activate-user")
  @Public()
  async activateUser(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    this.requireUsername(ctx);
    await this.users.activateAccount(ctx.username);
    (ctx.completion ??= {}).activated = true;
    return undefined;
  }

  // ── Phase B: confirmation ─────────────────────────────────────────────
  @Step("confirmation")
  @Public()
  confirmation(@WorkflowParam("context") ctx: InviteWfCtx): undefined | Promise<undefined> {
    (ctx.completion ??= {}).confirmationShown = true;
    // The auto-login terminal (`auto-login-finish`) merges this envelope's
    // `message` into its own data response so the SPA still surfaces the
    // configured confirmation text alongside the tokens (WF-INVITE-020). The
    // `freshLoginFinish` terminal still overwrites with an immediate redirect
    // — there's no SPA surface to paint the message before the redirect
    // fires, so that branch intentionally drops it.
    finishWf({
      data: { confirmed: true },
      message: { level: "success", text: ctx.accept!.confirmationMessage! },
    });
    return undefined;
  }

  // ── Phase B: freshLoginFinish ─────────────────────────────────────────
  @Step("fresh-login-finish")
  @Public()
  freshLoginFinish(@WorkflowParam("context") ctx: InviteWfCtx): undefined | Promise<undefined> {
    finishWf({
      next: {
        trigger: "immediate",
        action: {
          type: "redirect",
          target: ctx.accept!.loginUrl!,
          reason: "fresh-login-required",
        },
      },
    });
    return undefined;
  }

  // ── Phase B: autoLoginFinish ──────────────────────────────────────────
  @Step("auto-login-finish")
  @Public()
  async autoLoginFinish(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    this.requireUsername(ctx);
    const issue = await this.auth.issue(ctx.username);
    (ctx.completion ??= {}).tokensIssued = true;
    const auth = useAuth();
    // Preserve a `message` set by an earlier terminal (typically
    // `confirmation` when `accept.showConfirmation` is on) so the SPA
    // can paint the configured confirmation text alongside the tokens.
    // Additive only — when nothing set a message we emit the envelope as
    // before. See WF-INVITE-020.
    const previousMessage = (useWfFinished().get()?.value as WfFinished | undefined)?.message;
    // Raw `useWfFinished` path: cookies are wooks-level, helpers don't expose them.
    const envelope: WfFinished = {
      finished: true,
      data: auth.buildLoginResponse(ctx.username, issue),
      ...(previousMessage && { message: previousMessage }),
    };
    useWfFinished().set({
      type: "data",
      value: envelope,
      cookies: auth.buildFinishedCookies(issue),
    });
    return undefined;
  }

  // ── Helpers ───────────────────────────────────────────────────────────
  private async loadUserOrNull(username: string): Promise<UserCredentials | null> {
    try {
      return await this.users.getUser(username);
    } catch (err) {
      if (err instanceof UserAuthError && err.type === "NOT_FOUND") return null;
      throw err;
    }
  }
}
