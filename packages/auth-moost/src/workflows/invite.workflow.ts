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
import { Controller } from "moost";

import { AuthOpts } from "../auth.opts";
import { type ConsentDescriptor, ConsentStore } from "../consent.store";
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

export interface InviteWfCtx extends AuthWfCtxBase {
  // Resolved policy (populated by prepare-* steps; reads via resolveXxx() getters):
  adminForm?: { collectRoles: boolean };
  accept?: {
    alreadyAcceptedRedirectUrl: string;
    freshLoginRequired: boolean;
    loginUrl: string;
    showConfirmation: boolean;
    confirmationMessage: string;
  };
  mfa?: { issuer: string };

  /** Boolean projection of `this.getProfileForm() !== undefined` — schema gates on it. */
  acceptProfileFormPresent?: boolean;

  // ── Admin-side (Phase A) ────────────────────────────────────────────────
  /**
   * Populated by `prepare-available-roles` when the override returns a list.
   * Surfaced into the `InviteForm` via `@wf.context.pass 'availableRoles'` so
   * the role multi-select renders the whitelisted choices; also used by
   * `admin-form` to reject admin-submitted roles outside the list.
   */
  availableRoles?: string[];
  roles?: string[];
  /**
   * Extras dict prepared by `build-user-extras` (calls `prepareUser`) and
   * consumed by `create-user` to populate the user-row fields beyond the
   * base credential shape. Split apart so consumers can inject e.g. a
   * tenant-validation step between extras-build and create-user without
   * copying either body.
   */
  userExtras?: Record<string, unknown>;
  /** Marks that `send-email` already emitted the outlet — resume → advance. */
  linkSent?: boolean;

  // ── User-side (Phase B) ─────────────────────────────────────────────────
  /** Detected at `check-pending-invitation`; triggers `idempotent-redirect`. */
  alreadyAccepted?: boolean;
  passwordSet?: boolean;
  /**
   * MFA policy (set by `inviteSetupMfa` setter — overridable per consumer).
   *   - `'required'` — invitee MUST enroll a second factor BEFORE activation.
   *   - `'optional'` — invitee is prompted but may `skip` the enrollment form.
   *   - `'disabled'` — enrollment loop is skipped entirely.
   */
  mfaMode?: "required" | "optional" | "disabled";
  /** Available MFA transports (set by `inviteSetupMfa` setter — overridable per consumer). */
  availableMfaTransports?: Array<"sms" | "email" | "totp">;
  /** Raw input from `collect-profile`. */
  profile?: Record<string, unknown>;
  profileApplied?: boolean;
  pendingInvitationCleared?: boolean;
  activated?: boolean;
  confirmationShown?: boolean;

  // ── Flat aliases (compat) — removed in B1.4 once forms.as migrates to nested ──
  // Each one mirrors a `ctx.<group>.<field>` on `AuthWfCtxBase` via dual-write
  // in the step bodies below; kept here for forms.as `@wf.context.pass 'flatKey'`
  // compat. Type-safe consumers should read the nested form.
  /** Flat alias for `ctx.mfaEnroll.method`. */
  enrollMethod?: "sms" | "email" | "totp";
  /** Flat alias for `ctx.mfaEnroll.address`. */
  enrollAddress?: string;
  /** Flat alias for `ctx.mfaEnroll.secret`. */
  enrollSecret?: string;
  /** Flat alias for `ctx.mfaEnroll.uri`. */
  enrollUri?: string;
  /** Flat alias for `ctx.mfaEnroll.availableTransports`. */
  enrollAvailableTransports?: Array<"sms" | "email" | "totp">;
  /** Flat alias for `ctx.mfaEnroll.mode`. */
  enrollMode?: "required" | "optional";
  /** Flat alias for `ctx.mfaEnroll.done`. */
  enrollDone?: boolean;
  /** Flat alias for `ctx.mfaEnroll.pincodeCooldown`. */
  enrollPincodeCooldown?: number;
  /** Flat alias for `ctx.pincode.sentTo`. */
  pinSentTo?: string;
  /** Flat alias for `ctx.consents.pending`. */
  pendingConsents?: ConsentDescriptor[];
  /** Flat alias for `ctx.consents.accepted`. */
  acceptedConsentIds?: string[];
  /** Flat alias for `ctx.consents.decidedAt`. */
  consentsDecidedAt?: number;
  /** Flat alias for `ctx.consents.persisted`. */
  consentsPersisted?: boolean;
  /** Flat alias for `ctx.completion.tokensIssued`. */
  tokensIssued?: boolean;
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
 * Phase-B steps (post `ctx.linkSent`, accept tail) are method-level
 * `@Public()` because they fire on the anonymous magic-link resume.
 * `send-email` is the boundary: also `@Public()` because the @prostojs/wf
 * runtime re-enters the saved step on resume (the loop restarts at
 * `indexes[level]`, not after it). Its body is idempotent via
 * `if (ctx.linkSent) return`.
 */
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
   * `ctx.availableRoles` so the UI renders a multi-select AND the
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
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.accept = resolved;
        return undefined;
      });
    }
    ctx.accept = result;
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

  /**
   * Populate `ctx.pendingConsents` with the customer-defined general-consent
   * descriptors (terms, marketing, jurisdiction, ...) the invitee still needs
   * to accept. Phase 4 transport only — nothing reads `ctx.pendingConsents`
   * yet; Phase 5 will migrate the carrier `SetPasswordForm` from the
   * `WithInlineConsentForm` static-checkbox mixin onto this dynamic array.
   *
   * Username MUST be bound before we fetch consents — schema places this step
   * AFTER `check-pending-invitation` (which sets `ctx.username` from the
   * pending-invite row) inside the `linkSent` accept-tail subflow, so the
   * `if (!ctx.username)` guard is belt-and-brace. `@Public()` is required
   * because this step fires on the anonymous magic-link resume side of the
   * workflow.
   */
  @Step("prepare-consents")
  @Public()
  prepareConsents(@WorkflowParam("context") ctx: InviteWfCtx): undefined | Promise<undefined> {
    if (!ctx.username) return undefined;
    const result = this.consentStore.getPendingConsents(ctx.username, {
      workflow: "auth/invite/start",
    });
    // dual-write — flat alias removed in B1.4
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.pendingConsents = resolved;
        (ctx.consents ??= {}).pending = resolved;
        return undefined;
      });
    }
    ctx.pendingConsents = result;
    (ctx.consents ??= {}).pending = result;
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
      condition: (ctx) => !!(ctx.email && !ctx.username && !ctx.userExtras),
    },
    {
      id: "create-user",
      condition: (ctx) => !!(ctx.email && !ctx.username && !!ctx.userExtras),
    },
    {
      id: "send-email",
      condition: (ctx) => !!ctx.username,
    },
    // ── Phase B (accept tail): runs only after the magic link resumes here.
    // `ctx.linkSent` flips ONCE in `send-email` and stays true — safe to
    // hoist as a subflow condition (evaluated once when the engine reaches
    // the subflow).
    {
      condition: (ctx) => !!ctx.linkSent,
      steps: [
        // Resolve accept + mfa policies on the anonymous resume side — the
        // admin-side `prepare-*` runs (above) don't survive across the
        // magic-link boundary in all cases; re-resolve here so accept-tail
        // step bodies + schema conditions read populated ctx slots.
        { id: "prepare-accept" },
        { id: "check-pending-invitation" },
        {
          id: "idempotent-redirect",
          condition: (ctx) => !!ctx.alreadyAccepted,
        },
        { id: "prepare-password-rules" },
        ...consentsPreludeSchema,
        {
          id: "create-password-form",
          condition: (ctx) => !ctx.passwordSet,
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
          // (which clears `enrollMethod` via `cleanupEnrollment`) causes the schema
          // to re-evaluate from the picker instead of falling through to
          // activation with no method enrolled. Mirrors login's MFA loop. Loop
          // exits when `enrollDone` flips true (Phase-3 confirm OR user-skip in
          // optional mode). `passwordSet` + `mode !== 'disabled'` live on the
          // while-gate so each inner step condition only checks the ctx fields
          // that distinguish ITS phase.
          while: (ctx) => !!(ctx.passwordSet && ctx.mfaMode !== "disabled" && !ctx.enrollDone),
          steps: [
            {
              id: "enroll-pick-method",
              condition: (ctx) =>
                !!((ctx.availableMfaTransports?.length ?? 0) > 1 && !ctx.enrollMethod),
            },
            {
              id: "enroll-address",
              condition: (ctx) =>
                !!(
                  ctx.enrollMethod &&
                  (ctx.enrollMethod === "sms" || ctx.enrollMethod === "email") &&
                  !ctx.enrollAddress
                ),
            },
            {
              id: "enroll-confirm",
              condition: (ctx) =>
                !!(ctx.enrollMethod && (ctx.enrollMethod === "totp" || !!ctx.enrollAddress)),
            },
          ],
        },
        {
          id: "collect-profile",
          condition: (ctx) => !!(ctx.passwordSet && ctx.acceptProfileFormPresent && !ctx.profile),
        },
        {
          id: "apply-profile",
          condition: (ctx) =>
            !!(
              ctx.passwordSet &&
              ctx.acceptProfileFormPresent &&
              ctx.profile &&
              !ctx.profileApplied
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
          condition: (ctx) => !!(ctx.passwordSet && !ctx.pendingInvitationCleared),
        },
        {
          id: "activate-user",
          condition: (ctx) => !!(ctx.pendingInvitationCleared && !ctx.activated),
        },
        {
          id: "confirmation",
          condition: (ctx) =>
            !!(ctx.activated && ctx.accept?.showConfirmation && !ctx.confirmationShown),
        },
        {
          id: "fresh-login-finish",
          condition: (ctx) => !!(ctx.activated && ctx.accept?.freshLoginRequired),
        },
        {
          id: "auto-login-finish",
          condition: (ctx) =>
            !!(ctx.activated && !ctx.accept?.freshLoginRequired && !ctx.tokensIssued),
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
    ctx.acceptProfileFormPresent = this.getProfileForm() !== undefined;
    return undefined;
  }

  // ── Phase A: prepareAvailableRoles ────────────────────────────────────
  @Step("prepare-available-roles")
  async prepareAvailableRoles(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    const roles = await this.getAvailableRoles();
    if (roles) ctx.availableRoles = roles;
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
    // list (surfaced as `ctx.availableRoles` by `prepare-available-roles`),
    // reject any admin-submitted role outside the whitelist. Skipped when no
    // whitelist is configured — see `getAvailableRoles` doc.
    if (Array.isArray(ctx.availableRoles)) {
      const allowed = new Set(ctx.availableRoles);
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
    if (parsed.length > 0) ctx.roles = parsed;
    return undefined;
  }

  // ── Phase A: inferRolesStep ───────────────────────────────────────────
  @Step("infer-roles")
  async inferRolesStep(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    if (!ctx.email) return undefined;
    const inferred = await this.inferRoles({ email: ctx.email });
    if (inferred.length === 0) return undefined;
    const merged = new Set<string>([...(ctx.roles ?? []), ...inferred]);
    ctx.roles = Array.from(merged);
    return undefined;
  }

  // ── Phase A: buildUserExtras ──────────────────────────────────────────
  /**
   * Build the extras dict that `create-user` merges into the new user
   * row. Calls `prepareUser({email, roles, invitedBy})` and writes the
   * result onto `ctx.userExtras`.
   */
  @Step("build-user-extras")
  async buildUserExtras(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    if (!ctx.email) throw new HttpError(500, "Workflow state corrupted: missing email");

    const invitedBy = useAuth().getAuthContext()?.userId;
    const preparedInput: PreparedUserInput = {
      email: ctx.email,
      roles: ctx.roles ?? [],
      ...(invitedBy && { invitedBy }),
    };

    ctx.userExtras = await this.prepareUser(preparedInput);
    return undefined;
  }

  // ── Phase A: createUser ───────────────────────────────────────────────
  /**
   * Create the user row from `ctx.userExtras` (plus the admin-supplied
   * `ctx.roles`), translate store-level CONFLICT into HTTP 409, then stamp
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
    const fields: Record<string, unknown> = {
      ...ctx.userExtras,
      ...(ctx.roles && ctx.roles.length > 0 && { roles: ctx.roles }),
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
    if (ctx.linkSent) return undefined;
    ctx.linkSent = true;
    return {
      ...outletEmail(ctx.email as string, "invite.magicLink", {
        username: ctx.username,
        // userId travels in the outlet context so `buildMagicLinkUrl` can embed
        // `&uid=…` in the URL. The SPA uses it to fall through to the
        // post-redemption side route when a second click hits a 410. In this
        // workflow `username` IS the user-id (see `autoLoginFinish` → `auth.issue(ctx.username)`).
        ...(ctx.username && { userId: ctx.username }),
        ...(ctx.roles && { roles: ctx.roles }),
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
      ctx.alreadyAccepted = true;
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
        loginUrl: ctx.accept!.loginUrl,
        alreadyAcceptedRedirectUrl: ctx.accept!.alreadyAcceptedRedirectUrl,
      }),
    );
    return undefined;
  }

  // ── Phase B: preparePasswordRules ─────────────────────────────────────
  @Step("prepare-password-rules")
  @Public()
  preparePasswordRules(@WorkflowParam("context") ctx: InviteWfCtx): undefined | Promise<undefined> {
    const policies = this.users.getTransferablePolicies();
    // dual-write — flat alias removed in B1.4
    (ctx as Record<string, unknown>).passwordPolicies = policies;
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
    // when `ctx.pendingConsents` is empty (default), so the call is safe to
    // make on every accept-tail invite run; unknown ids are silently dropped
    // per its SECURITY contract.
    this.processInlineConsent(ctx, input, wf);
    // dual-write — flat alias removed in B1.4
    if (ctx.acceptedConsentIds !== undefined) {
      (ctx.consents ??= {}).accepted = ctx.acceptedConsentIds;
    }
    if (ctx.consentsDecidedAt !== undefined) {
      (ctx.consents ??= {}).decidedAt = ctx.consentsDecidedAt;
    }
    ctx.passwordSet = true;
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
   * step bodies. Sets `ctx.enrollMode` (mirrored onto ctx so
   * `EnrollPickMethodForm` can hide the `skip` action unless mode is
   * `'optional'`). Omits `onComplete` because invite's enrollment while-loop
   * is gated on `!enrollDone` directly — no mirror needed.
   */
  private buildInviteEnrollDeps(ctx: InviteWfCtx): MfaEnrollDeps {
    this.requireUsername(ctx);
    // `'disabled'` is filtered at each step's schema condition, so the cast is safe.
    const mode = (ctx.mfaMode ?? "optional") as "required" | "optional";
    // dual-write — flat alias removed in B1.4
    ctx.enrollMode = mode;
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
      issuer: ctx.mfa?.issuer ?? this.authOpts.totpIssuer,
      mode,
    };
  }

  /**
   * Prepare MFA enrolment setup: writes `ctx.mfaMode`,
   * `ctx.availableMfaTransports`, and pre-picks `ctx.enrollMethod` when only
   * one transport is available. Override to compute any of the three from
   * tenant policy / invitee role / request context in a single hook. Return
   * type allows a sync override (skip the promise round-trip) when no async
   * work is needed.
   */
  @Step("setup-mfa")
  @Public()
  inviteSetupMfa(@WorkflowParam("context") ctx: InviteWfCtx): undefined | Promise<undefined> {
    ctx.mfaMode = "optional";
    ctx.availableMfaTransports = ["sms", "email", "totp"];
    if (!ctx.enrollMethod && ctx.availableMfaTransports.length === 1) {
      // dual-write — flat alias removed in B1.4
      ctx.enrollMethod = ctx.availableMfaTransports[0];
      (ctx.mfaEnroll ??= {}).method = ctx.enrollMethod;
    }
    return undefined;
  }

  /**
   * Mirror flat `enroll*` / `pinSentTo` fields written by the
   * `enrollPickPhase` / `enrollAddressPhase` / `enrollConfirmPhase` helpers
   * (which still write the OLD flat shape) into the nested
   * `ctx.mfaEnroll` / `ctx.pincode` groups so `@wf.context.pass 'mfaEnroll'`
   * / `'pincode'` consumers can read the same data nested.
   *
   * dual-write — flat alias removed in B1.4
   */
  private mirrorEnrollFlatToNested(ctx: InviteWfCtx): void {
    const m = (ctx.mfaEnroll ??= {});
    if (ctx.enrollMethod !== undefined) m.method = ctx.enrollMethod;
    else delete m.method;
    if (ctx.enrollAddress !== undefined) m.address = ctx.enrollAddress;
    else delete m.address;
    if (ctx.enrollSecret !== undefined) m.secret = ctx.enrollSecret;
    else delete m.secret;
    if (ctx.enrollUri !== undefined) m.uri = ctx.enrollUri;
    else delete m.uri;
    if (ctx.enrollAvailableTransports !== undefined)
      m.availableTransports = ctx.enrollAvailableTransports;
    if (ctx.enrollDone !== undefined) m.done = ctx.enrollDone;
    if (ctx.enrollPincodeCooldown !== undefined) m.pincodeCooldown = ctx.enrollPincodeCooldown;
    else delete m.pincodeCooldown;
    if (ctx.pinSentTo !== undefined) (ctx.pincode ??= {}).sentTo = ctx.pinSentTo;
    else if (ctx.pincode) delete ctx.pincode.sentTo;
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
    const result = this.enrollPickPhase(this.buildInviteEnrollDeps(ctx));
    if (result instanceof Promise) {
      return result.then(() => {
        this.mirrorEnrollFlatToNested(ctx);
        return undefined;
      });
    }
    this.mirrorEnrollFlatToNested(ctx);
    return undefined;
  }

  /**
   * Forced MFA enrollment — Phase 2 (collect sms/email address + send
   * pincode). Gated out for totp by the schema condition.
   */
  @Step("enroll-address")
  @Public()
  inviteEnrollAddress(@WorkflowParam("context") ctx: InviteWfCtx): undefined | Promise<undefined> {
    return this.enrollAddressPhase(this.buildInviteEnrollDeps(ctx)).then(() => {
      this.mirrorEnrollFlatToNested(ctx);
      return undefined;
    });
  }

  /**
   * Forced MFA enrollment — Phase 3 (verify code + activate method). Sets
   * `enrollDone` on success, which the schema's enrollment while-loop reads
   * as the exit signal directly.
   */
  @Step("enroll-confirm")
  @Public()
  inviteEnrollConfirm(@WorkflowParam("context") ctx: InviteWfCtx): undefined | Promise<undefined> {
    return this.enrollConfirmPhase(this.buildInviteEnrollDeps(ctx)).then(() => {
      this.mirrorEnrollFlatToNested(ctx);
      return undefined;
    });
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
      ctx.profile = {};
      return undefined;
    }
    const input = wf.resolveInput({ partial: "deep" });
    ctx.profile = input as Record<string, unknown>;
    return undefined;
  }

  // ── Phase B: applyProfile ─────────────────────────────────────────────
  @Step("apply-profile")
  @Public()
  async applyProfileStep(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    this.requireUsername(ctx);
    const sanitized = stripReservedUserKeys(ctx.profile ?? {});
    if (Object.keys(sanitized).length === 0) {
      ctx.profileApplied = true;
      return undefined;
    }
    await this.applyProfile({ username: ctx.username, profile: sanitized });
    ctx.profileApplied = true;
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

  // ── Phase B: persist-consents ─────────────────────────────────────────
  /**
   * Batched consent persistence — delegates to
   * `AuthWorkflowBase.runPersistConsents`. See that helper for the full
   * audit-friendly-default / idempotency / silent-drop contract.
   */
  @Step("persist-consents")
  @Public()
  persistConsentsStep(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    return this.runPersistConsents(ctx, this.consentStore).then(() => {
      // dual-write — flat alias removed in B1.4
      if (ctx.consentsPersisted !== undefined) {
        (ctx.consents ??= {}).persisted = ctx.consentsPersisted;
      }
      return undefined;
    });
  }

  // ── Phase B: unsetPendingInvitation ───────────────────────────────────
  @Step("unset-pending-invitation")
  @Public()
  async unsetPendingInvitation(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    this.requireUsername(ctx);
    await this.users.update(ctx.username, {
      account: { pendingInvitation: false },
    } as Partial<UserCredentials>);
    ctx.pendingInvitationCleared = true;
    return undefined;
  }

  // ── Phase B: activateUser ─────────────────────────────────────────────
  @Step("activate-user")
  @Public()
  async activateUser(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    this.requireUsername(ctx);
    await this.users.activateAccount(ctx.username);
    ctx.activated = true;
    return undefined;
  }

  // ── Phase B: confirmation ─────────────────────────────────────────────
  @Step("confirmation")
  @Public()
  confirmation(@WorkflowParam("context") ctx: InviteWfCtx): undefined | Promise<undefined> {
    ctx.confirmationShown = true;
    // The auto-login terminal (`auto-login-finish`) merges this envelope's
    // `message` into its own data response so the SPA still surfaces the
    // configured confirmation text alongside the tokens (WF-INVITE-020). The
    // `freshLoginFinish` terminal still overwrites with an immediate redirect
    // — there's no SPA surface to paint the message before the redirect
    // fires, so that branch intentionally drops it.
    finishWf({
      data: { confirmed: true },
      message: { level: "success", text: ctx.accept!.confirmationMessage },
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
          target: ctx.accept!.loginUrl,
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
    // dual-write — flat alias removed in B1.4
    ctx.tokensIssued = true;
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
