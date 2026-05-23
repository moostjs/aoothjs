/**
 * InviteWorkflow — registers three workflow ids:
 *
 *   - `auth.invite`       — admin invites a new user → user accepts (full flow)
 *   - `auth.reInvite`     — admin resends to an existing `pendingInvitation` user
 *   - `auth.cancelInvite` — admin hard-deletes a pending invite (gated by
 *                           `opts.cancellation.allowed`)
 *
 * Full step catalog per `WF_INVITE.md`. Step IDs are workflow-scoped (all
 * prefixed `invite*`) because `@moostjs/event-wf` registers `@Step('id')`
 * globally — identical IDs across login/recovery/invite would silently
 * collide and overwrite handlers. The accept tail (`inviteCheckPending…`
 * through `inviteAutoLoginFinish`) is shared between `auth.invite` and
 * `auth.reInvite` schemas by re-referencing the same step IDs.
 *
 * **Step routing model.** Same shape as `RecoveryWorkflow`: alt-action
 * handlers run BEFORE form validation so `cancel` works without filling
 * fields, then return the `ALT_HANDLED` sentinel after short-circuiting via
 * `useWfFinished().set(...)`. Actions are read via
 * `useAtscriptWf(form).resolveAction()` — the form's static `@ui.form.action`
 * whitelist validates the action id; unknown ids throw `StepRetriableError`
 * before the step body runs. Terminal steps gate on `!ctx.aborted` so the
 * abort response stays.
 *
 * **Consumer subclass pattern (Phase 4 reshape).** Consumers subclass
 * `InviteWorkflow` to override `protected` hook methods. The subclass MUST
 * re-apply `@Inherit() @Injectable('FOR_EVENT') @Controller()` and re-declare
 * the constructor signature (TS emits fresh design-paramtypes per class).
 *
 * **Side-effect deps as protected methods.** Sender/store/emitter DI
 * providers have been DROPPED from the constructor. Hooks live as `protected`
 * methods consumers override:
 *
 *   - `deliver(payload)` — unified email + SMS dispatch (see `DeliverPayload`).
 *     Default throws; override to wire your senders. The default invite send
 *     uses `outletEmail` (handled by `createAuthEmailOutlet` at the trigger
 *     route) so `deliver()` is only invoked if a consumer's accept-tail steps
 *     drive a manual send. Kept exposed for parity with login/recovery and to
 *     give consumer subclasses a single override seam for future SMS-invite
 *     work.
 *   - `audit(event)` — fire audit events. Default: no-op.
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
import {
  abortWf,
  finishWf,
  type FinishWfOpts,
  useAtscriptWf,
  type WfFinished,
} from "@atscript/moost-wf";
import { HttpError } from "@moostjs/event-http";
import {
  outlet,
  outletEmail,
  Step,
  useWfFinished,
  Workflow,
  WorkflowParam,
  WorkflowSchema,
} from "@moostjs/event-wf";
import { Controller, Injectable } from "moost";

import type { AuditEvent } from "../audit/index";
import { useAuth } from "../auth.composables";
import { Public } from "../auth.decorator";
import {
  type DuplicateAction,
  type InviteWorkflowOpts,
  mergeInviteOpts,
  type PreparedUserInput,
  type ResolvedInviteWorkflowOpts,
} from "./invite.workflow.options";
import { AuthWorkflowBase, stripReservedUserKeys } from "./auth-workflow.base";
import type { DeliverPayload } from "./login.workflow";

export interface InviteWfCtx {
  opts?: ResolvedInviteWorkflowOpts;
  /** Boolean projection of `this.getProfileForm() !== undefined` — schema gates on it. */
  acceptProfileFormPresent?: boolean;

  // ── Admin-side (Phase A) ────────────────────────────────────────────────
  /**
   * Populated by `invitePrepareAvailableRoles` when the override returns a list.
   * Surfaced into the `InviteForm` via `@wf.context.pass 'availableRoles'` so
   * the role multi-select renders the whitelisted choices; also used by
   * `inviteAdminInviteForm` to reject admin-submitted roles outside the list.
   */
  availableRoles?: string[];
  email?: string;
  /** Typically same as `email`; consumers can override the mapping. */
  username?: string;
  firstName?: string;
  lastName?: string;
  roles?: string[];
  /** Populated by `inviteSelectSendMode` (when `send.mode === 'choice'`). */
  selectedSendMode?: "email" | "shareableLink";
  /** Resolved send mode the workflow committed to (set in `inviteInit` or `inviteSelectSendMode`). */
  resolvedSendMode?: "email" | "shareableLink";
  /** Populated by `inviteReturnShareableLink` so the admin's UI can display it. */
  shareableLinkUrl?: string;
  /** Marks that `inviteSendInviteEmail` already emitted the outlet — resume → advance. */
  linkSent?: boolean;

  // ── User-side (Phase B) ─────────────────────────────────────────────────
  /** Detected at `inviteCheckPendingInvitation`; triggers `inviteIdempotentRedirect`. */
  alreadyAccepted?: boolean;
  passwordSet?: boolean;
  // MFA enrollment state (mirrors LoginWfCtx fields used by the shared
  // `AuthWorkflowBase.runMfaEnrollment` helper).
  enrollMethod?: "sms" | "email" | "totp";
  enrollAddress?: string;
  enrollSecret?: string;
  enrollUri?: string;
  enrollAvailableTransports?: Array<"sms" | "email" | "totp">;
  /**
   * Mirror of `opts.mfa.mode` (only set when not `'disabled'`). Surfaced to
   * `EnrollPickMethodForm` via `@wf.context.pass` so the `skip` action can
   * hide unless mode is `'optional'`.
   */
  enrollMode?: "required" | "optional";
  enrollDone?: boolean;
  /** Pincode scratch shared with the enrollment helper. */
  pin?: string;
  pinExpire?: number;
  pinSentTo?: string;
  /** Raw input from `inviteCollectProfile`. */
  profile?: Record<string, unknown>;
  profileApplied?: boolean;
  pendingInvitationCleared?: boolean;
  activated?: boolean;
  confirmationShown?: boolean;
  tokensIssued?: boolean;

  /** Set true by abort alt-actions (`cancel`). Gates all terminal steps. */
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
 * (`audit()` no-op) protected methods that consumers override. Rate-limit is
 * gone from the workflow entirely, so the only thing left to assert is that
 * the resolved opts shape itself is internally consistent. Currently no
 * cross-field invariants survive — the function stays for symmetry with
 * `LoginWorkflow` / `RecoveryWorkflow` and to give future opts somewhere to
 * land their checks without re-plumbing the ctor.
 */
function validateOpts(_opts: ResolvedInviteWorkflowOpts): void {
  // No cross-field invariants today.
}

/** Audit `kind` → `wfid` reverse map. Default falls through to `auth.invite`. */
const AUDIT_WORKFLOW_BY_KIND: Record<string, string> = {
  "invite.cancelled": "auth.cancelInvite",
  "invite.resent": "auth.reInvite",
};

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
 * envelope. Used by both `inviteIdempotentRedirect` (in-workflow) and by
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
 * `allow('auth.invite', 'start')`.
 *
 * The three `@Workflow` body methods (`inviteFlow` / `reInviteFlow` /
 * `cancelInviteFlow`) are `@Public()` because the wf adapter dispatches the
 * flow body on EVERY `start()` / `resume()` call — gating it would 401 the
 * anonymous magic-link resume before any step runs. The real gate is the
 * step methods themselves, which the wf runtime invokes through the same
 * interceptor chain.
 *
 * Phase-B steps (post `ctx.linkSent`, accept tail) are method-level
 * `@Public()` because they fire on the anonymous magic-link resume.
 * `inviteSendInviteEmail` / `inviteReturnShareableLink` are the boundary:
 * also `@Public()` because the @prostojs/wf runtime re-enters the saved step
 * on resume (the loop restarts at `indexes[level]`, not after it). Their
 * bodies are idempotent via `if (ctx.linkSent) return`.
 *
 * `auth.reInvite` / `auth.cancelInvite` are admin-only end-to-end (admin
 * confirms in their own UI; no anonymous boundary), so their phase-A steps
 * stay class-gated under the same `auth.invite` / `start` grant.
 */
@ArbacResource("auth.invite")
@ArbacAction("start")
@Injectable("FOR_EVENT")
@Controller()
export class InviteWorkflow extends AuthWorkflowBase {
  protected readonly opts: ResolvedInviteWorkflowOpts;
  protected readonly users: UserService;
  protected readonly auth: AuthCredential;

  constructor(opts: InviteWorkflowOpts, users: UserService, auth: AuthCredential) {
    super();
    this.opts = mergeInviteOpts(opts);
    this.users = users;
    this.auth = auth;
    validateOpts(this.opts);
  }

  // ── Protected extension surface ───────────────────────────────────────
  /**
   * Dispatch an email or SMS event. Default throws — the default invite send
   * uses `outletEmail` (handled by `createAuthEmailOutlet`) so this method is
   * only invoked when a consumer's accept-tail steps drive a manual send.
   * Override to wire your senders.
   */
  protected async deliver(_payload: DeliverPayload): Promise<void> {
    throw new Error(
      "InviteWorkflow.deliver() not configured — override to wire your email/sms sender",
    );
  }

  /**
   * Emit an audit event. Default: no-op. Consumers override to fan out to
   * their audit sink.
   */
  protected async audit(_event: AuditEvent): Promise<void> {
    // No-op default.
  }

  /**
   * Build the extras dictionary merged into the freshly-created user row in
   * `invitePreCreateUser`. Default: `{}`. Override to populate e.g. a
   * required `tenantId`. This is the ONLY seam through which the admin form's
   * `firstName` / `lastName` reach persistence — map them into your schema's
   * own columns (e.g. `displayName`) and return them here.
   */
  protected async prepareUser(_input: PreparedUserInput): Promise<Record<string, unknown>> {
    return {};
  }

  /**
   * Return the list of selectable role identifiers for the admin invite form.
   * When defined AND `adminForm.collectRoles` is true → form ships
   * `ctx.availableRoles` so the UI renders a multi-select AND the
   * `inviteAdminInviteForm` step rejects admin-submitted roles outside the
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
  protected async inferRoles(_input: {
    email: string;
    firstName?: string;
    lastName?: string;
  }): Promise<string[]> {
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
   * Override the structural duplicate rule for `inviteAdminInviteForm`.
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
   * `inviteCollectProfile` step. `undefined` (default) skips the step
   * entirely (just password collection).
   */
  protected getProfileForm(): TAtscriptAnnotatedType | undefined {
    return undefined;
  }

  /**
   * Returns the JSON-safe projection of `opts` stashed onto `ctx` for schema
   * conditions to read. Default: drop `forms` (atscript classes aren't plain
   * JSON) so `AsWfStore` persistence doesn't choke; step bodies still read
   * form classes via `this.opts.forms.*`. Override to strip any extra
   * non-JSON values you've added to the opts type.
   */
  protected snapshotOpts(opts: ResolvedInviteWorkflowOpts): ResolvedInviteWorkflowOpts {
    const { forms: _forms, ...rest } = opts;
    return rest as ResolvedInviteWorkflowOpts;
  }

  // ╔═══════════════════════════════════════════════════════════════════════╗
  // ║ Workflow definitions                                                  ║
  // ╚═══════════════════════════════════════════════════════════════════════╝

  @Workflow("auth.invite")
  @WorkflowSchema<InviteWfCtx>([
    { id: "inviteInit" },
    {
      id: "invitePrepareAvailableRoles",
      condition: (ctx) => ctx.opts!.adminForm.collectRoles && !ctx.aborted,
    },
    {
      id: "inviteSelectSendMode",
      condition: (ctx) => ctx.opts!.send.mode === "choice" && !ctx.resolvedSendMode && !ctx.aborted,
    },
    { id: "inviteAdminInviteForm", condition: (ctx) => !ctx.email && !ctx.aborted },
    {
      id: "inviteInferRolesStep",
      condition: (ctx) => !!(ctx.email && !ctx.aborted),
    },
    {
      id: "invitePreCreateUser",
      condition: (ctx) => !!(ctx.email && !ctx.username && !ctx.aborted),
    },
    {
      id: "inviteSendInviteEmail",
      condition: (ctx) => !!(ctx.username && ctx.resolvedSendMode === "email" && !ctx.aborted),
    },
    {
      id: "inviteReturnShareableLink",
      condition: (ctx) =>
        !!(ctx.username && ctx.resolvedSendMode === "shareableLink" && !ctx.aborted),
    },
    // ── Phase B (accept tail): runs only after the magic link resumes here.
    {
      id: "inviteCheckPendingInvitation",
      condition: (ctx) => !!(ctx.linkSent && !ctx.aborted),
    },
    {
      id: "inviteIdempotentRedirect",
      condition: (ctx) => !!(ctx.alreadyAccepted && !ctx.aborted),
    },
    {
      id: "invitePreparePasswordRules",
      condition: (ctx) => !!(ctx.linkSent && !ctx.alreadyAccepted && !ctx.aborted),
    },
    {
      id: "inviteCreatePasswordForm",
      condition: (ctx) =>
        !!(ctx.linkSent && !ctx.alreadyAccepted && !ctx.passwordSet && !ctx.aborted),
    },
    // ── Forced MFA enrollment (3 entries — one per phase, since the invite
    // schema is linear and can't loop a single step like login does). The
    // shared `runMfaEnrollment` helper routes internally based on ctx state.
    {
      // `!ctx.enrollDone` is critical when `mfa.mode === 'optional'`: after a
      // user clicks `skip` in Phase 1, the helper sets `enrollDone` without
      // setting `enrollMethod`. Without this gate the schema would re-enter
      // the pick form forever.
      id: "inviteEnrollPickMethod",
      condition: (ctx) =>
        !!(
          ctx.passwordSet &&
          ctx.opts!.mfa.mode !== "disabled" &&
          !ctx.enrollMethod &&
          !ctx.enrollDone &&
          !ctx.aborted
        ),
    },
    {
      id: "inviteEnrollAddress",
      condition: (ctx) =>
        !!(
          ctx.passwordSet &&
          ctx.opts!.mfa.mode !== "disabled" &&
          ctx.enrollMethod &&
          (ctx.enrollMethod === "sms" || ctx.enrollMethod === "email") &&
          !ctx.enrollAddress &&
          !ctx.aborted
        ),
    },
    {
      id: "inviteEnrollConfirm",
      condition: (ctx) =>
        !!(
          ctx.passwordSet &&
          ctx.opts!.mfa.mode !== "disabled" &&
          ctx.enrollMethod &&
          (ctx.enrollMethod === "totp" || !!ctx.enrollAddress) &&
          !ctx.enrollDone &&
          !ctx.aborted
        ),
    },
    {
      id: "inviteCollectProfile",
      condition: (ctx) =>
        !!(ctx.passwordSet && ctx.acceptProfileFormPresent && !ctx.profile && !ctx.aborted),
    },
    {
      id: "inviteApplyProfile",
      condition: (ctx) =>
        !!(
          ctx.passwordSet &&
          ctx.acceptProfileFormPresent &&
          ctx.profile &&
          !ctx.profileApplied &&
          !ctx.aborted
        ),
    },
    // Consumer extension point — see `inviteExtraStep()` method.
    { id: "inviteExtraStep" },
    {
      id: "inviteUnsetPendingInvitation",
      condition: (ctx) => !!(ctx.passwordSet && !ctx.pendingInvitationCleared && !ctx.aborted),
    },
    {
      id: "inviteActivateUser",
      condition: (ctx) => !!(ctx.pendingInvitationCleared && !ctx.activated && !ctx.aborted),
    },
    {
      id: "inviteConfirmation",
      condition: (ctx) =>
        !!(
          ctx.activated &&
          ctx.opts!.accept.showConfirmation &&
          !ctx.confirmationShown &&
          !ctx.aborted
        ),
    },
    {
      id: "inviteFreshLoginFinish",
      condition: (ctx) => !!(ctx.activated && ctx.opts!.accept.freshLoginRequired && !ctx.aborted),
    },
    {
      id: "inviteAutoLoginFinish",
      condition: (ctx) =>
        !!(
          ctx.activated &&
          !ctx.opts!.accept.freshLoginRequired &&
          !ctx.tokensIssued &&
          !ctx.aborted
        ),
    },
  ])
  @Public()
  inviteFlow(): void {}

  @Workflow("auth.reInvite")
  @WorkflowSchema<InviteWfCtx>([
    { id: "inviteInit" },
    { id: "inviteLoadPendingUser", condition: (ctx) => !ctx.aborted },
    {
      id: "inviteSendInviteEmail",
      condition: (ctx) => !!(ctx.username && ctx.resolvedSendMode === "email" && !ctx.aborted),
    },
    {
      id: "inviteReturnShareableLink",
      condition: (ctx) =>
        !!(ctx.username && ctx.resolvedSendMode === "shareableLink" && !ctx.aborted),
    },
    // Accept tail — same steps; runs only after the magic link resumes.
    {
      id: "inviteCheckPendingInvitation",
      condition: (ctx) => !!(ctx.linkSent && !ctx.aborted),
    },
    {
      id: "inviteIdempotentRedirect",
      condition: (ctx) => !!(ctx.alreadyAccepted && !ctx.aborted),
    },
    {
      id: "invitePreparePasswordRules",
      condition: (ctx) => !!(ctx.linkSent && !ctx.alreadyAccepted && !ctx.aborted),
    },
    {
      id: "inviteCreatePasswordForm",
      condition: (ctx) =>
        !!(ctx.linkSent && !ctx.alreadyAccepted && !ctx.passwordSet && !ctx.aborted),
    },
    // ── Forced MFA enrollment (3 entries — one per phase, since the invite
    // schema is linear and can't loop a single step like login does). The
    // shared `runMfaEnrollment` helper routes internally based on ctx state.
    {
      // `!ctx.enrollDone` is critical when `mfa.mode === 'optional'`: after a
      // user clicks `skip` in Phase 1, the helper sets `enrollDone` without
      // setting `enrollMethod`. Without this gate the schema would re-enter
      // the pick form forever.
      id: "inviteEnrollPickMethod",
      condition: (ctx) =>
        !!(
          ctx.passwordSet &&
          ctx.opts!.mfa.mode !== "disabled" &&
          !ctx.enrollMethod &&
          !ctx.enrollDone &&
          !ctx.aborted
        ),
    },
    {
      id: "inviteEnrollAddress",
      condition: (ctx) =>
        !!(
          ctx.passwordSet &&
          ctx.opts!.mfa.mode !== "disabled" &&
          ctx.enrollMethod &&
          (ctx.enrollMethod === "sms" || ctx.enrollMethod === "email") &&
          !ctx.enrollAddress &&
          !ctx.aborted
        ),
    },
    {
      id: "inviteEnrollConfirm",
      condition: (ctx) =>
        !!(
          ctx.passwordSet &&
          ctx.opts!.mfa.mode !== "disabled" &&
          ctx.enrollMethod &&
          (ctx.enrollMethod === "totp" || !!ctx.enrollAddress) &&
          !ctx.enrollDone &&
          !ctx.aborted
        ),
    },
    {
      id: "inviteCollectProfile",
      condition: (ctx) =>
        !!(ctx.passwordSet && ctx.acceptProfileFormPresent && !ctx.profile && !ctx.aborted),
    },
    {
      id: "inviteApplyProfile",
      condition: (ctx) =>
        !!(
          ctx.passwordSet &&
          ctx.acceptProfileFormPresent &&
          ctx.profile &&
          !ctx.profileApplied &&
          !ctx.aborted
        ),
    },
    // Consumer extension point — see `inviteExtraStep()` method.
    { id: "inviteExtraStep" },
    {
      id: "inviteUnsetPendingInvitation",
      condition: (ctx) => !!(ctx.passwordSet && !ctx.pendingInvitationCleared && !ctx.aborted),
    },
    {
      id: "inviteActivateUser",
      condition: (ctx) => !!(ctx.pendingInvitationCleared && !ctx.activated && !ctx.aborted),
    },
    {
      id: "inviteConfirmation",
      condition: (ctx) =>
        !!(
          ctx.activated &&
          ctx.opts!.accept.showConfirmation &&
          !ctx.confirmationShown &&
          !ctx.aborted
        ),
    },
    {
      id: "inviteFreshLoginFinish",
      condition: (ctx) => !!(ctx.activated && ctx.opts!.accept.freshLoginRequired && !ctx.aborted),
    },
    {
      id: "inviteAutoLoginFinish",
      condition: (ctx) =>
        !!(
          ctx.activated &&
          !ctx.opts!.accept.freshLoginRequired &&
          !ctx.tokensIssued &&
          !ctx.aborted
        ),
    },
  ])
  @Public()
  reInviteFlow(): void {}

  @Workflow("auth.cancelInvite")
  @WorkflowSchema<InviteWfCtx>([
    { id: "inviteInit" },
    { id: "inviteCancelInvite", condition: (ctx) => !ctx.aborted },
  ])
  @Public()
  cancelInviteFlow(): void {}

  // ╔═══════════════════════════════════════════════════════════════════════╗
  // ║ Steps — shared across the three workflow schemas above                ║
  // ╚═══════════════════════════════════════════════════════════════════════╝

  // ── Phase 0 ────────────────────────────────────────────────────────────
  @Step("inviteInit")
  init(@WorkflowParam("context") ctx: InviteWfCtx): undefined {
    ctx.opts = this.snapshotOpts(this.opts);
    ctx.acceptProfileFormPresent = this.getProfileForm() !== undefined;
    // Resolve send-mode up-front when fixed; `'choice'` defers to `inviteSelectSendMode`.
    if (this.opts.send.mode !== "choice") {
      ctx.resolvedSendMode = this.opts.send.mode;
    }
    return undefined;
  }

  // ── Phase A: prepareAvailableRoles ────────────────────────────────────
  @Step("invitePrepareAvailableRoles")
  async prepareAvailableRoles(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    const roles = await this.getAvailableRoles();
    if (roles) ctx.availableRoles = roles;
    return undefined;
  }

  // ── Phase A: selectSendMode ───────────────────────────────────────────
  @Step("inviteSelectSendMode")
  selectSendMode(@WorkflowParam("context") ctx: InviteWfCtx): unknown {
    const wf = useAtscriptWf(this.opts.forms.inviteSendMode);
    if (wf.resolveAction() === "cancel") {
      return this.abort(ctx, "cancel");
    }
    const input = wf.resolveInput() as { mode: string };
    const mode = input.mode as "email" | "shareableLink";
    ctx.selectedSendMode = mode;
    ctx.resolvedSendMode = mode;
    return undefined;
  }

  // ── Phase A: adminInviteForm ──────────────────────────────────────────
  @Step("inviteAdminInviteForm")
  async adminInviteForm(@WorkflowParam("context") ctx: InviteWfCtx): Promise<unknown> {
    const wf = useAtscriptWf(this.opts.forms.invite);
    if (wf.resolveAction() === "cancel") {
      return this.abort(ctx, "cancel");
    }
    const input = wf.resolveInput() as {
      email: string;
      firstName?: string;
      lastName?: string;
      roles?: string[];
    };

    const email = input.email;

    const parsed = parseInviteRoles(input.roles);
    // Server-side whitelist enforcement: when `getAvailableRoles()` returned a
    // list (surfaced as `ctx.availableRoles` by `invitePrepareAvailableRoles`),
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
    // `reuseAsReInvite` falls through as a no-op — the consumer is responsible
    // for their own multi-tenant model; `invitePreCreateUser` will surface
    // ALREADY_EXISTS from the store cleanly.
    const existing = await this.loadUserOrNull(email);
    const action: DuplicateAction = await this.duplicateCheck({ email, existingUser: existing });
    if (action === "reject") {
      if (existing?.account?.pendingInvitation) {
        throw new HttpError(409, "Invite already pending, use reInvite");
      }
      if (existing) throw new HttpError(409, "User already exists");
      throw new HttpError(409, "Duplicate invite rejected");
    }

    ctx.email = email;
    if (input.firstName) ctx.firstName = input.firstName;
    if (input.lastName) ctx.lastName = input.lastName;
    if (parsed.length > 0) ctx.roles = parsed;
    return undefined;
  }

  // ── Phase A: inferRolesStep ───────────────────────────────────────────
  @Step("inviteInferRolesStep")
  async inferRolesStep(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    if (!ctx.email) return undefined;
    const inferred = await this.inferRoles({
      email: ctx.email,
      ...(ctx.firstName && { firstName: ctx.firstName }),
      ...(ctx.lastName && { lastName: ctx.lastName }),
    });
    if (inferred.length === 0) return undefined;
    const merged = new Set<string>([...(ctx.roles ?? []), ...inferred]);
    ctx.roles = Array.from(merged);
    return undefined;
  }

  // ── Phase A: preCreateUser ────────────────────────────────────────────
  @Step("invitePreCreateUser")
  async preCreateUser(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    if (!ctx.email) throw new HttpError(500, "Workflow state corrupted: missing email");

    const invitedBy = useAuth().getAuthContext()?.userId;
    const preparedInput: PreparedUserInput = {
      email: ctx.email,
      ...(ctx.firstName && { firstName: ctx.firstName }),
      ...(ctx.lastName && { lastName: ctx.lastName }),
      roles: ctx.roles ?? [],
      ...(invitedBy && { invitedBy }),
    };

    const extras = await this.prepareUser(preparedInput);

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
      ...extras,
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
    await this.emitAudit("invite.created", ctx);
    return undefined;
  }

  // ── Boundary: sendInviteEmail (fires on admin send AND on anonymous resume) ─
  @Step("inviteSendInviteEmail")
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
        expiresAtMs: this.opts.send.tokenTtlMs,
      }),
      expires: Date.now() + this.opts.send.tokenTtlMs,
    };
  }

  // ── Boundary: returnShareableLink (same boundary semantics as sendInviteEmail) ─
  @Step("inviteReturnShareableLink")
  @Public()
  returnShareableLink(@WorkflowParam("context") ctx: InviteWfCtx): unknown {
    if (ctx.linkSent) return undefined;
    ctx.linkSent = true;
    // Dedicated `shareableLink` outlet — surfaces the URL in the admin's HTTP
    // response so the trigger provider can wire `createAuthShareableLinkOutlet`
    // (no email send). The state token is still minted + persisted normally.
    return {
      ...outlet("shareableLink", {
        target: ctx.email as string,
        template: "invite.magicLink",
        context: {
          username: ctx.username,
          // See `sendInviteEmail` — userId rides in the outlet context so the
          // demo's `buildMagicLinkUrl` can append `&uid=…` to the URL.
          ...(ctx.username && { userId: ctx.username }),
          ...(ctx.roles && { roles: ctx.roles }),
          expiresAtMs: this.opts.send.tokenTtlMs,
        },
      }),
      expires: Date.now() + this.opts.send.tokenTtlMs,
    };
  }

  // ── Phase A (reInvite): loadPendingUser ───────────────────────────────
  @Step("inviteLoadPendingUser")
  async loadPendingUser(@WorkflowParam("context") ctx: InviteWfCtx): Promise<unknown> {
    const wf = useAtscriptWf(this.opts.forms.inviteEmail);
    if (wf.resolveAction() === "cancel") {
      return this.abort(ctx, "cancel");
    }
    const input = wf.resolveInput() as { email: string };

    const email = input.email;
    const existing = await this.loadUserOrNull(email);
    if (!existing) throw new HttpError(404, "No pending invite for this email");
    if (!existing.account?.pendingInvitation) {
      throw new HttpError(409, "User has already accepted; cannot resend");
    }
    ctx.email = email;
    ctx.username = existing.username;
    // Repopulate context from the existing record so the email template / link
    // payload looks identical to the original invite.
    const u = existing as UserCredentials & {
      firstName?: string;
      lastName?: string;
      roles?: string[];
    };
    if (u.firstName) ctx.firstName = u.firstName;
    if (u.lastName) ctx.lastName = u.lastName;
    if (u.roles && u.roles.length > 0) ctx.roles = u.roles;
    await this.emitAudit("invite.resent", ctx);
    return undefined;
  }

  // ── Phase B: checkPendingInvitation ───────────────────────────────────
  @Step("inviteCheckPendingInvitation")
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
  @Step("inviteIdempotentRedirect")
  @Public()
  idempotentRedirect(@WorkflowParam("context") ctx: InviteWfCtx): undefined {
    // Labels are hardcoded English (consistent with login/recovery finishers);
    // localization is a cross-workflow concern not yet wired.
    finishWf(
      buildInviteAlreadyAcceptedEnvelope({
        loginUrl: this.opts.accept.loginUrl,
        alreadyAcceptedRedirectUrl: this.opts.accept.alreadyAcceptedRedirectUrl,
      }),
    );
    ctx.aborted = true;
    return undefined;
  }

  // ── Phase B: preparePasswordRules ─────────────────────────────────────
  @Step("invitePreparePasswordRules")
  @Public()
  preparePasswordRules(@WorkflowParam("context") ctx: InviteWfCtx): undefined {
    (ctx as Record<string, unknown>).passwordPolicies = this.users.getTransferablePolicies();
    return undefined;
  }

  // ── Phase B: createPasswordForm ───────────────────────────────────────
  @Step("inviteCreatePasswordForm")
  @Public()
  async createPasswordForm(@WorkflowParam("context") ctx: InviteWfCtx): Promise<unknown> {
    const wf = useAtscriptWf(this.opts.forms.setPassword);
    if (wf.resolveAction() === "cancel") {
      // User abort: stop the flow but DO NOT delete the user record. Admin can
      // reInvite later. The pending-invitation flag stays true.
      return this.abort(ctx, "cancel");
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
    ctx.passwordSet = true;
    return undefined;
  }

  // ── Phase B: forced MFA enrollment ────────────────────────────────────
  // Three @Step methods (pick / address / confirm) all delegate to the same
  // helper — the schema's per-phase conditions ensure only one fires per
  // workflow tick, and `runMfaEnrollment` internally routes to the matching
  // phase based on ctx state. Three steps (vs one) is required because the
  // invite schema is linear; a single step couldn't pause between phases.
  private async runInviteEnrollment(ctx: InviteWfCtx): Promise<void> {
    this.requireUsername(ctx);
    // `'disabled'` is filtered at each step's schema condition, so the cast is
    // safe. Mirror onto ctx so `EnrollPickMethodForm` can hide the `skip`
    // action unless mode is `'optional'`.
    const mode = this.opts.mfa.mode as "required" | "optional";
    ctx.enrollMode = mode;
    await this.runMfaEnrollment({
      ctx,
      username: ctx.username,
      users: this.users,
      deliver: (p) => this.deliver(p as DeliverPayload),
      forms: {
        pickMethod: this.opts.forms.enrollPickMethod,
        address: this.opts.forms.enrollAddress,
        confirm: this.opts.forms.enrollConfirm,
      },
      transports: this.opts.mfa.transports,
      pincodeLength: this.opts.mfa.pincodeLength,
      pincodeTtlMs: this.opts.mfa.pincodeTtlMs,
      issuer: this.opts.mfa.issuer,
      mode,
    });
  }

  @Step("inviteEnrollPickMethod")
  @Public()
  async inviteEnrollPickMethod(@WorkflowParam("context") ctx: InviteWfCtx): Promise<unknown> {
    await this.runInviteEnrollment(ctx);
    return undefined;
  }

  @Step("inviteEnrollAddress")
  @Public()
  async inviteEnrollAddress(@WorkflowParam("context") ctx: InviteWfCtx): Promise<unknown> {
    await this.runInviteEnrollment(ctx);
    return undefined;
  }

  @Step("inviteEnrollConfirm")
  @Public()
  async inviteEnrollConfirm(@WorkflowParam("context") ctx: InviteWfCtx): Promise<unknown> {
    await this.runInviteEnrollment(ctx);
    return undefined;
  }

  // ── Phase B: collectProfile ───────────────────────────────────────────
  @Step("inviteCollectProfile")
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
  @Step("inviteApplyProfile")
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
  @Step("inviteExtraStep")
  @Public()
  async inviteExtraStep(): Promise<unknown> {
    return undefined;
  }

  // ── Phase B: unsetPendingInvitation ───────────────────────────────────
  @Step("inviteUnsetPendingInvitation")
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
  @Step("inviteActivateUser")
  @Public()
  async activateUser(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    this.requireUsername(ctx);
    await this.users.activateAccount(ctx.username);
    ctx.activated = true;
    await this.emitAudit("invite.accepted", ctx);
    return undefined;
  }

  // ── Phase B: confirmation ─────────────────────────────────────────────
  @Step("inviteConfirmation")
  @Public()
  confirmation(@WorkflowParam("context") ctx: InviteWfCtx): undefined {
    ctx.confirmationShown = true;
    // The auto-login terminal (`inviteAutoLoginFinish`) merges this envelope's
    // `message` into its own data response so the SPA still surfaces the
    // configured confirmation text alongside the tokens (WF-INVITE-020). The
    // `freshLoginFinish` terminal still overwrites with an immediate redirect
    // — there's no SPA surface to paint the message before the redirect
    // fires, so that branch intentionally drops it.
    finishWf({
      data: { confirmed: true },
      message: { level: "success", text: this.opts.accept.confirmationMessage },
    });
    return undefined;
  }

  // ── Phase B: freshLoginFinish ─────────────────────────────────────────
  @Step("inviteFreshLoginFinish")
  @Public()
  freshLoginFinish(@WorkflowParam("context") _ctx: InviteWfCtx): undefined {
    finishWf({
      next: {
        trigger: "immediate",
        action: {
          type: "redirect",
          target: this.opts.accept.loginUrl,
          reason: "fresh-login-required",
        },
      },
    });
    return undefined;
  }

  // ── Phase B: autoLoginFinish ──────────────────────────────────────────
  @Step("inviteAutoLoginFinish")
  @Public()
  async autoLoginFinish(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    this.requireUsername(ctx);
    const issue = await this.auth.issue(ctx.username);
    ctx.tokensIssued = true;
    const auth = useAuth();
    // Preserve a `message` set by an earlier terminal (typically
    // `inviteConfirmation` when `accept.showConfirmation` is on) so the SPA
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

  // ── auth.cancelInvite ─────────────────────────────────────────────────
  @Step("inviteCancelInvite")
  async cancelInvite(@WorkflowParam("context") ctx: InviteWfCtx): Promise<unknown> {
    if (!this.opts.cancellation.allowed) {
      throw new HttpError(403, "Invite cancellation is disabled");
    }
    const wf = useAtscriptWf(this.opts.forms.inviteEmail);
    const input = wf.resolveInput() as { email: string };
    const email = input.email;
    const existing = await this.loadUserOrNull(email);
    if (!existing) throw new HttpError(404, "No invite to cancel for this email");
    if (!existing.account?.pendingInvitation) {
      throw new HttpError(409, "Cannot cancel: user has already accepted the invite");
    }
    await this.users.deleteUser(existing.username);
    await this.emitAudit("invite.cancelled", {
      ...ctx,
      email,
      username: existing.username,
    });
    finishWf({
      data: { cancelled: true, email },
      message: { level: "info", text: "Invite cancelled." },
    });
    return undefined;
  }

  // ── Helpers ───────────────────────────────────────────────────────────
  private abort(ctx: InviteWfCtx, reason: string): AltHandled {
    abortWf(reason, { message: { level: "info", text: "Invite cancelled." } });
    ctx.aborted = true;
    return ALT_HANDLED;
  }

  private async loadUserOrNull(username: string): Promise<UserCredentials | null> {
    try {
      return await this.users.getUser(username);
    } catch (err) {
      if (err instanceof UserAuthError && err.type === "NOT_FOUND") return null;
      throw err;
    }
  }

  private async emitAudit(kind: string, ctx: InviteWfCtx): Promise<void> {
    if (!this.opts.audit.enabled) return;
    const invitedBy = useAuth().getAuthContext()?.userId;
    await this.audit({
      kind,
      workflow: AUDIT_WORKFLOW_BY_KIND[kind] ?? "auth.invite",
      ...(ctx.username && { userId: ctx.username }),
      ...(invitedBy && { invitedBy }),
      ...(ctx.email && { email: ctx.email }),
      ip: this.resolveClientIp(),
    });
  }
}
