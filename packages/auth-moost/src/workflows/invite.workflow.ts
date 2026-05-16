/**
 * InviteWorkflow — registers three workflow ids:
 *
 *   - `auth.invite`       — admin invites a new user → user accepts (full flow)
 *   - `auth.reInvite`     — admin resends to an existing `pendingInvitation` user
 *   - `auth.cancelInvite` — admin hard-deletes a pending invite (gated by
 *                           `opts.allowCancel`)
 *
 * Full step catalog per `WF_INVITE.md`. Step IDs are workflow-scoped (all
 * prefixed `invite*`) because `@moostjs/event-wf` registers `@Step('id')`
 * globally — identical IDs across login/recovery/invite would silently
 * collide and overwrite handlers. The accept tail (`inviteCheckPending…`
 * through `inviteAutoLoginFinish`) is shared between `auth.invite` and
 * `auth.reInvite` schemas by re-referencing the same step IDs.
 *
 * **Step routing model.** Same shape as `RecoveryWorkflow`: alt-action
 * handlers run BEFORE form validation (so `cancel` works without filling
 * fields) and return the `ALT_HANDLED` sentinel after short-circuiting via
 * `useWfFinished().set(...)`. Terminal steps gate on `!ctx.aborted` so the
 * abort response stays.
 */
import { AuthCredential, type EmailSender, type SmsSender } from "@aoothjs/auth";
import { UserAuthError, type UserCredentials, UserService } from "@aoothjs/user";
import { HttpError } from "@moostjs/event-http";
import {
  outletEmail,
  Step,
  useWfFinished,
  Workflow,
  WorkflowParam,
  WorkflowSchema,
} from "@moostjs/event-wf";
import { Controller, Inject, Injectable, Optional } from "moost";

import {
  InviteEmailForm,
  InviteForm,
  InviteSendModeForm,
  SetPasswordForm,
} from "../atscript/models/forms.as.js";
import { type AuditEmitter, NoopAuditEmitter } from "../audit/index";
import { useAuth } from "../auth.composables";
import { MoostAuthConfig } from "../auth.config";
import { buildLoginResponse } from "../auth.cookies";
import type { WorkflowRateLimitStore } from "../rate-limit/index";
import {
  type DuplicateAction,
  InviteWorkflowOptions,
  type PreparedUserInput,
} from "./invite.workflow.options";
import {
  buildFinishedCookies,
  httpInputRequired,
  requireUsername,
  resolveClientIp,
  translatePasswordSetError,
  validateFormInput,
} from "./wf-helpers";

export interface InviteWfCtx {
  opts?: InviteWorkflowOptions;

  // ── Admin-side (Phase A) ────────────────────────────────────────────────
  /** Populated by `invitePrepareAvailableRoles` when getAvailableRoles is wired. */
  availableRoles?: Array<{ id: string; label: string }>;
  email?: string;
  /** Typically same as `email`; consumers can override the mapping. */
  username?: string;
  firstName?: string;
  lastName?: string;
  roles?: string[];
  /** Populated by `inviteSelectSendMode` (when `sendMode === 'choice'`). */
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
 * Strip non-JSON values (functions, atscript form classes) from the options
 * object so the snapshot persists cleanly into the workflow state store. Add
 * `*Enabled` / `*Present` boolean projections so schema `condition` predicates
 * can gate on callback presence without holding the original reference.
 */
function snapshotOpts(opts: InviteWorkflowOptions): InviteWorkflowOptions {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(opts)) {
    if (v === undefined) continue;
    if (typeof v === "function") continue;
    if (v && typeof v === "object" && !Array.isArray(v)) {
      if ((v as Record<string, unknown>).__is_atscript_annotated_type) continue;
    }
    out[k] = v;
  }
  out.getAvailableRolesEnabled = typeof opts.getAvailableRoles === "function";
  out.inferRolesEnabled = typeof opts.inferRoles === "function";
  out.acceptProfileFormPresent = Boolean(opts.acceptProfileForm);
  return out as unknown as InviteWorkflowOptions;
}

/** Boot-time invariants — called once per options instance via `validatedOpts`. */
function validateOpts(
  opts: InviteWorkflowOptions,
  emailSender: EmailSender | undefined,
  rateLimitStore: WorkflowRateLimitStore | undefined,
): void {
  if (opts.rateLimit !== null) {
    if (!rateLimitStore) {
      throw new Error(
        "InviteWorkflow: WorkflowRateLimitStore required when opts.rateLimit is non-null",
      );
    }
    if (opts.rateLimit.count <= 0 || opts.rateLimit.windowMs <= 0) {
      throw new Error(
        "InviteWorkflow: opts.rateLimit.count and opts.rateLimit.windowMs must be > 0 (set rateLimit: null to disable)",
      );
    }
  }
  if (opts.sendMode !== "shareableLink" && !emailSender) {
    // 'email' and 'choice' both need the email outlet.
    throw new Error('InviteWorkflow: EmailSender required when sendMode is "email" or "choice"');
  }
}

const validatedOpts = new WeakSet<InviteWorkflowOptions>();

/** Audit `kind` → `wfid` reverse map. Default falls through to `auth.invite`. */
const AUDIT_WORKFLOW_BY_KIND: Record<string, string> = {
  "invite.cancelled": "auth.cancelInvite",
  "invite.resent": "auth.reInvite",
};

/** Trim/split `roles` free-text input — `"admin, editor"` → `["admin", "editor"]`. */
export function parseInviteRoles(input?: string | string[]): string[] {
  if (!input) return [];
  if (Array.isArray(input)) return input.map((r) => String(r).trim()).filter(Boolean);
  return input
    .split(",")
    .map((r) => r.trim())
    .filter(Boolean);
}

/**
 * Authorization is the trigger route's responsibility. Mount admin-gated
 * triggers (e.g. `@ArbacAuthorize({ resource: 'auth.invite', action: '*' })`)
 * for these workflow ids; never put them on a public trigger allow-list.
 */
@Injectable("FOR_EVENT")
@Controller()
export class InviteWorkflow {
  constructor(
    private readonly opts: InviteWorkflowOptions,
    private readonly users: UserService,
    private readonly auth: AuthCredential,
    private readonly authConfig: MoostAuthConfig,
    @Optional() @Inject("EmailSender") private readonly mailer?: EmailSender,
    @Optional() @Inject("SmsSender") private readonly sms?: SmsSender,
    @Optional()
    @Inject("WorkflowRateLimitStore")
    private readonly rateLimitStore?: WorkflowRateLimitStore,
    @Optional() @Inject("AuditEmitter") private readonly audit?: AuditEmitter,
  ) {
    // Silence unused-DI lint for the optional SMS injection — kept on the
    // constructor signature for parity with recovery / future invite-SMS work.
    void this.sms;
  }

  // ╔═══════════════════════════════════════════════════════════════════════╗
  // ║ Workflow definitions                                                  ║
  // ╚═══════════════════════════════════════════════════════════════════════╝

  @Workflow("auth.invite")
  @WorkflowSchema<InviteWfCtx>([
    { id: "inviteInit" },
    {
      id: "invitePrepareAvailableRoles",
      condition: (ctx) =>
        Boolean(ctx.opts?.collectRoles && ctx.opts?.getAvailableRolesEnabled && !ctx.aborted),
    },
    {
      id: "inviteSelectSendMode",
      condition: (ctx) =>
        Boolean(ctx.opts?.sendMode === "choice" && !ctx.resolvedSendMode && !ctx.aborted),
    },
    { id: "inviteAdminInviteForm", condition: (ctx) => Boolean(!ctx.email && !ctx.aborted) },
    {
      id: "inviteInferRolesStep",
      condition: (ctx) => Boolean(ctx.email && ctx.opts?.inferRolesEnabled && !ctx.aborted),
    },
    {
      id: "invitePreCreateUser",
      condition: (ctx) => Boolean(ctx.email && !ctx.username && !ctx.aborted),
    },
    {
      id: "inviteSendInviteEmail",
      condition: (ctx) => Boolean(ctx.username && ctx.resolvedSendMode === "email" && !ctx.aborted),
    },
    {
      id: "inviteReturnShareableLink",
      condition: (ctx) =>
        Boolean(ctx.username && ctx.resolvedSendMode === "shareableLink" && !ctx.aborted),
    },
    // ── Phase B (accept tail): runs only after the magic link resumes here.
    {
      id: "inviteCheckPendingInvitation",
      condition: (ctx) => Boolean(ctx.linkSent && !ctx.aborted),
    },
    {
      id: "inviteIdempotentRedirect",
      condition: (ctx) => Boolean(ctx.alreadyAccepted && !ctx.aborted),
    },
    {
      id: "invitePreparePasswordRules",
      condition: (ctx) => Boolean(ctx.linkSent && !ctx.alreadyAccepted && !ctx.aborted),
    },
    {
      id: "inviteCreatePasswordForm",
      condition: (ctx) =>
        Boolean(ctx.linkSent && !ctx.alreadyAccepted && !ctx.passwordSet && !ctx.aborted),
    },
    {
      id: "inviteCollectProfile",
      condition: (ctx) =>
        Boolean(
          ctx.passwordSet && ctx.opts?.acceptProfileFormPresent && !ctx.profile && !ctx.aborted,
        ),
    },
    {
      id: "inviteApplyProfile",
      condition: (ctx) =>
        Boolean(
          ctx.passwordSet &&
          ctx.opts?.acceptProfileFormPresent &&
          ctx.profile &&
          !ctx.profileApplied &&
          !ctx.aborted,
        ),
    },
    {
      id: "inviteUnsetPendingInvitation",
      condition: (ctx) => Boolean(ctx.passwordSet && !ctx.pendingInvitationCleared && !ctx.aborted),
    },
    {
      id: "inviteActivateUser",
      condition: (ctx) => Boolean(ctx.pendingInvitationCleared && !ctx.activated && !ctx.aborted),
    },
    {
      id: "inviteConfirmation",
      condition: (ctx) =>
        Boolean(
          ctx.activated && ctx.opts?.showConfirmation && !ctx.confirmationShown && !ctx.aborted,
        ),
    },
    {
      id: "inviteFreshLoginFinish",
      condition: (ctx) => Boolean(ctx.activated && ctx.opts?.freshLoginRequired && !ctx.aborted),
    },
    {
      id: "inviteAutoLoginFinish",
      condition: (ctx) =>
        Boolean(
          ctx.activated && !ctx.opts?.freshLoginRequired && !ctx.tokensIssued && !ctx.aborted,
        ),
    },
  ])
  inviteFlow(): void {}

  @Workflow("auth.reInvite")
  @WorkflowSchema<InviteWfCtx>([
    { id: "inviteInit" },
    { id: "inviteLoadPendingUser", condition: (ctx) => !ctx.aborted },
    {
      id: "inviteSendInviteEmail",
      condition: (ctx) => Boolean(ctx.username && ctx.resolvedSendMode === "email" && !ctx.aborted),
    },
    {
      id: "inviteReturnShareableLink",
      condition: (ctx) =>
        Boolean(ctx.username && ctx.resolvedSendMode === "shareableLink" && !ctx.aborted),
    },
    // Accept tail — same steps; runs only after the magic link resumes.
    {
      id: "inviteCheckPendingInvitation",
      condition: (ctx) => Boolean(ctx.linkSent && !ctx.aborted),
    },
    {
      id: "inviteIdempotentRedirect",
      condition: (ctx) => Boolean(ctx.alreadyAccepted && !ctx.aborted),
    },
    {
      id: "invitePreparePasswordRules",
      condition: (ctx) => Boolean(ctx.linkSent && !ctx.alreadyAccepted && !ctx.aborted),
    },
    {
      id: "inviteCreatePasswordForm",
      condition: (ctx) =>
        Boolean(ctx.linkSent && !ctx.alreadyAccepted && !ctx.passwordSet && !ctx.aborted),
    },
    {
      id: "inviteCollectProfile",
      condition: (ctx) =>
        Boolean(
          ctx.passwordSet && ctx.opts?.acceptProfileFormPresent && !ctx.profile && !ctx.aborted,
        ),
    },
    {
      id: "inviteApplyProfile",
      condition: (ctx) =>
        Boolean(
          ctx.passwordSet &&
          ctx.opts?.acceptProfileFormPresent &&
          ctx.profile &&
          !ctx.profileApplied &&
          !ctx.aborted,
        ),
    },
    {
      id: "inviteUnsetPendingInvitation",
      condition: (ctx) => Boolean(ctx.passwordSet && !ctx.pendingInvitationCleared && !ctx.aborted),
    },
    {
      id: "inviteActivateUser",
      condition: (ctx) => Boolean(ctx.pendingInvitationCleared && !ctx.activated && !ctx.aborted),
    },
    {
      id: "inviteConfirmation",
      condition: (ctx) =>
        Boolean(
          ctx.activated && ctx.opts?.showConfirmation && !ctx.confirmationShown && !ctx.aborted,
        ),
    },
    {
      id: "inviteFreshLoginFinish",
      condition: (ctx) => Boolean(ctx.activated && ctx.opts?.freshLoginRequired && !ctx.aborted),
    },
    {
      id: "inviteAutoLoginFinish",
      condition: (ctx) =>
        Boolean(
          ctx.activated && !ctx.opts?.freshLoginRequired && !ctx.tokensIssued && !ctx.aborted,
        ),
    },
  ])
  reInviteFlow(): void {}

  @Workflow("auth.cancelInvite")
  @WorkflowSchema<InviteWfCtx>([
    { id: "inviteInit" },
    { id: "inviteCancelInvite", condition: (ctx) => !ctx.aborted },
  ])
  cancelInviteFlow(): void {}

  // ╔═══════════════════════════════════════════════════════════════════════╗
  // ║ Steps — shared across the three workflow schemas above                ║
  // ╚═══════════════════════════════════════════════════════════════════════╝

  // ── Phase 0 ────────────────────────────────────────────────────────────
  @Step("inviteInit")
  init(@WorkflowParam("context") ctx: InviteWfCtx): undefined {
    if (!validatedOpts.has(this.opts)) {
      validateOpts(this.opts, this.mailer, this.rateLimitStore);
      validatedOpts.add(this.opts);
    }
    ctx.opts = snapshotOpts(this.opts);
    // Resolve send-mode up-front when fixed; `'choice'` defers to `inviteSelectSendMode`.
    if (this.opts.sendMode !== "choice") {
      ctx.resolvedSendMode = this.opts.sendMode;
    }
    return undefined;
  }

  // ── Phase A: prepareAvailableRoles ────────────────────────────────────
  @Step("invitePrepareAvailableRoles")
  async prepareAvailableRoles(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    if (!this.opts.getAvailableRoles) return undefined;
    ctx.availableRoles = await this.opts.getAvailableRoles();
    return undefined;
  }

  // ── Phase A: selectSendMode ───────────────────────────────────────────
  @Step("inviteSelectSendMode")
  selectSendMode(
    @WorkflowParam("input") input: { mode?: string; action?: string } | undefined,
    @WorkflowParam("context") ctx: InviteWfCtx,
  ): unknown {
    if (!input) return httpInputRequired(InviteSendModeForm, ctx);
    if (input.action === "cancel") {
      return this.abort(ctx, "cancel");
    }
    const errors = validateFormInput(InviteSendModeForm, input);
    if (errors) return httpInputRequired(InviteSendModeForm, ctx, errors);
    const mode = input.mode as "email" | "shareableLink";
    ctx.selectedSendMode = mode;
    ctx.resolvedSendMode = mode;
    return undefined;
  }

  // ── Phase A: adminInviteForm ──────────────────────────────────────────
  @Step("inviteAdminInviteForm")
  async adminInviteForm(
    @WorkflowParam("input") input:
      | {
          email?: string;
          firstName?: string;
          lastName?: string;
          roles?: string | string[];
          action?: string;
        }
      | undefined,
    @WorkflowParam("context") ctx: InviteWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(InviteForm, ctx);
    if (input.action === "cancel") {
      return this.abort(ctx, "cancel");
    }

    const errors = validateFormInput(InviteForm, input);
    if (errors) return httpInputRequired(InviteForm, ctx, errors);

    const email = input.email as string;

    // Rate-limit BEFORE the user lookup so spammers can't fish for
    // existing-email signals via the duplicate-check error path. Per-admin key
    // is best-effort: an unauthenticated trigger context simply skips the cap
    // (authorization is the trigger route's responsibility — ARBAC).
    const adminId = useAuth().getAuthContext()?.userId;
    if (this.opts.rateLimit && this.rateLimitStore && adminId) {
      const res = await this.rateLimitStore.consume(
        adminId,
        this.opts.rateLimit.windowMs,
        this.opts.rateLimit.count,
      );
      if (!res.allowed) {
        throw new HttpError(429, "Invite rate limit exceeded for this admin");
      }
    }

    // Duplicate check — escape hatch overrides the structural rule. Structural
    // rule: any existing row → reject (with a different message per pending /
    // accepted). `reuseAsReInvite` falls through as a no-op — the consumer is
    // responsible for their own multi-tenant model; `invitePreCreateUser` will
    // surface ALREADY_EXISTS from the store cleanly.
    const existing = await this.loadUserOrNull(email);
    const action: DuplicateAction = this.opts.duplicateCheck
      ? await this.opts.duplicateCheck({ email, existingUser: existing })
      : existing
        ? "reject"
        : "allow";
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
    const parsed = parseInviteRoles(input.roles);
    if (parsed.length > 0) ctx.roles = parsed;
    return undefined;
  }

  // ── Phase A: inferRolesStep ───────────────────────────────────────────
  @Step("inviteInferRolesStep")
  async inferRolesStep(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    if (!this.opts.inferRoles || !ctx.email) return undefined;
    const inferred = await this.opts.inferRoles({
      email: ctx.email,
      firstName: ctx.firstName,
      lastName: ctx.lastName,
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

    const extras = this.opts.prepareUser ? await this.opts.prepareUser(preparedInput) : {};

    // `UserService.createUser` shallow-merges `extras` over `base`, so passing
    // an `account` key would wipe out the base's `active: false` / `locked:
    // false` defaults (and atscript-db validation would reject the row). Set
    // `pendingInvitation` via a follow-up `update` instead — preserves the
    // base defaults AND uses the same `@db.patch.strategy 'merge'` path the
    // rest of the workflow relies on.
    const fields: Record<string, unknown> = {
      ...extras,
      ...(ctx.firstName && { firstName: ctx.firstName }),
      ...(ctx.lastName && { lastName: ctx.lastName }),
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

  // ── Phase A: sendInviteEmail ──────────────────────────────────────────
  @Step("inviteSendInviteEmail")
  sendInviteEmail(@WorkflowParam("context") ctx: InviteWfCtx): unknown {
    if (ctx.linkSent) return undefined;
    ctx.linkSent = true;
    return {
      ...outletEmail(ctx.email as string, "invite.magicLink", {
        username: ctx.username,
        ...(ctx.roles && { roles: ctx.roles }),
        expiresAtMs: this.opts.inviteTokenTtlMs,
      }),
      expires: Date.now() + this.opts.inviteTokenTtlMs,
    };
  }

  // ── Phase A: returnShareableLink ──────────────────────────────────────
  @Step("inviteReturnShareableLink")
  returnShareableLink(@WorkflowParam("context") ctx: InviteWfCtx): unknown {
    if (ctx.linkSent) return undefined;
    // PUNT: shareable-link mode currently piggy-backs on the email outlet
    // (admin's UI is expected to display the same magic-link URL that gets
    // emailed). A dedicated `shareableLinkSink` outlet that finishes admin-
    // side with the URL instead of sending email is future work.
    ctx.linkSent = true;
    return {
      ...outletEmail(ctx.email as string, "invite.magicLink", {
        username: ctx.username,
        ...(ctx.roles && { roles: ctx.roles }),
        expiresAtMs: this.opts.inviteTokenTtlMs,
        shareableLink: true,
      }),
      expires: Date.now() + this.opts.inviteTokenTtlMs,
    };
  }

  // ── Phase A (reInvite): loadPendingUser ───────────────────────────────
  @Step("inviteLoadPendingUser")
  async loadPendingUser(
    @WorkflowParam("input") input: { email?: string; action?: string } | undefined,
    @WorkflowParam("context") ctx: InviteWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(InviteEmailForm, ctx);
    if (input.action === "cancel") {
      return this.abort(ctx, "cancel");
    }
    const errors = validateFormInput(InviteEmailForm, input);
    if (errors) return httpInputRequired(InviteEmailForm, ctx, errors);

    const email = input.email as string;
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
  idempotentRedirect(@WorkflowParam("context") ctx: InviteWfCtx): undefined {
    useWfFinished().set({ type: "redirect", value: this.opts.alreadyAcceptedRedirectUrl });
    ctx.aborted = true;
    return undefined;
  }

  // ── Phase B: preparePasswordRules ─────────────────────────────────────
  @Step("invitePreparePasswordRules")
  preparePasswordRules(@WorkflowParam("context") ctx: InviteWfCtx): undefined {
    (ctx as Record<string, unknown>).passwordPolicies = this.users.getTransferablePolicies();
    return undefined;
  }

  // ── Phase B: createPasswordForm ───────────────────────────────────────
  @Step("inviteCreatePasswordForm")
  async createPasswordForm(
    @WorkflowParam("input") input:
      | { newPassword?: string; confirmPassword?: string; action?: string }
      | undefined,
    @WorkflowParam("context") ctx: InviteWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(SetPasswordForm, ctx);
    if (input.action === "cancel") {
      // User abort: stop the flow but DO NOT delete the user record. Admin can
      // reInvite later. The pending-invitation flag stays true.
      useWfFinished().set({ type: "data", value: { aborted: true, reason: "cancel" } });
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
    ctx.passwordSet = true;
    return undefined;
  }

  // ── Phase B: collectProfile ───────────────────────────────────────────
  @Step("inviteCollectProfile")
  async collectProfile(
    @WorkflowParam("input") input: Record<string, unknown> | undefined,
    @WorkflowParam("context") ctx: InviteWfCtx,
  ): Promise<unknown> {
    const form = this.opts.acceptProfileForm;
    if (!form) return undefined; // Defensive — condition gates on `acceptProfileFormPresent`.
    if (!input) return httpInputRequired(form, ctx);
    if ((input as { action?: string }).action === "skip") {
      // 'skip' alt-action — record an empty profile and let `applyProfile` no-op.
      ctx.profile = {};
      return undefined;
    }
    const errors = validateFormInput(form, input, { partial: "deep" });
    if (errors) return httpInputRequired(form, ctx, errors);
    ctx.profile = input;
    return undefined;
  }

  // ── Phase B: applyProfile ─────────────────────────────────────────────
  @Step("inviteApplyProfile")
  async applyProfile(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    requireUsername(ctx);
    const profile = ctx.profile ?? {};
    if (Object.keys(profile).length === 0) {
      ctx.profileApplied = true;
      return undefined;
    }
    if (this.opts.applyProfile) {
      await this.opts.applyProfile({ username: ctx.username, profile });
    } else {
      // Default: deep-merge into the user record via UserService.update.
      await this.users.update(ctx.username, profile as Partial<UserCredentials>);
    }
    ctx.profileApplied = true;
    return undefined;
  }

  // ── Phase B: unsetPendingInvitation ───────────────────────────────────
  @Step("inviteUnsetPendingInvitation")
  async unsetPendingInvitation(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    requireUsername(ctx);
    await this.users.update(ctx.username, {
      account: { pendingInvitation: false },
    } as Partial<UserCredentials>);
    ctx.pendingInvitationCleared = true;
    return undefined;
  }

  // ── Phase B: activateUser ─────────────────────────────────────────────
  @Step("inviteActivateUser")
  async activateUser(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
    requireUsername(ctx);
    await this.users.activateAccount(ctx.username);
    ctx.activated = true;
    await this.emitAudit("invite.accepted", ctx);
    return undefined;
  }

  // ── Phase B: confirmation ─────────────────────────────────────────────
  @Step("inviteConfirmation")
  confirmation(@WorkflowParam("context") ctx: InviteWfCtx): undefined {
    ctx.confirmationShown = true;
    // When auto-login is the next step, the data finish here is OVERWRITTEN
    // by `inviteAutoLoginFinish` (which calls useWfFinished().set with the
    // login response). When freshLoginRequired, the freshLoginFinish step
    // overrides with a redirect. The confirmation message is therefore only
    // visible in flows where BOTH freshLoginRequired AND showConfirmation are
    // tuned together — that's by design per WF_INVITE.md §"confirmation".
    useWfFinished().set({
      type: "data",
      value: { message: this.opts.confirmationMessage, confirmed: true },
    });
    return undefined;
  }

  // ── Phase B: freshLoginFinish ─────────────────────────────────────────
  @Step("inviteFreshLoginFinish")
  freshLoginFinish(@WorkflowParam("context") _ctx: InviteWfCtx): undefined {
    useWfFinished().set({ type: "redirect", value: this.opts.loginUrl });
    return undefined;
  }

  // ── Phase B: autoLoginFinish ──────────────────────────────────────────
  @Step("inviteAutoLoginFinish")
  async autoLoginFinish(@WorkflowParam("context") ctx: InviteWfCtx): Promise<undefined> {
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

  // ── auth.cancelInvite ─────────────────────────────────────────────────
  @Step("inviteCancelInvite")
  async cancelInvite(
    @WorkflowParam("input") input: { email?: string } | undefined,
    @WorkflowParam("context") ctx: InviteWfCtx,
  ): Promise<unknown> {
    if (!this.opts.allowCancel) {
      throw new HttpError(403, "Invite cancellation is disabled");
    }
    if (!input) return httpInputRequired(InviteEmailForm, ctx);
    const errors = validateFormInput(InviteEmailForm, input);
    if (errors) return httpInputRequired(InviteEmailForm, ctx, errors);
    const email = input.email as string;
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
    useWfFinished().set({
      type: "data",
      value: { cancelled: true, email },
    });
    return undefined;
  }

  // ── Helpers ───────────────────────────────────────────────────────────
  private abort(ctx: InviteWfCtx, reason: string): AltHandled {
    useWfFinished().set({ type: "data", value: { aborted: true, reason } });
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
    if (!this.opts.auditEvents) return;
    const emitter = this.audit ?? NoopAuditEmitter;
    const invitedBy = useAuth().getAuthContext()?.userId;
    await emitter.emit({
      kind,
      workflow: AUDIT_WORKFLOW_BY_KIND[kind] ?? "auth.invite",
      ...(ctx.username && { userId: ctx.username }),
      ...(invitedBy && { invitedBy }),
      ...(ctx.email && { email: ctx.email }),
      ip: resolveClientIp(),
    });
  }
}
