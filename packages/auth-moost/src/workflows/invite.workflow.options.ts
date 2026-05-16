/**
 * Full shape per `WF_INVITE.md` §"`InviteWorkflowOptions` — full shape".
 *
 * Defaults match the doc's "drop in and use" baseline: collect first/last/roles
 * (free text), email-only send mode, 7-day TTL, no accept-time profile form,
 * auto-login after accept, confirmation message, cancellation allowed,
 * 50/hour per-admin rate limit, audit emission ON. Admin authorization is the
 * trigger route's responsibility (ARBAC), not the workflow class.
 */
import type { UserCredentials } from "@aoothjs/user";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { Injectable } from "moost";

export const DEFAULT_INVITE_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Input passed to {@link InviteWorkflowOptions.prepareUser}. The workflow
 * resolves the admin form to these fields before calling the hook, so callers
 * see a fully-typed payload regardless of which optional fields the admin
 * filled in.
 */
export interface PreparedUserInput {
  email: string;
  firstName?: string;
  lastName?: string;
  roles: string[];
  /** Admin's `username` (`useAuth().getUserId()` at invite time). */
  invitedBy?: string;
}

/** Output shape of {@link InviteWorkflowOptions.duplicateCheck}. */
export type DuplicateAction = "allow" | "reject" | "reuseAsReInvite";

@Injectable()
export class InviteWorkflowOptions {
  // ── Admin invite form fields ─────────────────────────────────────────────
  collectFirstName = true;
  collectLastName = true;
  /** When false, no roles input is shown; programmatically populated via `inferRoles`. */
  collectRoles = true;
  /**
   * When defined AND `collectRoles=true` → admin form ships
   * `ctx.availableRoles` so the UI renders a multi-select. When undefined →
   * free-text comma-separated input.
   */
  getAvailableRoles?: () => Promise<Array<{ id: string; label: string }>>;
  /**
   * Called after the admin form submits, before `inviteePreCreateUser`. Lets
   * consumers derive roles from email domain / AD lookup / etc. without admin
   * choice. Result is merged with admin-selected roles (when
   * `collectRoles=true`) or used standalone (when false).
   */
  inferRoles?: (input: {
    email: string;
    firstName?: string;
    lastName?: string;
  }) => Promise<string[]>;

  // ── Pre-create-user shape & persistence ──────────────────────────────────
  /**
   * Called in `invitePreCreateUser` immediately before
   * `users.createUser(email, undefined, extras)`. Returns extra fields merged
   * into the user record (e.g. `tenantId`).
   */
  prepareUser?: (
    input: PreparedUserInput,
  ) => Promise<Record<string, unknown>> | Record<string, unknown>;

  // ── Send mode ────────────────────────────────────────────────────────────
  /**
   * `'email'` → library sends the magic link.
   * `'shareableLink'` → library returns the magic-link URL to the admin (no
   *   email sent); admin shares it however they want.
   * `'choice'` → admin picks per-invite via `inviteSelectSendMode`.
   */
  sendMode: "email" | "shareableLink" | "choice" = "email";

  inviteTokenTtlMs = DEFAULT_INVITE_TOKEN_TTL_MS;

  // ── Accept-side custom profile form ──────────────────────────────────────
  /**
   * Consumer-supplied `.as` form schema for the `inviteCollectProfile` step.
   * When undefined → step is skipped entirely (just password collection).
   * Reference (class) — NOT persisted into `ctx.opts`; the step looks it up
   * via `this.opts.acceptProfileForm`. A boolean projection
   * (`acceptProfileFormPresent`) lands on the snapshot so schema conditions
   * can gate on its presence.
   */
  acceptProfileForm?: TAtscriptAnnotatedType;
  /**
   * Escape hatch. Called after `inviteCollectProfile` submits + after the
   * user record exists. Receives the raw profile data; consumer transforms +
   * persists wherever (separate profile table, external CRM, ...). When
   * undefined AND `acceptProfileForm` is set → fields are deep-merged into
   * the user record via `UserService.update(username, profile)`.
   */
  applyProfile?: (input: {
    username: string;
    profile: Record<string, unknown>;
  }) => Promise<void> | void;

  // ── Idempotency on magic-link click ──────────────────────────────────────
  alreadyAcceptedRedirectUrl = "/login";

  // ── Post-accept ──────────────────────────────────────────────────────────
  /** Default: auto-login after accept. Set `true` to redirect to `loginUrl`. */
  freshLoginRequired = false;
  loginUrl = "/login";
  /** When true, render a confirmation data payload before the redirect / auto-login. */
  showConfirmation = true;
  confirmationMessage = "Your account has been created.";

  // ── Cancellation ─────────────────────────────────────────────────────────
  /**
   * Enables `auth.cancelInvite` workflow id. Cancellation is HARD DELETE
   * (per WF_INVITE.md). Subsequent clicks on the orphaned magic link return
   * `410 Gone` from `inviteCheckPendingInvitation`.
   */
  allowCancel = true;

  // ── Anti-duplicate (escape hatch on top of the structural rule) ──────────
  /**
   * Optional override for the default structural duplicate rule (pending
   * invite → 409 reInvite hint; already-accepted → 409 user exists; not
   * found → continue). Multi-tenant apps where the same email can invite into
   * different tenants reach for this.
   */
  duplicateCheck?: (input: {
    email: string;
    existingUser: UserCredentials | null;
  }) => Promise<DuplicateAction> | DuplicateAction;

  // ── Rate limiting (per-admin spam guard) ─────────────────────────────────
  /**
   * Per-ADMIN cap (key = admin's `userId`). Default: max 50 invites per hour
   * per admin. Set `null` to disable. When non-null, a `WorkflowRateLimitStore`
   * MUST be registered against `WORKFLOW_RATE_LIMIT_STORE_TOKEN` — the
   * workflow constructor fails loud if it is not.
   */
  rateLimit: { count: number; windowMs: number } | null = {
    count: 50,
    windowMs: 60 * 60_000,
  };

  // ── Audit ────────────────────────────────────────────────────────────────
  /**
   * Emits `invite.created`, `invite.resent`, `invite.accepted`,
   * `invite.cancelled` via the registered `AuditEmitter`. No-op when no
   * emitter is wired.
   */
  auditEvents = true;

  // ── JSON-safe presence flags (populated by snapshotOpts) ─────────────────
  /** True when `getAvailableRoles` is set — gates `invitePrepareAvailableRoles`. */
  getAvailableRolesEnabled?: boolean;
  /** True when `inferRoles` is set — gates `inviteInferRolesStep`. */
  inferRolesEnabled?: boolean;
  /** True when `acceptProfileForm` is set — gates `inviteCollectProfile` + `inviteApplyProfile`. */
  acceptProfileFormPresent?: boolean;

  constructor(opts: Partial<InviteWorkflowOptions> = {}) {
    Object.assign(this, opts);
  }
}

/**
 * Backwards-compat name for callers that still import the original type.
 * `InvitePrepareUserInput` is the prior shape; {@link PreparedUserInput} is
 * the current name in WF_INVITE.md.
 */
export type InvitePrepareUserInput = PreparedUserInput;
