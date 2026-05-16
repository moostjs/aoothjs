/**
 * `InviteWorkflowOpts` — nested-pojo configuration for `InviteWorkflow`.
 *
 * Phase 4 of the workflow OOP-reshape (see TASKS.md): the options class +
 * callbacks have been replaced by a nested-object pojo passed as the first
 * ctor arg, plus protected methods on `InviteWorkflow` that consumers override
 * via subclassing. Defaults are applied by `mergeInviteOpts(opts)` so step
 * bodies + schema conditions can read `ctx.opts.<group>.<flag>` without `?.`.
 *
 * Rate-limit was dropped from the workflow surface entirely — consumers who
 * want a cap wire it themselves at the trigger / HTTP layer (the standalone
 * `WorkflowRateLimitStore` interface + memory impl still ship for that).
 * Admin authorization is the trigger route's responsibility (ARBAC).
 */
import type { UserCredentials } from "@aoothjs/user";

export const DEFAULT_INVITE_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Input passed to {@link InviteWorkflow.prepareUser}. The workflow resolves the
 * admin form to these fields before calling the hook, so the override sees a
 * fully-typed payload regardless of which optional fields the admin filled in.
 */
export interface PreparedUserInput {
  email: string;
  firstName?: string;
  lastName?: string;
  roles: string[];
  /** Admin's `username` (`useAuth().getAuthContext()?.userId` at invite time). */
  invitedBy?: string;
}

/** Return value of {@link InviteWorkflow.duplicateCheck}. */
export type DuplicateAction = "allow" | "reject" | "reuseAsReInvite";

export type InviteSendMode = "email" | "shareableLink" | "choice";

export interface InviteWorkflowOpts {
  adminForm?: {
    collectFirstName?: boolean;
    collectLastName?: boolean;
    collectRoles?: boolean;
  };
  send?: {
    mode?: InviteSendMode;
    tokenTtlMs?: number;
  };
  accept?: {
    alreadyAcceptedRedirectUrl?: string;
    freshLoginRequired?: boolean;
    loginUrl?: string;
    showConfirmation?: boolean;
    confirmationMessage?: string;
  };
  cancellation?: {
    allowed?: boolean;
  };
  audit?: {
    enabled?: boolean;
  };
}

/**
 * Fully-resolved view used by the workflow at runtime — every nested group is
 * always populated by `mergeInviteOpts`, so schema conditions can read
 * `ctx.opts.<group>.<flag>` directly without optional chaining.
 */
export interface ResolvedInviteWorkflowOpts {
  adminForm: {
    collectFirstName: boolean;
    collectLastName: boolean;
    collectRoles: boolean;
  };
  send: {
    mode: InviteSendMode;
    tokenTtlMs: number;
  };
  accept: {
    alreadyAcceptedRedirectUrl: string;
    freshLoginRequired: boolean;
    loginUrl: string;
    showConfirmation: boolean;
    confirmationMessage: string;
  };
  cancellation: {
    allowed: boolean;
  };
  audit: {
    enabled: boolean;
  };
}

/**
 * Deep-merge defaults with the user-supplied nested pojo. Each group has its
 * own `{ ...defaults, ...input }` line — small enough that pulling in lodash
 * would be silly.
 */
export function mergeInviteOpts(opts: InviteWorkflowOpts = {}): ResolvedInviteWorkflowOpts {
  return {
    adminForm: {
      collectFirstName: true,
      collectLastName: true,
      collectRoles: true,
      ...opts.adminForm,
    },
    send: {
      mode: "email",
      tokenTtlMs: DEFAULT_INVITE_TOKEN_TTL_MS,
      ...opts.send,
    },
    accept: {
      alreadyAcceptedRedirectUrl: "/login",
      freshLoginRequired: false,
      loginUrl: "/login",
      showConfirmation: true,
      confirmationMessage: "Your account has been created.",
      ...opts.accept,
    },
    cancellation: {
      allowed: true,
      ...opts.cancellation,
    },
    audit: {
      enabled: true,
      ...opts.audit,
    },
  };
}

/**
 * Backwards-compat alias for the prior input-shape name. Consumers who type
 * their `prepareUser()` override against this still compile.
 */
export type InvitePrepareUserInput = PreparedUserInput;

/**
 * Re-export `UserCredentials` shape used by the `duplicateCheck` override
 * signature — keeps the import surface clean for consumer subclasses.
 */
export type DuplicateCheckUserShape = UserCredentials;
