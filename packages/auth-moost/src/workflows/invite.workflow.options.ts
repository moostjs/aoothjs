/**
 * `InviteWorkflowOpts` — infrastructure-only nested-pojo configuration for
 * `InviteWorkflow`.
 *
 * Phase 5 of the workflow OOP-reshape (Step 2 of the InviteWorkflow refactor):
 * policy fields (`adminForm.collectRoles`, `send.mode`, `accept.*`,
 * `cancellation.allowed`, `audit.enabled`, `mfa.issuer`) have moved off opts
 * and onto protected `resolveXxx(ctx)` getter methods on `InviteWorkflow` (one
 * per group), mirroring `LoginWorkflow`. What remains here is infrastructure
 * only: magic-link TTL, pincode timers/length, and the form schemas. Step
 * bodies + schema conditions read policy from `ctx.<group>` (populated by
 * `prepare-<group>` @Step methods that call the resolvers).
 *
 * Rate limiting will be addressed systematically in a later pass — for now
 * consumers who want a cap wire it themselves at the trigger / HTTP layer.
 * Admin authorization is the trigger route's responsibility (ARBAC).
 */
import type { UserCredentials } from "@aooth/user";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";

import {
  EnrollAddressForm,
  EnrollConfirmForm,
  EnrollPickMethodForm,
  InviteEmailForm,
  InviteForm,
  InviteSendModeForm,
  SetPasswordForm,
} from "../atscript/models/forms.as";
export type { MfaTransport } from "./login.workflow.options";

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
  send?: {
    tokenTtlMs?: number;
  };
  mfa?: {
    pincodeTtlMs?: number;
    /** Per-method resend cooldown for the Phase 3 confirm pincode (sms/email). Default: 60_000. */
    pincodeResendTimeoutMs?: number;
    pincodeLength?: number;
  };
  /**
   * Replaceable form schemas. Each field defaults to the corresponding
   * `.as` form shipped under `@aooth/auth-moost/atscript/models`.
   */
  forms?: {
    enrollAddress?: TAtscriptAnnotatedType;
    enrollConfirm?: TAtscriptAnnotatedType;
    enrollPickMethod?: TAtscriptAnnotatedType;
    invite?: TAtscriptAnnotatedType;
    inviteEmail?: TAtscriptAnnotatedType;
    inviteSendMode?: TAtscriptAnnotatedType;
    setPassword?: TAtscriptAnnotatedType;
  };
}

/**
 * Fully-resolved view used by the workflow at runtime — every nested group is
 * always populated by `mergeInviteOpts`, so step bodies can read
 * `this.opts.<group>.<flag>` directly without optional chaining.
 */
export interface ResolvedInviteWorkflowOpts {
  send: {
    tokenTtlMs: number;
  };
  mfa: {
    pincodeTtlMs: number;
    pincodeResendTimeoutMs: number;
    pincodeLength: number;
  };
  forms: {
    enrollAddress: TAtscriptAnnotatedType;
    enrollConfirm: TAtscriptAnnotatedType;
    enrollPickMethod: TAtscriptAnnotatedType;
    invite: TAtscriptAnnotatedType;
    inviteEmail: TAtscriptAnnotatedType;
    inviteSendMode: TAtscriptAnnotatedType;
    setPassword: TAtscriptAnnotatedType;
  };
}

/**
 * Deep-merge defaults with the user-supplied nested pojo. Each group has its
 * own `{ ...defaults, ...input }` line — small enough that pulling in lodash
 * would be silly.
 */
export function mergeInviteOpts(opts: InviteWorkflowOpts = {}): ResolvedInviteWorkflowOpts {
  return {
    send: {
      tokenTtlMs: DEFAULT_INVITE_TOKEN_TTL_MS,
      ...opts.send,
    },
    mfa: {
      pincodeTtlMs: 5 * 60 * 1000,
      pincodeResendTimeoutMs: 60_000,
      pincodeLength: 6,
      ...opts.mfa,
    },
    forms: {
      enrollAddress: EnrollAddressForm as unknown as TAtscriptAnnotatedType,
      enrollConfirm: EnrollConfirmForm as unknown as TAtscriptAnnotatedType,
      enrollPickMethod: EnrollPickMethodForm as unknown as TAtscriptAnnotatedType,
      invite: InviteForm as unknown as TAtscriptAnnotatedType,
      inviteEmail: InviteEmailForm as unknown as TAtscriptAnnotatedType,
      inviteSendMode: InviteSendModeForm as unknown as TAtscriptAnnotatedType,
      setPassword: SetPasswordForm as unknown as TAtscriptAnnotatedType,
      ...opts.forms,
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
