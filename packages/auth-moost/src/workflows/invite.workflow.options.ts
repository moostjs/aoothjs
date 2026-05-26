/**
 * `InviteWorkflowOpts` — infrastructure-only nested-pojo configuration for
 * `InviteWorkflow`.
 *
 * Post-`AuthOpts` reshape: cross-workflow infrastructure (magic-link TTL,
 * pincode timers/length, TOTP issuer) moved onto the shared `AuthOpts` DI
 * provider — see `auth.opts.ts`. What remains here is invite-specific
 * infrastructure only: the form-schema replacement map. Policy still lives on
 * the `resolveXxx(ctx)` getter surface on `InviteWorkflow`.
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
  InviteForm,
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
  roles: string[];
  /** Admin's `username` (`useAuth().getAuthContext()?.userId` at invite time). */
  invitedBy?: string;
}

/** Return value of {@link InviteWorkflow.duplicateCheck}. */
export type DuplicateAction = "allow" | "reject" | "reuseAsReInvite";

export interface InviteWorkflowOpts {
  /**
   * Replaceable form schemas. Each field defaults to the corresponding
   * `.as` form shipped under `@aooth/auth-moost/atscript/models`.
   */
  forms?: {
    enrollAddress?: TAtscriptAnnotatedType;
    enrollConfirm?: TAtscriptAnnotatedType;
    enrollPickMethod?: TAtscriptAnnotatedType;
    invite?: TAtscriptAnnotatedType;
    setPassword?: TAtscriptAnnotatedType;
  };
}

/**
 * Fully-resolved view used by the workflow at runtime — every nested group is
 * always populated by `mergeInviteOpts`, so step bodies can read
 * `this.opts.<group>.<flag>` directly without optional chaining.
 */
export interface ResolvedInviteWorkflowOpts {
  forms: {
    enrollAddress: TAtscriptAnnotatedType;
    enrollConfirm: TAtscriptAnnotatedType;
    enrollPickMethod: TAtscriptAnnotatedType;
    invite: TAtscriptAnnotatedType;
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
    forms: {
      enrollAddress: EnrollAddressForm as unknown as TAtscriptAnnotatedType,
      enrollConfirm: EnrollConfirmForm as unknown as TAtscriptAnnotatedType,
      enrollPickMethod: EnrollPickMethodForm as unknown as TAtscriptAnnotatedType,
      invite: InviteForm as unknown as TAtscriptAnnotatedType,
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
