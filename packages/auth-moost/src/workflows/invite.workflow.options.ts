/**
 * `InviteWorkflowOpts` — nested-pojo configuration for `InviteWorkflow`.
 *
 * Phase 4 of the workflow OOP-reshape (see TASKS.md): the options class +
 * callbacks have been replaced by a nested-object pojo passed as the first
 * ctor arg, plus protected methods on `InviteWorkflow` that consumers override
 * via subclassing. Defaults are applied by `mergeInviteOpts(opts)` so step
 * bodies + schema conditions can read `ctx.opts.<group>.<flag>` without `?.`.
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
import type { MfaTransport } from "./login.workflow.options";

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
  adminForm?: {
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
  /**
   * MFA enrollment during the accept tail.
   *   - `'required'` — invitee MUST enroll a second factor BEFORE activation.
   *   - `'optional'` — invitee is prompted but may `skip` the enrollment form.
   *   - `'disabled'` — enrollment loop is skipped entirely.
   */
  mfa?: {
    mode?: "required" | "optional" | "disabled";
    transports?: MfaTransport[];
    pincodeTtlMs?: number;
    pincodeLength?: number;
    /** TOTP provisioning issuer (rendered in the authenticator app). Default: 'aooth'. */
    issuer?: string;
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
 * always populated by `mergeInviteOpts`, so schema conditions can read
 * `ctx.opts.<group>.<flag>` directly without optional chaining.
 */
export interface ResolvedInviteWorkflowOpts {
  adminForm: {
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
  mfa: {
    mode: "required" | "optional" | "disabled";
    transports: MfaTransport[];
    pincodeTtlMs: number;
    pincodeLength: number;
    issuer: string;
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
    adminForm: {
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
    mfa: {
      mode: "optional",
      transports: ["sms", "email", "totp"],
      pincodeTtlMs: 5 * 60 * 1000,
      pincodeLength: 6,
      issuer: "aooth",
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
