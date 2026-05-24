/**
 * `RecoveryWorkflowOpts` — nested-pojo configuration for `RecoveryWorkflow`.
 *
 * Post-`AuthOpts` reshape: cross-workflow infrastructure (magic-link TTL, OTP
 * pincode timers/length) moved onto the shared `AuthOpts` DI provider — see
 * `auth.opts.ts`. What remains here is recovery-specific infrastructure only:
 * the form-schema replacement map. Policy still lives on the `resolveXxx(ctx)`
 * getter surface on `RecoveryWorkflow`.
 */
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";

import {
  EmailIdentifierForm,
  PincodeForm,
  RecoveryFactorForm,
  RecoveryModeSelectForm,
  SetPasswordForm,
} from "../atscript/models/forms.as";

/** Magic-link TTL default — kept as a public constant for harness wiring. */
export const DEFAULT_RECOVERY_TOKEN_TTL_MS = 60 * 60 * 1000;

export type RecoveryDeliveryMode = "magicLink" | "otp" | "choice";
export type RecoveryOtpTransport = "sms" | "email";

export interface RecoveryWorkflowOpts {
  /**
   * Replaceable form schemas. Each field defaults to the corresponding
   * `.as` form shipped under `@aooth/auth-moost/atscript/models`.
   */
  forms?: {
    emailIdentifier?: TAtscriptAnnotatedType;
    pincode?: TAtscriptAnnotatedType;
    recoveryFactor?: TAtscriptAnnotatedType;
    recoveryModeSelect?: TAtscriptAnnotatedType;
    setPassword?: TAtscriptAnnotatedType;
  };
}

/**
 * Fully-resolved view used by the workflow at runtime — every nested group is
 * always populated by `mergeRecoveryOpts`, so step bodies can read
 * `this.opts.<group>.<flag>` directly without optional chaining.
 */
export interface ResolvedRecoveryWorkflowOpts {
  forms: {
    emailIdentifier: TAtscriptAnnotatedType;
    pincode: TAtscriptAnnotatedType;
    recoveryFactor: TAtscriptAnnotatedType;
    recoveryModeSelect: TAtscriptAnnotatedType;
    setPassword: TAtscriptAnnotatedType;
  };
}

/**
 * Deep-merge defaults with the user-supplied nested pojo. Each group has its
 * own `{ ...defaults, ...input }` line — small enough that pulling in lodash
 * would be silly.
 */
export function mergeRecoveryOpts(opts: RecoveryWorkflowOpts = {}): ResolvedRecoveryWorkflowOpts {
  return {
    forms: {
      emailIdentifier: EmailIdentifierForm as unknown as TAtscriptAnnotatedType,
      pincode: PincodeForm as unknown as TAtscriptAnnotatedType,
      recoveryFactor: RecoveryFactorForm as unknown as TAtscriptAnnotatedType,
      recoveryModeSelect: RecoveryModeSelectForm as unknown as TAtscriptAnnotatedType,
      setPassword: SetPasswordForm as unknown as TAtscriptAnnotatedType,
      ...opts.forms,
    },
  };
}
