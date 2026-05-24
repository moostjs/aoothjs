/**
 * `RecoveryWorkflowOpts` — nested-pojo configuration for `RecoveryWorkflow`.
 *
 * Post-resolver reshape: this is infrastructure-only (magic-link TTL, OTP
 * timers/length, replaceable forms). Policy (delivery mode + OTP transports,
 * preReset, postReset, altActions, audit) moved to `resolveXxx(ctx)` getter
 * overrides on `RecoveryWorkflow` — see `RecoveryPolicyOverrides`.
 */
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";

import {
  EmailIdentifierForm,
  PincodeForm,
  RecoveryFactorForm,
  RecoveryModeSelectForm,
  SetPasswordForm,
} from "../atscript/models/forms.as";

/** Magic-link TTL default — also used as the persisted wf-state token TTL. */
export const DEFAULT_RECOVERY_TOKEN_TTL_MS = 60 * 60 * 1000;

export type RecoveryDeliveryMode = "magicLink" | "otp" | "choice";
export type RecoveryOtpTransport = "sms" | "email";

export interface RecoveryWorkflowOpts {
  delivery?: {
    magicLinkTtlMs?: number;
    otp?: {
      codeLength?: number;
      ttlMs?: number;
      resendCooldownMs?: number;
    };
  };
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
  delivery: {
    magicLinkTtlMs: number;
    otp: {
      codeLength: number;
      ttlMs: number;
      resendCooldownMs: number;
    };
  };
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
  const inputDelivery = opts.delivery ?? {};
  const inputOtp = inputDelivery.otp ?? {};
  return {
    delivery: {
      magicLinkTtlMs: DEFAULT_RECOVERY_TOKEN_TTL_MS,
      ...inputDelivery,
      otp: {
        codeLength: 6,
        ttlMs: 5 * 60_000,
        resendCooldownMs: 60_000,
        ...inputOtp,
      },
    },
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
