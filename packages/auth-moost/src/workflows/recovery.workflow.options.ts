/**
 * `RecoveryWorkflowOpts` — nested-pojo configuration for `RecoveryWorkflow`.
 *
 * Phase 3 of the workflow OOP-reshape (see TASKS.md): the options class +
 * callbacks have been replaced by a nested-object pojo passed as the first
 * ctor arg, plus protected methods on `RecoveryWorkflow` that consumers
 * override via subclassing. Defaults are applied by `mergeRecoveryOpts(opts)`
 * so step bodies + schema conditions can read `ctx.opts.<group>.<flag>`
 * without `?.`.
 *
 * Defaults preserve today's behavior: one-step magic-link flow with anti-
 * enumeration short-circuit on unknown email, fresh-login redirect after
 * reset. (Rate-limit was dropped from the workflow surface — consumers who
 * want a cap wire it themselves at the trigger / HTTP layer.)
 */

/** Magic-link TTL default — also used as the persisted wf-state token TTL. */
export const DEFAULT_RECOVERY_TOKEN_TTL_MS = 60 * 60 * 1000;

export type RecoveryDeliveryMode = "magicLink" | "otp" | "choice";
export type RecoveryOtpTransport = "sms" | "email";

export interface RecoveryWorkflowOpts {
  delivery?: {
    mode?: RecoveryDeliveryMode;
    magicLinkTtlMs?: number;
    otp?: {
      transports?: RecoveryOtpTransport[];
      codeLength?: number;
      ttlMs?: number;
      resendCooldownMs?: number;
    };
  };
  preReset?: {
    requireKnownFactor?: boolean;
  };
  postReset?: {
    revokeAllSessions?: boolean;
    freshLoginRequired?: boolean;
    loginUrl?: string;
  };
  altActions?: {
    backToLogin?: boolean;
  };
  audit?: {
    enabled?: boolean;
  };
}

/**
 * Fully-resolved view used by the workflow at runtime — every nested group is
 * always populated by `mergeRecoveryOpts`, so schema conditions can read
 * `ctx.opts.<group>.<flag>` directly without optional chaining.
 */
export interface ResolvedRecoveryWorkflowOpts {
  delivery: {
    mode: RecoveryDeliveryMode;
    magicLinkTtlMs: number;
    otp: {
      transports: RecoveryOtpTransport[];
      codeLength: number;
      ttlMs: number;
      resendCooldownMs: number;
    };
  };
  preReset: {
    requireKnownFactor: boolean;
  };
  postReset: {
    revokeAllSessions: boolean;
    freshLoginRequired: boolean;
    loginUrl: string;
  };
  altActions: {
    backToLogin: boolean;
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
export function mergeRecoveryOpts(opts: RecoveryWorkflowOpts = {}): ResolvedRecoveryWorkflowOpts {
  const inputDelivery = opts.delivery ?? {};
  const inputOtp = inputDelivery.otp ?? {};
  return {
    delivery: {
      mode: "magicLink",
      magicLinkTtlMs: DEFAULT_RECOVERY_TOKEN_TTL_MS,
      ...inputDelivery,
      otp: {
        transports: ["email"],
        codeLength: 6,
        ttlMs: 5 * 60_000,
        resendCooldownMs: 60_000,
        ...inputOtp,
      },
    },
    preReset: {
      requireKnownFactor: false,
      ...opts.preReset,
    },
    postReset: {
      revokeAllSessions: true,
      freshLoginRequired: true,
      loginUrl: "/login",
      ...opts.postReset,
    },
    altActions: {
      backToLogin: true,
      ...opts.altActions,
    },
    audit: {
      enabled: true,
      ...opts.audit,
    },
  };
}
