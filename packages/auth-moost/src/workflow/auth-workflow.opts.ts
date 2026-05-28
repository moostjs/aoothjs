/**
 * `AuthWorkflowOpts` — infrastructure-only nested-pojo configuration for the
 * unified `AuthWorkflow` class. Replaces the prior trio
 * (`LoginWorkflowOpts` + `InviteWorkflowOpts` + `RecoveryWorkflowOpts`).
 *
 * Cross-workflow infrastructure defaults (pincode timers, magic-link TTL,
 * loginUrl, totpIssuer) continue to live on the `AuthOpts` DI singleton.
 * Policy continues to live on `protected resolveXxx(ctx)` methods on
 * `AuthWorkflow`. This shape carries only the few workflow-level static
 * knobs (auto-login defaults, device-trust cookie binding) plus the
 * form-schema replacement map.
 */
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";

export interface AuthWorkflowOpts {
  // ── Finalize behavior (cross-flow) ──
  autoLoginOnInvite?: boolean;
  autoLoginOnRecover?: boolean;

  // ── Login-specific infra ──
  deviceTrust?: {
    cookieName?: string;
    ttlMs?: number;
    bindsTo?: "cookie" | "cookie+ip";
  };

  // ── Form schemas ──
  forms?: {
    // Authentication entry
    loginCredentials?: TAtscriptAnnotatedType;
    invite?: TAtscriptAnnotatedType;
    recoveryEmailIdentifier?: TAtscriptAnnotatedType;

    // Channel enrolment (login Phase 3)
    askEmail?: TAtscriptAnnotatedType;
    askPhone?: TAtscriptAnnotatedType;

    // MFA enrolment
    enrollPickMethod?: TAtscriptAnnotatedType;
    enrollAddress?: TAtscriptAnnotatedType;
    enrollConfirm?: TAtscriptAnnotatedType;

    // MFA challenge
    select2fa?: TAtscriptAnnotatedType;
    mfaCode?: TAtscriptAnnotatedType;
    pincode?: TAtscriptAnnotatedType;

    // Password
    setPassword?: TAtscriptAnnotatedType;

    // Profile + consents
    profileComplete?: TAtscriptAnnotatedType;
    termsBump?: TAtscriptAnnotatedType;

    // Session policy
    concurrencyLimit?: TAtscriptAnnotatedType;

    // Recovery
    recoveryPincode?: TAtscriptAnnotatedType;
  };
}

/**
 * Fully-resolved view used by the workflow at runtime — every nested group
 * is populated by the (future) `mergeAuthOpts` so step bodies can read
 * `this.opts.<group>.<field>` without optional chaining. The two
 * auto-login booleans become required after defaults are applied.
 */
export interface ResolvedAuthWorkflowOpts {
  autoLoginOnInvite: boolean;
  autoLoginOnRecover: boolean;
  deviceTrust: {
    cookieName: string;
    ttlMs: number;
    bindsTo: "cookie" | "cookie+ip";
  };
  forms: {
    loginCredentials: TAtscriptAnnotatedType;
    invite: TAtscriptAnnotatedType;
    recoveryEmailIdentifier: TAtscriptAnnotatedType;
    askEmail: TAtscriptAnnotatedType;
    askPhone: TAtscriptAnnotatedType;
    enrollPickMethod: TAtscriptAnnotatedType;
    enrollAddress: TAtscriptAnnotatedType;
    enrollConfirm: TAtscriptAnnotatedType;
    select2fa: TAtscriptAnnotatedType;
    mfaCode: TAtscriptAnnotatedType;
    pincode: TAtscriptAnnotatedType;
    setPassword: TAtscriptAnnotatedType;
    profileComplete: TAtscriptAnnotatedType;
    termsBump: TAtscriptAnnotatedType;
    concurrencyLimit: TAtscriptAnnotatedType;
    recoveryPincode: TAtscriptAnnotatedType;
  };
}
