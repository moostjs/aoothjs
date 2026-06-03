/**
 * `AuthWorkflowOpts` — infrastructure-only nested-pojo configuration for the
 * unified `AuthWorkflow` class. Replaces the prior trio
 * (`LoginWorkflowOpts` + `InviteWorkflowOpts` + `RecoveryWorkflowOpts`).
 *
 * Cross-workflow infrastructure defaults that used to live on a separate
 * `AuthOpts` DI singleton (pincode timers, magic-link TTL, loginUrl,
 * totpIssuer) have been merged in. Policy continues to live on
 * `protected resolveXxx(ctx)` methods on `AuthWorkflow`.
 */
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";

export interface AuthWorkflowOpts {
  // ── Finalize behavior (cross-flow) ──
  autoLoginOnInvite?: boolean;
  autoLoginOnRecover?: boolean;

  // ── Cross-workflow infra ──
  /** Pincode infrastructure shared by login MFA, invite MFA, and recovery OTP. */
  mfa?: {
    pincodeLength?: number;
    pincodeTtlMs?: number;
    pincodeResendTimeoutMs?: number;
    /** Max wrong-code submissions per minted pincode before the code is invalidated and the user must request a fresh one. Defaults to 5. */
    pincodeMaxAttempts?: number;
  };
  /** Persisted-state TTL for the recovery flow — caps the window between OTP request and password reset. Applied at every recovery-side `requireInput` pause via the wf engine's `output.expires`. */
  recoveryStateTtlMs?: number;
  /** Canonical login URL — used by invite (post-accept redirect) and recovery (abort-to-login + post-reset redirect) as the resolver-default loginUrl. */
  loginUrl?: string;
  /** TOTP provisioning issuer — used by login MFA and invite MFA enrollment. */
  totpIssuer?: string;

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
    /** Authenticated self-service "change my password" form (current + new + confirm). */
    changePassword?: TAtscriptAnnotatedType;

    // Profile + consents
    termsBump?: TAtscriptAnnotatedType;

    // Session policy
    concurrencyLimit?: TAtscriptAnnotatedType;

    // Recovery
    recoveryPincode?: TAtscriptAnnotatedType;

    // Signup
    /** Self-signup identifier form (`auth/signup/flow` entry pause). */
    signup?: TAtscriptAnnotatedType;
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
  mfa: {
    pincodeLength: number;
    pincodeTtlMs: number;
    pincodeResendTimeoutMs: number;
    pincodeMaxAttempts: number;
  };
  recoveryStateTtlMs: number;
  loginUrl: string;
  totpIssuer: string;
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
    changePassword: TAtscriptAnnotatedType;
    termsBump: TAtscriptAnnotatedType;
    concurrencyLimit: TAtscriptAnnotatedType;
    recoveryPincode: TAtscriptAnnotatedType;
    signup: TAtscriptAnnotatedType;
  };
}
