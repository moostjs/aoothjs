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

  // ── Invite admin ──
  /**
   * Closed universe of role ids the admin invite form may assign. NOT policy
   * (it does not vary per request) — it is static configuration, like `forms`.
   * The base `getAvailableRoles()` intersects this list with the CURRENT
   * inviter's ARBAC grants (`auth.invite` / `assign:<role>`) at request time,
   * so each inviter is offered — and server-side limited to — only the roles
   * they may actually delegate. If ARBAC is unreachable the list is used
   * verbatim (still a CLOSED whitelist, never fail-open).
   *
   * Leave unset to keep the legacy behaviour (NO whitelist — any role can be
   * assigned). When unset, `getAvailableRoles` is not overridden, and
   * `allowAnyInviteRole` is not set, a one-time warning fires the first time
   * the admin invite flow runs.
   */
  invitableRoles?: string[];
  /**
   * Acknowledge an intentionally-unrestricted invite form — silences the
   * "invite role whitelist is OFF" warning when `invitableRoles` is unset and
   * `getAvailableRoles` is not overridden. Records intent only; it does not by
   * itself relax or tighten enforcement. Default `false`.
   */
  allowAnyInviteRole?: boolean;

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
  /**
   * Device RECOGNITION infra — the always-on `seenDevices` ledger + cookie
   * that suppress the "new sign-in" notification on devices the user has
   * already logged in from. Strictly a notification suppressor, NOT an MFA
   * bypass (that is `deviceTrust`, which stays opt-in and strict).
   * Cookie-only binding by design — recognition is pure noise control, so it
   * never binds to IP (IP churn must not re-trigger the email).
   *
   * `cookieName` defaults to `<deviceTrust.cookieName>_seen` so a consumer
   * renaming the trust cookie gets a matching recognition name for free.
   * No policy flags here — the on/off gate is the existing
   * `resolveFinalize().notifyNewDevice` policy.
   */
  deviceRecognition?: {
    cookieName?: string;
    ttlMs?: number;
    /** Cap on the per-user `seenDevices` ledger — LRU-evicted beyond it. */
    maxDevices?: number;
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
    /** TOTP QR step — shown before the code-entry pause (manage + opt-in). */
    enrollTotpQr?: TAtscriptAnnotatedType;
    enrollConfirm?: TAtscriptAnnotatedType;

    // Manage-MFA (standalone authenticated flow)
    /** Manage-MFA menu (Add / Change / Remove) shown after step-up. */
    manageMfa?: TAtscriptAnnotatedType;
    /** Confirm-removal pause for the manage-MFA "Remove" action. */
    removeMfaConfirm?: TAtscriptAnnotatedType;
    /** Password re-auth — step-up fallback when no factor is MFA-challengeable. */
    passwordReauth?: TAtscriptAnnotatedType;
    /** Step-up dispatch consent — "we'll send a code to ma•••@x" notice before the step-up pincode send. */
    stepUpConfirm?: TAtscriptAnnotatedType;

    // MFA challenge
    select2fa?: TAtscriptAnnotatedType;
    mfaCode?: TAtscriptAnnotatedType;
    pincode?: TAtscriptAnnotatedType;

    // Password
    setPassword?: TAtscriptAnnotatedType;
    /** Authenticated self-service "change my password" form (current + new + confirm). */
    changePassword?: TAtscriptAnnotatedType;

    // Federated needs-link proof-of-control (interactive completion)
    /** Password-proof form rendered by `prove-control` when the matched account has a real password. */
    proveControl?: TAtscriptAnnotatedType;
    /** OTP-proof form rendered by `prove-control` when the matched account is passwordless. */
    proveControlOtp?: TAtscriptAnnotatedType;

    // Profile + consents
    termsBump?: TAtscriptAnnotatedType;

    // Session policy
    concurrencyLimit?: TAtscriptAnnotatedType;

    // Recovery
    recoveryPincode?: TAtscriptAnnotatedType;

    // Signup
    /** Self-signup identifier form (`auth/signup/flow` entry pause). */
    signup?: TAtscriptAnnotatedType;

    // Authorization server
    /** Consent prompt shown before `mint-authz-code` mints an auth code (AUTH-SERVER.md §6). */
    authzConsent?: TAtscriptAnnotatedType;
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
  invitableRoles: string[];
  allowAnyInviteRole: boolean;
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
  deviceRecognition: {
    cookieName: string;
    ttlMs: number;
    maxDevices: number;
  };
  forms: {
    loginCredentials: TAtscriptAnnotatedType;
    invite: TAtscriptAnnotatedType;
    recoveryEmailIdentifier: TAtscriptAnnotatedType;
    askEmail: TAtscriptAnnotatedType;
    askPhone: TAtscriptAnnotatedType;
    enrollPickMethod: TAtscriptAnnotatedType;
    enrollAddress: TAtscriptAnnotatedType;
    enrollTotpQr: TAtscriptAnnotatedType;
    enrollConfirm: TAtscriptAnnotatedType;
    manageMfa: TAtscriptAnnotatedType;
    removeMfaConfirm: TAtscriptAnnotatedType;
    passwordReauth: TAtscriptAnnotatedType;
    stepUpConfirm: TAtscriptAnnotatedType;
    select2fa: TAtscriptAnnotatedType;
    mfaCode: TAtscriptAnnotatedType;
    pincode: TAtscriptAnnotatedType;
    setPassword: TAtscriptAnnotatedType;
    changePassword: TAtscriptAnnotatedType;
    proveControl: TAtscriptAnnotatedType;
    proveControlOtp: TAtscriptAnnotatedType;
    termsBump: TAtscriptAnnotatedType;
    concurrencyLimit: TAtscriptAnnotatedType;
    recoveryPincode: TAtscriptAnnotatedType;
    signup: TAtscriptAnnotatedType;
    authzConsent: TAtscriptAnnotatedType;
  };
}
