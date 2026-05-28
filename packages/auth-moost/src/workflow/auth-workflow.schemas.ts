import type { TWorkflowSchema } from "@moostjs/event-wf";

import type { AuthWfCtx } from "./auth-workflow.ctx";

/**
 * Canonical OTP send-then-check pair. Used by:
 * - Login's MFA-loop SMS/email challenge sub-branch (the outer MFA while provides iteration)
 * - Recovery's OTP while-loop (provides its own iteration)
 *
 * The step bodies are flow-agnostic — they read `ctx.mfa?.method` to pick form / target / alt-actions.
 * The pair is intentionally tiny but worth extracting: it encodes the "send if no pin, then check"
 * sequencing as one canonical pattern; changes to the pattern propagate to both call sites.
 */
export const pincodeSendCheckPair: TWorkflowSchema<AuthWfCtx> = [
  { id: "pincode-send", condition: (ctx) => !ctx.pin },
  { id: "pincode-check" },
];

/**
 * Shared MFA loop — challenge OR enrol. Used by login.flow + invite.start.
 * Loop exits when `ctx.otp.verified` flips true — set by ANY of: pincode-check (SMS/email challenge),
 * totp-check (TOTP challenge), enroll-confirm (forced enrolment of a new method, since enrol-confirm
 * verifies control of the new factor via pincode or TOTP).
 *
 * For invite users (zero enrolled methods), the enrol trio fires and its confirm step sets
 * `otp.verified=true`. For login users with enrolled methods, the challenge branches set it directly.
 */
export const mfaLoopSchema: TWorkflowSchema<AuthWfCtx> = [
  { id: "prepare-mfa" },
  {
    while: (ctx) => ctx.mfaPolicy?.mode !== "disabled" && !ctx.otp?.verified,
    steps: [
      {
        id: "check-trusted-device",
        condition: (ctx) =>
          !ctx.otp?.verified && !!ctx.deviceTrust?.enabled && ctx.deviceTrust.skipsMfa,
      },
      { id: "load-enrolled-mfa-methods", condition: (ctx) => !ctx.otp?.verified },
      { id: "select-mfa-method", condition: (ctx) => !ctx.otp?.verified },
      {
        id: "select-2fa",
        condition: (ctx) =>
          !ctx.otp?.verified && !ctx.mfa?.method && (ctx.mfa?.enrolledMethods?.length ?? 0) > 1,
      },
      // SMS/email challenge pair — UNIFIED step bodies (also used by recovery's OTP loop).
      // `ctx.mfa.method` set → step body picks MFA-context form (`opts.forms.pincode`).
      {
        condition: (ctx) =>
          !ctx.otp?.verified && (ctx.mfa?.method === "sms" || ctx.mfa?.method === "email"),
        steps: pincodeSendCheckPair,
      },
      // TOTP challenge
      { id: "totp-check", condition: (ctx) => !ctx.otp?.verified && ctx.mfa?.method === "totp" },
      // Forced enrolment trio (fires when user has no enrolled methods)
      {
        condition: (ctx) =>
          !ctx.otp?.verified &&
          (ctx.mfa?.enrolledMethods?.length ?? 0) === 0 &&
          (ctx.mfaPolicy?.availableTransports?.length ?? 0) > 0,
        steps: [
          { id: "enroll-pick-method", condition: (ctx) => !ctx.mfaEnroll?.method },
          {
            id: "enroll-address",
            condition: (ctx) =>
              !!ctx.mfaEnroll?.method &&
              (ctx.mfaEnroll.method === "sms" || ctx.mfaEnroll.method === "email") &&
              !ctx.mfaEnroll.address,
          },
          {
            id: "enroll-confirm",
            condition: (ctx) =>
              !!ctx.mfaEnroll?.method &&
              (ctx.mfaEnroll.method === "totp" || !!ctx.mfaEnroll.address) &&
              !ctx.mfaEnroll.done,
          },
        ],
      },
      // Risk step-up — may clear otp.verified to re-arm the loop
      {
        id: "risk-step-up",
        condition: (ctx) => !!ctx.otp?.verified && !ctx.session?.riskStepUpEvaluated,
      },
    ],
  },
];

/**
 * Forced password change — used by login.flow + invite.start (NOT recovery — recovery's
 * gating differs: gated directly on `otp.verified`, NOT `newPasswordRequired`).
 */
export const passwordPhaseSchema: TWorkflowSchema<AuthWfCtx> = [
  {
    condition: (ctx) => !!ctx.newPasswordRequired,
    steps: [{ id: "prepare-password-rules" }, { id: "create-password-form" }],
  },
];

/**
 * Batched consent persistence tail — used by all three flows.
 */
export const consentsPersistTailSchema: TWorkflowSchema<AuthWfCtx> = [
  {
    id: "persist-consents",
    condition: (ctx) => (ctx.consents?.pending?.length ?? 0) > 0 && !!ctx.consents?.decidedAt,
  },
];
