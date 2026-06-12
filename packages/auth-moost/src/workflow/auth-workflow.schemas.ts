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
  // `!ctx.aborted` lets `pincode-send` terminate the loop in-place: registered-
  // channel recovery (M2) aborts here when the confirmed method vanished between
  // `request` and this send (the request→send TOCTOU), staging the generic
  // anti-enumeration finish — without this guard `pincode-check` would run next
  // and overwrite that finish with a form pause. Login/MFA never set `aborted`
  // mid-pair, so the gate is a no-op there.
  { id: "pincode-check", condition: (ctx) => !ctx.aborted },
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
/**
 * The MFA enrolment trio — `enroll-pick-method` → `enroll-address` →
 * `enroll-confirm`. Shared verbatim by login/invite's forced first-time
 * enrolment (inside {@link mfaLoopSchema}) and the standalone add-mfa flow; the
 * only thing that differs between call sites is the OUTER gate (no-methods vs
 * un-enrolled-remainder), so the trio's own internal gating lives here once.
 */
export const enrollTrioSteps: TWorkflowSchema<AuthWfCtx> = [
  { id: "enroll-pick-method", condition: (ctx) => !ctx.mfaEnroll?.method },
  {
    id: "enroll-address",
    condition: (ctx) =>
      !!ctx.mfaEnroll?.method &&
      (ctx.mfaEnroll.method === "sms" || ctx.mfaEnroll.method === "email") &&
      !ctx.mfaEnroll.address,
  },
  // TOTP only — show the QR + manual secret on its OWN pause before code entry,
  // so the user scans first and types the code on the next screen. Shared by
  // both trio call sites (add-mfa AND login/invite first-time opt-in).
  {
    id: "enroll-totp-qr",
    condition: (ctx) => ctx.mfaEnroll?.method === "totp" && !ctx.mfaEnroll.qrSeen,
  },
  // The ONLY sms/email pincode dispatch of the trio — its own step (the
  // canonical "send if no pin" gate, mirroring `pincodeSendCheckPair`) so BOTH
  // address paths flow through it: collected by `enroll-address` on the previous
  // engine pass, or pre-seeded by a consumer (e.g. `resolveAccept` staging the
  // invited email), which skips `enroll-address` entirely — collection AND
  // dispatch — and previously stranded the user on a code form no code was ever
  // sent for. `!ctx.pin` makes re-pauses send-once; `resolveEnrollPreConfirmed`
  // may skip the dispatch altogether (verified-by-construction address).
  {
    id: "enroll-send",
    condition: (ctx) =>
      (ctx.mfaEnroll?.method === "sms" || ctx.mfaEnroll?.method === "email") &&
      !!ctx.mfaEnroll.address &&
      !ctx.mfaEnroll.done &&
      !ctx.mfaEnroll.preConfirmed &&
      !ctx.pin,
  },
  {
    id: "enroll-confirm",
    condition: (ctx) =>
      !!ctx.mfaEnroll?.method &&
      (ctx.mfaEnroll.method === "totp" ? !!ctx.mfaEnroll.qrSeen : !!ctx.mfaEnroll.address) &&
      !ctx.mfaEnroll.done,
  },
  // After a channel is confirmed (`mfaEnroll.done`), promote the verified
  // email/phone into its login handle. Default no-op; turns ON when the
  // consumer overrides `resolvePromoteHandleField`. Fires once per flow
  // (guarded by `promoteToHandleDone`). Shared by both trio call sites —
  // add-mfa AND login/invite forced first-time enrolment.
  {
    id: "promote-to-handle",
    condition: (ctx) => !!ctx.mfaEnroll?.done && !ctx.promoteToHandleDone,
  },
];

/**
 * MFA step-up loop — challenge an EXISTING confirmed factor (no enrolment).
 * Reuses the login challenge steps verbatim, but DELIBERATELY omits
 * `check-trusted-device` and `risk-step-up`: in a management context a trusted
 * device must NOT be allowed to bypass the step-up (that is the whole point of
 * re-verifying before letting the user change/remove a factor). It ADDS one
 * manage-only step the login loop doesn't have: `manage-stepup-confirm`, the
 * explicit-consent notice before the sms/email pincode dispatch (login is
 * mid-authentication, so its zero-click dispatch stays). Loop exits when
 * a challenge step flips `ctx.otp.verified`. Used by the standalone add/manage-
 * MFA flow, guarded by `ctx.addMfa.stepUpRequired` (set only when the user has
 * ≥1 confirmed method).
 *
 * The `while` also breaks on `ctx.aborted` so a cancel/exit on the challenge
 * form (the `manage-stepup-confirm` consent cancel, `pincode-check`'s `exit`
 * alt-action, or a customer-added Back on the MFA challenge) terminates the
 * loop instead of spinning the engine's guardless inner loop forever. Every
 * `addMfaFlow` step after this sub-schema is gated off `ctx.aborted` (or on
 * `otp.verified`, which an aborted step-up never set), so the run falls
 * through to `finish-add-mfa` (the cancelled terminal) — fail CLOSED: the
 * user reaches no management write without a fresh challenge. (Note: login's
 * `mfaLoopSchema` intentionally does NOT carry this guard — exiting login's
 * challenge loop without a paired failure terminal would risk issuing a
 * session, so that one stays fail-closed via the engine's no-progress stall
 * instead.)
 */
export const mfaStepUpLoop: TWorkflowSchema<AuthWfCtx> = [
  {
    while: (ctx) => !ctx.otp?.verified && !ctx.aborted,
    steps: [
      { id: "load-enrolled-mfa-methods", condition: (ctx) => !ctx.otp?.verified },
      { id: "select-mfa-method", condition: (ctx) => !ctx.otp?.verified },
      {
        id: "select-2fa",
        condition: (ctx) =>
          !ctx.otp?.verified && !ctx.mfa?.method && (ctx.mfa?.enrolledMethods?.length ?? 0) > 1,
      },
      // Explicit-consent pause BEFORE the sms/email dispatch — opening the
      // manage dialog must not email/text the user as a side effect (the
      // auto-picked single-factor / default-factor paths reach `pincode-send`
      // with zero user interaction otherwise). Skipped once consent exists:
      // a `select-2fa` pick counts (choosing "Email (ma•••@x)" IS consent),
      // and `resolveStepUpConfirmBeforeSend` can opt the deployment out.
      // `!ctx.pin` keeps it from re-firing once a code is already in flight.
      // TOTP needs no consent — its challenge dispatches nothing.
      {
        id: "manage-stepup-confirm",
        condition: (ctx) =>
          !ctx.otp?.verified &&
          (ctx.mfa?.method === "sms" || ctx.mfa?.method === "email") &&
          !ctx.addMfa?.stepUpConfirmed &&
          !ctx.pin,
      },
      // A consent-form `cancel` sets `aborted` with `mfa.method` still bound —
      // without this break the pincode pair below would dispatch the very code
      // the user just declined, in the same engine pass.
      { break: (ctx) => !!ctx.aborted },
      {
        condition: (ctx) =>
          !ctx.otp?.verified && (ctx.mfa?.method === "sms" || ctx.mfa?.method === "email"),
        steps: pincodeSendCheckPair,
      },
      { id: "totp-check", condition: (ctx) => !ctx.otp?.verified && ctx.mfa?.method === "totp" },
    ],
  },
];

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
        steps: enrollTrioSteps,
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
