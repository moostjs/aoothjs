/**
 * Per-option behaviour tests for `RecoveryWorkflow` — one (or two) cases per
 * policy / infra knob flagged in WF_RECOVERY.md §"Tasks" item #8.
 *
 * Anti-test guard (Rule 9): every test below asserts an observable outcome
 * that DIRECTLY depends on the flag under test — i.e. flipping the flag (or
 * removing the relevant production-code branch) would make the test fail.
 * No "step count == N" tests; no full-body snapshots; assertions target the
 * response payload, captured side effects (emails, sms, audit events,
 * revoked tokens), and the response shape parity required by anti-enumeration.
 *
 * Post-resolver reshape: policy (`delivery.mode` / `delivery.otpTransports`,
 * `preReset`, `postReset`, `altActions`, `audit`) moved from
 * `RecoveryWorkflowOpts` onto `resolveXxx(ctx)` getters. Tests flip the
 * matching group via `recoveryPolicy` rather than `recoveryOpts`. The
 * sender-absence runtime check still fires at first `deliver()` call;
 * empty-otpTransports-when-otp-mode now throws at `prepare-delivery` step time
 * (the ctx-driven equivalent of the old construction-time `validateOpts`).
 *
 * Callbacks (`emailToUserId`) remain `protected` methods on `RecoveryWorkflow`.
 * Tests that exercise those callbacks build a tiny subclass and pass it via
 * `recoveryWorkflowClass`. The harness has a built-in `emailToUserId` shortcut.
 */
import { AuthCredential } from "@aooth/auth";
import { generateTotpCode, generateTotpSecret, ppHasMinLength, UserService } from "@aooth/user";
import { Controller, Inherit } from "moost";
import { describe, expect, it } from "vite-plus/test";

import { AuthOpts } from "../auth.opts";
import { ConsentStore } from "../consent.store";
import {
  RecoveryWorkflow,
  type RecoveryWfCtx,
  type RecoveryWorkflowOpts,
} from "../workflows/index";
import { expectFinished, prepareWfApp, seedActiveUser } from "./workflow-utils";

/**
 * Build a `RecoveryWorkflow` subclass with optional protected-method overrides.
 * Mirrors the canonical consumer pattern — re-decorates the class and
 * re-declares the ctor so DI metadata regenerates.
 */
function makeRecoverySubclass(
  overrides: Partial<{
    emailToUserId: (this: RecoveryWorkflow, email: string) => Promise<string | null>;
    verifyRecoveryFactor: (
      this: RecoveryWorkflow,
      input: { factor: string; value: string; ctx: RecoveryWfCtx },
    ) => Promise<boolean>;
  }>,
): typeof RecoveryWorkflow {
  @Inherit()
  @Controller("auth/recovery")
  class SubclassedRecovery extends RecoveryWorkflow {
    constructor(
      opts: RecoveryWorkflowOpts,
      users: UserService,
      auth: AuthCredential,
      authOpts: AuthOpts,
      consentStore: ConsentStore,
    ) {
      super(opts, users, auth, authOpts, consentStore);
    }
    protected override async emailToUserId(email: string): Promise<string | null> {
      return overrides.emailToUserId
        ? overrides.emailToUserId.call(this, email)
        : super.emailToUserId(email);
    }
    protected override async verifyRecoveryFactor(input: {
      factor: string;
      value: string;
      ctx: RecoveryWfCtx;
    }): Promise<boolean> {
      return overrides.verifyRecoveryFactor
        ? overrides.verifyRecoveryFactor.call(this, input)
        : super.verifyRecoveryFactor(input);
    }
  }
  return SubclassedRecovery;
}

/** Drive a magic-link recovery to the `recovery-set-password` form and return the wfs token. */
async function driveMagicLinkToSetPassword(
  app: Awaited<ReturnType<typeof prepareWfApp>>,
  email: string,
): Promise<{ wfs: string }> {
  const r1 = await app.trigger({ wfid: "auth/recovery/flow" });
  await app.trigger({ wfs: r1.body?.wfs as string, input: { email } });
  const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
  const r3 = await app.resumeViaQuery(token);
  return { wfs: r3.body?.wfs as string };
}

/** Drive an OTP recovery to the `recovery-check-otp` form and return wfs + the captured code. */
async function driveOtpToCheck(
  app: Awaited<ReturnType<typeof prepareWfApp>>,
  email: string,
): Promise<{ wfs: string; code: string }> {
  const r1 = await app.trigger({ wfid: "auth/recovery/flow" });
  const r2 = await app.trigger({ wfs: r1.body?.wfs as string, input: { email } });
  const last = app.emails[app.emails.length - 1];
  if (!last?.code) throw new Error(`expected pincode email, got ${JSON.stringify(last)}`);
  return { wfs: r2.body?.wfs as string, code: last.code };
}

describe("RecoveryWorkflow — runtime validators (fail loud)", () => {
  // Post-reshape: sender absence is enforced at the first `deliver()` call;
  // empty-otpTransports-when-otp-mode is enforced at `prepare-delivery` step
  // time (since policy is now ctx-driven, not construction-time).

  it("delivery.mode 'otp' + otpTransports ['sms'] WITHOUT SmsSender → runtime throw at deliver()", async () => {
    const app = await prepareWfApp({
      recoveryPolicy: {
        delivery: { mode: "otp", otpTransports: ["sms"] },
      },
      registerSmsSender: false,
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    const r1 = await app.trigger({ wfid: "auth/recovery/flow" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "alice@test.com" },
    });
    expect(r2.status).toBe(500);
    expect(JSON.stringify(r2.body)).toMatch(/SmsSender/);
  });

  it("delivery.mode 'otp' + empty otpTransports → fail loud at prepare-delivery step", async () => {
    // Post-reshape: the empty-transports check moved off construction-time
    // `validateOpts` (policy left opts) onto the `prepare-delivery` step
    // body (the ctx slot is set inside `applyResolvedDelivery`). Earlier
    // failure surface than a per-request 500 on `deliver()`; same fail-loud
    // intent — the workflow now refuses to advance instead of corrupting
    // state.
    const app = await prepareWfApp({
      recoveryPolicy: {
        delivery: { mode: "otp", otpTransports: [] },
      },
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    const r1 = await app.trigger({ wfid: "auth/recovery/flow" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "alice@test.com" },
    });
    expect(r2.status).toBe(500);
    expect(JSON.stringify(r2.body)).toMatch(/otpTransports.*empty/);
  });
});

describe("RecoveryWorkflowOpts — deliveryMode otp end-to-end", () => {
  it("otp mode: request → sendOtp (email) → checkOtp (correct code) → setPassword → tokens (auto-login)", async () => {
    const app = await prepareWfApp({
      recoveryPolicy: {
        delivery: { mode: "otp", otpTransports: ["email"] },
        postReset: { freshLoginRequired: false, revokeAllSessions: false, loginUrl: "/login" },
      },
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");

    const { wfs: checkOtpWfs, code } = await driveOtpToCheck(app, "alice@test.com");
    // OTP went via email channel — recovery.pincode event with the code.
    expect(app.emails).toHaveLength(1);
    expect(app.emails[0].kind).toBe("recovery.pincode");
    expect(app.emails[0].code).toBe(code);
    expect(app.sms).toHaveLength(0);

    // Submit the code → advances to setPassword form.
    const r3 = await app.trigger({ wfs: checkOtpWfs, input: { code, rememberDevice: false } });
    expect(r3.body?.wfs).toBeTruthy();
    expect(JSON.stringify(r3.body)).toMatch(/newPassword/);

    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { newPassword: "NewPassword123", confirmPassword: "NewPassword123" },
    });
    // Auto-login terminal returns the buildLoginResponse payload wrapped in the envelope.
    const env4 = expectFinished<{ userId: string; accessToken: string }>(r4);
    expect(env4.data?.userId).toBe("alice@test.com");
    expect(typeof env4.data?.accessToken).toBe("string");

    const ok = await app.users.verifyPassword("alice@test.com", "NewPassword123");
    expect(ok).toBe(true);
  });

  it("otp mode: wrong code → form error 'Invalid code', no advance", async () => {
    const app = await prepareWfApp({
      recoveryPolicy: {
        delivery: { mode: "otp", otpTransports: ["email"] },
      },
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    const { wfs } = await driveOtpToCheck(app, "alice@test.com");
    const r = await app.trigger({ wfs, input: { code: "999999", rememberDevice: false } });
    const errors = r.body?.errors as Record<string, string> | undefined;
    expect(errors?.code).toMatch(/Invalid code/);
    // Still paused at checkOtp form (re-rendered with the error).
    expect(r.body?.wfs).toBeTruthy();
  });

  it("otp resend within cooldown → form error 'wait Ns'; no second email sent", async () => {
    const app = await prepareWfApp({
      recoveryPolicy: {
        delivery: { mode: "otp", otpTransports: ["email"] },
      },
      authOpts: { mfa: { pincodeResendTimeoutMs: 60_000 } },
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    const { wfs } = await driveOtpToCheck(app, "alice@test.com");
    expect(app.emails).toHaveLength(1);

    const r = await app.trigger({ wfs, input: { action: "resend" } });
    const errors = r.body?.errors as Record<string, string> | undefined;
    expect(errors?.__form).toMatch(/wait \d+s/i);
    // No new email sent during the cooldown.
    expect(app.emails).toHaveLength(1);
  });

  it("otp resend after cooldown elapsed → re-sends pincode (second email captured)", async () => {
    const app = await prepareWfApp({
      recoveryPolicy: {
        delivery: { mode: "otp", otpTransports: ["email"] },
      },
      authOpts: { mfa: { pincodeResendTimeoutMs: 50 } },
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    const { wfs } = await driveOtpToCheck(app, "alice@test.com");
    expect(app.emails).toHaveLength(1);

    await new Promise((r) => setTimeout(r, 80));
    const r = await app.trigger({ wfs, input: { action: "resend" } });
    // No error; advanced back through sendOtp → checkOtp form again.
    expect(r.body?.errors).toBeUndefined();
    expect(r.body?.wfs).toBeTruthy();
    expect(app.emails).toHaveLength(2);
    // New code (mintPin replaced ctx.pin); both emails are pincode kind.
    expect(app.emails[1].kind).toBe("recovery.pincode");
  });

  it("otp two transports + useDifferentTransport → switches email → sms, sms sender invoked", async () => {
    const app = await prepareWfApp({
      recoveryPolicy: {
        delivery: { mode: "otp", otpTransports: ["email", "sms"] },
      },
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    // Enroll an SMS factor so resolveUserPhone returns the recorded number.
    await app.users.addMfaMethod("alice@test.com", {
      name: "sms",
      value: "+15555550100",
      confirmed: true,
    });

    const { wfs } = await driveOtpToCheck(app, "alice@test.com");
    expect(app.emails).toHaveLength(1); // first transport = email
    expect(app.sms).toHaveLength(0);

    const r = await app.trigger({ wfs, input: { action: "useDifferentTransport" } });
    // Advances back into sendOtp on the alt transport, then pauses at checkOtp.
    expect(r.body?.wfs).toBeTruthy();
    expect(app.sms).toHaveLength(1);
    expect(app.sms[0].kind).toBe("recovery.pincode");
    expect(app.sms[0].recipient).toBe("+15555550100");

    // Code from the SMS verifies and advances.
    const r2 = await app.trigger({
      wfs: r.body?.wfs as string,
      input: { code: app.sms[0].code, rememberDevice: false },
    });
    expect(JSON.stringify(r2.body)).toMatch(/newPassword/);
  });

  it("otp single transport: useDifferentTransport alt → form error 'Only one transport configured'", async () => {
    const app = await prepareWfApp({
      recoveryPolicy: {
        delivery: { mode: "otp", otpTransports: ["email"] },
      },
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    const { wfs } = await driveOtpToCheck(app, "alice@test.com");
    const r = await app.trigger({ wfs, input: { action: "useDifferentTransport" } });
    const errors = r.body?.errors as Record<string, string> | undefined;
    expect(errors?.__form).toMatch(/Only one transport/);
  });
});

describe("RecoveryWorkflowOpts — anti-enumeration response parity", () => {
  it("unknown email path returns no `wfs` for client to advance on", async () => {
    // Belt-and-braces: prove the anti-enumeration short-circuit terminates the
    // workflow rather than leaving a paused state the client could probe.
    const app = await prepareWfApp({
      recoveryOpts: {},
    });
    const r1 = await app.trigger({ wfid: "auth/recovery/flow" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "ghost@nowhere.test" },
    });
    expect(r2.body?.wfs).toBeUndefined();
    // Envelope-finished signal — no further step.
    expect(r2.body?.finished).toBe(true);
  });
});

describe("RecoveryWorkflowOpts — requireKnownFactor", () => {
  it("happy path: phone last-4 matches → advances to setPassword", async () => {
    const app = await prepareWfApp({
      recoveryPolicy: {
        preReset: { requireKnownFactor: true },
        postReset: { freshLoginRequired: false, revokeAllSessions: false, loginUrl: "/login" },
      },
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    await app.users.addMfaMethod("alice@test.com", {
      name: "sms",
      value: "+15555550199",
      confirmed: true,
    });

    const { wfs: factorWfs } = await driveMagicLinkToSetPassword(app, "alice@test.com");
    // After magic-link click the schema gates setPassword behind verifyFactor.
    // The form returned is RecoveryFactorForm.
    expect(JSON.stringify(factorWfs)).toBeTruthy();
    // Verify factor: phone last-4 = "0199".
    const r = await app.trigger({ wfs: factorWfs, input: { factor: "phone", value: "0199" } });
    // Advances to setPassword.
    expect(JSON.stringify(r.body)).toMatch(/newPassword/);

    const r2 = await app.trigger({
      wfs: r.body?.wfs as string,
      input: { newPassword: "NewPassword123", confirmPassword: "NewPassword123" },
    });
    const env2 = expectFinished<{ userId: string }>(r2);
    expect(env2.data?.userId).toBe("alice@test.com");
  });

  it("bad factor: phone last-4 mismatch → opaque 'Invalid factor' error, no advance", async () => {
    const app = await prepareWfApp({
      recoveryPolicy: { preReset: { requireKnownFactor: true } },
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    await app.users.addMfaMethod("alice@test.com", {
      name: "sms",
      value: "+15555550199",
      confirmed: true,
    });

    const { wfs: factorWfs } = await driveMagicLinkToSetPassword(app, "alice@test.com");
    const r = await app.trigger({ wfs: factorWfs, input: { factor: "phone", value: "0000" } });
    const errors = r.body?.errors as Record<string, string> | undefined;
    expect(errors?.value).toMatch(/Invalid factor/);
    // Still paused at verifyFactor (no setPassword form).
    expect(JSON.stringify(r.body)).not.toMatch(/newPassword/);
  });

  it("totp factor: correct current TOTP → advances", async () => {
    const app = await prepareWfApp({
      recoveryPolicy: {
        preReset: { requireKnownFactor: true },
        postReset: { freshLoginRequired: false, revokeAllSessions: false, loginUrl: "/login" },
      },
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    const secret = generateTotpSecret();
    await app.users.addMfaMethod("alice@test.com", {
      name: "totp",
      value: secret,
      confirmed: true,
    });

    const { wfs: factorWfs } = await driveMagicLinkToSetPassword(app, "alice@test.com");
    const code = generateTotpCode(secret);
    const r = await app.trigger({ wfs: factorWfs, input: { factor: "totp", value: code } });
    expect(JSON.stringify(r.body)).toMatch(/newPassword/);
  });
});

describe("RecoveryWorkflowOpts — revokeAllSessions", () => {
  it("revokeAllSessions true: pre-existing token rejected after successful reset", async () => {
    const app = await prepareWfApp({
      recoveryPolicy: {
        postReset: { revokeAllSessions: true, freshLoginRequired: false, loginUrl: "/login" },
      },
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");

    // Issue a pre-existing token to simulate an active session.
    const pre = await app.auth.issue("alice@test.com");
    expect(await app.auth.validate(pre.accessToken)).not.toBeNull();

    const { wfs } = await driveMagicLinkToSetPassword(app, "alice@test.com");
    const fin = await app.trigger({
      wfs,
      input: { newPassword: "NewPassword123", confirmPassword: "NewPassword123" },
    });
    const envFin = expectFinished<{ userId: string }>(fin);
    expect(envFin.data?.userId).toBe("alice@test.com");

    // Pre-existing token now rejected (epoch bumped by revokeAllForUser).
    expect(await app.auth.validate(pre.accessToken)).toBeNull();
  });

  it("revokeAllSessions false: pre-existing token still valid after reset", async () => {
    const app = await prepareWfApp({
      recoveryPolicy: {
        postReset: { revokeAllSessions: false, freshLoginRequired: false, loginUrl: "/login" },
      },
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    const pre = await app.auth.issue("alice@test.com");
    expect(await app.auth.validate(pre.accessToken)).not.toBeNull();

    const { wfs } = await driveMagicLinkToSetPassword(app, "alice@test.com");
    await app.trigger({
      wfs,
      input: { newPassword: "NewPassword123", confirmPassword: "NewPassword123" },
    });
    // Pre-existing token still works — opt-out preserved.
    expect(await app.auth.validate(pre.accessToken)).not.toBeNull();
  });
});

describe("RecoveryWorkflowOpts — freshLoginRequired terminal", () => {
  it("freshLoginRequired true → envelope redirect to loginUrl, no tokens issued", async () => {
    const app = await prepareWfApp({
      recoveryPolicy: {
        postReset: { freshLoginRequired: true, revokeAllSessions: true, loginUrl: "/sign-in" },
      },
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    const { wfs } = await driveMagicLinkToSetPassword(app, "alice@test.com");
    const r = await app.trigger({
      wfs,
      input: { newPassword: "NewPassword123", confirmPassword: "NewPassword123" },
    });
    expect(r.status).not.toBe(302);
    const env = expectFinished<{ accessToken?: string; userId?: string }>(r);
    const next = env.next as Extract<NonNullable<typeof env.next>, { trigger: "immediate" }>;
    expect(next?.action?.type).toBe("redirect");
    expect(next?.action?.type === "redirect" && next.action.target).toBe("/sign-in");
    // No auto-login payload.
    expect(env.data?.accessToken).toBeUndefined();
    expect(env.data?.userId).toBeUndefined();
  });

  it("freshLoginFinish emits auto-trigger envelope with 5s countdown + success message", async () => {
    const app = await prepareWfApp({
      recoveryPolicy: {
        postReset: { freshLoginRequired: true, revokeAllSessions: true, loginUrl: "/sign-in" },
      },
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    const { wfs } = await driveMagicLinkToSetPassword(app, "alice@test.com");
    const r = await app.trigger({
      wfs,
      input: { newPassword: "NewPassword123", confirmPassword: "NewPassword123" },
    });
    const env = expectFinished(r);
    const next = env.next as Extract<NonNullable<typeof env.next>, { trigger: "auto" }>;
    expect(next?.trigger).toBe("auto");
    expect(next?.timeoutMs).toBe(5000);
    expect(next?.skipButton?.label).toBe("Go now");
    expect(next?.action?.type).toBe("redirect");
    expect(next?.action?.type === "redirect" && next.action.target).toBe("/sign-in");
    expect(next?.action?.type === "redirect" && next.action.reason).toBe("reset-success");
    expect(env.message?.level).toBe("success");
    expect(env.message?.text).toMatch(/Password updated/);
  });

  it("freshLoginRequired false → auto-login (issues access token in envelope data)", async () => {
    const app = await prepareWfApp({
      recoveryPolicy: {
        postReset: { freshLoginRequired: false, revokeAllSessions: true, loginUrl: "/login" },
      },
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    const { wfs } = await driveMagicLinkToSetPassword(app, "alice@test.com");
    const r = await app.trigger({
      wfs,
      input: { newPassword: "NewPassword123", confirmPassword: "NewPassword123" },
    });
    const env = expectFinished<{ userId: string; accessToken: string }>(r);
    expect(env.data?.userId).toBe("alice@test.com");
    expect(typeof env.data?.accessToken).toBe("string");
  });

  it("default freshLoginRequired: false → autoLoginFinish issues tokens (recovery + immediate validate)", async () => {
    // Regression guard: the default flips `freshLoginRequired` to false and
    // keeps `revokeAllSessions` true. The `revokeAllForUser` call in
    // `recovery-revoke-sessions` runs immediately before `auth.issue` in
    // `recovery-auto-login-finish` — if `passesEpoch` used strict `>` the
    // freshly minted token would race against the revoke epoch (same-ms) and
    // silently fail validation. The `>=` fix makes this safe; this test fails
    // the moment the comparison regresses.
    const app = await prepareWfApp({}); // pure defaults
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");

    const { wfs } = await driveMagicLinkToSetPassword(app, "alice@test.com");
    const r = await app.trigger({
      wfs,
      input: { newPassword: "NewPassword123", confirmPassword: "NewPassword123" },
    });
    // Default auto-login emits the buildLoginResponse payload under .data, no 302.
    expect(r.status).not.toBe(302);
    const env = expectFinished<{ userId: string; accessToken: string; refreshToken: string }>(r);
    expect(env.data?.userId).toBe("alice@test.com");
    expect(typeof env.data?.accessToken).toBe("string");
    expect(typeof env.data?.refreshToken).toBe("string");

    // Immediate validate proves the issued token survived the same-tick
    // revokeAllForUser → issue sequence (epoch `>=` race fix).
    const principal = await app.auth.validate(env.data!.accessToken);
    expect(principal).not.toBeNull();
    expect(principal?.userId).toBe("alice@test.com");
  });
});

describe("RecoveryWorkflowOpts — backToLogin alt-action", () => {
  it("request step: backToLogin alt → immediate redirect envelope to loginUrl, no email sent", async () => {
    const app = await prepareWfApp({
      recoveryPolicy: {
        altActions: { backToLogin: true },
        postReset: { revokeAllSessions: true, freshLoginRequired: false, loginUrl: "/login" },
      },
    });
    const r1 = await app.trigger({ wfid: "auth/recovery/flow" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { action: "backToLogin" },
    });
    expect(r2.status).not.toBe(302);
    const env2 = expectFinished(r2);
    const next2 = env2.next as Extract<NonNullable<typeof env2.next>, { trigger: "immediate" }>;
    expect(next2?.trigger).toBe("immediate");
    expect(next2?.action?.type).toBe("redirect");
    expect(next2?.action?.type === "redirect" && next2.action.target).toBe("/login");
    expect(next2?.action?.type === "redirect" && next2.action.reason).toBe("user-cancelled");
    expect(app.emails).toHaveLength(0);
  });

  it("setPassword step: backToLogin alt → envelope redirect, password NOT changed", async () => {
    const app = await prepareWfApp({
      recoveryPolicy: {
        altActions: { backToLogin: true },
        postReset: { revokeAllSessions: true, freshLoginRequired: false, loginUrl: "/login" },
      },
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    const { wfs } = await driveMagicLinkToSetPassword(app, "alice@test.com");
    const r = await app.trigger({ wfs, input: { action: "backToLogin" } });
    expect(r.status).not.toBe(302);
    const env = expectFinished(r);
    const next = env.next as Extract<NonNullable<typeof env.next>, { trigger: "immediate" }>;
    expect(next?.action?.type === "redirect" && next.action.target).toBe("/login");
    // Old password still works.
    const ok = await app.users.verifyPassword("alice@test.com", "OldPassword1");
    expect(ok).toBe(true);
  });
});

describe("RecoveryWorkflowOpts — audit", () => {
  it("emits recovery.requested (request step) and recovery.completed (terminal)", async () => {
    const captured: Array<Record<string, unknown>> = [];
    const app = await prepareWfApp({
      recoveryPolicy: {
        audit: { enabled: true },
        postReset: { freshLoginRequired: false, revokeAllSessions: true, loginUrl: "/login" },
      },
      auditEmitter: {
        emit(ev) {
          captured.push(ev);
        },
      },
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    const { wfs } = await driveMagicLinkToSetPassword(app, "alice@test.com");
    await app.trigger({
      wfs,
      input: { newPassword: "NewPassword123", confirmPassword: "NewPassword123" },
    });

    const kinds = captured.map((e) => e.kind);
    expect(kinds).toContain("recovery.requested");
    expect(kinds).toContain("recovery.completed");
    const completed = captured.find((e) => e.kind === "recovery.completed");
    expect(completed?.userId).toBe("alice@test.com");
    expect(completed?.workflow).toBe("auth/recovery/flow");
    expect(completed?.deliveryMode).toBe("magicLink");
    // revokeAllSessions defaults to true → sessionsRevoked flag set.
    expect(completed?.sessionsRevoked).toBe(true);
  });

  it("audit.enabled false → no recovery.requested or recovery.completed emitted", async () => {
    const captured: Array<Record<string, unknown>> = [];
    const app = await prepareWfApp({
      recoveryPolicy: {
        audit: { enabled: false },
        postReset: { freshLoginRequired: false, revokeAllSessions: true, loginUrl: "/login" },
      },
      auditEmitter: {
        emit(ev) {
          captured.push(ev);
        },
      },
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    const { wfs } = await driveMagicLinkToSetPassword(app, "alice@test.com");
    await app.trigger({
      wfs,
      input: { newPassword: "NewPassword123", confirmPassword: "NewPassword123" },
    });
    expect(captured.find((e) => e.kind === "recovery.requested")).toBeUndefined();
    expect(captured.find((e) => e.kind === "recovery.completed")).toBeUndefined();
  });
});

describe("RecoveryWorkflow — request step pre-fill from ?username= query", () => {
  it("WF-RECOVERY pre-fill: ?username= populates the EmailIdentifierForm", async () => {
    // Login workflow's `forgotPassword` alt-action hands off to the recovery
    // workflow with `?username=<email>` on the trigger URL so the user does
    // not have to retype the email they just typed. The `recovery-request`
    // step reads the param, pushes `{ email }` onto `formCtx.defaults`, and
    // only reaches the client if `@wf.context.pass 'defaults'` whitelists the
    // key on `EmailIdentifierForm` — otherwise `extractPassContext` strips it.
    const app = await prepareWfApp({});
    const response = await app.http.request("/wf/trigger?username=alice%40example.com", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ wfid: "auth/recovery/flow" }),
    });
    // `createHttpOutlet()` (test wiring) returns the form schema at the
    // response root with the whitelisted context keys merged in alongside it
    // (`{ id, type, metadata, defaults, wfs, ... }`). Production consumers
    // using `createAsHttpOutlet()` get the same fields wrapped under
    // `{ inputRequired: { payload, context } }`. Either way, the pre-fill
    // ships via `defaults.email` only when `@wf.context.pass 'defaults'` is
    // present on the form.
    if (!response) throw new Error("no response");
    const body = (await response.json()) as {
      id?: string;
      defaults?: { email?: string };
      wfs?: string;
    };
    expect(body.id).toBe("EmailIdentifierForm");
    expect(typeof body.wfs).toBe("string");
    expect(body.defaults?.email).toBe("alice@example.com");
  });
});

describe("RecoveryWorkflow subclass — protected method overrides", () => {
  it("emailToUserId override is invoked instead of the default identity mapping", async () => {
    // Default `emailToUserId` returns the email unchanged. A subclass that
    // maps email → handle should cause `users.getUser` to resolve a different
    // record — the captured email's `username` proves the override ran.
    const app = await prepareWfApp({
      recoveryWorkflowClass: makeRecoverySubclass({
        async emailToUserId(email) {
          if (email === "alice@corp.example") return "alice42";
          return null;
        },
      }),
    });
    await seedActiveUser(app.users, "alice42", "OldPassword1");

    const r1 = await app.trigger({ wfid: "auth/recovery/flow" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "alice@corp.example" },
    });
    expect(r2.status).toBe(201);
    expect(app.emails).toHaveLength(1);
    expect(app.emails[0].kind).toBe("recovery.magicLink");
    expect(app.emails[0].recipient).toBe("alice@corp.example");
    expect(app.emails[0].username).toBe("alice42");
  });

  it("emailToUserId returning null: enumeration-resistant short-circuit", async () => {
    const app = await prepareWfApp({
      recoveryWorkflowClass: makeRecoverySubclass({
        async emailToUserId() {
          return null;
        },
      }),
    });
    await seedActiveUser(app.users, "alice42", "OldPassword1");
    const r1 = await app.trigger({ wfid: "auth/recovery/flow" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "anyone@nowhere.test" },
    });
    const env2 = expectFinished<{ sent: boolean }>(r2);
    expect(env2.data?.sent).toBe(true);
    expect(app.emails).toHaveLength(0);
  });
});

describe("RecoveryWorkflow — passwordPolicies surfaces on SetPasswordForm pause", () => {
  it("WF-RECOVERY-PWPOLICY — passwordPolicies reaches client on SetPasswordForm pause", async () => {
    // Guards two regressions at once:
    //   1. `@wf.context.pass 'passwordPolicies'` on SetPasswordForm — without
    //      it `extractPassContext` strips the key before the inputRequired
    //      envelope leaves the engine.
    //   2. `recovery-set-password` seeding `ctx.passwordPolicies` BEFORE
    //      `requireInput()` — `requireInput()` snapshots `wfState.ctx()` at
    //      throw time, so the previous catch-then-rethrow pattern shipped a
    //      pre-mutation ctx and the field never reached the client.
    const policy = ppHasMinLength(8);
    const app = await prepareWfApp({
      userConfig: { password: { policies: [policy] } },
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");

    const r1 = await app.trigger({ wfid: "auth/recovery/flow" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "alice@test.com" },
    });
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);

    // The inputRequired wire envelope from `createHttpOutlet` is a flat object
    // (`{ id, type, ..., passwordPolicies, wfs }`) — whitelisted ctx keys are
    // merged in alongside the form schema. See the existing
    // "WF-RECOVERY pre-fill" test for the same shape via `defaults`.
    const body = r3.body as { id?: string; passwordPolicies?: unknown };
    expect(body.id).toBe("SetPasswordForm");
    expect(body.passwordPolicies).toEqual(app.users.getTransferablePolicies());
    expect(Array.isArray(body.passwordPolicies)).toBe(true);
    expect((body.passwordPolicies as unknown[]).length).toBeGreaterThan(0);
    expect(String((body.passwordPolicies as Array<{ rule: string }>)[0].rule)).toContain(
      "v.length",
    );
  });
});
