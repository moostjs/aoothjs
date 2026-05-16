/**
 * Per-option behaviour tests for `RecoveryWorkflow` — one (or two) cases per
 * `RecoveryWorkflowOptions` flag flagged in WF_RECOVERY.md §"Tasks" item #8.
 *
 * Anti-test guard (Rule 9): every test below asserts an observable outcome
 * that DIRECTLY depends on the flag under test — i.e. flipping the flag (or
 * removing the relevant production-code branch) would make the test fail.
 * No "step count == N" tests; no full-body snapshots; assertions target the
 * response payload, captured side effects (emails, sms, audit events,
 * revoked tokens), and the response shape parity required by anti-enumeration.
 */
import { generateTotpCode, generateTotpSecret } from "@aoothjs/user";
import { describe, expect, it } from "vite-plus/test";

import {
  type WorkflowRateLimitConsumeResult,
  type WorkflowRateLimitStore,
} from "../rate-limit/index";
import { RecoveryWorkflowOptions } from "../workflows/recovery.workflow.options";
import { prepareWfApp, seedActiveUser } from "./workflow-utils";

/** Drive a magic-link recovery to the `setPassword` form and return the wfs token. */
async function driveMagicLinkToSetPassword(
  app: Awaited<ReturnType<typeof prepareWfApp>>,
  email: string,
): Promise<{ wfs: string }> {
  const r1 = await app.trigger({ wfid: "auth.recovery" });
  await app.trigger({ wfs: r1.body?.wfs as string, input: { email } });
  const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
  const r3 = await app.resumeViaQuery(token);
  return { wfs: r3.body?.wfs as string };
}

/** Drive an OTP recovery to the `checkOtp` form and return wfs + the captured code. */
async function driveOtpToCheck(
  app: Awaited<ReturnType<typeof prepareWfApp>>,
  email: string,
): Promise<{ wfs: string; code: string }> {
  const r1 = await app.trigger({ wfid: "auth.recovery" });
  const r2 = await app.trigger({ wfs: r1.body?.wfs as string, input: { email } });
  const last = app.emails[app.emails.length - 1];
  if (!last?.code) throw new Error(`expected pincode email, got ${JSON.stringify(last)}`);
  return { wfs: r2.body?.wfs as string, code: last.code };
}

describe("RecoveryWorkflowOptions — boot-time validators (fail loud)", () => {
  it("rateLimit non-null WITHOUT registered store → first request 500 with WorkflowRateLimitStore message", async () => {
    // validateOpts runs inside the workflow's `init` step (one-shot via the
    // module-level WeakSet guard). The throw surfaces at the HTTP layer as a
    // 500 with the validator's exact message — that's the user-visible
    // fail-loud signal.
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({
        // Defaults to a non-null rateLimit cap — we just need a store missing.
      }),
      rateLimitStore: null,
    });
    const r = await app.trigger({ wfid: "auth.recovery" });
    expect(r.status).toBe(500);
    expect(JSON.stringify(r.body)).toMatch(/WorkflowRateLimitStore/);
  });

  it("rateLimit.count <= 0 → fail loud (500 with count/windowMs message)", async () => {
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({ rateLimit: { count: 0, windowMs: 60_000 } }),
    });
    const r = await app.trigger({ wfid: "auth.recovery" });
    expect(r.status).toBe(500);
    expect(JSON.stringify(r.body)).toMatch(/rateLimit.*must be > 0/);
  });

  it("rateLimit.windowMs <= 0 → fail loud (500 with count/windowMs message)", async () => {
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({ rateLimit: { count: 5, windowMs: 0 } }),
    });
    const r = await app.trigger({ wfid: "auth.recovery" });
    expect(r.status).toBe(500);
    expect(JSON.stringify(r.body)).toMatch(/rateLimit.*must be > 0/);
  });

  it("deliveryMode 'otp' + otpTransports ['sms'] WITHOUT SmsSender → fail loud (500 with SmsSender message)", async () => {
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({
        deliveryMode: "otp",
        otpTransports: ["sms"],
      }),
      registerSmsSender: false,
    });
    const r = await app.trigger({ wfid: "auth.recovery" });
    expect(r.status).toBe(500);
    expect(JSON.stringify(r.body)).toMatch(/SmsSender/);
  });

  it("deliveryMode 'otp' + empty otpTransports → fail loud (500 with otpTransports message)", async () => {
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({
        deliveryMode: "otp",
        otpTransports: [],
      }),
    });
    const r = await app.trigger({ wfid: "auth.recovery" });
    expect(r.status).toBe(500);
    expect(JSON.stringify(r.body)).toMatch(/otpTransports.*empty/);
  });
});

describe("RecoveryWorkflowOptions — deliveryMode otp end-to-end", () => {
  it("otp mode: request → sendOtp (email) → checkOtp (correct code) → setPassword → tokens (auto-login)", async () => {
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({
        deliveryMode: "otp",
        otpTransports: ["email"],
        freshLoginRequired: false, // exercise auto-login terminal
        revokeAllSessions: false, // simpler assertion
      }),
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");

    const { wfs: checkOtpWfs, code } = await driveOtpToCheck(app, "alice@test.com");
    // OTP went via email channel — recovery.pincode event with the code.
    expect(app.emails).toHaveLength(1);
    expect(app.emails[0].kind).toBe("recovery.pincode");
    expect(app.emails[0].code).toBe(code);
    expect(app.sms).toHaveLength(0);

    // Submit the code → advances to setPassword form.
    const r3 = await app.trigger({ wfs: checkOtpWfs, input: { code } });
    expect(r3.body?.wfs).toBeTruthy();
    expect(JSON.stringify(r3.body)).toMatch(/newPassword/);

    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { newPassword: "NewPassword123", confirmPassword: "NewPassword123" },
    });
    // Auto-login terminal returns the buildLoginResponse payload.
    expect(r4.body?.userId).toBe("alice@test.com");
    expect(typeof r4.body?.accessToken).toBe("string");

    const ok = await app.users.verifyPassword("alice@test.com", "NewPassword123");
    expect(ok).toBe(true);
  });

  it("otp mode: wrong code → form error 'Invalid code', no advance", async () => {
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({
        deliveryMode: "otp",
        otpTransports: ["email"],
      }),
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    const { wfs } = await driveOtpToCheck(app, "alice@test.com");
    const r = await app.trigger({ wfs, input: { code: "999999" } });
    const errors = r.body?.errors as Record<string, string> | undefined;
    expect(errors?.code).toMatch(/Invalid code/);
    // Still paused at checkOtp form (re-rendered with the error).
    expect(r.body?.wfs).toBeTruthy();
  });

  it("otp resend within cooldown → form error 'wait Ns'; no second email sent", async () => {
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({
        deliveryMode: "otp",
        otpTransports: ["email"],
        otpResendCooldownMs: 60_000, // generous so we land inside the window
      }),
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
      recoveryOptions: new RecoveryWorkflowOptions({
        deliveryMode: "otp",
        otpTransports: ["email"],
        otpResendCooldownMs: 50, // tiny so the cooldown passes within the test
      }),
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
      recoveryOptions: new RecoveryWorkflowOptions({
        deliveryMode: "otp",
        otpTransports: ["email", "sms"],
      }),
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
      input: { code: app.sms[0].code },
    });
    expect(JSON.stringify(r2.body)).toMatch(/newPassword/);
  });

  it("otp single transport: useDifferentTransport alt → form error 'Only one transport configured'", async () => {
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({
        deliveryMode: "otp",
        otpTransports: ["email"],
      }),
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    const { wfs } = await driveOtpToCheck(app, "alice@test.com");
    const r = await app.trigger({ wfs, input: { action: "useDifferentTransport" } });
    const errors = r.body?.errors as Record<string, string> | undefined;
    expect(errors?.__form).toMatch(/Only one transport/);
  });
});

describe("RecoveryWorkflowOptions — rate-limit cap (anti-enumeration)", () => {
  it("third request inside the window short-circuits to generic response; no email; audit emits rateLimited:true", async () => {
    const auditEvents: Array<{ kind: string; rateLimited?: boolean; userId?: string }> = [];
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({
        rateLimit: { count: 2, windowMs: 60_000 },
        freshLoginRequired: false,
      }),
      auditEmitter: {
        emit(ev) {
          auditEvents.push(ev);
        },
      },
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");

    // First request — allowed, magic-link email sent.
    const r1a = await app.trigger({ wfid: "auth.recovery" });
    const r1b = await app.trigger({
      wfs: r1a.body?.wfs as string,
      input: { email: "alice@test.com" },
    });
    expect(app.emails).toHaveLength(1);
    expect(r1b.body?.errors).toBeUndefined();

    // Second request — also allowed (cap=2).
    const r2a = await app.trigger({ wfid: "auth.recovery" });
    await app.trigger({
      wfs: r2a.body?.wfs as string,
      input: { email: "alice@test.com" },
    });
    expect(app.emails).toHaveLength(2);

    // Third request — cap hit → generic short-circuit, no email sent.
    const r3a = await app.trigger({ wfid: "auth.recovery" });
    const r3b = await app.trigger({
      wfs: r3a.body?.wfs as string,
      input: { email: "alice@test.com" },
    });
    expect(r3b.body?.sent).toBe(true);
    expect(app.emails).toHaveLength(2);

    // Audit emits recovery.requested for ALL three (per spec: always emits).
    // The rate-limited one carries `rateLimited: true`. The two below-cap ones
    // do NOT carry the flag.
    const requested = auditEvents.filter((e) => e.kind === "recovery.requested");
    expect(requested.length).toBe(3);
    const rateLimitedHits = requested.filter((e) => e.rateLimited === true);
    expect(rateLimitedHits.length).toBe(1);
    expect(rateLimitedHits[0].userId).toBeUndefined(); // generic path skips user-id leak
  });

  it("rateLimit null disables the cap — N requests all go through", async () => {
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({ rateLimit: null }),
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    for (let i = 0; i < 5; i++) {
      const r1 = await app.trigger({ wfid: "auth.recovery" });
      await app.trigger({
        wfs: r1.body?.wfs as string,
        input: { email: "alice@test.com" },
      });
    }
    expect(app.emails).toHaveLength(5);
  });
});

describe("RecoveryWorkflowOptions — anti-enumeration response parity", () => {
  it("unknown email vs rate-limited known email: identical client-visible response shape (THE critical security invariant)", async () => {
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({
        rateLimit: { count: 1, windowMs: 60_000 },
      }),
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");

    // First request from alice — burns the rate-limit (count=1).
    const seedA = await app.trigger({ wfid: "auth.recovery" });
    await app.trigger({
      wfs: seedA.body?.wfs as string,
      input: { email: "alice@test.com" },
    });
    expect(app.emails).toHaveLength(1);

    // (B) Unknown email.
    const b1 = await app.trigger({ wfid: "auth.recovery" });
    const b2 = await app.trigger({
      wfs: b1.body?.wfs as string,
      input: { email: "ghost@nowhere.test" },
    });

    // (C) Rate-limited known email (second alice request — cap=1 already hit).
    const c1 = await app.trigger({ wfid: "auth.recovery" });
    const c2 = await app.trigger({
      wfs: c1.body?.wfs as string,
      input: { email: "alice@test.com" },
    });
    expect(app.emails).toHaveLength(1); // still only the first one — no leak

    // THE critical security invariant: an attacker cannot distinguish an
    // unknown email from a rate-limited known one. Identical status + body.
    expect(c2.status).toBe(b2.status);
    expect(JSON.stringify(c2.body)).toBe(JSON.stringify(b2.body));
    expect(c2.body?.sent).toBe(true);
    expect(c2.body?.message).toBe("If an account exists, you will receive instructions.");
    expect(c2.body?.errors).toBeUndefined();
    expect(b2.body?.errors).toBeUndefined();
    // Neither path leaks an `outlet` field (which the successful magic-link
    // path emits) — that field is the unavoidable "real success" signal
    // outletEmail produces, and is by-design observably present ONLY when
    // there is a real account + cap headroom.
    expect(b2.body?.outlet).toBeUndefined();
    expect(c2.body?.outlet).toBeUndefined();
  });

  it("unknown email path returns no `wfs` for client to advance on", async () => {
    // Belt-and-braces: prove the anti-enumeration short-circuit terminates the
    // workflow rather than leaving a paused state the client could probe.
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({}),
    });
    const r1 = await app.trigger({ wfid: "auth.recovery" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "ghost@nowhere.test" },
    });
    expect(r2.body?.wfs).toBeUndefined();
  });
});

describe("RecoveryWorkflowOptions — requireKnownRecoveryFactor", () => {
  it("happy path: phone last-4 matches → advances to setPassword", async () => {
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({
        requireKnownRecoveryFactor: true,
        freshLoginRequired: false,
        revokeAllSessions: false,
      }),
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
    expect(r2.body?.userId).toBe("alice@test.com");
  });

  it("bad factor: phone last-4 mismatch → opaque 'Invalid factor' error, no advance", async () => {
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({
        requireKnownRecoveryFactor: true,
      }),
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
      recoveryOptions: new RecoveryWorkflowOptions({
        requireKnownRecoveryFactor: true,
        freshLoginRequired: false,
        revokeAllSessions: false,
      }),
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

describe("RecoveryWorkflowOptions — revokeAllSessions", () => {
  it("revokeAllSessions true: pre-existing token rejected after successful reset", async () => {
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({
        revokeAllSessions: true,
        freshLoginRequired: false, // so we get auto-login response
      }),
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
    expect(fin.body?.userId).toBe("alice@test.com");

    // Pre-existing token now rejected (epoch bumped by revokeAllForUser).
    expect(await app.auth.validate(pre.accessToken)).toBeNull();
  });

  it("revokeAllSessions false: pre-existing token still valid after reset", async () => {
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({
        revokeAllSessions: false,
        freshLoginRequired: false,
      }),
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

describe("RecoveryWorkflowOptions — freshLoginRequired terminal", () => {
  it("freshLoginRequired true → redirect to loginUrl, no tokens issued", async () => {
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({
        freshLoginRequired: true,
        loginUrl: "/sign-in",
      }),
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    const { wfs } = await driveMagicLinkToSetPassword(app, "alice@test.com");
    const r = await app.trigger({
      wfs,
      input: { newPassword: "NewPassword123", confirmPassword: "NewPassword123" },
    });
    expect(r.status).toBe(302);
    expect(r.location).toBe("/sign-in");
    // No auto-login payload.
    expect(r.body?.accessToken).toBeUndefined();
    expect(r.body?.userId).toBeUndefined();
  });

  it("freshLoginRequired false → auto-login (issues access token in body)", async () => {
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({
        freshLoginRequired: false,
      }),
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    const { wfs } = await driveMagicLinkToSetPassword(app, "alice@test.com");
    const r = await app.trigger({
      wfs,
      input: { newPassword: "NewPassword123", confirmPassword: "NewPassword123" },
    });
    expect(r.body?.userId).toBe("alice@test.com");
    expect(typeof r.body?.accessToken).toBe("string");
  });
});

describe("RecoveryWorkflowOptions — backToLogin alt-action", () => {
  it("request step: backToLogin alt → redirect to loginUrl, no email sent", async () => {
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({
        backToLoginAction: true,
        loginUrl: "/login",
      }),
    });
    const r1 = await app.trigger({ wfid: "auth.recovery" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { action: "backToLogin" },
    });
    expect(r2.status).toBe(302);
    expect(r2.location).toBe("/login");
    expect(app.emails).toHaveLength(0);
  });

  it("setPassword step: backToLogin alt → redirect, password NOT changed", async () => {
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({
        backToLoginAction: true,
        loginUrl: "/login",
      }),
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");
    const { wfs } = await driveMagicLinkToSetPassword(app, "alice@test.com");
    const r = await app.trigger({ wfs, input: { action: "backToLogin" } });
    expect(r.status).toBe(302);
    expect(r.location).toBe("/login");
    // Old password still works.
    const ok = await app.users.verifyPassword("alice@test.com", "OldPassword1");
    expect(ok).toBe(true);
  });
});

describe("RecoveryWorkflowOptions — auditEvents", () => {
  it("emits recovery.requested (request step) and recovery.completed (terminal)", async () => {
    const captured: Array<Record<string, unknown>> = [];
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({
        auditEvents: true,
        freshLoginRequired: false,
      }),
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
    expect(completed?.workflow).toBe("auth.recovery");
    expect(completed?.deliveryMode).toBe("magicLink");
    // revokeAllSessions defaults to true → sessionsRevoked flag set.
    expect(completed?.sessionsRevoked).toBe(true);
  });

  it("auditEvents false → no recovery.requested or recovery.completed emitted", async () => {
    const captured: Array<Record<string, unknown>> = [];
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({
        auditEvents: false,
        freshLoginRequired: false,
      }),
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

describe("RecoveryWorkflowOptions — custom rate-limit store wiring", () => {
  it("custom store is consulted for each request and its decision is honored", async () => {
    // A deterministic stub that denies on the second call regardless of cap.
    let calls = 0;
    const store: WorkflowRateLimitStore = {
      async consume(): Promise<WorkflowRateLimitConsumeResult> {
        calls += 1;
        return calls < 2
          ? { allowed: true, remaining: 0, resetAt: Date.now() + 60_000 }
          : { allowed: false, remaining: 0, resetAt: Date.now() + 60_000 };
      },
    };
    const app = await prepareWfApp({
      recoveryOptions: new RecoveryWorkflowOptions({
        rateLimit: { count: 100, windowMs: 60_000 }, // irrelevant — stub decides
      }),
      rateLimitStore: store,
    });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");

    const r1a = await app.trigger({ wfid: "auth.recovery" });
    await app.trigger({
      wfs: r1a.body?.wfs as string,
      input: { email: "alice@test.com" },
    });
    expect(app.emails).toHaveLength(1);

    const r2a = await app.trigger({ wfid: "auth.recovery" });
    const r2b = await app.trigger({
      wfs: r2a.body?.wfs as string,
      input: { email: "alice@test.com" },
    });
    // Stub denied → generic short-circuit, no new email.
    expect(r2b.body?.sent).toBe(true);
    expect(app.emails).toHaveLength(1);
    expect(calls).toBe(2);
  });
});

describe("RecoveryWorkflow — request step pre-fill from ?username= query", () => {
  it("WF-RECOVERY pre-fill: ?username= populates the EmailIdentifierForm", async () => {
    // Login workflow's `forgotPassword` alt-action hands off to the recovery
    // workflow with `?username=<email>` on the trigger URL so the user does
    // not have to retype the email they just typed. The `request` step reads
    // the param, pushes `{ email }` onto `formCtx.defaults`, and only reaches
    // the client if `@wf.context.pass 'defaults'` whitelists the key on
    // `EmailIdentifierForm` — otherwise `extractPassContext` strips it.
    const app = await prepareWfApp({});
    const response = await app.http.request("/wf/trigger?username=alice%40example.com", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ wfid: "auth.recovery" }),
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
