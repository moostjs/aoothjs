/**
 * Recovery via a REGISTERED channel (M2) — `recovery-registered` variant.
 *
 * M1 (covered by recovery.spec.ts / phone.spec.ts) delivers the OTP to the
 * identifier the user TYPES (identifier == destination). M2 instead delivers it
 * to a channel ALREADY VERIFIED on the row: the user types only an account
 * identifier (here a plain username), `emailToUserId` resolves the account, and
 * `selectRecoveryRegisteredMethod` (SMS-first, then email) picks the confirmed
 * MFA method to text/email — the destination is never taken from input, so it
 * can't be redirected cross-account. A row with no deliverable confirmed method
 * hits the SAME anti-enumeration generic finish as an unknown identifier.
 *
 * The `recovery-registered` variant sets `policy.deliverySource: "registered"`,
 * which `DemoAuthWorkflow.resolveRecoveryDeliverySource` reads to arm M2, and
 * swaps in the phone/username-capable `RecoveryIdentifierForm`.
 *
 * Seed (packages/e2e-demo/src/seed.ts):
 *   t1_ivy       — SMS-only, phone +15555550101
 *   t1_henry     — email-only (henry@acme.test)
 *   t1_multi_mfa — email + sms (+15555550110) + totp, default = totp
 *   t1_grace     — TOTP-only (no deliverable channel)
 */
import { expect, test } from "@playwright/test";

import {
  clickAction,
  fillField,
  getEmails,
  getSms,
  readFinishEnvelope,
  resetApp,
  submitForm,
  USERS,
  waitForEmail,
  waitForFormInput,
  waitForSms,
  wfUrl,
} from "./harness";

const IVY_PHONE = "+15555550101";
const MULTI_PHONE = "+15555550110";
const HENRY_EMAIL = "henry@acme.test";
const NEW_PASSWORD = "NewPassword2!";

test.describe("recovery — registered-channel (M2)", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-RECOVERY-REGISTERED-01: username identifier → OTP to the registered phone → set password", async ({
    page,
    request,
  }) => {
    await page.goto(wfUrl("auth/recovery/flow", "recovery-registered"));

    // The user types only their USERNAME — not a phone or email. The OTP is
    // delivered to the SMS channel verified on the row, proving the typed
    // identifier and the destination are decoupled in M2.
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", USERS.ivy.username);
    await submitForm(page);

    const sms = await waitForSms(
      request,
      (e) => e.kind === "recovery.pincode" && (e.recipient ?? "").startsWith("+1555"),
      15_000,
    );
    expect(sms.recipient, "OTP must go to the row's registered phone, not the typed username").toBe(
      IVY_PHONE,
    );
    expect(sms.code, "recovery OTP delivered by SMS").toMatch(/^\d{6}$/);

    // No email OTP — the registered branch picks ONE channel (SMS here).
    expect((await getEmails(request)).find((e) => e.kind === "recovery.pincode")).toBeFalsy();

    await waitForFormInput(page, "code", 15_000);
    await fillField(page, "code", sms.code);
    await submitForm(page);

    await waitForFormInput(page, "newPassword", 15_000);
    await fillField(page, "newPassword", NEW_PASSWORD);
    await fillField(page, "confirmPassword", NEW_PASSWORD);
    await submitForm(page);

    await expect(page.getByText("Workflow finished.")).toBeVisible();
    const envelope = (await readFinishEnvelope(page)) as { finished?: boolean };
    expect(envelope.finished).toBe(true);
  });

  test("WF-RECOVERY-REGISTERED-02: multiple enrolled channels → SMS-first selection (not email, not default TOTP)", async ({
    page,
    request,
  }) => {
    // t1_multi_mfa has email + sms + totp with TOTP as the DEFAULT. M2 ignores
    // the default and prefers SMS (TOTP is undeliverable; email is the fallback,
    // not the pick), so the OTP must reach the registered phone — never the
    // email, never TOTP.
    await page.goto(wfUrl("auth/recovery/flow", "recovery-registered"));

    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", USERS.multi_mfa.username);
    await submitForm(page);

    const sms = await waitForSms(
      request,
      (e) => e.kind === "recovery.pincode" && (e.recipient ?? "").startsWith("+1555"),
      15_000,
    );
    expect(sms.recipient, "SMS-first: OTP to the registered phone").toBe(MULTI_PHONE);
    expect(sms.code).toMatch(/^\d{6}$/);

    // Email channel was NOT chosen even though it is also confirmed.
    expect(
      (await getEmails(request)).find((e) => e.kind === "recovery.pincode"),
      "SMS-first must not also send an email OTP",
    ).toBeFalsy();
  });

  test("WF-RECOVERY-REGISTERED-03: email-only account → email fallback (no SMS method)", async ({
    page,
    request,
  }) => {
    // t1_henry has only a confirmed email method. With no SMS to prefer, M2
    // falls back to the email channel.
    await page.goto(wfUrl("auth/recovery/flow", "recovery-registered"));

    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", USERS.henry.username);
    await submitForm(page);

    const email = await waitForEmail(request, (e) => e.kind === "recovery.pincode", 15_000);
    expect(email.recipient, "email fallback delivers to the registered email").toBe(HENRY_EMAIL);
    expect(email.code).toMatch(/^\d{6}$/);

    // No SMS — the row has no deliverable SMS method.
    expect((await getSms(request)).find((e) => e.kind === "recovery.pincode")).toBeFalsy();
  });

  test("WF-RECOVERY-REGISTERED-04: TOTP-only account → generic finish, no OTP (anti-enumeration)", async ({
    page,
    request,
  }) => {
    // t1_grace's only factor is TOTP, which carries no deliverable address. M2
    // must NOT leak that the account exists-but-is-unrecoverable: it emits the
    // SAME generic envelope as an unknown identifier and sends no OTP on either
    // channel.
    await page.goto(wfUrl("auth/recovery/flow", "recovery-registered"));

    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", USERS.grace.username);
    await submitForm(page);

    await expect(page.getByText("Workflow finished.")).toBeVisible();
    const envelope = (await readFinishEnvelope(page)) as { data?: { accessToken?: string } };
    expect(envelope.data?.accessToken, "generic finish must not issue tokens").toBeFalsy();

    // No OTP delivered on EITHER channel — TOTP is not a recovery channel.
    expect((await getSms(request)).find((e) => e.kind === "recovery.pincode")).toBeFalsy();
    expect((await getEmails(request)).find((e) => e.kind === "recovery.pincode")).toBeFalsy();
  });

  test("WF-RECOVERY-REGISTERED-05: method deleted between request and resend → generic finish, no 500", async ({
    page,
    request,
  }) => {
    // The request→send TOCTOU. ivy has a deliverable SMS method, so the FIRST
    // send succeeds and pauses on the PincodeForm. We then delete her MFA method
    // mid-flow (admin/user action) and resend: pincode-send re-resolves the
    // target, finds nothing deliverable, and MUST degrade to the same generic
    // anti-enumeration finish as an unknown identifier — never a distinguishable
    // 500 — so a known account can't be told apart from an unknown one.
    await page.goto(wfUrl("auth/recovery/flow", "recovery-registered-fast-resend"));

    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", USERS.ivy.username);
    await submitForm(page);

    // First OTP delivered (deliverable method present at request time).
    await waitForSms(
      request,
      (e) => e.kind === "recovery.pincode" && (e.recipient ?? "").startsWith("+1555"),
      15_000,
    );
    await waitForFormInput(page, "code", 15_000);

    // Method vanishes mid-flow.
    const zap = await request.post(`/__test/reset-mfa/${encodeURIComponent(USERS.ivy.username)}`);
    expect(zap.ok()).toBeTruthy();

    // Wait past the 1s resend cooldown, then resend.
    await page.waitForTimeout(1200);
    await clickAction(page, "Resend code");

    // Graceful generic finish — NOT a 500/error block, NOT a new OTP.
    await expect(page.getByText("Workflow finished.")).toBeVisible();
    await expect(page.locator(".as-wf-form-error, .scope-error")).toHaveCount(0);
    const envelope = (await readFinishEnvelope(page)) as { data?: { accessToken?: string } };
    expect(envelope.data?.accessToken, "generic finish must not issue tokens").toBeFalsy();

    // Still exactly one SMS — the resend delivered nothing.
    expect(
      (await getSms(request)).filter((e) => e.kind === "recovery.pincode"),
      "resend after method deletion must not deliver a second OTP",
    ).toHaveLength(1);
  });
});
