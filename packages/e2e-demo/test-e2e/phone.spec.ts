/**
 * Phone-as-handle — login by phone + recovery-via-SMS (M1).
 *
 * Login: a phone number resolves the account because `DemoUser.phone` is a
 * `@aooth.user.phone` handle (unique-indexed), so `findByHandle` resolves it —
 * no login-workflow change. Recovery-via-SMS: the `recovery-via-sms` variant
 * swaps in a phone-capable identifier form; `DemoAuthWorkflow.resolveRecoveryChannel`
 * infers `sms` from the typed phone's shape, so the OTP is delivered by SMS to
 * the typed handle (= the verified phone). Seeded user `t1_ivy` has
 * `users.phone = +15555550101`.
 */
import { expect, test } from "@playwright/test";

import {
  fillField,
  getSms,
  readFinishEnvelope,
  resetApp,
  submitForm,
  USERS,
  waitForFormInput,
  waitForSms,
  wfUrl,
} from "./harness";

const IVY_PHONE = "+15555550101";
const NEW_PASSWORD = "NewPassword2!";

test.describe("phone-as-handle — login + SMS recovery", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-LOGIN-PHONE-01: a phone number resolves the account as a login handle (minimal, no MFA)", async ({
    page,
  }) => {
    await page.goto(wfUrl("auth/login/flow", "minimal"));
    await waitForFormInput(page, "username", 15_000);
    // The identifier field is `username`, but findByHandle tries username, then
    // the resolved handle fields (email, phone) — so the seeded phone resolves.
    await fillField(page, "username", IVY_PHONE);
    await fillField(page, "password", USERS.ivy.password);
    await submitForm(page);

    const envelope = (await readFinishEnvelope(page)) as { data?: { accessToken?: string } };
    expect(typeof envelope.data?.accessToken, "phone login must issue tokens").toBe("string");
  });

  test("WF-RECOVERY-SMS-01: phone identifier → SMS OTP (recovery.pincode) → set password", async ({
    page,
    request,
  }) => {
    await page.goto(wfUrl("auth/recovery/flow", "recovery-via-sms"));

    // Phone-capable RecoveryIdentifierForm (field still named `email`).
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", IVY_PHONE);
    await submitForm(page);

    // OTP delivered by SMS — kind `recovery.pincode` proves the toSmsKind fix
    // (not mislabeled as `login.pincode`), recipient is the typed handle.
    const sms = await waitForSms(
      request,
      (e) => e.kind === "recovery.pincode" && (e.recipient ?? "").startsWith("+1555"),
      15_000,
    );
    expect(sms.code, "recovery OTP delivered by SMS").toMatch(/^\d{6}$/);
    expect(sms.recipient).toBe(IVY_PHONE);

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

  test("WF-RECOVERY-SMS-02: unknown phone → generic finish, no SMS (anti-enumeration)", async ({
    page,
    request,
  }) => {
    await page.goto(wfUrl("auth/recovery/flow", "recovery-via-sms"));

    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", "+15555559999"); // not a registered handle
    await submitForm(page);

    await expect(page.getByText("Workflow finished.")).toBeVisible();
    const events = await getSms(request);
    expect(
      events.find((e) => e.kind === "recovery.pincode"),
      "no SMS for an unknown identifier",
    ).toBeFalsy();
  });
});
