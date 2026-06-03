/**
 * Self-signup workflow — verify-first open signup (unified `AuthWorkflow`).
 *
 * Drives `auth/signup/flow` end-to-end through the SPA against the demo backend
 * (`DEMO_MODE=test`). Shape = recovery's email→OTP front + invite's create→
 * set-password→activate→auto-login tail:
 *   1. SignupForm  — submit an email (verify-first; no account yet).
 *   2. PincodeForm — enter the emailed OTP (proves email ownership).
 *   3. SetPasswordForm — choose a password (set AFTER verification, so nothing
 *      plaintext is held in wf-state across the OTP wait).
 *   4. auto-login — finish envelope carries tokens.
 *
 * The demo enables signup via `DemoAuthWorkflow.resolveSignupPolicy`
 * (`allowSignup: true`; the library default is OFF / invite-only) and sources
 * the required `tenantId` from the SHARED `prepareUser` hook (also used by
 * invite). The demo maps the `signup-pincode` delivery kind onto its
 * `recovery.pincode` email template, so the mailbox event kind is
 * `recovery.pincode` — disambiguated here by recipient.
 */
import { expect, test } from "@playwright/test";

import {
  clickAction,
  fillField,
  readFinishEnvelope,
  resetApp,
  submitForm,
  uniqueEmail,
  waitForEmail,
  waitForFormInput,
  wfUrl,
} from "./harness";

const ALICE_EMAIL = "alice@acme.test";
const NEW_PASSWORD = "NewPassword2!";

test.describe("signup — verify-first self-signup (auth/signup/flow)", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-SIGNUP-001: new email → email OTP → set password → auto-login (tokens issued)", async ({
    page,
    request,
  }) => {
    const email = uniqueEmail("newbie");
    await page.goto(wfUrl("auth/signup/flow"));

    // Phase 1 — SignupForm (email entry; verify-first, no row yet).
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", email);
    await submitForm(page);

    // Verification OTP — minted in wf-state, delivered to the submitted email.
    const otp = await waitForEmail(
      request,
      (e) => e.kind === "recovery.pincode" && e.recipient === email,
    );
    expect(otp.code, "signup OTP must be a numeric code").toMatch(/^\d{6}$/);

    // Phase 2 — PincodeForm (proves ownership).
    await waitForFormInput(page, "code", 15_000);
    await fillField(page, "code", otp.code as string);
    await submitForm(page);

    // Phase 3 — SetPasswordForm (password chosen POST-verify).
    await waitForFormInput(page, "newPassword", 15_000);
    await fillField(page, "newPassword", NEW_PASSWORD);
    await fillField(page, "confirmPassword", NEW_PASSWORD);
    await submitForm(page);

    await expect(page.getByText("Workflow finished.")).toBeVisible();
    const envelope = (await readFinishEnvelope(page)) as {
      finished?: boolean;
      data?: { accessToken?: string; userId?: string };
    };
    expect(envelope.finished).toBe(true);
    // Auto-login: a fresh account is signed straight in.
    expect(envelope.data?.accessToken, "signup auto-login must issue tokens").toBeTruthy();
    // userId is the new stable surrogate id (the token subject), not the email.
    expect(envelope.data?.userId, "subject must be a stable id, not the email").toBeTruthy();
    expect(envelope.data?.userId).not.toBe(email);
  });

  test("WF-SIGNUP-002: existing email → identical OTP pause (no enumeration) → post-OTP 'already registered', no tokens", async ({
    page,
    request,
  }) => {
    // Anti-enumeration: a REGISTERED email gets the SAME OTP pause as a new one
    // — the wire path is identical, so an attacker cannot probe account
    // existence. Existence is resolved only AFTER proof-of-ownership (the OTP),
    // at which point we route to sign-in WITHOUT issuing tokens.
    await page.goto(wfUrl("auth/signup/flow"));

    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    const otp = await waitForEmail(
      request,
      (e) => e.kind === "recovery.pincode" && e.recipient === ALICE_EMAIL,
    );
    await waitForFormInput(page, "code", 15_000);
    await fillField(page, "code", otp.code as string);
    await submitForm(page);

    await expect(page.getByText("Workflow finished.")).toBeVisible();
    const envelope = (await readFinishEnvelope(page)) as {
      next?: { action?: { type?: string; reason?: string } };
      data?: { accessToken?: string };
    };
    expect(envelope.next?.action?.type).toBe("redirect");
    expect(envelope.next?.action?.reason).toBe("already-registered");
    expect(
      envelope.data?.accessToken,
      "an already-registered email must never be auto-logged-in",
    ).toBeFalsy();
  });

  test("WF-SIGNUP-003: 'I already have an account' on SignupForm → redirect to login (reason='goto-login'), no token", async ({
    page,
  }) => {
    await page.goto(wfUrl("auth/signup/flow"));
    await waitForFormInput(page, "email", 15_000);
    // Signup is the initial flow; existing users cross-link to sign-in here.
    await clickAction(page, "I already have an account");

    await expect(page.getByText("Workflow finished.")).toBeVisible();
    const envelope = (await readFinishEnvelope(page)) as {
      finished?: boolean;
      next?: { action?: { type?: string; reason?: string } };
      data?: { accessToken?: string };
    };
    expect(envelope.finished).toBe(true);
    expect(envelope.next?.action?.type).toBe("redirect");
    expect(envelope.next?.action?.reason).toBe("goto-login");
    expect(envelope.data?.accessToken).toBeFalsy();
  });
});
