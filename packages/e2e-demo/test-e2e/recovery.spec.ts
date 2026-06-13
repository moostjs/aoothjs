/**
 * Recovery workflow — stories from USER_STORIES.md §5 (unified `AuthWorkflow`).
 *
 * Drives `auth.recovery` end-to-end through the SPA against the demo backend
 * (`DEMO_MODE=test`). The recovery flow is OTP-via-email: the user submits
 * their email, receives a numeric pincode, then sets a new password.
 *
 * Variant selection is delegated to the `?variant=...` query param read by
 * `WfPage.vue` and forwarded as the `x-wf-variant` request header — see
 * `RECOVERY_VARIANTS` in `packages/e2e-demo/src/variants.ts`.
 */
import { expect, test } from "@playwright/test";

import {
  clickAction,
  fillField,
  getEmails,
  loginViaUi,
  readFinishEnvelope,
  resetApp,
  submitForm,
  USERS,
  waitForEmail,
  waitForFormInput,
  wfUrl,
} from "./harness";

const ALICE_EMAIL = "alice@acme.test";
const NEW_PASSWORD = "NewPassword2!";

test.describe("recovery — default (OTP-via-email)", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-RECOVERY-001: alice → email OTP → set password → fresh-login redirect, no tokens", async ({
    page,
    request,
  }) => {
    await page.goto(wfUrl("auth/recovery/flow"));

    // Phase 1 — EmailIdentifierForm.
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    // Recovery pincode email captured by the test mailbox.
    const email = await waitForEmail(request, (e) => e.kind === "recovery.pincode");
    expect(email.recipient).toBe(ALICE_EMAIL);
    expect(email.code, "OTP email must carry a numeric code").toMatch(/^\d{6}$/);

    // Phase 2 — PincodeForm.
    await waitForFormInput(page, "code", 15_000);
    await fillField(page, "code", email.code as string);
    await submitForm(page);

    // Phase 3 — SetPasswordForm.
    await waitForFormInput(page, "newPassword", 15_000);
    // Pin the reset-flow heading + intro copy. `create-password-form` stages
    // these on `ctx.password.heading` / `ctx.password.intro` based on
    // `changeReason='reset'` set by `init-recovery`. A regression that fell
    // through to the 'initial' branch (the default fallback) would silently
    // rename the screen to "Set your initial password".
    await expect(page.getByText("Reset your password")).toBeVisible();
    await expect(page.getByText(/Choose a new password for your account/i)).toBeVisible();
    await fillField(page, "newPassword", NEW_PASSWORD);
    await fillField(page, "confirmPassword", NEW_PASSWORD);
    await submitForm(page);

    await expect(page.getByText("Workflow finished.")).toBeVisible();
    const envelope = (await readFinishEnvelope(page)) as {
      finished?: boolean;
      next?: { action?: { type?: string; target?: string } };
      data?: { accessToken?: string };
    };
    expect(envelope.finished).toBe(true);
    expect(envelope.next?.action?.type).toBe("redirect");
    expect(envelope.next?.action?.target).toMatch(/\/login/);
    expect(envelope.data?.accessToken, "fresh-login finish must NOT issue tokens").toBeFalsy();

    // Lifecycle: the reset happened, so `afterPasswordReset` fires — but this is
    // the FRESH-login finalize (no session issued), so `afterLogin` must NOT
    // fire. Proves the funnel correctly treats no-session finalize as a non-login.
    const events = (await (await request.get("/__test/lifecycle")).json()) as { event: string }[];
    const names = events.map((e) => e.event);
    expect(names, "recovery reset fires afterPasswordReset").toContain("afterPasswordReset");
    expect(names, "fresh-login recovery is not a login (no session)").not.toContain("afterLogin");
  });

  test("WF-RECOVERY-002: unknown email → generic finish, no mailbox event", async ({
    page,
    request,
  }) => {
    // Anti-enumeration: the request step short-circuits to a generic finish
    // for unknown emails. No `recovery.pincode` event for the ghost address.
    await page.goto(wfUrl("auth/recovery/flow"));

    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", "ghost@nowhere.test");
    await submitForm(page);

    await expect(page.getByText("Workflow finished.")).toBeVisible();
    const envelope = (await readFinishEnvelope(page)) as {
      data?: { accessToken?: string };
    };
    expect(envelope.data?.accessToken, "unknown email must not issue tokens").toBeFalsy();

    // No recovery email sent for the ghost address.
    const events = await getEmails(request);
    const recoveryEvents = events.filter((e) => e.kind === "recovery.pincode");
    expect(recoveryEvents).toEqual([]);
  });

  test("WF-RECOVERY-003: password mismatch on SetPasswordForm → inline 'Passwords do not match'", async ({
    page,
    request,
  }) => {
    await page.goto(wfUrl("auth/recovery/flow"));
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    const email = await waitForEmail(request, (e) => e.kind === "recovery.pincode");
    await waitForFormInput(page, "code", 15_000);
    await fillField(page, "code", email.code as string);
    await submitForm(page);

    await waitForFormInput(page, "newPassword", 15_000);
    await fillField(page, "newPassword", NEW_PASSWORD);
    await fillField(page, "confirmPassword", "DifferentPass2!");
    await submitForm(page);

    // SPA's `SetPasswordForm` renders client-side password-rule rows; the
    // "passwords must match" row trips before submit reaches the server,
    // so the user sees the live rule rather than the server-side
    // "Passwords do not match" message. Pin the live row's failure state.
    await expect(page.getByText(/Passwords must match/i)).toBeVisible();
    await expect(page.getByText("Workflow finished.")).not.toBeVisible();
  });

  test("WF-RECOVERY-005: PincodeForm renders code mask + 'code' hint; valid OTP advances to SetPasswordForm", async ({
    page,
    request,
  }) => {
    // Focused assertion on the PincodeForm step — separate from the
    // end-to-end happy path in -001.
    await page.goto(wfUrl("auth/recovery/flow"));
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    const email = await waitForEmail(request, (e) => e.kind === "recovery.pincode");
    expect(email.code).toMatch(/^\d{6}$/);

    await waitForFormInput(page, "code", 15_000);
    await expect(page.locator('[name="code"]').first()).toBeVisible();
    // Hint paragraph mentions "code" (recipient mask or "Code sent to…").
    const formText = (await page.locator("form").first().textContent()) ?? "";
    expect(formText.toLowerCase()).toContain("code");

    await fillField(page, "code", email.code as string);
    await submitForm(page);

    // Valid OTP advances to SetPasswordForm.
    await waitForFormInput(page, "newPassword", 15_000);
    await expect(page.locator('[name="newPassword"]').first()).toBeVisible();
  });

  test("WF-RECOVERY-009: wrong OTP → errors.code='Invalid code', form re-renders", async ({
    page,
    request,
  }) => {
    await page.goto(wfUrl("auth/recovery/flow"));
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    // Drain the pincode email so we know the code was minted, then submit a
    // wrong one.
    await waitForEmail(request, (e) => e.kind === "recovery.pincode");

    await waitForFormInput(page, "code", 15_000);
    await fillField(page, "code", "000000");
    await submitForm(page);

    await expect(page.getByText("Invalid code")).toBeVisible();
    // Still paused on PincodeForm — no SetPasswordForm yet.
    await expect(page.locator('[name="code"]').first()).toBeVisible();
    await expect(page.locator('[name="newPassword"]')).toHaveCount(0);
  });

  test("WF-RECOVERY-017: backToLogin on EmailIdentifierForm → finish reason='user-cancelled', no token", async ({
    page,
  }) => {
    // `recoveryAltActions.backToLogin` defaults to true. Click the pushed-down
    // "Remembered your password? Sign in" alt-action (link = "Sign in") before
    // submitting an email — `abortRecoveryToLogin` emits a redirect-with-reason
    // finish envelope.
    await page.goto(wfUrl("auth/recovery/flow"));
    await waitForFormInput(page, "email", 15_000);
    await clickAction(page, "Sign in");

    await expect(page.getByText("Workflow finished.")).toBeVisible();
    const envelope = (await readFinishEnvelope(page)) as {
      finished?: boolean;
      next?: { action?: { type?: string; reason?: string } };
      data?: { accessToken?: string };
    };
    expect(envelope.finished).toBe(true);
    expect(envelope.next?.action?.type).toBe("redirect");
    expect(envelope.next?.action?.reason).toBe("user-cancelled");
    expect(envelope.data?.accessToken).toBeFalsy();
  });

  test("WF-RECOVERY-018: post-reset old session token rejected (default revokeAllSessions=true)", async ({
    page,
    request,
    context,
  }) => {
    // Phase 1: log alice in via the SPA so the browser context's cookie jar
    // gets the `aooth_session` cookie. Snapshot the cookie as the "old" token.
    await loginViaUi(page, USERS.alice);
    const cookiesBefore = await context.cookies();
    const oldSession = cookiesBefore.find((c) => c.name === "aooth_session");
    expect(oldSession?.value, "login must set aooth_session cookie").toBeTruthy();

    // whoami with the old session returns 200 pre-recovery.
    const oldAuth = { Authorization: `Bearer ${oldSession?.value}` };
    const before = await request.get("/__test/whoami", { headers: oldAuth });
    expect(before.status()).toBe(200);

    // Phase 2: drive recovery (OTP-via-email) end-to-end on the same context.
    await page.goto(wfUrl("auth/recovery/flow"));
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    const email = await waitForEmail(request, (e) => e.kind === "recovery.pincode");
    await waitForFormInput(page, "code", 15_000);
    await fillField(page, "code", email.code as string);
    await submitForm(page);

    await waitForFormInput(page, "newPassword", 15_000);
    await fillField(page, "newPassword", NEW_PASSWORD);
    await fillField(page, "confirmPassword", NEW_PASSWORD);
    await submitForm(page);
    await expect(page.getByText("Workflow finished.")).toBeVisible();

    // Old session token is now rejected — `revoke-sessions` bumped alice's
    // epoch past the token's iat.
    const after = await request.get("/__test/whoami", { headers: oldAuth });
    expect(after.status(), "old token must be rejected after revoke-sessions").toBe(401);
  });
});

test.describe("recovery — recovery-auto-login", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-RECOVERY-016: autoLoginOnRecover=true → finish envelope carries accessToken", async ({
    page,
    request,
  }) => {
    await page.goto(wfUrl("auth/recovery/flow", "recovery-auto-login"));
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    const email = await waitForEmail(request, (e) => e.kind === "recovery.pincode");
    await waitForFormInput(page, "code", 15_000);
    await fillField(page, "code", email.code as string);
    await submitForm(page);

    await waitForFormInput(page, "newPassword", 15_000);
    await fillField(page, "newPassword", NEW_PASSWORD);
    await fillField(page, "confirmPassword", NEW_PASSWORD);
    await submitForm(page);

    await expect(page.getByText("Workflow finished.")).toBeVisible();
    const envelope = (await readFinishEnvelope(page)) as {
      data?: { accessToken?: string };
    };
    expect(envelope.data?.accessToken, "auto-login variant must issue tokens").toBeTruthy();
  });
});

test.describe("recovery — recovery-short-ttl", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-RECOVERY-004: expired recovery state cannot resume → error block, no SetPasswordForm", async ({
    page,
    request,
  }) => {
    // `recoveryStateTtlMs: 1` stamps every recovery-side pause with an
    // immediate expiry. Waiting 50ms between OTP-mint and OTP-submit makes
    // the resume hit @prostojs/wf's "Invalid or expired workflow state"
    // branch; the SPA renders the failure in `.scope-error` / `.as-wf-form-error`.
    await page.goto(wfUrl("auth/recovery/flow", "recovery-short-ttl"));
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    const email = await waitForEmail(request, (e) => e.kind === "recovery.pincode");
    await waitForFormInput(page, "code", 15_000);

    // Wait past the 1ms TTL — 50ms is generous against clock jitter.
    await page.waitForTimeout(50);
    await fillField(page, "code", email.code as string);
    await submitForm(page);

    await expect(page.locator(".as-wf-form-error, .scope-error").first()).toBeVisible({
      timeout: 5_000,
    });
    await expect(page.locator('[name="newPassword"]')).toHaveCount(0);
  });
});

test.describe("recovery — recovery-fast-resend", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-RECOVERY-010: resend within cooldown → 'Please wait' error, no new email", async ({
    page,
    request,
  }) => {
    // The unified pincode-check resend branch enforces the cooldown server-
    // side and throws `requireInput({ errors: { code: 'Please wait before
    // requesting a new code.' } })`. Mailbox must still hold exactly one
    // pincode email.
    await page.goto(wfUrl("auth/recovery/flow", "recovery-fast-resend"));
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    const firstEmail = await waitForEmail(request, (e) => e.kind === "recovery.pincode");
    await waitForFormInput(page, "code", 15_000);

    // Click `Resend code` immediately — well inside the 1s cooldown.
    await clickAction(page, "Resend code");
    await expect(page.getByText(/Please wait/i)).toBeVisible();

    const events = await getEmails(request);
    const pincodeEmails = events.filter((e) => e.kind === "recovery.pincode");
    expect(pincodeEmails).toHaveLength(1);
    expect(pincodeEmails[0].code).toBe(firstEmail.code);
  });

  test("WF-RECOVERY-011: resend after cooldown → new code emitted, codes differ", async ({
    page,
    request,
  }) => {
    await page.goto(wfUrl("auth/recovery/flow", "recovery-fast-resend"));
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    const firstEmail = await waitForEmail(request, (e) => e.kind === "recovery.pincode");
    await waitForFormInput(page, "code", 15_000);

    // Wait past the 1s cooldown configured by `recovery-fast-resend`.
    await page.waitForTimeout(1200);
    await clickAction(page, "Resend code");

    await expect
      .poll(
        async () => (await getEmails(request)).filter((e) => e.kind === "recovery.pincode").length,
        { timeout: 5_000 },
      )
      .toBe(2);

    const events = await getEmails(request);
    const pincodeEmails = events.filter((e) => e.kind === "recovery.pincode");
    expect(pincodeEmails[0].code).toBe(firstEmail.code);
    expect(pincodeEmails[1].code).not.toBe(firstEmail.code);
  });
});

test.describe("recovery — recovery-terms-bump (inline consent)", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-RECOVERY-CONSENT-01: SetPasswordForm renders AsConsentArray; tick + submit persists consent", async ({
    page,
    request,
  }) => {
    // `DemoConsentStore.getPendingConsents` returns a single required-terms
    // v2 descriptor for this variant — `AsConsentArray` renders the row on
    // `SetPasswordForm`. After submit, `persist-consents` writes one event
    // into the shared consent log. The variant has no `autoLoginOnRecover`
    // override → finish envelope must NOT carry an accessToken (default
    // `false`).
    const username = USERS.alice.username;

    // Sanity: consent log starts empty for alice.
    const before = await request.get(`/__test/consent-log/${encodeURIComponent(username)}`);
    expect(before.status()).toBe(200);
    expect((await before.json()) as unknown[]).toEqual([]);

    await page.goto(wfUrl("auth/recovery/flow", "recovery-terms-bump"));

    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    const email = await waitForEmail(request, (e) => e.kind === "recovery.pincode");
    await waitForFormInput(page, "code", 15_000);
    await fillField(page, "code", email.code as string);
    await submitForm(page);

    await waitForFormInput(page, "newPassword", 15_000);
    await expect(page.getByText("I accept the updated Terms")).toBeVisible();
    await fillField(page, "newPassword", NEW_PASSWORD);
    await fillField(page, "confirmPassword", NEW_PASSWORD);
    await page.locator('input[type="checkbox"]').first().check();
    await submitForm(page);

    await expect(page.getByText("Workflow finished.")).toBeVisible();
    const envelope = (await readFinishEnvelope(page)) as {
      finished?: boolean;
      data?: { accessToken?: string };
    };
    expect(envelope.finished).toBe(true);
    expect(envelope.data?.accessToken, "default autoLoginOnRecover=false → no token").toBeFalsy();

    // Unified consent log carries the captured event in the new shape.
    const after = await request.get(`/__test/consent-log/${encodeURIComponent(username)}`);
    expect(after.status()).toBe(200);
    const events = (await after.json()) as Array<{
      id: string;
      accepted: boolean;
      version?: string;
      at: number;
    }>;
    expect(events.length).toBe(1);
    expect(events[0].id).toBe("terms");
    expect(events[0].accepted).toBe(true);
    expect(events[0].version).toBe("v2");
    expect(typeof events[0].at).toBe("number");
  });
});
