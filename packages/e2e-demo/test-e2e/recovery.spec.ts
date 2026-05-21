/**
 * Recovery workflow — P0 stories from USER_STORIES.md §4.
 *
 * Drives `auth.recovery` end-to-end through the SPA against the demo backend
 * (`DEMO_MODE=test`). Each story walks the WfPage UI and asserts both
 * rendered DOM (the Playwright value-add over the in-process vitest suite)
 * AND captured mailbox events (proof the backend reached the right outlet).
 *
 * Variant selection is delegated to the `?variant=...` query param read by
 * `WfPage.vue` and forwarded as the `x-wf-variant` request header — see
 * `packages/e2e-demo/src/variants.ts` (`RECOVERY_VARIANTS`).
 *
 * Infra gap (flagged via `test.fixme` below): in the LIVE demo server
 * (`pnpm dev` + `DEMO_MODE=test`), `/auth/trigger` responds `{sent:true,
 * outlet:"email"}` after the EmailIdentifierForm submit — proving the
 * workflow advanced through the `outletEmail` step — yet `/__test/emails`
 * stays empty. The same flow (same `buildApp`, same `CaptureEmailSender`)
 * works in-process under vitest. Until the live-server mailbox capture is
 * fixed, every magic-link / OTP-bearing story must `fixme`. The two stories
 * that don't depend on a captured email (WF-RECOVERY-002 — unknown email
 * → no email expected) run green.
 */
import { expect, test } from "@playwright/test";

import {
  fillField,
  getEmails,
  resetApp,
  submitForm,
  waitForEmail,
  waitForFormInput,
  waitForSms,
  wfUrl,
} from "./harness";

const ALICE_EMAIL = "alice@acme.test";
const NEW_PASSWORD = "NewPassword2!";

/**
 * Live-demo mailbox capture is currently a no-op for outlet-driven emails —
 * see file header. Every story that depends on extracting a magic-link URL
 * or an OTP code is parked on this reason until the demo server's
 * `CaptureEmailSender` ref is reconnected to the outlet wiring.
 */
const MAILBOX_OUTLET_GAP =
  "Live demo: /__test/emails stays empty after outlet-driven send (vitest in-process works, http server does not). Tracked under demo infra; un-fixme once /__test/emails captures outletEmail-issued events.";

/** WfPage shows the unified `WfFinished` envelope in a `<pre>` after finish. */
async function readFinishedEnvelope(page: import("@playwright/test").Page): Promise<unknown> {
  const pre = page.locator("pre").first();
  await pre.waitFor({ state: "visible" });
  const raw = (await pre.textContent()) ?? "";
  return JSON.parse(raw) as unknown;
}

/**
 * Magic-link `url` lives in `AuthEmailEvent.url` as the absolute frontend URL
 * (e.g. `http://localhost:5173/recover?wfs=...`). Reuse the same `?wfs=...`
 * token against the BASE_URL so the test runs against the demo backend.
 */
function rewriteToBaseUrl(absolute: string, baseURL: string): string {
  const parsed = new URL(absolute);
  return `${baseURL.replace(/\/$/, "")}${parsed.pathname}${parsed.search}`;
}

test.describe("recovery — default-magiclink (R-A)", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-RECOVERY-001: alice → magic link → set password → tokens issued", async ({
    page,
    request,
    baseURL,
  }) => {
    test.fixme(true, MAILBOX_OUTLET_GAP);
    await page.goto(wfUrl("auth.recovery", "default-magiclink"));

    // Phase 1 — EmailIdentifierForm
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    // Magic link email captured by the test mailbox.
    const email = await waitForEmail(request, (e) => e.kind === "recovery.magicLink");
    expect(email.recipient).toBe(ALICE_EMAIL);
    expect(email.url, "magic-link email must carry a resume url").toBeTruthy();
    expect(email.url).toContain("wfs=");

    // Phase 2 — click the magic link. Rewrite to BASE_URL so the test stays
    // within the backend demo (which serves the SPA in test mode).
    const resumeUrl = rewriteToBaseUrl(email.url as string, baseURL ?? "");
    await page.goto(resumeUrl);

    // SetPasswordForm renders the two password fields. `passwordPolicies` is
    // shipped via `@wf.context.pass` but the default form has no visible
    // "policy hint" paragraph — only the input fields with their `@expect.*`
    // metadata. Assert what is actually rendered.
    await waitForFormInput(page, "newPassword", 15_000);
    await expect(page.locator('[name="newPassword"]').first()).toBeVisible();
    await expect(page.locator('[name="confirmPassword"]').first()).toBeVisible();

    await fillField(page, "newPassword", NEW_PASSWORD);
    await fillField(page, "confirmPassword", NEW_PASSWORD);
    await submitForm(page);

    await expect(page.getByText("Workflow finished.")).toBeVisible();
    const envelope = (await readFinishedEnvelope(page)) as {
      finished?: boolean;
      data?: { accessToken?: string };
    };
    expect(envelope.finished).toBe(true);
    expect(envelope.data?.accessToken, "auto-login issues tokens after reset").toBeTruthy();
  });

  test("WF-RECOVERY-002: unknown email → generic finish, no mailbox email", async ({
    page,
    request,
  }) => {
    await page.goto(wfUrl("auth.recovery", "default-magiclink"));

    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", "ghost@nowhere.test");
    await submitForm(page);

    await expect(page.getByText("Workflow finished.")).toBeVisible();
    const envelope = (await readFinishedEnvelope(page)) as {
      message?: { text?: string };
      data?: { accessToken?: string };
    };
    // Anti-enumeration: same generic message known + unknown emails would
    // both receive (no `accessToken`, no leakage of "user not found").
    expect(envelope.message?.text ?? "").toMatch(/if an account exists/i);
    expect(envelope.data?.accessToken, "unknown email must not issue tokens").toBeFalsy();

    // No magic link sent for the ghost address.
    const emails = await getEmails(request);
    expect(emails).toEqual([]);
  });
});

test.describe("recovery — otp-email (R-B)", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-RECOVERY-005: alice → email OTP → set password → tokens issued", async ({
    page,
    request,
  }) => {
    test.fixme(true, MAILBOX_OUTLET_GAP);
    await page.goto(wfUrl("auth.recovery", "otp-email"));

    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    // Capture the OTP code from the recovery.pincode email.
    const email = await waitForEmail(request, (e) => e.kind === "recovery.pincode");
    expect(email.recipient).toBe(ALICE_EMAIL);
    expect(email.code, "OTP email must carry a numeric code").toMatch(/^\d{6}$/);

    // PincodeForm's transportHint paragraph is driven by `@ui.form.fn.value`
    // — when `installDynamicResolver()` is wired it reads "Code sent to ...
    // — check the dev server console for the code." Assert SOME mask
    // (asterisk or word "Code") is visible rather than the exact recipient.
    await waitForFormInput(page, "code", 15_000);
    const formText = (await page.locator("form").first().textContent()) ?? "";
    expect(formText.toLowerCase()).toContain("code");

    await fillField(page, "code", email.code as string);
    await submitForm(page);

    // SetPasswordForm
    await waitForFormInput(page, "newPassword", 15_000);
    await fillField(page, "newPassword", NEW_PASSWORD);
    await fillField(page, "confirmPassword", NEW_PASSWORD);
    await submitForm(page);

    await expect(page.getByText("Workflow finished.")).toBeVisible();
    const envelope = (await readFinishedEnvelope(page)) as {
      data?: { accessToken?: string };
    };
    expect(envelope.data?.accessToken).toBeTruthy();
  });
});

test.describe("recovery — otp-sms (R-C)", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-RECOVERY-006: t1_ivy → SMS OTP → set password → tokens issued", async ({
    page,
    request,
  }) => {
    test.fixme(true, MAILBOX_OUTLET_GAP);
    await page.goto(wfUrl("auth.recovery", "otp-sms"));

    // `t1_ivy` is seeded with SMS MFA confirmed on +15555550101 — see seed.ts.
    // RecoveryWorkflow.emailToUserId maps email → username; in this demo the
    // store treats email as the lookup key, so submit ivy's email.
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", "ivy@acme.test");
    await submitForm(page);

    // SMS OTP captured by the test mailbox.
    const sms = await waitForSms(request, (e) => e.kind === "recovery.pincode");
    expect(sms.recipient).toBe("+15555550101");
    expect(sms.code).toMatch(/^\d{6}$/);

    await waitForFormInput(page, "code", 15_000);
    await fillField(page, "code", sms.code);
    await submitForm(page);

    await waitForFormInput(page, "newPassword", 15_000);
    await fillField(page, "newPassword", NEW_PASSWORD);
    await fillField(page, "confirmPassword", NEW_PASSWORD);
    await submitForm(page);

    await expect(page.getByText("Workflow finished.")).toBeVisible();
    const envelope = (await readFinishedEnvelope(page)) as {
      data?: { accessToken?: string };
    };
    expect(envelope.data?.accessToken).toBeTruthy();
  });
});

test.describe("recovery — choice (R-E)", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-RECOVERY-012: choice mode → pick magicLink → email sent", async ({ page, request }) => {
    test.fixme(true, MAILBOX_OUTLET_GAP);
    await page.goto(wfUrl("auth.recovery", "choice"));

    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    // RecoveryModeSelectForm — a text field with regex pattern
    // `^(magicLink|otp)$`. Today it's a free-text input (no proper picker
    // widget yet) — assert the field is present and submit `magicLink`.
    await waitForFormInput(page, "mode", 15_000);
    await expect(page.locator('[name="mode"]').first()).toBeVisible();
    await fillField(page, "mode", "magicLink");
    await submitForm(page);

    // Magic-link email captured — proves the chosen branch executed.
    const email = await waitForEmail(request, (e) => e.kind === "recovery.magicLink");
    expect(email.recipient).toBe(ALICE_EMAIL);
    expect(email.url).toContain("wfs=");
  });
});

test.describe("recovery — fresh-login (R-G)", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-RECOVERY-016: freshLoginRequired → finish envelope has 5s auto redirect, no tokens", async ({
    page,
    request,
    baseURL,
  }) => {
    test.fixme(true, MAILBOX_OUTLET_GAP);
    await page.goto(wfUrl("auth.recovery", "fresh-login"));

    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    const email = await waitForEmail(request, (e) => e.kind === "recovery.magicLink");
    const resumeUrl = rewriteToBaseUrl(email.url as string, baseURL ?? "");
    // `fresh-login` variant enables revokeAllSessions=true. The resume happens
    // anonymously (the recovery workflow is `@Public()`) so the engine
    // proceeds through setPassword on the resumed state.
    await page.goto(resumeUrl);

    await waitForFormInput(page, "newPassword", 15_000);
    await fillField(page, "newPassword", NEW_PASSWORD);
    await fillField(page, "confirmPassword", NEW_PASSWORD);
    await submitForm(page);

    await expect(page.getByText("Workflow finished.")).toBeVisible();
    const envelope = (await readFinishedEnvelope(page)) as {
      finished?: boolean;
      next?: { trigger?: string; timeoutMs?: number; action?: { type?: string } };
      data?: { accessToken?: string };
    };
    expect(envelope.finished).toBe(true);
    expect(envelope.next?.trigger).toBe("auto");
    expect(envelope.next?.timeoutMs).toBe(5000);
    expect(envelope.next?.action?.type).toBe("redirect");
    // freshLoginRequired skips the auto-login step entirely.
    expect(envelope.data?.accessToken).toBeFalsy();
  });
});
