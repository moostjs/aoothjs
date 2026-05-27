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
 */
import { expect, test } from "@playwright/test";

import {
  clickAction,
  fillField,
  getEmails,
  loginViaUi,
  readFinishEnvelope,
  resetApp,
  rewriteToBaseUrl,
  submitForm,
  USERS,
  waitForEmail,
  waitForFormInput,
  waitForSms,
  wfUrl,
} from "./harness";

/**
 * Extract the `wfs=<token>` from a magic-link URL emitted by the demo's
 * `buildMagicLinkUrl`. Tests that need to resume into a non-default variant
 * (e.g. WF-RECOVERY-004's short-TTL variant) can't just `rewriteToBaseUrl`
 * the email — the SPA router collapses `/recover?wfs=…` into
 * `/wf?id=auth.recovery&wfs=…`, dropping any `?variant=` the test boot used.
 * Reconstructing the URL with `wfUrl(wfId, variant) + "&wfs="` keeps the
 * variant header alive on the resume request.
 */
function extractWfs(url: string): string {
  const parsed = new URL(url);
  const wfs = parsed.searchParams.get("wfs");
  if (!wfs) throw new Error(`magic-link URL missing wfs param: ${url}`);
  return wfs;
}

const ALICE_EMAIL = "alice@acme.test";
const NEW_PASSWORD = "NewPassword2!";

test.describe("recovery — default-magiclink (R-A)", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-RECOVERY-001: alice → magic link → set password → tokens issued", async ({
    page,
    request,
    baseURL,
  }) => {
    await page.goto(wfUrl("auth/recovery/flow", "default-magiclink"));

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

    // SetPasswordForm renders the two password fields. `password.policies` is
    // shipped via `@wf.context.pass 'password'` but the default form has no
    // visible "policy hint" paragraph — only the input fields with their
    // `@expect.*` metadata. Assert what is actually rendered.
    await waitForFormInput(page, "newPassword", 15_000);
    await expect(page.locator('[name="newPassword"]').first()).toBeVisible();
    await expect(page.locator('[name="confirmPassword"]').first()).toBeVisible();

    // Pin the recovery-specific heading + intro copy. Bundled phantom
    // paragraphs read `ctx.password.heading` / `ctx.password.intro` set
    // by `set-password` before the pause.
    await expect(page.getByText("Reset your password")).toBeVisible();
    await expect(page.getByText(/Choose a new password/i)).toBeVisible();

    await fillField(page, "newPassword", NEW_PASSWORD);
    await fillField(page, "confirmPassword", NEW_PASSWORD);
    await submitForm(page);

    await expect(page.getByText("Workflow finished.")).toBeVisible();
    const envelope = (await readFinishEnvelope(page)) as {
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
    await page.goto(wfUrl("auth/recovery/flow", "default-magiclink"));

    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", "ghost@nowhere.test");
    await submitForm(page);

    await expect(page.getByText("Workflow finished.")).toBeVisible();
    const envelope = (await readFinishEnvelope(page)) as {
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
    await page.goto(wfUrl("auth/recovery/flow", "otp-email"));

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
    const envelope = (await readFinishEnvelope(page)) as {
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
    await page.goto(wfUrl("auth/recovery/flow", "otp-sms"));

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
    const envelope = (await readFinishEnvelope(page)) as {
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
    await page.goto(wfUrl("auth/recovery/flow", "choice"));

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
    await page.goto(wfUrl("auth/recovery/flow", "fresh-login"));

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
    const envelope = (await readFinishEnvelope(page)) as {
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

// =====================================================================
// P1 stories — secondary branches and validation/error paths.
// =====================================================================

test.describe("recovery — default-magiclink P1 branches", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-RECOVERY-003: password mismatch on SetPasswordForm → inline 'Passwords do not match'", async ({
    page,
    request,
    baseURL,
  }) => {
    // BRANCH: setPassword step's `newPassword !== confirmPassword` guard —
    // workflow throws `requireInput({ errors: { confirmPassword: ... } })`
    // which AsWfForm renders next to the confirmPassword field.
    await page.goto(wfUrl("auth/recovery/flow", "default-magiclink"));
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    const email = await waitForEmail(request, (e) => e.kind === "recovery.magicLink");
    await page.goto(rewriteToBaseUrl(email.url as string, baseURL ?? ""));

    await waitForFormInput(page, "newPassword", 15_000);
    await fillField(page, "newPassword", NEW_PASSWORD);
    await fillField(page, "confirmPassword", "DifferentPass2!");
    await submitForm(page);

    // The error text appears inline; form remains paused (no finish banner).
    await expect(page.getByText("Passwords do not match")).toBeVisible();
    await expect(page.getByText("Workflow finished.")).not.toBeVisible();
  });

  test("WF-RECOVERY-004: expired magic link → error banner on resume, no setPassword form", async ({
    page,
    request,
  }) => {
    // BRANCH: @wooksjs/event-wf strategy.consume returns null for an
    // expired state → controller responds 410 `{ error: "Invalid or expired
    // workflow state" }`. AsWfForm surfaces a non-ok response as `error.value`
    // which WfPage renders inside the `scope-error` div.
    await page.goto(wfUrl("auth/recovery/flow", "recovery-short-ttl"));
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    const email = await waitForEmail(request, (e) => e.kind === "recovery.magicLink");
    const wfs = extractWfs(email.url as string);

    // Wait past the 1ms TTL — 50ms is generous against clock jitter.
    await page.waitForTimeout(50);

    // Rebuild the resume URL so the `recovery-short-ttl` variant header is
    // re-sent on the resume request (`rewriteToBaseUrl` would strip it).
    // `page.goto` resolves the relative URL against playwright's `use.baseURL`.
    await page.goto(`${wfUrl("auth/recovery/flow", "recovery-short-ttl")}&wfs=${wfs}`);

    // SetPasswordForm must NOT appear; the error block must be shown.
    await expect(page.locator(".as-wf-form-error, .scope-error")).toBeVisible({ timeout: 5_000 });
    await expect(page.locator('[name="newPassword"]')).toHaveCount(0);
  });

  test("WF-RECOVERY-017: backToLogin on request form → finish envelope with reason='user-cancelled'", async ({
    page,
  }) => {
    // BRANCH: `recoveryRequest` resolves the `backToLogin` alt-action BEFORE
    // form validation. `abortToLogin` calls `finishWf({ next: { action: {
    // type:'redirect', reason:'user-cancelled' } } })` and sets ctx.aborted
    // so every downstream step short-circuits.
    await page.goto(wfUrl("auth/recovery/flow", "default-magiclink"));
    await waitForFormInput(page, "email", 15_000);
    // Click the `Back to sign-in` action — no email value needed since the
    // action is resolved before required-field validation.
    await clickAction(page, "Back to sign-in");

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
});

test.describe("recovery — otp-email P1 branches", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-RECOVERY-008: useDifferentTransport hidden when only 1 transport configured", async ({
    page,
  }) => {
    // BRANCH: `PincodeForm.useDifferentTransport` is gated by
    // `@ui.form.fn.hidden '(_, _d, ctx) => (ctx.otp?.transportCount ?? 0) < 2'`.
    // `recoveryInit` mirrors `opts.delivery.otp.transports.length` into
    // `ctx.otp?.transportCount`, so a single-transport variant hides the
    // alt-action button entirely.
    await page.goto(wfUrl("auth/recovery/flow", "otp-email"));
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    await waitForFormInput(page, "code", 15_000);
    await expect(page.getByRole("button", { name: "Use a different transport" })).toHaveCount(0);
    // The other PincodeForm actions ARE expected to render.
    await expect(page.getByRole("button", { name: "Resend code" })).toBeVisible();
  });

  test("WF-RECOVERY-009: wrong OTP → errors.code='Invalid code', form re-renders", async ({
    page,
    request,
  }) => {
    // BRANCH: `recoveryCheckOtp` → `verifyPin` returns `{ code: "Invalid
    // code" }` for any pin !== ctx.pin. The error is rendered inline next to
    // the `code` field via AsWfForm's per-field error map.
    await page.goto(wfUrl("auth/recovery/flow", "otp-email"));
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    // Drain the captured pincode email so we know the code was minted (but
    // we deliberately submit a wrong one).
    await waitForEmail(request, (e) => e.kind === "recovery.pincode");

    await waitForFormInput(page, "code", 15_000);
    await fillField(page, "code", "000000");
    await submitForm(page);

    await expect(page.getByText("Invalid code")).toBeVisible();
    // Still paused — pincode input still present, no setPassword pause yet.
    await expect(page.locator('[name="code"]').first()).toBeVisible();
    await expect(page.locator('[name="newPassword"]')).toHaveCount(0);
  });
});

test.describe("recovery — fast-resend P1 branches", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-RECOVERY-010: resend within cooldown → 'Please wait Ns' form error, no new email", async ({
    page,
    request,
  }) => {
    // BRANCH: `recoveryCheckOtp` `resend` action checks `ctx.otp?.resendAllowedAt`
    // and throws `requireInput({ formMessage: 'Please wait Ns' })` when still
    // inside the cooldown. The mailbox must NOT gain a second pincode email.
    await page.goto(wfUrl("auth/recovery/flow", "recovery-fast-resend"));
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    const firstEmail = await waitForEmail(request, (e) => e.kind === "recovery.pincode");
    await waitForFormInput(page, "code", 15_000);

    // Click `Resend code` immediately — well inside the 1s cooldown.
    await clickAction(page, "Resend code");
    await expect(page.getByText(/Please wait \d+s/)).toBeVisible();

    // Mailbox still has exactly one pincode email — no fresh code was minted.
    const events = await getEmails(request);
    const pincodeEmails = events.filter((e) => e.kind === "recovery.pincode");
    expect(pincodeEmails).toHaveLength(1);
    expect(pincodeEmails[0].code).toBe(firstEmail.code);
  });

  test("WF-RECOVERY-011: resend after cooldown → new code emitted, codes differ", async ({
    page,
    request,
  }) => {
    // BRANCH: same `resend` action — after the cooldown elapses the action
    // deletes `ctx.pin` and the while-loop re-fires `sendOtp`, minting a
    // fresh code and re-delivering. Mailbox ends up with 2 pincode emails.
    await page.goto(wfUrl("auth/recovery/flow", "recovery-fast-resend"));
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    const firstEmail = await waitForEmail(request, (e) => e.kind === "recovery.pincode");
    await waitForFormInput(page, "code", 15_000);

    // Wait past the 1s cooldown configured by `recovery-fast-resend`.
    await page.waitForTimeout(1200);
    await clickAction(page, "Resend code");

    // A second pincode email must arrive with a different code. We poll until
    // the buffer has 2 entries, then compare.
    await expect
      .poll(
        async () => (await getEmails(request)).filter((e) => e.kind === "recovery.pincode").length,
        { timeout: 5_000 },
      )
      .toBe(2);

    const events = await getEmails(request);
    const pincodeEmails = events.filter((e) => e.kind === "recovery.pincode");
    expect(pincodeEmails[0].code).toBe(firstEmail.code);
    // Different code on the resend.
    expect(pincodeEmails[1].code).not.toBe(firstEmail.code);
  });
});

test.describe("recovery — otp-both (R-D) P1 branches", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-RECOVERY-007: switch transport email → sms via useDifferentTransport", async ({
    page,
    request,
  }) => {
    // BRANCH: `recoveryCheckOtp` `useDifferentTransport` rotates
    // `ctx.otp?.transport` from the first element of `delivery.otp.transports`
    // (`email`) to the next (`sms`), clears the pin, and the while-loop
    // re-runs `recoverySendOtp` on the new channel. Mailbox: 1 email
    // pincode + 1 sms pincode. Uses t1_ivy because she has a confirmed phone
    // (+15555550101) so the SMS deliver has a real recipient.
    await page.goto(wfUrl("auth/recovery/flow", "otp-both"));
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", "ivy@acme.test");
    await submitForm(page);

    // First leg — email pincode.
    const emailCode = await waitForEmail(request, (e) => e.kind === "recovery.pincode");
    expect(emailCode.recipient).toBe("ivy@acme.test");

    await waitForFormInput(page, "code", 15_000);
    await clickAction(page, "Use a different transport");

    // Second leg — SMS pincode delivered to the user's recorded phone.
    const sms = await waitForSms(request, (e) => e.kind === "recovery.pincode");
    expect(sms.recipient).toBe("+15555550101");
    expect(sms.code).toMatch(/^\d{6}$/);
  });
});

test.describe("recovery — choice (R-E) P1 branches", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-RECOVERY-013: choice mode → pick otp → PincodeForm appears", async ({
    page,
    request,
  }) => {
    // BRANCH: `recoverySelectMode` sets `ctx.delivery?.resolvedMode = 'otp'` and
    // selects the default OTP transport (`email` per merge defaults). The
    // schema's while-loop then runs sendOtp + checkOtp, so the next form is
    // PincodeForm rather than SetPasswordForm.
    await page.goto(wfUrl("auth/recovery/flow", "choice"));
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    await waitForFormInput(page, "mode", 15_000);
    await fillField(page, "mode", "otp");
    await submitForm(page);

    // Pincode email arrives; PincodeForm's `code` input becomes visible.
    const email = await waitForEmail(request, (e) => e.kind === "recovery.pincode");
    expect(email.recipient).toBe(ALICE_EMAIL);
    expect(email.code).toMatch(/^\d{6}$/);

    await waitForFormInput(page, "code", 15_000);
    await expect(page.locator('[name="code"]').first()).toBeVisible();
  });
});

test.describe("recovery — pre-factor (R-F) P1 branches", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-RECOVERY-014: pre-reset factor (phone last-4) → SetPasswordForm renders", async ({
    page,
    request,
    baseURL,
  }) => {
    // BRANCH: `preReset.requireKnownFactor=true` inserts `recoveryVerifyFactor`
    // between the magic-link click and `recoverySetPassword`. t1_ivy is
    // enrolled with phone +15555550101, so submitting factor='phone' value=
    // last-4 '0101' should pass `verifyRecoveryFactor` and advance to the
    // setPassword step.
    await page.goto(wfUrl("auth/recovery/flow", "pre-factor"));
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", "ivy@acme.test");
    await submitForm(page);

    const email = await waitForEmail(request, (e) => e.kind === "recovery.magicLink");
    await page.goto(rewriteToBaseUrl(email.url as string, baseURL ?? ""));

    // RecoveryFactorForm — factor + value text inputs.
    await waitForFormInput(page, "factor", 15_000);
    await fillField(page, "factor", "phone");
    await fillField(page, "value", "0101");
    await submitForm(page);

    // setPassword pause — newPassword input must now be visible.
    await waitForFormInput(page, "newPassword", 15_000);
    await expect(page.locator('[name="newPassword"]').first()).toBeVisible();
    await expect(page.locator('[name="confirmPassword"]').first()).toBeVisible();
  });
});

// =====================================================================
// ─── P2 STORIES ───
// Edge cases: wrong factor, post-reset session revocation, audit events.
// =====================================================================

test.describe("recovery — pre-factor (R-F) P2 branches", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-RECOVERY-015: pre-reset factor wrong → opaque 'Invalid factor' error", async ({
    page,
    request,
    baseURL,
  }) => {
    // BRANCH: `recoveryVerifyFactor` step calls `verifyRecoveryFactor` and
    // throws `requireInput({ errors: { value: "Invalid factor" } })` when the
    // last-4 doesn't match. Opaque-by-design: same string regardless of
    // which factor was attempted (no enumeration). The variant `pre-factor`
    // inherits demoRecoveryOpts' default `delivery.mode: 'magicLink'`, so
    // the factor step runs AFTER the magic-link click (resume path).
    await page.goto(wfUrl("auth/recovery/flow", "pre-factor"));
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", "ivy@acme.test");
    await submitForm(page);

    const email = await waitForEmail(request, (e) => e.kind === "recovery.magicLink");
    await page.goto(rewriteToBaseUrl(email.url as string, baseURL ?? ""));

    // RecoveryFactorForm renders factor + value inputs. Submit the right
    // factor but a wrong last-4 — `verifyRecoveryFactor` returns false →
    // inline error on the `value` field.
    await waitForFormInput(page, "factor", 15_000);
    await fillField(page, "factor", "phone");
    await fillField(page, "value", "9999");
    await submitForm(page);

    // Error is keyed on `value` (per recovery.workflow.ts:485) — the opaque
    // string "Invalid factor" doesn't reveal which factor was tried.
    await expect(page.getByText("Invalid factor")).toBeVisible();
    // Form re-rendered: factor input still present, setPassword not reached.
    await expect(page.locator('[name="factor"]').first()).toBeVisible();
    await expect(page.locator('[name="newPassword"]')).toHaveCount(0);
  });
});

test.describe("recovery — fresh-login (R-G) P2 branches", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-RECOVERY-018: post-reset old session token rejected (revokeAllSessions=true)", async ({
    page,
    request,
    baseURL,
    context,
  }) => {
    // BRANCH: `recoveryRevokeSessions` step calls `auth.revokeAllForUser`
    // (gated on `opts.postReset.revokeAllSessions === true` — `fresh-login`
    // variant). With CredentialStoreJwt this bumps the user's epoch so the
    // pre-recovery token fails the guard's `passesEpoch` check on the next
    // request → 401 on `/__test/whoami`.
    //
    // Phase 1: log alice in via the SPA so the browser context's cookie jar
    // gets the `aooth_session` cookie. Capture the cookie value as the "old"
    // token snapshot before recovery revokes it.
    await loginViaUi(page, USERS.alice);
    const cookiesBefore = await context.cookies();
    const oldSession = cookiesBefore.find((c) => c.name === "aooth_session");
    expect(oldSession?.value, "login must set aooth_session cookie").toBeTruthy();

    // whoami with the old session returns 200. `request` is a fresh
    // APIRequestContext (no cookie jar shared with `context`) so we hand the
    // token over via Authorization. Proves the token IS valid pre-recovery.
    const oldAuth = { Authorization: `Bearer ${oldSession?.value}` };
    const before = await request.get("/__test/whoami", { headers: oldAuth });
    expect(before.status()).toBe(200);

    // Phase 2: drive the `fresh-login` recovery flow on the same page/context.
    // The recovery workflow is @Public() so it doesn't need auth; the resume
    // happens anonymously. After setPassword the revokeSessions step runs and
    // bumps the epoch on alice.
    await page.goto(wfUrl("auth/recovery/flow", "fresh-login"));
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    const email = await waitForEmail(request, (e) => e.kind === "recovery.magicLink");
    await page.goto(rewriteToBaseUrl(email.url as string, baseURL ?? ""));

    await waitForFormInput(page, "newPassword", 15_000);
    await fillField(page, "newPassword", NEW_PASSWORD);
    await fillField(page, "confirmPassword", NEW_PASSWORD);
    await submitForm(page);
    await expect(page.getByText("Workflow finished.")).toBeVisible();

    // Use the OLD session token explicitly via Authorization header — even if
    // the browser cookie jar still holds it, the JWT credential store's
    // `passesEpoch` check now rejects it because `revokeAllForUser` bumped
    // alice's epoch past the token's iat.
    const after = await request.get("/__test/whoami", { headers: oldAuth });
    expect(after.status(), "old token must be rejected after revokeAllSessions").toBe(401);
  });
});

test.describe("recovery — default-magiclink (R-A) P2 audit", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-RECOVERY-019: audit events emitted — requested + completed", async ({
    page,
    request,
    baseURL,
  }) => {
    // BRANCH: `audit.enabled` defaults to true (see mergeRecoveryOpts) so the
    // demo's default-magiclink variant already fires:
    //   - `recovery.requested` (kind) — emitted inside `recoveryRequest` via
    //     `emitRequested(ctx, username)` after the email→userId lookup.
    //   - `recovery.completed` (kind) — emitted by the `recoveryAudit` step
    //     after `passwordChanged === true`.
    // The demo's `DemoRecoveryWorkflow.audit()` override pushes into the
    // globalThis-anchored buffer; `/__test/audit` returns it.
    await page.goto(wfUrl("auth/recovery/flow", "default-magiclink"));
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    const email = await waitForEmail(request, (e) => e.kind === "recovery.magicLink");
    await page.goto(rewriteToBaseUrl(email.url as string, baseURL ?? ""));

    await waitForFormInput(page, "newPassword", 15_000);
    await fillField(page, "newPassword", NEW_PASSWORD);
    await fillField(page, "confirmPassword", NEW_PASSWORD);
    await submitForm(page);
    await expect(page.getByText("Workflow finished.")).toBeVisible();

    // Audit buffer must contain both phases. `event.kind` carries the event
    // name (see audit/index.ts AuditEvent shape).
    const res = await request.get("/__test/audit");
    expect(res.status()).toBe(200);
    const events = (await res.json()) as Array<{ kind: string; userId?: string }>;
    const requested = events.find((e) => e.kind === "recovery.requested");
    const completed = events.find((e) => e.kind === "recovery.completed");
    expect(requested, "recovery.requested audit event must be emitted").toBeTruthy();
    expect(completed, "recovery.completed audit event must be emitted").toBeTruthy();
    // Both events resolve to alice's userId (username in this demo).
    expect(requested?.userId).toBe(USERS.alice.username);
    expect(completed?.userId).toBe(USERS.alice.username);
  });
});

// ── Phase-5 dynamic inline-consent on recovery ──────────────────────────────
//
// Mirrors WF-CONSENT-ARRAY-01 + WF-INVITE-CONSENT-01. The `recovery-terms-bump`
// variant keys the customer `DemoConsentStore.getPendingConsents` to return a
// single required-terms descriptor → `SetPasswordForm` renders the
// `AsConsentArray` row for the dynamic `consents: string[]` field. The
// post-form `persist-consents` step batches one event per pending descriptor
// into one `DemoConsentStore.save` call, which appends to the SAME globalThis
// consent log fed by login + invite. The `/__test/consent-log/:username`
// endpoint returns the event for assertion here. Without the new
// `processInlineConsent` call in `setPassword` (Phase-2 production change),
// the submitted `consents` array would be a stripped form-extra and the log
// would stay empty.
test.describe("recovery — inline-consent (Phase 5)", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-RECOVERY-CONSENT-01: recovery-terms-bump variant → SetPasswordForm shows AsConsentArray; tick + submit → consent-log carries {id:'terms', accepted:true, version:'v2'}", async ({
    page,
    request,
    baseURL,
  }) => {
    // The consent log keys by the resolved username, which is what
    // `emailToUserId(ALICE_EMAIL)` returns — for alice in this demo that's
    // `t1_alice`, not the email.
    const username = USERS.alice.username;

    // Sanity: consent log starts empty for alice.
    const before = await request.get(`/__test/consent-log/${encodeURIComponent(username)}`);
    expect(before.status()).toBe(200);
    expect((await before.json()) as unknown[]).toEqual([]);

    await page.goto(wfUrl("auth/recovery/flow", "recovery-terms-bump"));

    // Phase 1 — EmailIdentifierForm.
    await waitForFormInput(page, "email", 15_000);
    await fillField(page, "email", ALICE_EMAIL);
    await submitForm(page);

    // Magic link → resume.
    const email = await waitForEmail(request, (e) => e.kind === "recovery.magicLink");
    expect(email.recipient).toBe(ALICE_EMAIL);
    await page.goto(rewriteToBaseUrl(email.url as string, baseURL ?? ""));

    // SetPasswordForm — `AsConsentArray` row visible because the variant's
    // ConsentStore returned a required terms descriptor.
    await waitForFormInput(page, "newPassword", 15_000);
    await expect(page.getByText("I accept the updated Terms")).toBeVisible();
    await fillField(page, "newPassword", NEW_PASSWORD);
    await fillField(page, "confirmPassword", NEW_PASSWORD);
    // The consent checkbox is the first checkbox rendered by AsConsentArray
    // on this form.
    await page.locator('input[type="checkbox"]').first().check();
    await submitForm(page);

    // Workflow finishes with tokens — proof recovery completed through the
    // `persist-consents` step.
    await expect(page.getByText("Workflow finished.")).toBeVisible();
    const envelope = (await readFinishEnvelope(page)) as {
      finished?: boolean;
      data?: { accessToken?: string };
    };
    expect(envelope.finished).toBe(true);
    expect(envelope.data?.accessToken, "auto-login issues tokens after reset").toBeTruthy();

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
