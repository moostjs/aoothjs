/**
 * Playwright coverage for the Phase-7 password-rules surface — the
 * `AsPasswordRules` component rendered from `SetPasswordForm.passwordRules`
 * against the customer-defined `ctx.passwordPolicies` array (seeded by the
 * workflow's `prepare-password-rules` @Step from
 * `UserService.getTransferablePolicies()`).
 *
 * The vitest suite (auth-moost `workflows.login.options.spec.ts` →
 * `WF-LOGIN-PWPOLICY`) covers the wire shape (`@wf.context.pass` keeps
 * `passwordPolicies` alive across `extractPassContext`; the array's
 * `{rule, description?, errorMessage?}` round-trips). Playwright pins the
 * end-to-end SPA → component → keystroke-evaluation path: each rule row's
 * `data-passed` flag MUST reflect the current `newPassword` value.
 */
import { expect, test } from "@playwright/test";

import {
  fillField,
  readFinishEnvelope,
  resetApp,
  submitForm,
  USERS,
  waitForEmail,
  waitForFormInput,
  wfUrl,
} from "./harness";

const LOGIN_WF = "auth/login/flow";

test.beforeEach(async ({ request }) => {
  await resetApp(request);
});

test.describe("LoginWorkflow / variant=guards (Phase 7 AsPasswordRules)", () => {
  // WHY (Rule 9): pins the full Phase-7 round-trip:
  //   UserService.getTransferablePolicies() → prepare-password-rules seeds
  //   ctx.passwordPolicies → @wf.context.pass survives extractPassContext →
  //   AsPasswordRules renders one row per descriptor → @ui.form.fn.attr
  //   'password', '(_, data) => data.newPassword' re-evaluates on every
  //   keystroke → each row's data-passed flag reflects the current value.
  //
  // The keystroke-by-keystroke reactivity is load-bearing — a regression
  // that froze the `password` attr at first render (e.g. via a stale
  // closure or by reading from initial `data` instead of the live ref)
  // would silently lie about policy fulfillment. The two-stage assertion
  // ("short" fails the length rule + digit rule; "longenough1A!" passes
  // all three) is what catches that class of regression.
  //
  // The demo's seeded policies (packages/e2e-demo/src/aooth.ts) are:
  //   1. "At least 8 characters"  — (v) => v.length >= 8
  //   2. "Contains a letter"       — (v) => /[A-Za-z]/.test(v)
  //   3. "Contains a digit"        — (v) => /[0-9]/.test(v)
  test("WF-PASSWORD-RULES-LIVE-01: SetPasswordForm renders backend-supplied password policies + each row's data-passed reflects live keystroke evaluation", async ({
    page,
    request,
  }) => {
    // Variant `guards` flips passwordInitial+passwordExpiry+emailVerifiedRequired
    // (see e2e-demo/src/variants.ts). t1_jack is seeded with passwordInitial=true
    // so post-credentials the workflow MUST reach SetPasswordForm — but first
    // it gates through ensureEmail (AskEmailForm + email-OTP) because
    // emailVerifiedRequired is also on. Mirrors the existing WF-LOGIN-021
    // walkthrough; we re-use that path because there's no dedicated
    // "password-initial only" variant today.
    await page.goto(wfUrl(LOGIN_WF, "guards"));
    await fillField(page, "username", USERS.jack.username);
    await fillField(page, "password", USERS.jack.password);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();

    // 1. AskEmailForm — supply jack's email so ensureEmail can deliver an OTP.
    await waitForFormInput(page, "email");
    await fillField(page, "email", "jack@acme.test");
    await page
      .getByRole("button", { name: /Submit|Continue/i })
      .first()
      .click();

    // 2. PincodeForm — read the captured email OTP and verify.
    await waitForFormInput(page, "code");
    const otpEmail = await waitForEmail(
      request,
      (e) => e.kind === "login.pincode" && e.recipient === "jack@acme.test",
    );
    expect(otpEmail.code, "email pincode captured").toBeTruthy();
    await fillField(page, "code", otpEmail.code as string);
    await page.getByRole("button", { name: "Verify", exact: true }).click();

    // 3. SetPasswordForm pause — both inputs visible + AsPasswordRules
    // rendered. The component's root div carries `field-class="as-password-rules"`
    // (AsFieldShell propagates field-class as a class on its host). One row
    // per policy descriptor with `data-passed` toggles.
    await waitForFormInput(page, "newPassword");
    await waitForFormInput(page, "confirmPassword");

    const rules = page.locator(".as-password-rules-row");
    // 3 seeded policies in the demo UserService config.
    await expect(rules).toHaveCount(3);

    // Each row carries its descriptor as text content — pins that the
    // backend `description` field actually reaches the DOM (regression
    // guard against the prior wire shape where `description` was renamed
    // to `label` or dropped).
    await expect(rules.nth(0)).toContainText("At least 8 characters");
    await expect(rules.nth(1)).toContainText("Contains a letter");
    await expect(rules.nth(2)).toContainText("Contains a digit");

    // Empty newPassword — the component's `hasPassword` guard short-circuits
    // every rule to data-passed=false, even rules that would technically
    // return true for empty input (e.g. a no-op rule). Pins the "don't
    // mislead the user at the empty initial state" UX contract.
    await expect(rules.nth(0)).toHaveAttribute("data-passed", "false");
    await expect(rules.nth(1)).toHaveAttribute("data-passed", "false");
    await expect(rules.nth(2)).toHaveAttribute("data-passed", "false");

    // Type 5 chars, all letters, no digit. Expected:
    //   length>=8        → false
    //   contains letter  → true
    //   contains digit   → false
    await fillField(page, "newPassword", "short");
    await expect(rules.nth(0)).toHaveAttribute("data-passed", "false");
    await expect(rules.nth(1)).toHaveAttribute("data-passed", "true");
    await expect(rules.nth(2)).toHaveAttribute("data-passed", "false");

    // Type a longer value with all required classes. Expected: all 3 pass.
    // The transition from "some passing" to "all passing" without remounting
    // the form is what pins the live re-evaluation contract — a regression
    // that cached the first password value would leave rules 0 + 2 at
    // their previous "false" state forever.
    await fillField(page, "newPassword", "longenough1A!");
    await expect(rules.nth(0)).toHaveAttribute("data-passed", "true");
    await expect(rules.nth(1)).toHaveAttribute("data-passed", "true");
    await expect(rules.nth(2)).toHaveAttribute("data-passed", "true");

    // Sanity tail — submit with matching confirm to prove the phantom
    // field doesn't break form submission (a `ui.paragraph` carries no
    // value; the workflow's setPassword step must not see passwordRules
    // in the input payload).
    await fillField(page, "confirmPassword", "longenough1A!");
    await submitForm(page);
    const envelope = (await readFinishEnvelope(page)) as { data?: { accessToken?: string } };
    expect(typeof envelope.data?.accessToken).toBe("string");
  });
});
