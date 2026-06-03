/**
 * Playwright coverage for the Phase-5 dynamic consent surface — the
 * `AsConsentArray` component rendered from `WithInlineConsentForm.consents`
 * against the customer-defined `pendingConsents` descriptor array.
 *
 * The vitest suite (auth-moost `workflows.login.options.spec.ts` →
 * `PERSIST-CONSENT-*`, `BUMP-PROMPT-*`) covers the wire/server layer;
 * Playwright pins the end-to-end SPA → server → audit-log path.
 */
import { expect, test } from "@playwright/test";

import {
  fillField,
  readFinishEnvelope,
  resetApp,
  submitForm,
  USERS,
  waitForFormInput,
  wfUrl,
} from "./harness";

const LOGIN_WF = "auth/login/flow";

test.beforeEach(async ({ request }) => {
  await resetApp(request);
});

test.describe("LoginWorkflow / variant=consent-array (Phase 5 dynamic consent)", () => {
  // WHY (Rule 9): pins the full Phase-5 round-trip: ConsentStore.getPendingConsents
  // → ctx.consents.pending → AsConsentArray renders one row per descriptor →
  // user submits the validated subset via the dynamic `consents: string[]`
  // field → server-side processInlineConsent silent-drops unknown ids +
  // throws form-error on missing-required → persist-consents writes one
  // event per pending descriptor with `accepted` reflecting user ticks.
  // A regression at any layer (component not registered, descriptor shape
  // change, helper losing the required-string error copy, persist step
  // dropping declined-optional rows) would fail at least one assertion
  // here. clickAction(submitForm)+waitForFormInput is intentionally minimal
  // — what we're pinning is content/error/persistence, not button polish.
  test("WF-CONSENT-ARRAY-01: t1_alice → SetPasswordForm renders 2 consents; first submit (no terms) errors; check both + submit → workflow finishes and consent-log records both events", async ({
    page,
    request,
  }) => {
    await page.goto(wfUrl(LOGIN_WF, "consent-array"));

    // Submit credentials → workflow lands on TermsBumpForm (no enrollment /
    // profile-complete gates on this variant, so pendingConsents drives the
    // standalone bump pause).
    await waitForFormInput(page, "username");
    await fillField(page, "username", USERS.alice.username);
    await fillField(page, "password", USERS.alice.password);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();

    // Both descriptor rows visible — pins (a) `AsConsentArray` is registered
    // and rendered, (b) `pendingConsents` made it through `@wf.context.pass`
    // and the `@ui.form.fn.attr` binding. The two text fragments are
    // descriptor.text from the variant's pending array.
    await expect(page.getByText("I accept the Terms of Service")).toBeVisible();
    await expect(page.getByText("Send me product updates")).toBeVisible();

    // Attempt 1: submit WITHOUT ticking terms → per-row error from the
    // descriptor's `required` string. Pins the mandatory-by-message
    // contract — the customer-defined error copy is what the user sees.
    await submitForm(page);
    await expect(page.getByText("Terms are mandatory")).toBeVisible();

    // Workflow must NOT have advanced — no consent-log row yet.
    const midRes = await request.get(
      `/__test/consent-log/${encodeURIComponent(USERS.alice.username)}`,
    );
    const midLog = (await midRes.json()) as Array<unknown>;
    expect(midLog.length).toBe(0);

    // Attempt 2: tick both checkboxes (terms is required, marketing is
    // optional — picked here to prove the optional-accepted path produces
    // accepted:true rather than the audit-default false).
    await page.locator('input[type="checkbox"]').nth(0).check();
    await page.locator('input[type="checkbox"]').nth(1).check();
    await submitForm(page);

    // Workflow finishes — tokens issued (no enrollment / MFA gates on this
    // variant).
    const envelope = (await readFinishEnvelope(page)) as {
      finished: boolean;
      data?: { accessToken?: string; userId?: string };
    };
    expect(envelope.finished).toBe(true);
    // userId is the stable subject id (a uuid) now, not the username handle.
    expect(typeof envelope.data?.userId).toBe("string");
    expect(envelope.data?.userId).toBeTruthy();
    expect(typeof envelope.data?.accessToken).toBe("string");

    // Consent log records ONE event per pending descriptor with accepted=true
    // for both ids. Pins (a) the `id` field shape (NOT pre-Phase-5 `kind`),
    // (b) `accepted: true` per the user's tick, (c) version stamped from the
    // descriptor for the terms row + absent for marketing (no version on
    // that descriptor).
    const finalRes = await request.get(
      `/__test/consent-log/${encodeURIComponent(USERS.alice.username)}`,
    );
    const finalLog = (await finalRes.json()) as Array<{
      id: string;
      accepted: boolean;
      version?: string;
      at: number;
    }>;
    expect(finalLog.length).toBe(2);
    const byId = Object.fromEntries(finalLog.map((e) => [e.id, e]));
    expect(byId.terms).toMatchObject({ id: "terms", accepted: true, version: "v2" });
    expect(byId.marketing).toMatchObject({ id: "marketing", accepted: true });
    // marketing has no version on the descriptor — must NOT have one on the
    // event. A regression that always stamped a default version would
    // break consumers who key versioning to the FK side.
    expect(byId.marketing.version).toBeUndefined();
  });
});
