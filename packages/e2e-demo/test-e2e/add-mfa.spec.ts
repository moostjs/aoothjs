import type { APIRequestContext, Page } from "@playwright/test";
import { expect, test } from "@playwright/test";

import {
  clickAction,
  continuePastTotpQr,
  fillField,
  getEmails,
  loginViaUi,
  readFinishEnvelope,
  resetApp,
  submitForm,
  totp,
  USERS,
  waitForEmail,
  waitForFormInput,
  readTotpQrSecret,
  waitForTotpQrStep,
  wfStatesCount,
  wfUrl,
} from "./harness";

const MANAGE_WF = "auth/add-mfa/flow";
const ENROLL_EMAIL = "alice-2fa@test.example";

// WHY: the authenticated "Manage two-factor authentication" flow (add / change /
// remove) is the profile-maintenance twin of change-password. It REUSES the
// login/invite enrolment trio (proven by the invite + login suites), so these
// tests pin the MANAGE-SPECIFIC guarantees:
//   - STEP-UP first: a user who already has a factor must verify an EXISTING one
//     before any add/change/remove (security — the menu never renders first).
//   - the sms/email step-up asks for EXPLICIT consent before dispatching its
//     code ("we will send a verification code to ma•••@x") — opening the manage
//     dialog must never email/text the user as a side effect, and a Cancel on
//     the notice consumes no code send.
//   - a zero-MFA user skips step-up + menu and lands on the enrol picker (the
//     first-time opt-in path), in `manage` mode (Cancel, never "Skip for now").
//   - the menu offers add (un-enrolled) + change/remove (enrolled), OMITTING any
//     handle-bound factor (locked — the demo locks an MFA email/phone that IS a
//     login handle).
//   - replace re-verifies the new factor; remove deletes it.
//   - TOTP shows the QR on its OWN step before code entry.
//   - the address field rejects a malformed email.

interface UserRec {
  email?: string;
  mfa: {
    methods: Array<{ name: string; confirmed: boolean; value: string }>;
    defaultMethod: string;
  };
}

async function readUser(request: APIRequestContext, username: string): Promise<UserRec> {
  const res = await request.get(`/__test/user/${encodeURIComponent(username)}`);
  expect(res.status()).toBe(200);
  return (await res.json()) as UserRec;
}

async function totpSecret(request: APIRequestContext, username: string): Promise<string> {
  const res = await request.get(`/__test/totp-secret/${encodeURIComponent(username)}`);
  expect(res.status()).toBe(200);
  const { secret } = (await res.json()) as { secret: string };
  expect(secret).toBeTruthy();
  return secret;
}

/** Step-up by verifying an existing TOTP factor → lands on the manage menu. */
async function stepUpTotp(page: Page, request: APIRequestContext, username: string): Promise<void> {
  await waitForFormInput(page, "code"); // step-up challenge, NOT the menu yet
  await fillField(page, "code", totp(await totpSecret(request, username)));
  await submitForm(page);
  await waitForFormInput(page, "operation"); // the menu radio
}

/** Step-up by verifying an existing email factor → lands on the manage menu. */
async function stepUpEmail(page: Page, request: APIRequestContext, email: string): Promise<void> {
  // The email step-up opens on the dispatch-consent notice — nothing has been
  // sent yet; the Continue submit triggers the (single) code send.
  await passStepUpConsent(page);
  await waitForFormInput(page, "code");
  const code = (await waitForEmail(request, (e) => e.recipient === email && !!e.code)).code;
  expect(code).toBeTruthy();
  await fillField(page, "code", code as string);
  await submitForm(page);
  await waitForFormInput(page, "operation");
}

/** Wait for the step-up dispatch-consent notice, then Continue past it. */
async function passStepUpConsent(page: Page): Promise<void> {
  await page
    .getByText(/we will send a verification code to/i)
    .waitFor({ state: "visible", timeout: 5000 });
  await submitForm(page);
}

/** Drive EnrollAddressForm → EnrollConfirmForm for an email factor (on the address form). */
async function enterEmailAndPincode(
  page: Page,
  request: APIRequestContext,
  address: string,
): Promise<void> {
  await waitForFormInput(page, "address");
  await fillField(page, "address", address);
  await submitForm(page);
  await waitForFormInput(page, "code");
  const code = (await waitForEmail(request, (e) => e.recipient === address && !!e.code)).code;
  expect(code).toBeTruthy();
  await fillField(page, "code", code as string);
  await submitForm(page);
}

test.describe("Manage-MFA workflow (WF-MANAGE-MFA / MME)", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("MME-01: a zero-MFA user skips step-up → enrol picker in MANAGE mode (Cancel, not Skip) → factor added + default", async ({
    page,
    request,
  }) => {
    await loginViaUi(page, USERS.alice);

    await page.goto(wfUrl(MANAGE_WF));
    // No confirmed factor → no step-up, no menu: straight to the enrol picker.
    await waitForFormInput(page, "method");
    // MANAGE mode: never "Skip for now" (that's the login opt-in affordance).
    // The form's built-in `cancel` is HIDDEN (kept whitelisted); the demo, as a
    // consumer, renders its OWN Cancel via the host-cancel shell — so there is
    // exactly one Cancel button and it is the host's `.wf-host-cancel`.
    await expect(page.getByRole("button", { name: /Skip/i })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Cancel", exact: false })).toHaveCount(1);
    await expect(page.locator(".wf-host-cancel")).toHaveCount(1);

    await fillField(page, "method", "email");
    await submitForm(page);
    await enterEmailAndPincode(page, request, ENROLL_EMAIL);

    const env = (await readFinishEnvelope(page)) as {
      finished: boolean;
      data?: { added?: boolean; method?: string };
      message?: { level?: string };
    };
    expect(env.finished).toBe(true);
    expect(env.data?.added).toBe(true);
    expect(env.data?.method).toBe("email");
    expect(env.message?.level).toBe("success");

    const rec = await readUser(request, USERS.alice.username);
    expect(rec.mfa.methods.find((m) => m.name === "email")?.confirmed).toBe(true);
    expect(rec.mfa.defaultMethod).toBe("email"); // first factor becomes default

    // Lifecycle: a real factor add fires `afterMfaChanged`. The user keeps their
    // session (no re-issue), so the add-mfa flow adds NO `afterLogin` — the only
    // one in the buffer is the initial `loginViaUi` sign-in.
    const events = (await (await request.get("/__test/lifecycle")).json()) as { event: string }[];
    const names = events.map((e) => e.event);
    expect(names, "an MFA add fires afterMfaChanged").toContain("afterMfaChanged");
    expect(
      names.filter((n) => n === "afterLogin"),
      "managing MFA is not a login (only the initial sign-in fired afterLogin)",
    ).toHaveLength(1);
  });

  test("MME-02 (step-up gate): a user WITH a factor must verify it BEFORE the menu renders", async ({
    page,
    request,
  }) => {
    await loginViaUi(page, USERS.grace); // single TOTP

    await page.goto(wfUrl(MANAGE_WF));
    // The FIRST pause is the step-up challenge (a `code` field) — NOT the menu.
    await waitForFormInput(page, "code");
    await expect(page.locator('[name="operation"]')).toHaveCount(0);

    // A wrong step-up code is rejected — no menu, no progress.
    await fillField(page, "code", "000000");
    await submitForm(page);
    await expect(page.getByText("Invalid code", { exact: true })).toBeVisible();
    await expect(page.locator('[name="operation"]')).toHaveCount(0);

    // The correct existing-factor code unlocks the menu.
    await fillField(page, "code", totp(await totpSecret(request, USERS.grace.username)));
    await submitForm(page);
    await waitForFormInput(page, "operation");
    // Menu offers add (un-enrolled email/sms) + change/remove the TOTP.
    expect(
      await page.locator('input[name="operation"][value="replace:totp"]').count(),
    ).toBeGreaterThan(0);
    expect(
      await page.locator('input[name="operation"][value="remove:totp"]').count(),
    ).toBeGreaterThan(0);
  });

  test("MME-03 (add after step-up): grace verifies TOTP → adds email → both factors confirmed, TOTP not clobbered", async ({
    page,
    request,
  }) => {
    await loginViaUi(page, USERS.grace);

    await page.goto(wfUrl(MANAGE_WF));
    await stepUpTotp(page, request, USERS.grace.username);

    await fillField(page, "operation", "add:email");
    await submitForm(page);
    await enterEmailAndPincode(page, request, "grace-2fa@test.example");

    const env = (await readFinishEnvelope(page)) as { data?: { added?: boolean; method?: string } };
    expect(env.data?.added).toBe(true);
    expect(env.data?.method).toBe("email");

    const rec = await readUser(request, USERS.grace.username);
    // ADD ≠ replace: the new email is confirmed AND the existing TOTP survives.
    expect(rec.mfa.methods.find((m) => m.name === "email")?.confirmed).toBe(true);
    expect(rec.mfa.methods.find((m) => m.name === "totp")?.confirmed).toBe(true);
    // grace had no explicit seeded default, so the freshly-added factor becomes
    // it (the keep-existing-default guard only fires when a default already
    // exists — exercised once a user has set one).
    expect(rec.mfa.defaultMethod).toBe("email");
  });

  test("MME-04 (replace, no-strand): grace re-enrols TOTP → the stored secret changes, factor stays confirmed", async ({
    page,
    request,
  }) => {
    await loginViaUi(page, USERS.grace);
    const oldSecret = await totpSecret(request, USERS.grace.username);

    await page.goto(wfUrl(MANAGE_WF));
    await stepUpTotp(page, request, USERS.grace.username);

    await fillField(page, "operation", "replace:totp");
    await submitForm(page);

    // QR step stages a NEW secret in wf-state (write-on-confirm: the live
    // confirmed secret in the store is NOT touched yet). Read the rendered secret
    // and prove it changed — AND that the store still holds the OLD one (no
    // pre-confirm clobber → the no-strand guarantee).
    const newSecret = await readTotpQrSecret(page);
    expect(newSecret).toBeTruthy();
    expect(newSecret).not.toBe(oldSecret);
    const midReplace = await readUser(request, USERS.grace.username);
    expect(midReplace.mfa.methods.find((m) => m.name === "totp")?.value).toBe(oldSecret);

    await continuePastTotpQr(page);
    await waitForFormInput(page, "code");
    await fillField(page, "code", totp(newSecret));
    await submitForm(page);

    const env = (await readFinishEnvelope(page)) as {
      data?: { changed?: boolean; method?: string };
    };
    expect(env.data?.changed).toBe(true);
    expect(env.data?.method).toBe("totp");

    const rec = await readUser(request, USERS.grace.username);
    const totpRow = rec.mfa.methods.find((m) => m.name === "totp");
    expect(totpRow?.confirmed).toBe(true);
    expect(totpRow?.value).toBe(newSecret); // new value persisted
    expect(rec.mfa.defaultMethod).toBe("totp"); // default name unchanged
  });

  test("MME-05 (remove): grace verifies TOTP → removes it → factor gone", async ({
    page,
    request,
  }) => {
    await loginViaUi(page, USERS.grace);

    await page.goto(wfUrl(MANAGE_WF));
    await stepUpTotp(page, request, USERS.grace.username);

    await fillField(page, "operation", "remove:totp");
    await submitForm(page);

    // RemoveMfaConfirmForm — fieldless apart from the notice; the primary submit
    // ('Remove') performs the removal.
    await page.getByRole("button", { name: "Remove", exact: true }).waitFor({ state: "visible" });
    await submitForm(page);

    const env = (await readFinishEnvelope(page)) as {
      data?: { removed?: boolean; method?: string };
    };
    expect(env.data?.removed).toBe(true);
    expect(env.data?.method).toBe("totp");

    const rec = await readUser(request, USERS.grace.username);
    expect(rec.mfa.methods.find((m) => m.name === "totp")).toBeUndefined();
  });

  test("MME-06 (locked): henry's email IS his login handle → menu omits change/remove for email, offers add", async ({
    page,
    request,
  }) => {
    await loginViaUi(page, USERS.henry); // single Email-OTP (value == handle email)
    const henry = await readUser(request, USERS.henry.username);
    expect(henry.email).toBeTruthy();

    await page.goto(wfUrl(MANAGE_WF));
    await stepUpEmail(page, request, henry.email as string);

    // Email is handle-bound → LOCKED: no change/remove options for it.
    expect(await page.locator('input[name="operation"][value="replace:email"]').count()).toBe(0);
    expect(await page.locator('input[name="operation"][value="remove:email"]').count()).toBe(0);
    // But un-enrolled transports are still addable.
    expect(await page.locator('input[name="operation"][value="add:sms"]').count()).toBeGreaterThan(
      0,
    );
    expect(await page.locator('input[name="operation"][value="add:totp"]').count()).toBeGreaterThan(
      0,
    );
    // The locked-note explains why.
    await expect(page.getByText(/can’t be changed here|can't be changed here/i)).toBeVisible();
  });

  test("MME-07 (QR-then-code): adding TOTP shows the QR on its OWN step before the code field", async ({
    page,
    request,
  }) => {
    await loginViaUi(page, USERS.alice);

    await page.goto(wfUrl(MANAGE_WF));
    await waitForFormInput(page, "method");
    await fillField(page, "method", "totp");
    await submitForm(page);

    // QR step: the scannable QR renders and there is NO code input yet. The
    // secret is staged in wf-state (write-on-confirm) — read it from the QR.
    await waitForTotpQrStep(page);
    await expect(page.locator('[name="code"]')).toHaveCount(0);
    const secret = await readTotpQrSecret(page);
    expect(secret).toBeTruthy();

    await continuePastTotpQr(page);
    // NOW the code field appears.
    await waitForFormInput(page, "code");
    await fillField(page, "code", totp(secret));
    await submitForm(page);

    const env = (await readFinishEnvelope(page)) as { data?: { added?: boolean; method?: string } };
    expect(env.data?.added).toBe(true);
    expect(env.data?.method).toBe("totp");

    // write-on-confirm: only after confirm is the factor persisted (as the
    // rendered secret).
    const rec = await readUser(request, USERS.alice.username);
    const totpRow = rec.mfa.methods.find((m) => m.name === "totp");
    expect(totpRow?.confirmed).toBe(true);
    expect(totpRow?.value).toBe(secret);
  });

  test("MME-08 (address validation): a malformed email is rejected before any code is sent", async ({
    page,
  }) => {
    await loginViaUi(page, USERS.alice);

    await page.goto(wfUrl(MANAGE_WF));
    await waitForFormInput(page, "method");
    await fillField(page, "method", "email");
    await submitForm(page);

    await waitForFormInput(page, "address");
    await fillField(page, "address", "blbalba");
    await submitForm(page);

    // Rejected: an error shows and we never reach the code-entry step.
    await expect(page.getByText(/valid email/i)).toBeVisible();
    await expect(page.locator('[name="code"]')).toHaveCount(0);

    // A valid address then proceeds.
    await fillField(page, "address", "alice-valid@test.example");
    await submitForm(page);
    await waitForFormInput(page, "code");
  });

  test("MME-09: anonymous POST to the guarded /auth/add-mfa trigger is rejected (401)", async ({
    request,
  }) => {
    const res = await request.post("/auth/add-mfa", {
      data: { schemaId: MANAGE_WF, input: {} },
    });
    expect(res.status()).toBe(401);
  });

  test("MME-11 (step-up consent): opening Manage MFA dispatches NOTHING until Continue; Cancel consumes no code", async ({
    page,
    request,
  }) => {
    await loginViaUi(page, USERS.henry); // single Email-OTP factor
    const henry = await readUser(request, USERS.henry.username);
    const codeEmails = async () =>
      (await getEmails(request)).filter((e) => e.recipient === henry.email && !!e.code).length;

    // Opening the manage dialog pauses on the consent NOTICE — masked target
    // shown, no code field, and crucially no email in flight yet.
    await page.goto(wfUrl(MANAGE_WF));
    await page
      .getByText(/we will send a verification code to/i)
      .waitFor({ state: "visible", timeout: 5000 });
    await expect(page.locator('[name="code"]')).toHaveCount(0);
    const before = await codeEmails();

    // Opened by mistake → host Cancel: clean cancelled terminal, zero sends,
    // no resend cooldown burnt.
    await clickAction(page, "Cancel");
    const env = (await readFinishEnvelope(page)) as { data?: { added?: boolean } };
    expect(env.data?.added).toBe(false);
    expect(await codeEmails(), "cancel on the notice consumed no code send").toBe(before);

    // Re-open and Continue: exactly one code dispatches, then the challenge.
    await page.goto(wfUrl(MANAGE_WF));
    await passStepUpConsent(page);
    await waitForFormInput(page, "code");
    expect(await codeEmails(), "Continue dispatched exactly one code").toBe(before + 1);
  });

  test("MME-10 (cancel): grace verifies TOTP → host Cancel aborts → no change + wf-state cleaned", async ({
    page,
    request,
  }) => {
    await loginViaUi(page, USERS.grace);

    await page.goto(wfUrl(MANAGE_WF));
    await stepUpTotp(page, request, USERS.grace.username);

    // After step-up the manage flow has swapped to the durable store, so a row
    // exists. The form's built-in cancel is hidden — the demo's host-cancel
    // shell supplies the only Cancel button. Clicking it fires the `cancel`
    // action, which is the WHOLE POINT of keeping cancel whitelisted: it aborts
    // the run server-side so the durable wf-state row is cleaned up rather than
    // left to expire.
    const rowsBeforeCancel = await wfStatesCount(request);
    expect(
      rowsBeforeCancel,
      "manage flow swapped to store → ≥1 durable row",
    ).toBeGreaterThanOrEqual(1);

    await clickAction(page, "Cancel");
    const env = (await readFinishEnvelope(page)) as { data?: { added?: boolean; reason?: string } };
    expect(env.data?.added).toBe(false);

    // The cancel aborted the flow → the durable row is gone (not orphaned).
    expect(await wfStatesCount(request), "cancel cleaned up the wf-state row").toBeLessThan(
      rowsBeforeCancel,
    );

    // Untouched: grace still has exactly her TOTP and her (empty, unseeded) default.
    const rec = await readUser(request, USERS.grace.username);
    expect(rec.mfa.methods.filter((m) => m.confirmed).map((m) => m.name)).toEqual(["totp"]);
    expect(rec.mfa.defaultMethod).toBe("");
  });
});
