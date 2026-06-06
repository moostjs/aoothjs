import type { APIRequestContext, Page } from "@playwright/test";
import { expect, test } from "@playwright/test";

import {
  clickAction,
  continuePastTotpQr,
  fillField,
  loginViaUi,
  readFinishEnvelope,
  resetApp,
  submitForm,
  totp,
  USERS,
  waitForEmail,
  waitForFormInput,
  waitForTotpQrStep,
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
  await waitForFormInput(page, "code");
  const code = (await waitForEmail(request, (e) => e.recipient === email && !!e.code)).code;
  expect(code).toBeTruthy();
  await fillField(page, "code", code as string);
  await submitForm(page);
  await waitForFormInput(page, "operation");
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
    // MANAGE mode: the picker offers "Cancel" (the user opened this on purpose),
    // never "Skip for now" (that's the login opt-in affordance).
    await expect(page.getByRole("button", { name: /Skip/i })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Cancel", exact: false })).toHaveCount(1);

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

    // QR step provisions a NEW secret (the single TOTP slot is clobbered, with
    // the old one stashed for cancel/restore). Read it back from the unconfirmed
    // row and prove it changed.
    await waitForTotpQrStep(page);
    const provisioned = await readUser(request, USERS.grace.username);
    const newSecret = provisioned.mfa.methods.find((m) => m.name === "totp")?.value;
    expect(newSecret).toBeTruthy();
    expect(newSecret).not.toBe(oldSecret);

    await continuePastTotpQr(page);
    await waitForFormInput(page, "code");
    await fillField(page, "code", totp(newSecret as string));
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

    // QR step: the scannable QR renders and there is NO code input yet.
    await waitForTotpQrStep(page);
    await expect(page.locator('[name="code"]')).toHaveCount(0);

    await continuePastTotpQr(page);
    // NOW the code field appears.
    await waitForFormInput(page, "code");
    const provisioned = await readUser(request, USERS.alice.username);
    const secret = provisioned.mfa.methods.find((m) => m.name === "totp")?.value;
    expect(secret).toBeTruthy();
    await fillField(page, "code", totp(secret as string));
    await submitForm(page);

    const env = (await readFinishEnvelope(page)) as { data?: { added?: boolean; method?: string } };
    expect(env.data?.added).toBe(true);
    expect(env.data?.method).toBe("totp");
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

  test("MME-10 (cancel): grace verifies TOTP → cancels the menu → no change", async ({
    page,
    request,
  }) => {
    await loginViaUi(page, USERS.grace);

    await page.goto(wfUrl(MANAGE_WF));
    await stepUpTotp(page, request, USERS.grace.username);

    await clickAction(page, "Cancel");
    const env = (await readFinishEnvelope(page)) as { data?: { added?: boolean; reason?: string } };
    expect(env.data?.added).toBe(false);

    // Untouched: grace still has exactly her TOTP and her (empty, unseeded) default.
    const rec = await readUser(request, USERS.grace.username);
    expect(rec.mfa.methods.filter((m) => m.confirmed).map((m) => m.name)).toEqual(["totp"]);
    expect(rec.mfa.defaultMethod).toBe("");
  });
});
