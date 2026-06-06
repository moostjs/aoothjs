/**
 * promote-to-handle — a confirmed email/SMS factor is promoted into its
 * `@aooth.user.*` login-handle column (`DemoUser.phone` / `.email`), so the
 * verified value becomes a login + recovery handle (`findByHandle`).
 *
 * Wiring: the shared MFA-enrolment trio runs a `promote-to-handle` @Step after
 * `enroll-confirm`; `DemoAuthWorkflow.resolvePromoteHandleField` turns it ON by
 * returning the handle field resolved at boot from the model's annotations.
 * The store's unique index makes promotion best-effort: a value already owned
 * by ANOTHER account leaves the second account MFA-only (no handle written).
 *
 * Fixtures: `t1_alice` (no MFA, no phone) is the clean promotion driver;
 * `t1_ivy` already owns phone `+15555550101` (its handle column), so promoting
 * that same number onto alice must collide and be swallowed.
 */
import type { APIRequestContext, Page } from "@playwright/test";
import { expect, test } from "@playwright/test";

import {
  fillField,
  loginViaUi,
  readFinishEnvelope,
  resetApp,
  submitForm,
  USERS,
  waitForFormInput,
  waitForSms,
  wfUrl,
} from "./harness";

const ADD_MFA_WF = "auth/add-mfa/flow";
const NEW_PHONE = "+15555550199"; // fresh — not seeded on any user
const IVY_PHONE = "+15555550101"; // already t1_ivy's phone handle

interface UserRec {
  email?: string;
  phone?: string;
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

/** Drive the add-mfa flow's SMS leg to confirmation for the signed-in user. */
async function addConfirmedSmsFactor(
  page: Page,
  request: APIRequestContext,
  phone: string,
): Promise<void> {
  await page.goto(wfUrl(ADD_MFA_WF));
  await waitForFormInput(page, "method");
  await fillField(page, "method", "sms");
  await submitForm(page);
  await waitForFormInput(page, "address");
  await fillField(page, "address", phone);
  await submitForm(page);
  await waitForFormInput(page, "code");
  const sms = await waitForSms(request, (e) => (e.recipient ?? "").startsWith(phone) && !!e.code);
  await fillField(page, "code", sms.code);
  await submitForm(page);
  await readFinishEnvelope(page);
}

test.describe("promote-to-handle — confirmed channel becomes a login handle", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-PROMOTE-01: confirming a new SMS factor promotes the phone into the login handle", async ({
    page,
    request,
  }) => {
    await loginViaUi(page, USERS.alice);

    // Pre-condition: alice has no phone handle yet.
    let rec = await readUser(request, USERS.alice.username);
    expect(rec.phone, "alice starts with no phone handle").toBeUndefined();

    await addConfirmedSmsFactor(page, request, NEW_PHONE);

    // The confirmed value was promoted into the `phone` handle column...
    rec = await readUser(request, USERS.alice.username);
    expect(rec.mfa.methods.find((m) => m.name === "sms")?.confirmed).toBe(true);
    expect(rec.phone, "confirmed phone promoted to the login handle").toBe(NEW_PHONE);

    // ...and is now a login handle: the phone resolves the account (minimal
    // variant skips MFA, isolating the findByHandle resolution).
    await page.goto(wfUrl("auth/login/flow", "minimal"));
    await waitForFormInput(page, "username", 15_000);
    await fillField(page, "username", NEW_PHONE);
    await fillField(page, "password", USERS.alice.password);
    await submitForm(page);
    const env = (await readFinishEnvelope(page)) as { data?: { accessToken?: string } };
    expect(typeof env.data?.accessToken, "promoted phone logs the account in").toBe("string");
  });

  test("WF-PROMOTE-02: promoting a phone already owned by another account is swallowed (stays MFA-only)", async ({
    page,
    request,
  }) => {
    await loginViaUi(page, USERS.alice);

    // Adding ivy's existing phone as an MFA factor is fine (factors aren't
    // unique); promotion into the unique `phone` handle collides and is
    // swallowed — alice keeps the factor but gets NO handle.
    await addConfirmedSmsFactor(page, request, IVY_PHONE);

    const rec = await readUser(request, USERS.alice.username);
    expect(rec.mfa.methods.find((m) => m.name === "sms")?.confirmed, "factor still added").toBe(
      true,
    );
    expect(rec.phone, "colliding phone NOT promoted — alice stays MFA-only").toBeUndefined();

    // The phone still resolves its original owner, not alice.
    const ivy = await readUser(request, USERS.ivy.username);
    expect(ivy.phone, "ivy keeps the phone handle").toBe(IVY_PHONE);
  });
});
