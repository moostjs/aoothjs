import type { APIRequestContext, Page } from "@playwright/test";
import { expect, test } from "@playwright/test";

import {
  fillField,
  loginViaUi,
  readFinishEnvelope,
  resetApp,
  submitForm,
  totp,
  USERS,
  waitForEmail,
  waitForFormInput,
  waitForSms,
  wfUrl,
} from "./harness";

const ADD_MFA_WF = "auth/add-mfa/flow";
const ENROLL_EMAIL = "alice-2fa@test.example";
const ENROLL_PHONE = "+15555550199";

// WHY: "add an MFA method" is the authenticated profile-maintenance twin of
// change-password. It REUSES the login/invite enrolment trio (already proven by
// the invite suite), so these tests pin only the add-MFA-SPECIFIC guarantees:
// (1) a logged-in user can add a factor and it sticks; (2) the picker offers
// ONLY the transports they haven't enrolled, auto-picking when one remains;
// (3) adding a secondary factor does NOT steal the existing default; (4) with
// everything enrolled the flow finishes benignly ("nothing to add"); (5) the
// route is guarded — an anonymous caller is rejected. `t1_alice` (no MFA) is the
// fixture because she logs in without an MFA challenge, then builds up factors
// through the flow itself.

interface UserRec {
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

/** Drive EnrollAddressForm → EnrollConfirmForm for an sms/email factor (already on the address form). */
async function enterAddressAndPincode(
  page: Page,
  request: APIRequestContext,
  channel: "email" | "sms",
  address: string,
): Promise<void> {
  await waitForFormInput(page, "address");
  await fillField(page, "address", address);
  await submitForm(page);
  await waitForFormInput(page, "code");
  const code =
    channel === "email"
      ? (await waitForEmail(request, (e) => e.recipient === address && !!e.code)).code
      : (await waitForSms(request, (e) => (e.recipient ?? "").startsWith(address) && !!e.code))
          .code;
  expect(code).toBeTruthy();
  await fillField(page, "code", code as string);
  await submitForm(page);
}

/** Pick a method from EnrollPickMethodForm, then complete the sms/email tail. */
async function addAddressMethod(
  page: Page,
  request: APIRequestContext,
  method: "email" | "sms",
  address: string,
): Promise<void> {
  await page.goto(wfUrl(ADD_MFA_WF));
  await waitForFormInput(page, "method");
  await fillField(page, "method", method);
  await submitForm(page);
  await enterAddressAndPincode(page, request, method, address);
  await readFinishEnvelope(page);
}

test.describe("Add-MFA workflow (WF-ADDMFA / AME)", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("AME-01: signed-in user with no MFA picks a method → factor saved, becomes default", async ({
    page,
    request,
  }) => {
    await loginViaUi(page, USERS.alice);

    await page.goto(wfUrl(ADD_MFA_WF));
    // No methods yet → the picker offers all three transports.
    await waitForFormInput(page, "method");
    await fillField(page, "method", "email");
    await submitForm(page);
    await enterAddressAndPincode(page, request, "email", ENROLL_EMAIL);

    const env = (await readFinishEnvelope(page)) as {
      finished: boolean;
      data?: { added?: boolean; method?: string };
      message?: { level?: string };
    };
    expect(env.finished).toBe(true);
    expect(env.data?.added).toBe(true);
    expect(env.data?.method).toBe("email");
    expect(env.message?.level).toBe("success");

    // Persisted + confirmed, and the first method becomes the default (no prior).
    const rec = await readUser(request, USERS.alice.username);
    expect(rec.mfa.methods.find((m) => m.name === "email")?.confirmed).toBe(true);
    expect(rec.mfa.defaultMethod).toBe("email");
  });

  test("AME-02: a second factor narrows the picker (no already-enrolled) and does NOT steal the default", async ({
    page,
    request,
  }) => {
    await loginViaUi(page, USERS.alice);

    // First factor: SMS → becomes the default (no prior default).
    await addAddressMethod(page, request, "sms", ENROLL_PHONE);
    let rec = await readUser(request, USERS.alice.username);
    expect(rec.mfa.defaultMethod).toBe("sms");

    // Second add: the picker must offer ONLY the un-enrolled transports — `sms`
    // is gone (email + totp remain).
    await page.goto(wfUrl(ADD_MFA_WF));
    await waitForFormInput(page, "method");
    expect(await page.locator('input[name="method"][value="sms"]').count()).toBe(0);
    await fillField(page, "method", "email");
    await submitForm(page);
    await enterAddressAndPincode(page, request, "email", ENROLL_EMAIL);
    const env = (await readFinishEnvelope(page)) as { data?: { added?: boolean } };
    expect(env.data?.added).toBe(true);

    rec = await readUser(request, USERS.alice.username);
    expect(rec.mfa.methods.find((m) => m.name === "email")?.confirmed).toBe(true);
    expect(rec.mfa.methods.find((m) => m.name === "sms")?.confirmed).toBe(true);
    // The load-bearing add-MFA guarantee: the newly-added factor must NOT become
    // the default when the user already had one.
    expect(rec.mfa.defaultMethod).toBe("sms");
  });

  test("AME-03: the last remaining transport auto-picks (no picker), and with all enrolled the flow finds nothing to add", async ({
    page,
    request,
  }) => {
    await loginViaUi(page, USERS.alice);

    // Enrol email + sms so only TOTP is left.
    await addAddressMethod(page, request, "email", ENROLL_EMAIL);
    await addAddressMethod(page, request, "sms", ENROLL_PHONE);

    // Only TOTP remains → enroll-pick-method AUTO-PICKS it: there is NO picker
    // pause, the flow lands straight on the EnrollConfirmForm `code` field.
    // (If auto-pick regressed to a picker, `waitForFormInput("code")` would time
    // out on the method form.)
    await page.goto(wfUrl(ADD_MFA_WF));
    await waitForFormInput(page, "code");
    // The unconfirmed TOTP secret was provisioned during auto-pick; read it back
    // (via the raw method value) to compute the setup code.
    const provisioned = await readUser(request, USERS.alice.username);
    const secret = provisioned.mfa.methods.find((m) => m.name === "totp")?.value;
    expect(secret).toBeTruthy();
    await fillField(page, "code", totp(secret as string));
    await submitForm(page);

    const env = (await readFinishEnvelope(page)) as { data?: { added?: boolean; method?: string } };
    expect(env.data?.added).toBe(true);
    expect(env.data?.method).toBe("totp");

    const rec = await readUser(request, USERS.alice.username);
    expect(rec.mfa.methods.find((m) => m.name === "totp")?.confirmed).toBe(true);
    // Default still the very first factor (email) — preserved across every add.
    expect(rec.mfa.defaultMethod).toBe("email");

    // Everything enrolled → the flow finishes immediately with "nothing to add"
    // (no form pause).
    await page.goto(wfUrl(ADD_MFA_WF));
    const done = (await readFinishEnvelope(page)) as {
      data?: { added?: boolean; reason?: string };
    };
    expect(done.data?.added).toBe(false);
    expect(done.data?.reason).toBe("no-methods-available");
  });

  test("AME-04: anonymous POST to the guarded /auth/add-mfa trigger is rejected (401)", async ({
    request,
  }) => {
    // NOT @Public — the auth guard rejects an unauthenticated caller before the
    // flow starts (the `request` fixture carries no session cookie).
    const res = await request.post("/auth/add-mfa", {
      data: { schemaId: ADD_MFA_WF, input: {} },
    });
    expect(res.status()).toBe(401);
  });
});
