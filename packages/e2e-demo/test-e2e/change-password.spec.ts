import { expect, test } from "@playwright/test";

import {
  fillField,
  loginViaUi,
  readFinishEnvelope,
  resetApp,
  submitForm,
  USERS,
  waitForFormInput,
  wfUrl,
} from "./harness";

const LOGIN_WF = "auth/login/flow";
const CHANGE_PASSWORD_WF = "auth/change-password/flow";

const NEW_PASSWORD = "BrandNew2!Pass";

// WHY: "change my password" is an AUTHENTICATED self-service flow. Its three
// load-bearing guarantees — (1) the current password is the primary protection
// (re-auth, not rate limiting), (2) the route is guarded so an anonymous caller
// can't reach it, (3) a successful change actually rotates the credential — are
// each pinned by one test below. A regression in any of them is a real security
// defect, so these fail loud rather than asserting surface behaviour only.
//
// Auth is established via `loginViaUi` (the same helper the invite suite uses)
// so the session cookie rides along on the guarded change-password trigger.
test.describe("Change-password workflow (WF-CHPWD)", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("WF-CHPWD-001: signed-in user changes password → tokens rotate, new password takes effect", async ({
    page,
  }) => {
    await loginViaUi(page, USERS.alice);

    await page.goto(wfUrl(CHANGE_PASSWORD_WF));
    await waitForFormInput(page, "currentPassword");
    await fillField(page, "currentPassword", USERS.alice.password);
    await fillField(page, "newPassword", NEW_PASSWORD);
    await fillField(page, "confirmPassword", NEW_PASSWORD);
    await submitForm(page);

    // Finish envelope rotates the acting session onto a fresh token (OWASP:
    // no ghost session survives a credential change) and confirms success.
    const envelope = (await readFinishEnvelope(page)) as {
      finished: boolean;
      data?: { accessToken?: string };
      message?: { level?: string; text?: string };
    };
    expect(envelope.finished).toBe(true);
    expect(typeof envelope.data?.accessToken).toBe("string");
    expect((envelope.data?.accessToken ?? "").length).toBeGreaterThan(0);
    expect(envelope.message?.level).toBe("success");

    // The change actually took effect: the OLD password no longer authenticates…
    await page.goto(wfUrl(LOGIN_WF, "minimal"));
    await waitForFormInput(page, "username");
    await fillField(page, "username", USERS.alice.username);
    await fillField(page, "password", USERS.alice.password);
    await submitForm(page);
    await expect(page.getByText("Invalid credentials").first()).toBeVisible();

    // …and the NEW password does.
    await page.goto(wfUrl(LOGIN_WF, "minimal"));
    await waitForFormInput(page, "username");
    await fillField(page, "username", USERS.alice.username);
    await fillField(page, "password", NEW_PASSWORD);
    await submitForm(page);
    const reloginEnvelope = (await readFinishEnvelope(page)) as { data?: { accessToken?: string } };
    expect(typeof reloginEnvelope.data?.accessToken).toBe("string");
  });

  test("WF-CHPWD-002: wrong current password → form error, password unchanged", async ({
    page,
  }) => {
    await loginViaUi(page, USERS.alice);

    await page.goto(wfUrl(CHANGE_PASSWORD_WF));
    await waitForFormInput(page, "currentPassword");
    await fillField(page, "currentPassword", "Definitely-Wrong!");
    await fillField(page, "newPassword", NEW_PASSWORD);
    await fillField(page, "confirmPassword", NEW_PASSWORD);
    await submitForm(page);

    // Current-password re-entry is THE primary protection: a wrong value is a
    // user-fixable form error (requireInput), not a finish — the flow must not
    // proceed and the password must stay put. The copy can render in both a
    // per-field slot and a form-error summary, so scope to the first match.
    await expect(page.getByText("Invalid credentials").first()).toBeVisible();
    await expect(page.locator("pre")).toHaveCount(0);

    // The original password still authenticates — nothing was changed.
    await page.goto(wfUrl(LOGIN_WF, "minimal"));
    await waitForFormInput(page, "username");
    await fillField(page, "username", USERS.alice.username);
    await fillField(page, "password", USERS.alice.password);
    await submitForm(page);
    const envelope = (await readFinishEnvelope(page)) as { data?: { accessToken?: string } };
    expect(typeof envelope.data?.accessToken).toBe("string");
  });

  test("WF-CHPWD-003: anonymous POST to the guarded trigger is rejected (401)", async ({
    request,
  }) => {
    // The flow is NOT @Public — the auth guard rejects an unauthenticated caller
    // BEFORE the workflow starts. The `request` fixture carries no session, so
    // this proves the route can't be driven anonymously (unlike /auth/trigger).
    // Path is `/auth/change-password` (the backend mounts auth routes at /auth,
    // not /api/auth). Wire envelope uses `schemaId` (the AsWfForm field).
    const res = await request.post("/auth/change-password", {
      data: { schemaId: CHANGE_PASSWORD_WF, input: {} },
    });
    expect(res.status()).toBe(401);
  });
});
