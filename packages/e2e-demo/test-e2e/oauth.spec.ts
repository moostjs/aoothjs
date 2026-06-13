/**
 * Federated login (OAuth2 / OIDC) e2e — drives the full browser bounce through
 * the test-only fake IdP, now via the MERGED login workflow:
 *
 *   /login (auth/login/flow form) → pick "Continue with Google" → the
 *     data-carrying `sso` action seed-derives PKCE + redirects to
 *     GET /__fake-idp/authorize (mints a code, registers the profile)
 *     → 302 → GET /auth/oauth/google/callback?code&state  (SPA bridge page)
 *     → POST /auth/trigger { wfid: auth/login/flow, input.formData: { code, state } }
 *     → init-login captures the callback → sso-callback (verify state + CSRF
 *        cookie + re-derived verifier + verified ID token) → shared login tail
 *     → finish { data.accessToken, userId } → SPA stashes token + navigates home
 *
 * STATELESS — no flow store: the PKCE verifier + OIDC nonce are RE-DERIVED from
 * the signed-state seed, so nothing secret rides through the browser (only the
 * single-use `code`). Asserts the first federated login CREATES the account and
 * a second login with the same provider `subject` LINKS to the SAME user.
 */
import { expect, test } from "@playwright/test";

import {
  clickAction,
  fillField,
  getEmails,
  getSms,
  resetApp,
  submitForm,
  USERS,
  waitForSms,
} from "./harness";

const DEMO_TOKEN_KEY = "aooth_demo_access_token";

/** Drive one full OAuth round-trip via the login form; return the authenticated session. */
async function signInWithProvider(
  page: import("@playwright/test").Page,
  buttonName: string,
): Promise<{ userId: string; token: string }> {
  await page.goto("/login");
  // The login form offers SSO providers from `ctx.public.altActions.ssoProviders`
  // via the `AsSsoProviders` one-click picker: each provider is a single button
  // whose click both selects the provider id AND fires the data-carrying `sso`
  // action (the chosen provider rides in `ssoProvider`) — no separate submit.
  await page.getByRole("button", { name: buttonName }).click();

  // Success path: the callback bridge stashes the access token and navigates home.
  // Google/GitHub bounce via a 302 GET; Apple via a `form_post` POST that the
  // OAuthController converts back to the SAME GET SPA bridge — both land here.
  await page.waitForURL((url) => url.pathname === "/", { timeout: 15_000 });
  const token = await page.evaluate((k) => sessionStorage.getItem(k), DEMO_TOKEN_KEY);
  expect(token, "access token stashed after federated login").toBeTruthy();

  // The issued token authenticates a real session.
  const status = await page.request.get("/auth/status", {
    headers: { authorization: `Bearer ${token}` },
  });
  expect(status.status(), "issued token authenticates a session").toBe(200);
  const ctx = (await status.json()) as { userId?: string };
  expect(ctx.userId, "session carries a user id").toBeTruthy();
  return { userId: ctx.userId!, token: token! };
}

function signInWithGoogle(
  page: import("@playwright/test").Page,
): Promise<{ userId: string; token: string }> {
  return signInWithProvider(page, "Continue with Google");
}

test.beforeEach(async ({ request }) => {
  await resetApp(request);
});

test.describe("OAuth / federated login (merged into auth/login/flow)", () => {
  test("OAUTH-001: first federated login creates the account and issues a session", async ({
    page,
  }) => {
    const { userId } = await signInWithGoogle(page);
    expect(userId, "first federated login created/linked a user").toBeTruthy();
  });

  test("OAUTH-002: second login with the same provider subject links to the SAME user", async ({
    page,
  }) => {
    const first = await signInWithGoogle(page);
    // Second round trip — same fake-IdP default subject → `resolveUser` finds the
    // existing `(google, sub)` link → `linked` → same account (no duplicate).
    const second = await signInWithGoogle(page);
    expect(second.userId, "linked to the same user, not a new one").toBe(first.userId);
  });

  test("OAUTH-LASTLOGIN-01: federated login stamps account.lastLogin (issue terminal)", async ({
    page,
    request,
  }) => {
    // Federated login enters via `sso-callback`, which resolves the subject
    // WITHOUT calling `users.login()` — so unless the `issue` terminal records
    // the login, `lastLogin` stays 0 and the derived `isFirstLogin = !lastLogin`
    // re-fires first-login-only steps on every subsequent SSO sign-in. Prove the
    // first login now stamps it (which is what makes the next login NOT a first).
    await signInWithGoogle(page);
    const res = await request.get("/__test/user/oauth.user@acme.test");
    expect(res.status()).toBe(200);
    const user = (await res.json()) as { id: string; account: { lastLogin: number } };
    expect(user.account.lastLogin, "federated login must stamp lastLogin").toBeGreaterThan(0);

    // The federated login routes through the SAME `record-login` funnel, so the
    // `afterLogin` hook fires for the federated subject too (not just password).
    const events = (await (await request.get("/__test/lifecycle")).json()) as {
      event: string;
      userId?: string;
    }[];
    expect(events, "federated login fires afterLogin").toContainEqual(
      expect.objectContaining({ event: "afterLogin", userId: user.id }),
    );
  });

  test("OAUTH-PROVISION-01: a first-time federated account is provisioned via prepareUser (baseline roles seeded)", async ({
    page,
    request,
  }) => {
    // Fresh provider identity whose verified email matches NO seeded account →
    // `resolveUser` returns `created` (a brand-new federated signup).
    await request.post("/__fake-idp/profile", {
      data: { email: "sso-new@acme.test", sub: "sub-provision-1", emailVerified: true },
    });
    const { userId } = await signInWithGoogle(page);
    expect(userId, "first federated login created the account").toBeTruthy();

    // The federated `created` path now runs the FederatedLoginService
    // `prepareUser` hook → the new account lands with the app-required columns a
    // password-signup / invite-accept account gets. Before the fix it was a
    // bare, role-less half-account (no roles → ARBAC would deny every API).
    const res = await request.get("/__test/user/sso-new@acme.test");
    expect(res.status()).toBe(200);
    const user = (await res.json()) as { id: string; roles: string[] };
    expect(user.id, "the queried account is the one just created").toBe(userId);
    expect(user.roles, "baseline roles seeded by prepareUser").toEqual(["member", "viewer"]);
  });

  test("OAUTH-GITHUB-01: GitHub federated login (GET callback) creates a provisioned account", async ({
    page,
    request,
  }) => {
    // GitHub uses the SAME GET-callback transport as Google — a second provider
    // on the identical state/PKCE/wf path. A first login creates the account and
    // runs the shared provisioning tail (baseline roles).
    const { userId } = await signInWithProvider(page, "Continue with GitHub");
    expect(userId, "GitHub federated login created/linked a user").toBeTruthy();

    const res = await request.get("/__test/user/github.user@acme.test");
    expect(res.status()).toBe(200);
    const user = (await res.json()) as { id: string; roles: string[] };
    expect(user.id).toBe(userId);
    expect(user.roles, "baseline roles seeded by prepareUser").toEqual(["member", "viewer"]);
  });

  test("OAUTH-APPLE-FORMPOST-01: Apple federated login completes through the form_post POST→GET bounce", async ({
    page,
    request,
  }) => {
    // Apple's `response_mode=form_post` makes the callback a cross-site POST: the
    // fake IdP returns an auto-submitting form that POSTs to
    // /auth/oauth/apple/callback, the OAuthController 303-bounces it to the GET
    // SPA bridge, and from there the flow is byte-identical to Google/GitHub.
    // This is the end-to-end proof that the POST→GET bounce works in a browser.
    const { userId } = await signInWithProvider(page, "Continue with Apple");
    expect(
      userId,
      "Apple federated login created/linked a user via the form_post bounce",
    ).toBeTruthy();

    const res = await request.get("/__test/user/apple.user@acme.test");
    expect(res.status()).toBe(200);
    const user = (await res.json()) as { id: string; roles: string[] };
    expect(user.id).toBe(userId);
    expect(user.roles, "baseline roles seeded by prepareUser").toEqual(["member", "viewer"]);
  });
});

/** Read a seeded user's stable id (the `/__test/user` helper exposes it). */
async function readUserId(
  request: import("@playwright/test").APIRequestContext,
  handle: string,
): Promise<string> {
  const res = await request.get(`/__test/user/${handle}`);
  expect(res.status()).toBe(200);
  return ((await res.json()) as { id: string }).id;
}

/**
 * Drive an SSO bounce whose verified profile email COLLIDES with an existing
 * seeded account (under a fresh provider subject) — `resolveUser` returns
 * `needs-link`, so the merged login workflow pauses on the `prove-control`
 * form (rendered by the same callback-page `<AsWfForm>`) instead of issuing.
 */
async function bounceWithCollidingEmail(
  page: import("@playwright/test").Page,
  request: import("@playwright/test").APIRequestContext,
  email: string,
  sub: string,
): Promise<void> {
  await request.post("/__fake-idp/profile", {
    data: { email, sub, emailVerified: true },
  });
  await page.goto("/login");
  // One-click SSO pill (see signInWithGoogle) — fires the `sso` action directly.
  await page.getByRole("button", { name: "Continue with Google" }).click();
  // Wait out the /login → fake-IdP → callback navigation chain before any fill:
  // the /login form ALSO has a `password` field, so filling before the
  // prove-control form has rendered would race the bounce navigation.
  await waitForProveControlForm(page);
}

/** Wait until the prove-control form (its "Verify and link" submit) is rendered. */
async function waitForProveControlForm(page: import("@playwright/test").Page): Promise<void> {
  await page
    .getByRole("button", { name: "Verify and link" })
    .waitFor({ state: "visible", timeout: 15_000 });
}

test.describe("OAuth / federated needs-link interactive completion", () => {
  test("OAUTH-NEEDSLINK-01: a colliding federated email requires proof-of-control, then links to the EXISTING account (no duplicate)", async ({
    page,
    request,
  }) => {
    const aliceId = await readUserId(request, "t1_alice");
    await bounceWithCollidingEmail(page, request, "alice@acme.test", "google-needs-link-001");

    // The prove-control PASSWORD form pauses on the callback page; proving control
    // of the matched account is what authorizes linking + the session.
    await fillField(page, "password", USERS.alice.password);
    await submitForm(page);

    // Proof passes → linkIdentity → shared login tail → issue → SPA navigates home.
    await page.waitForURL((url) => url.pathname === "/", { timeout: 15_000 });
    const token = await page.evaluate((k) => sessionStorage.getItem(k), DEMO_TOKEN_KEY);
    expect(token, "session issued after proving control + linking").toBeTruthy();

    const status = await page.request.get("/auth/status", {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(status.status()).toBe(200);
    const ctx = (await status.json()) as { userId?: string };
    // The verified identity attached to the PRE-EXISTING account — not a new one.
    expect(ctx.userId, "linked to the pre-existing account").toBe(aliceId);
  });

  test("OAUTH-NEEDSLINK-02: a wrong proof re-pauses on the same form; the correct password then links", async ({
    page,
    request,
  }) => {
    await bounceWithCollidingEmail(page, request, "alice@acme.test", "google-needs-link-002");

    // Wrong password → generic inline error, no token, form re-pauses.
    await fillField(page, "password", "WrongPassword9!");
    await submitForm(page);
    await expect(page.getByText("Invalid password")).toBeVisible({ timeout: 10_000 });
    expect(await page.evaluate((k) => sessionStorage.getItem(k), DEMO_TOKEN_KEY)).toBeNull();

    // Correct password → proof passes → linked + session issued. Wait for the
    // re-paused form to settle before refilling (the re-pause re-renders).
    await waitForProveControlForm(page);
    await fillField(page, "password", USERS.alice.password);
    await submitForm(page);
    await page.waitForURL((url) => url.pathname === "/", { timeout: 15_000 });
    expect(await page.evaluate((k) => sessionStorage.getItem(k), DEMO_TOKEN_KEY)).toBeTruthy();
  });
});

/**
 * OTP FALLBACK of the needs-link completion. When the matched account is
 * PASSWORDLESS (`password.isInitial`), there is no password to re-enter, so
 * `prove-control` mints a one-time code and delivers it to the account's OWN
 * confirmed channel. `t1_otplink` is passwordless with a single confirmed SMS
 * factor at a phone DISTINCT from its email — so the regression lock is
 * unmistakable: the proof code must ride the SMS channel, NEVER the
 * provider-supplied email (which an attacker controlling the IdP account owns).
 */
test.describe("OAuth / federated needs-link OTP fallback (passwordless account)", () => {
  const OTP_USER_EMAIL = "otplink@acme.test";
  const OTP_USER_PHONE = "+15555550144";

  test("OAUTH-NEEDSLINK-OTP-01: a passwordless colliding account proves control via an OTP sent to its OWN sms channel (never the provider email), then links to the EXISTING account", async ({
    page,
    request,
  }) => {
    const otplinkId = await readUserId(request, "t1_otplink");
    await bounceWithCollidingEmail(page, request, OTP_USER_EMAIL, "google-otp-needs-link-001");

    // OTP fallback form (passwordless → no password to re-enter): the code
    // input is present and there is NO password field on the prove-control form.
    await expect(page.locator('[name="code"]')).toBeVisible();
    expect(await page.locator('[name="password"]').count()).toBe(0);
    // The form must NOT surface the provider-supplied email as the delivery
    // target — the masked recipient is the OWN sms channel (invariant 3).
    await expect(page.getByTestId("oauth-callback")).not.toContainText(OTP_USER_EMAIL);

    // INVARIANT 3 — the proof code reached the account's OWN sms channel…
    const sms = await waitForSms(request, (e) => e.recipient === OTP_USER_PHONE);
    expect(sms.code, "OTP delivered to the account's own confirmed sms channel").toBeTruthy();
    // …and NOT the federation-matched email (no code-bearing mail to it).
    const emails = await getEmails(request);
    expect(
      emails.some((e) => e.recipient === OTP_USER_EMAIL && !!e.code),
      "no OTP code may be delivered to the provider-supplied email",
    ).toBe(false);

    await fillField(page, "code", sms.code);
    await submitForm(page);

    // Proof passes → linkIdentity → shared login tail → issue → navigate home.
    await page.waitForURL((url) => url.pathname === "/", { timeout: 15_000 });
    const token = await page.evaluate((k) => sessionStorage.getItem(k), DEMO_TOKEN_KEY);
    expect(token, "session issued after OTP proof + link").toBeTruthy();
    const status = await page.request.get("/auth/status", {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(status.status()).toBe(200);
    const ctx = (await status.json()) as { userId?: string };
    // Attached to the PRE-EXISTING passwordless account, not a new one.
    expect(ctx.userId, "linked to the pre-existing passwordless account").toBe(otplinkId);
  });

  test("OAUTH-NEEDSLINK-OTP-02: an immediate resend is refused by the cooldown (armed on first dispatch); no second code is sent", async ({
    page,
    request,
  }) => {
    await bounceWithCollidingEmail(page, request, OTP_USER_EMAIL, "google-otp-needs-link-002");
    await expect(page.locator('[name="code"]')).toBeVisible();

    // First dispatch delivered exactly one code to the own channel + armed the
    // resend cooldown (default 60s — the OAuth callback sends no fast variant).
    const first = await waitForSms(request, (e) => e.recipient === OTP_USER_PHONE);
    expect(first.code).toBeTruthy();
    const countBefore = (await getSms(request)).filter(
      (e) => e.recipient === OTP_USER_PHONE,
    ).length;

    // Immediate resend → the cooldown gate refuses with a "Please wait" message.
    await clickAction(page, "Resend code");
    await expect(page.getByText(/Please wait/i)).toBeVisible({ timeout: 10_000 });

    // No second code was minted/delivered.
    const countAfter = (await getSms(request)).filter((e) => e.recipient === OTP_USER_PHONE).length;
    expect(countAfter, "cooldown blocked the resend — no new code").toBe(countBefore);
  });
});

/**
 * Connected-accounts SELF-SERVICE surface — `GET /auth/oauth/identities` (the
 * list route added to OAuthController) rendered by the SPA's `/accounts` page,
 * with the existing self-scoped `DELETE /auth/oauth/:provider/:subject` unlink.
 * Both routes derive identity from the session (the demo replays the stashed
 * Bearer), so a sign-in must precede them.
 */
test.describe("OAuth / connected-accounts surface (GET identities + /accounts page)", () => {
  test("OAUTH-CONNECTED-01: the page lists a linked identity and unlinks it (password account)", async ({
    page,
    request,
  }) => {
    // Link google to alice — a PASSWORD account — via the needs-link proof path,
    // so the later unlink won't trip the last-sign-in-method guard.
    await bounceWithCollidingEmail(page, request, "alice@acme.test", "google-connected-01");
    await fillField(page, "password", USERS.alice.password);
    await submitForm(page);
    await page.waitForURL((url) => url.pathname === "/", { timeout: 15_000 });

    // The /accounts page lists the freshly linked google identity.
    await page.goto("/accounts");
    const row = page.getByTestId("connected-account-google");
    await expect(row).toBeVisible({ timeout: 10_000 });
    await expect(row).toContainText(/google/i);

    // Unlink it — alice keeps her password, so the guard allows removal; the row
    // drops (optimistic local removal, since unlink revokes the session).
    await row.getByRole("button", { name: /unlink/i }).click();
    await expect(page.getByTestId("connected-account-google")).toHaveCount(0);
    await expect(page.getByTestId("ca-empty")).toBeVisible();
  });

  test("OAUTH-CONNECTED-02: unlinking the ONLY sign-in method is refused by the last-credential guard", async ({
    page,
  }) => {
    // First federated login CREATES a passwordless, google-only account
    // (`createUser` sets `password.isInitial = true`).
    await signInWithGoogle(page);

    await page.goto("/accounts");
    const row = page.getByTestId("connected-account-google");
    await expect(row).toBeVisible({ timeout: 10_000 });

    // Unlink is refused — it's the only sign-in method (no password, no other
    // link). The server 409 surfaces inline and the row stays.
    await row.getByRole("button", { name: /unlink/i }).click();
    await expect(page.getByTestId("ca-error")).toContainText(/only sign-in method/i);
    await expect(page.getByTestId("connected-account-google")).toBeVisible();
  });
});
