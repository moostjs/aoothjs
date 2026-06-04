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

import { fillField, resetApp, submitForm, USERS } from "./harness";

const DEMO_TOKEN_KEY = "aooth_demo_access_token";

/** Drive one full OAuth round-trip via the login form; return the authenticated session. */
async function signInWithGoogle(
  page: import("@playwright/test").Page,
): Promise<{ userId: string; token: string }> {
  await page.goto("/login");
  // The login form offers SSO providers from `ctx.public.altActions.ssoProviders`
  // via the `AsSsoProviders` one-click picker: each provider is a single button
  // whose click both selects the provider id AND fires the data-carrying `sso`
  // action (the chosen provider rides in `ssoProvider`) — no separate submit.
  await page.getByRole("button", { name: "Continue with Google" }).click();

  // Success path: the callback bridge stashes the access token and navigates home.
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
