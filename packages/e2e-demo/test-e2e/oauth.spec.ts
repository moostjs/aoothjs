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

import { resetApp } from "./harness";

const DEMO_TOKEN_KEY = "aooth_demo_access_token";

/** Drive one full OAuth round-trip via the login form; return the authenticated session. */
async function signInWithGoogle(
  page: import("@playwright/test").Page,
): Promise<{ userId: string; token: string }> {
  await page.goto("/login");
  // The login form offers SSO providers from `ctx.public.altActions.ssoProviders`
  // as a radio group; selecting one + "Continue" fires the data-carrying `sso`
  // action (the chosen provider id rides in `ssoProvider`).
  await page.getByRole("radio", { name: "Continue with Google" }).check();
  await page.getByRole("button", { name: "Continue", exact: true }).click();

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
