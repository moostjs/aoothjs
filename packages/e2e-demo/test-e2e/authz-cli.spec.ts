/**
 * Authorization-server CLI grant (AUTH-SERVER.md Tier 1) e2e — drives the REAL
 * `@aooth/login-client` loopback helper against the demo's `/auth/authorize` +
 * `/auth/token`, with Playwright standing in for the user's browser:
 *
 *   authorize() opens a one-shot 127.0.0.1 listener + builds the authorize URL →
 *     page.goto(authorizeUrl) → GET /auth/authorize (validates loopback redirect,
 *       records a pending authorization) → 302 /login?authz=<handle>
 *     → the SPA forwards `authz` into auth/login/flow's START input → init-login
 *       raises ctx.authz → the user authenticates (password, OR a mid-login
 *       "Continue with Google" detour that carries the handle through the signed
 *       federated state) → `mint-authz-code` terminal 302s the loopback with
 *       ?code&state (NO browser session, NO cookies)
 *     → the loopback catches the code → POST /auth/token (PKCE-verified) → token.
 *
 * The token is minted off the browser (back-channel) — nothing long-lived ever
 * rides the redirect. Asserts the returned token authenticates a real session.
 */
import { authorize, type AuthorizeResult } from "@aooth/login-client";
import { expect, test, type Page } from "@playwright/test";

import { fillField, resetApp, submitForm, USERS } from "./harness";

/**
 * Run the loopback grant: kick off `authorize()` (which sets up the loopback and
 * surfaces the authorize URL via `onUrl`), drive the browser through it, and
 * resolve with the token. The loopback listener is up before `onUrl` fires, so
 * the browser can navigate immediately.
 */
async function runCliLogin(
  page: Page,
  origin: string,
  drive: (page: Page) => Promise<void>,
): Promise<AuthorizeResult> {
  let authUrl: string | undefined;
  const pending = authorize({
    authorizeUrl: `${origin}/auth/authorize`,
    tokenUrl: `${origin}/auth/token`,
    openBrowser: false,
    onUrl: (u) => {
      authUrl = u;
    },
    timeoutMs: 25_000,
  });
  await expect.poll(() => Boolean(authUrl), { timeout: 10_000 }).toBe(true);
  await page.goto(authUrl!);
  await drive(page);
  return pending;
}

test.beforeEach(async ({ request }) => {
  await resetApp(request);
});

test("AUTHZ-CLI-01: a password loopback login mints a working token", async ({ page, baseURL }) => {
  const origin = baseURL ?? "http://localhost:3001";

  const result = await runCliLogin(page, origin, async (p) => {
    await fillField(p, "username", USERS.alice.username);
    await fillField(p, "password", USERS.alice.password);
    await submitForm(p);
  });

  expect(result.accessToken, "the CLI received an access token").toBeTruthy();
  expect(result.userId, "the token response carries the user id").toBeTruthy();

  // The minted token authenticates a real session against the API.
  const status = await page.request.get(`${origin}/auth/status`, {
    headers: { authorization: `Bearer ${result.accessToken}` },
  });
  expect(status.status(), "the CLI token authenticates").toBe(200);
  const ctx = (await status.json()) as { userId?: string };
  expect(ctx.userId).toBe(result.userId);
});

test("AUTHZ-CLI-02: a mid-login 'Continue with Google' detour still mints the token", async ({
  page,
  baseURL,
}) => {
  const origin = baseURL ?? "http://localhost:3001";

  // Instead of typing a password, the user picks SSO mid-authorize. `beginSso`
  // folds the pending-auth handle into the signed federated state; after the
  // provider bounce, `sso-callback` re-raises ctx.authz in the SECOND login run,
  // so its terminal mints the code for the original CLI client.
  const result = await runCliLogin(page, origin, async (p) => {
    await p.getByRole("button", { name: "Continue with Google" }).click();
  });

  expect(result.accessToken, "the CLI received an access token via the SSO detour").toBeTruthy();
  expect(result.userId).toBeTruthy();

  const status = await page.request.get(`${origin}/auth/status`, {
    headers: { authorization: `Bearer ${result.accessToken}` },
  });
  expect(status.status()).toBe(200);
});
