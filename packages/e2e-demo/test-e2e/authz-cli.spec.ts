/**
 * Authorization-server CLI grant (AUTH-SERVER.md Tier 1) e2e — drives the REAL
 * `@aooth/login-client` loopback helper against the demo's `/auth/authorize` +
 * `/auth/token`, with Playwright standing in for the user's browser:
 *
 *   authorize() opens a one-shot 127.0.0.1 listener + builds the authorize URL →
 *     page.goto(authorizeUrl) → GET /auth/authorize (validates loopback redirect,
 *       records a pending authorization, drops the `aooth_authz` browser-binding
 *       cookie) → 302 /login?authz=<handle>
 *     → the SPA forwards `authz` into auth/login/flow's START input → init-login
 *       raises ctx.authz → the user authenticates (password, OR a mid-login
 *       "Continue with Google" detour that carries the handle through the signed
 *       federated state) → the `authz-consent` step verifies the browser binding
 *       and the user presses 'Authorize' → `mint-authz-code` terminal 302s the
 *       loopback with ?code&state (NO browser session, NO cookies)
 *     → the loopback catches the code → POST /auth/token (PKCE-verified) → token.
 *
 * The token is minted off the browser (back-channel) — nothing long-lived ever
 * rides the redirect. Asserts the returned token authenticates a real session,
 * that the consent gate is mandatory, and that the browser-binding cookie
 * neutralises a phished `authz` handle (AUTH-SERVER.md §6).
 */
import { authorize, type AuthorizeError, type AuthorizeResult } from "@aooth/login-client";
import { expect, test, type Page } from "@playwright/test";

import {
  approveConsent,
  clickAction,
  fillField,
  resetApp,
  submitForm,
  USERS,
  waitForConsent,
} from "./harness";

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

test("AUTHZ-CLI-01: a password loopback login + consent mints a working token", async ({
  page,
  baseURL,
}) => {
  const origin = baseURL ?? "http://localhost:3001";

  const result = await runCliLogin(page, origin, async (p) => {
    await fillField(p, "username", USERS.alice.username);
    await fillField(p, "password", USERS.alice.password);
    await submitForm(p);
    await approveConsent(p);
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

test("AUTHZ-CLI-02: a mid-login 'Continue with Google' detour + consent still mints the token", async ({
  page,
  baseURL,
}) => {
  const origin = baseURL ?? "http://localhost:3001";

  // Instead of typing a password, the user picks SSO mid-authorize. `beginSso`
  // folds the pending-auth handle into the signed federated state; after the
  // provider bounce, `sso-callback` re-raises ctx.authz in the SECOND login run,
  // so its terminal mints the code for the original CLI client. The binding
  // cookie (SameSite=Lax) survives the top-level GET back from the provider, so
  // the consent gate's binding check passes for the SAME browser.
  const result = await runCliLogin(page, origin, async (p) => {
    await p.getByRole("button", { name: "Continue with Google" }).click();
    await approveConsent(p);
  });

  expect(result.accessToken, "the CLI received an access token via the SSO detour").toBeTruthy();
  expect(result.userId).toBeTruthy();

  const status = await page.request.get(`${origin}/auth/status`, {
    headers: { authorization: `Bearer ${result.accessToken}` },
  });
  expect(status.status()).toBe(200);
});

test("AUTHZ-CLI-03: declining consent delivers access_denied and mints no token", async ({
  page,
  baseURL,
}) => {
  const origin = baseURL ?? "http://localhost:3001";

  // The user authenticates but DENIES the authorization — the `authz-consent`
  // step 302s the client back with `?error=access_denied`, mints nothing, and
  // the login-client surfaces it as a `provider_denied` AuthorizeError.
  const attempt = runCliLogin(page, origin, async (p) => {
    await fillField(p, "username", USERS.alice.username);
    await fillField(p, "password", USERS.alice.password);
    await submitForm(p);
    await waitForConsent(p);
    await clickAction(p, "Deny");
  });

  await expect(attempt).rejects.toThrow(/access_denied/i);
  await expect(attempt).rejects.toMatchObject({
    code: "provider_denied",
  } satisfies Partial<AuthorizeError>);
});

test("AUTHZ-CLI-04: an authz handle phished into a different browser cannot be redeemed (binding)", async ({
  browser,
  baseURL,
}) => {
  const origin = baseURL ?? "http://localhost:3001";
  const LOOPBACK = "http://127.0.0.1:5000/callback";

  // ── Attacker browser: initiate the authorize to mint a pending handle. The
  // browser-binding cookie (`aooth_authz`) is dropped HERE, in the attacker's
  // context — never the victim's. The attacker reads the opaque handle off the
  // /login?authz= bounce. (A real attacker injects their own client/redirect;
  // a loopback redirect is enough to demonstrate the binding wall.)
  const attacker = await browser.newContext();
  const aPage = await attacker.newPage();
  await aPage.goto(
    `${origin}/auth/authorize?response_type=code` +
      `&redirect_uri=${encodeURIComponent(LOOPBACK)}` +
      `&code_challenge=phished-challenge&code_challenge_method=S256&state=atk`,
  );
  await aPage.waitForURL(/\/login\?authz=/, { timeout: 10_000 });
  const handle = new URL(aPage.url()).searchParams.get("authz");
  expect(handle, "the attacker captured the pending-auth handle").toBeTruthy();

  // ── Victim browser: a FRESH context (no `aooth_authz` cookie) opens the
  // phished link and logs in for real. The `authz-consent` step's binding check
  // fails (no matching cookie), so the consent prompt never renders and NO code
  // is minted — the handle is inert in a browser it was phished into.
  const victim = await browser.newContext();
  const vPage = await victim.newPage();
  await vPage.goto(`${origin}/login?authz=${handle}`);
  // Let the SPA's START round-trip settle before filling — otherwise the login
  // form re-renders mid-fill (clearing the fields) on a direct (non-302) nav.
  await vPage.waitForLoadState("networkidle");
  await fillField(vPage, "username", USERS.alice.username);
  await fillField(vPage, "password", USERS.alice.password);
  await submitForm(vPage);

  await expect(
    vPage.locator(".as-wf-finish-message", { hasText: "could not be verified for your browser" }),
    "the binding wall blocks a phished handle in a foreign browser",
  ).toBeVisible({ timeout: 10_000 });
  // The consent prompt must NEVER appear → no path to a minted code.
  await expect(vPage.getByRole("button", { name: "Authorize" })).toHaveCount(0);

  await attacker.close();
  await victim.close();
});
