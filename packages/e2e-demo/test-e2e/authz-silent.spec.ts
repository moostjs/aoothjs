/**
 * Consent-only authorize (silent session → consent) e2e — the
 * `resolveAuthzReauthPolicy() → { mode: 'consent-only' }` policy the demo's
 * workflow subclass opts into.
 *
 * With a LIVE browser session on the consumer SPA, the authorize leg must show
 * ONLY the consent screen — no credentials form, no MFA — exactly like GitHub /
 * Google / Auth0. The session credential reaches the flow trigger because the
 * SPA replays the stashed access token as `Authorization: Bearer` on every
 * trigger (WfPage's `fetchOptions`); the auth guard validates it on the
 * `@Public()` route and `init-login`'s probe binds `ctx.subject` from it.
 *
 * The two account-takeover defenses stay in force on the silent path:
 * browser binding (`aooth_authz` cookie — AUTHZ-SILENT-04) and explicit
 * consent (Deny leg — AUTHZ-SILENT-02). Anonymous authorize legs keep the
 * full credentials path (every other authz spec runs in a fresh context, so
 * they double as always-behaved regression coverage).
 */
import { authorize, type AuthorizeError, type AuthorizeResult } from "@aooth/login-client";
import { expect, test, type Page } from "@playwright/test";

import { clickAction, fillField, resetApp, submitForm, USERS, waitForConsent } from "./harness";

const DEMO_TOKEN_KEY = "aooth_demo_access_token";

/** Password-login through the SPA so the browser holds a live demo session. */
async function loginViaSpa(page: Page): Promise<void> {
  await page.goto("/login");
  await fillField(page, "username", USERS.alice.username);
  await fillField(page, "password", USERS.alice.password);
  await submitForm(page);
  // The finish envelope stashes the access token — the SPA replays it as a
  // Bearer on every subsequent flow trigger. That stash IS the live session.
  await page.waitForFunction((k) => sessionStorage.getItem(k) !== null, DEMO_TOKEN_KEY, {
    timeout: 15_000,
  });
}

/** Loopback grant runner (same shape as authz-cli.spec.ts). */
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

test("AUTHZ-SILENT-01: a live session lands straight on consent (no credentials form) and the code mints + redeems", async ({
  page,
  baseURL,
  request,
}) => {
  const origin = baseURL ?? "http://localhost:3001";
  await loginViaSpa(page);

  const result = await runCliLogin(page, origin, async (p) => {
    // The consent prompt renders DIRECTLY — the credentials form never
    // appears on this leg.
    await waitForConsent(p);
    expect(await p.locator('input[name="username"]').count(), "no credentials form").toBe(0);
    expect(await p.locator('input[name="password"]').count(), "no password field").toBe(0);
    // The acting identity is named so a wrong-account grant is catchable.
    await expect(p.getByText("Signed in as", { exact: false })).toContainText(USERS.alice.username);
    await submitForm(p); // Authorize
  });

  expect(result.accessToken, "the client received an access token").toBeTruthy();
  const status = await page.request.get(`${origin}/auth/status`, {
    headers: { authorization: `Bearer ${result.accessToken}` },
  });
  expect(status.status(), "the silently-minted token authenticates").toBe(200);

  // A silent consent is NOT a login event: exactly one afterLogin fired (the
  // SPA login) — the silent authorize leg recorded nothing.
  const events = (await (await request.get("/__test/lifecycle")).json()) as { event: string }[];
  expect(events.filter((e) => e.event === "afterLogin")).toHaveLength(1);
});

test("AUTHZ-SILENT-02: Deny on the silent consent delivers access_denied and mints nothing", async ({
  page,
  baseURL,
}) => {
  const origin = baseURL ?? "http://localhost:3001";
  await loginViaSpa(page);

  const attempt = runCliLogin(page, origin, async (p) => {
    await waitForConsent(p);
    await clickAction(p, "Deny");
  });

  await expect(attempt).rejects.toThrow(/access_denied/i);
  await expect(attempt).rejects.toMatchObject({
    code: "provider_denied",
  } satisfies Partial<AuthorizeError>);
});

test("AUTHZ-SILENT-03: a fresh credentials authorize shows consent WITHOUT the 'Signed in as' line", async ({
  page,
  baseURL,
}) => {
  const origin = baseURL ?? "http://localhost:3001";

  // No SPA login — anonymous context → the credentials path is unchanged and
  // `signedInAs` (a silent-run-only stamp) never reaches the consent copy.
  const result = await runCliLogin(page, origin, async (p) => {
    await fillField(p, "username", USERS.alice.username);
    await fillField(p, "password", USERS.alice.password);
    await submitForm(p);
    await waitForConsent(p);
    // `@ui.form.fn.hidden` keeps the node in the DOM — assert on visibility.
    await expect(p.getByText("Signed in as", { exact: false })).toBeHidden();
    await submitForm(p);
  });

  expect(result.accessToken).toBeTruthy();
});

test("AUTHZ-SILENT-04: a phished handle in a session-holding browser still fails the binding wall before consent", async ({
  browser,
  baseURL,
}) => {
  const origin = baseURL ?? "http://localhost:3001";
  const LOOPBACK = "http://127.0.0.1:5000/callback";

  // Attacker context mints the pending handle (and owns the binding cookie).
  const attacker = await browser.newContext();
  const aPage = await attacker.newPage();
  await aPage.goto(
    `${origin}/auth/authorize?response_type=code` +
      `&redirect_uri=${encodeURIComponent(LOOPBACK)}` +
      `&code_challenge=phished-challenge&code_challenge_method=S256&state=atk`,
  );
  await aPage.waitForURL(/\/login\?authz=/, { timeout: 10_000 });
  const handle = new URL(aPage.url()).searchParams.get("authz");
  expect(handle).toBeTruthy();

  // Victim context holds a LIVE session — the worst case for consent-only:
  // the probe binds the subject with zero keystrokes, so the binding check is
  // the only wall left. It must fail closed BEFORE any consent prompt.
  const victim = await browser.newContext({ baseURL: origin });
  const vPage = await victim.newPage();
  await loginViaSpa(vPage);
  await vPage.goto(`${origin}/login?authz=${handle}`);

  await expect(
    vPage.locator(".as-wf-finish-message", { hasText: "could not be verified for your browser" }),
    "the binding wall blocks a phished handle even on the silent path",
  ).toBeVisible({ timeout: 10_000 });
  await expect(vPage.getByRole("button", { name: "Authorize" })).toHaveCount(0);
  // And no credentials form either — the run bound silently, then died at the wall.
  await expect(vPage.locator('input[name="password"]')).toHaveCount(0);

  await attacker.close();
  await victim.close();
});
