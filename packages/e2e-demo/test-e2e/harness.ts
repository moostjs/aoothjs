/**
 * Shared helpers for the Playwright e2e suite. Every spec resets the demo
 * via `POST /__test/reset` in `beforeEach` so tests are independent.
 *
 * Boot the demo with `DEMO_MODE=test SEED=true pnpm dev` (BASE_URL defaults
 * to http://localhost:3001 in playwright.config.ts; override via env when
 * Vite bumps to 3002+ because something else holds the default port).
 */
import type { AuthEmailEvent, AuthSmsEvent } from "@aooth/auth";
import { authorize, type AuthorizeResult } from "@aooth/login-client";
import { generateTotpCode } from "@aooth/user";
import type { APIRequestContext, Browser, BrowserContext, Page } from "@playwright/test";
import { expect } from "@playwright/test";

/**
 * SessionStorage key `WfPage.vue` stashes the demo access token under (source
 * of truth: `src/ui/demoToken.ts` — specs don't import from `src/`, so the
 * literal is mirrored here once for the whole suite).
 */
export const DEMO_TOKEN_KEY = "aooth_demo_access_token";

/** Re-seed the demo DB and clear captured email/SMS buffers. */
export async function resetApp(request: APIRequestContext): Promise<void> {
  const res = await request.post("/__test/reset");
  expect(res.status(), "reset endpoint mounted (run with DEMO_MODE=test)").toBe(201);
}

export async function getEmails(request: APIRequestContext): Promise<AuthEmailEvent[]> {
  const res = await request.get("/__test/emails");
  expect(res.status()).toBe(200);
  return (await res.json()) as AuthEmailEvent[];
}

export async function getSms(request: APIRequestContext): Promise<AuthSmsEvent[]> {
  const res = await request.get("/__test/sms");
  expect(res.status()).toBe(200);
  return (await res.json()) as AuthSmsEvent[];
}

/** Count the durable wf-state rows (`GET /__test/wf-states/count`, all rows). */
export async function wfStatesCount(request: APIRequestContext): Promise<number> {
  const res = await request.get("/__test/wf-states/count");
  expect(res.status(), "wf-states/count endpoint mounted (run with DEMO_MODE=test)").toBe(200);
  return ((await res.json()) as { count: number }).count;
}

/**
 * Polls the captured-emails buffer until at least one event matches `filter`,
 * then returns the most recent match. Times out at 5s — workflows emit
 * outletEmail synchronously so this should always resolve within one tick.
 */
export async function waitForEmail(
  request: APIRequestContext,
  filter: (event: AuthEmailEvent) => boolean,
  timeoutMs = 5000,
): Promise<AuthEmailEvent> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const events = await getEmails(request);
    const match = [...events].toReversed().find(filter);
    if (match) return match;
    await new Promise((r) => setTimeout(r, 100));
  }
  const events = await getEmails(request);
  throw new Error(
    `waitForEmail timed out after ${timeoutMs}ms. captured events: ${JSON.stringify(events)}`,
  );
}

export async function waitForSms(
  request: APIRequestContext,
  filter: (event: AuthSmsEvent) => boolean,
  timeoutMs = 5000,
): Promise<AuthSmsEvent> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const events = await getSms(request);
    const match = [...events].toReversed().find(filter);
    if (match) return match;
    await new Promise((r) => setTimeout(r, 100));
  }
  const events = await getSms(request);
  throw new Error(
    `waitForSms timed out after ${timeoutMs}ms. captured events: ${JSON.stringify(events)}`,
  );
}

/** Build the `/wf` SPA URL for a given workflow id + optional variant. */
export function wfUrl(wfId: string, variant?: string): string {
  const params = new URLSearchParams({ id: wfId });
  if (variant) params.set("variant", variant);
  return `/wf?${params.toString()}`;
}

/** TOTP code for a known seeded secret (used for t1_grace, t1_multi_mfa, etc.). */
export function totp(secret: string): string {
  return generateTotpCode(secret);
}

/**
 * Per-test seed metadata. The `__test/reset` log surfaces the TOTP secrets
 * for t1_grace, t1_multi_mfa each time the demo seeds; these change on every
 * boot. Tests that need TOTP read the secret from the seed log (the dev
 * terminal).
 *
 * For now we hard-code well-known TEST usernames and passwords; secrets are
 * fetched ad-hoc per spec.
 */
export const USERS = {
  alice: { username: "t1_alice", password: "Password1!" },
  bob: { username: "t1_bob", password: "Password1!" },
  grace: { username: "t1_grace", password: "Password1!" }, // single TOTP
  henry: { username: "t1_henry", password: "Password1!" }, // single Email-OTP
  iris: { username: "t1_iris", password: "Password1!" }, // full-variant walkthrough (WF-LOGIN-032)
  ivy: { username: "t1_ivy", password: "Password1!" }, // single SMS-OTP
  jack: { username: "t1_jack", password: "Password1!" }, // passwordInitial
  multi_mfa: { username: "t1_multi_mfa", password: "Password1!" }, // email + sms + totp
  locked: { username: "t1_locked", password: "Password1!" },
  pending: { username: "t1_pending", password: "Password1!" }, // pendingInvitation=true
  redeemed: { username: "t1_redeemed", password: "Password1!" },
  admin_inviter: { username: "_admin_inviter", password: "Password1!" },
} as const;

/** Wait for the workflow form to be ready for input (any input named on the page). */
export async function waitForFormInput(page: Page, name: string, timeoutMs = 5000): Promise<void> {
  await page.locator(`[name="${name}"]`).first().waitFor({ state: "visible", timeout: timeoutMs });
}

/**
 * Set a form field value by name. Handles four cases:
 * - `<input type="radio">` (multiple inputs share `name`): click the input
 *   whose `value` attribute matches `value`.
 * - `<select>`: `selectOption(value)` (atscript-ui's dynamic-options selects
 *   ship `{ key, label }` entries — the option's `value` is `key`).
 * - `<input type="checkbox">`: check/uncheck based on truthy `value`.
 * - everything else (text, password, number, textarea): native `fill(value)`.
 */
export async function fillField(page: Page, name: string, value: string): Promise<void> {
  await waitForFormInput(page, name);
  const named = page.locator(`[name="${name}"]`);
  const first = named.first();
  const meta = await first.evaluate((el) => ({
    tag: el.tagName.toLowerCase(),
    type: (el as HTMLInputElement).type?.toLowerCase() ?? "",
  }));
  if (meta.tag === "input" && meta.type === "radio") {
    await page.locator(`input[type="radio"][name="${name}"][value="${value}"]`).first().check();
    return;
  }
  if (meta.tag === "input" && meta.type === "checkbox") {
    if (value === "true" || value === "1") await first.check();
    else await first.uncheck();
    return;
  }
  if (meta.tag === "select") {
    await first.selectOption(value);
    return;
  }
  await first.fill(value);
}

export async function clickAction(page: Page, label: string): Promise<void> {
  await page.getByRole("button", { name: label, exact: false }).first().click();
}

/**
 * Wait for the TOTP QR step (`EnrollTotpQrForm`) — the `AsQrCode` root renders
 * the scannable QR + manual secret on its OWN pause, between method-pick and
 * code-entry. (Shared by login/invite opt-in AND the manage-MFA flow.)
 */
export async function waitForTotpQrStep(page: Page, timeoutMs = 5000): Promise<void> {
  await page.locator(".as-qr-code").first().waitFor({ state: "visible", timeout: timeoutMs });
}

/** Advance past the TOTP QR step by clicking its "Continue" submit. */
export async function continuePastTotpQr(page: Page): Promise<void> {
  await waitForTotpQrStep(page);
  await submitForm(page);
}

/**
 * Read the manual-entry base32 secret rendered on the TOTP QR step. Under
 * write-on-confirm the secret is staged in wf-state and NOT persisted to the
 * user record until the setup code verifies, so the rendered secret (not a DB
 * row) is the source of truth for computing the enrollment code. Call this while
 * the QR step is showing, BEFORE `continuePastTotpQr`.
 */
export async function readTotpQrSecret(page: Page): Promise<string> {
  await waitForTotpQrStep(page);
  const el = page.locator(".as-qr-code .as-qr-code-secret").first();
  await el.waitFor({ state: "visible", timeout: 5000 });
  return ((await el.textContent()) ?? "").trim();
}

/** Submit the form via its primary submit button (the one rendered by AsForm). */
export async function submitForm(page: Page): Promise<void> {
  await page.locator("button.as-submit-btn, button[type=submit]").first().click();
}

/**
 * Wait for the authorization-server consent prompt (AUTH-SERVER.md §6) — the
 * `AuthorizeConsentForm` pause the `authz-consent` step renders after
 * authentication on an authorize-initiated login.
 */
export async function waitForConsent(page: Page): Promise<void> {
  await page
    .getByText("wants to sign in to your account", { exact: false })
    .waitFor({ state: "visible", timeout: 10_000 });
}

/**
 * Approve the authorization-server consent gate: wait for the prompt, then
 * press 'Authorize' (the form's primary submit) so the code mint can proceed.
 */
export async function approveConsent(page: Page): Promise<void> {
  await waitForConsent(page);
  await submitForm(page);
}

/**
 * Run the loopback grant: kick off `authorize()` (which sets up the loopback and
 * surfaces the authorize URL via `onUrl`), drive the browser through it, and
 * resolve with the token. The loopback listener is up before `onUrl` fires, so
 * the browser can navigate immediately.
 */
export async function runCliLogin(
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

/**
 * Attacker leg for the browser-binding specs: initiate an authorize in a FRESH
 * context to mint a pending handle. The browser-binding cookie (`aooth_authz`)
 * is dropped HERE, in the attacker's context — never the victim's. The attacker
 * reads the opaque handle off the `/login?authz=` bounce. (A real attacker
 * injects their own client/redirect; a loopback redirect is enough to
 * demonstrate the binding wall.) The caller owns closing the returned context.
 */
export async function mintPhishedHandle(
  browser: Browser,
  origin: string,
): Promise<{ handle: string; attacker: BrowserContext }> {
  const attacker = await browser.newContext();
  const page = await attacker.newPage();
  await page.goto(
    `${origin}/auth/authorize?response_type=code` +
      `&redirect_uri=${encodeURIComponent("http://127.0.0.1:5000/callback")}` +
      `&code_challenge=phished-challenge&code_challenge_method=S256&state=atk`,
  );
  await page.waitForURL(/\/login\?authz=/, { timeout: 10_000 });
  const handle = new URL(page.url()).searchParams.get("authz");
  expect(handle, "the attacker captured the pending-auth handle").toBeTruthy();
  return { handle: handle!, attacker };
}

/**
 * Rewrite an absolute magic-link URL onto BASE_URL so the resume hits the
 * demo backend (which serves the SPA in test mode). Magic links land with
 * the SPA dev origin (e.g. http://localhost:5173) baked in by AuthEmailEvent.
 */
export function rewriteToBaseUrl(absolute: string, baseURL: string | undefined): string {
  const parsed = new URL(absolute);
  return `${(baseURL ?? "").replace(/\/$/, "")}${parsed.pathname}${parsed.search}`;
}

/** Read the `WfFinished` envelope JSON rendered by `WfPage.vue` after `@finished`. */
export async function readFinishEnvelope(page: Page): Promise<unknown> {
  const pre = page.locator("pre").first();
  await pre.waitFor({ state: "visible" });
  const raw = (await pre.textContent()) ?? "";
  return JSON.parse(raw) as unknown;
}

/**
 * Drive `auth.login` (variant `minimal`) through the SPA so the finish
 * cookies are written to the browser context. Asserts the rendered finish
 * envelope so subsequent calls can assume an authenticated cookie jar.
 */
export async function loginViaUi(
  page: Page,
  user: { username: string; password: string },
): Promise<void> {
  await page.goto(wfUrl("auth/login/flow", "minimal"));
  await fillField(page, "username", user.username);
  await fillField(page, "password", user.password);
  await submitForm(page);
  await expect(page.locator("text=Workflow finished")).toBeVisible({ timeout: 5000 });
  await expect(page.locator("pre").first()).toContainText("accessToken");
}

/** Per-run unique email so re-runs against a non-reset server don't collide. */
export function uniqueEmail(prefix: string): string {
  return `${prefix}-${Date.now()}@test.example`;
}

/**
 * Mint an access token for `username` via `POST /__test/token-attenuated`.
 * An empty `claims` body (the default) mints a FULL-authority token; pass
 * typed `@arbac.attenuate.*` fields to mint a down-scoped one.
 */
export async function mintToken(
  request: APIRequestContext,
  username: string,
  claims: { roles?: string[]; attrs?: Record<string, unknown> } = {},
): Promise<string> {
  // request.post({ data }) sends application/json — the @Body() parser needs it.
  const res = await request.post(`/__test/token-attenuated/${username}`, { data: claims });
  expect(res.ok()).toBeTruthy();
  return ((await res.json()) as { accessToken: string }).accessToken;
}

/** Bearer header object for `request.get(url, { headers: bearerAuth(token) })`. */
export function bearerAuth(token: string): { Authorization: string } {
  return { Authorization: `Bearer ${token}` };
}
