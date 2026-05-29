/**
 * Playwright stories for the workflow STATE-STRATEGY behaviour + the TOTP QR.
 *
 * THE WHY. Every workflow now STARTS on the `encapsulated` strategy: state
 * lives entirely inside the SPA-held `wfs` token and there is ZERO server-side
 * `wf_states` row before the first validated input. Only after a step validates
 * input does it call `swapStrategy("store")` to move onto the durable
 * DB-backed `AsWfStore`. This kills the old failure mode: a user who idled on
 * the login form then submitted got 410-GONE because the server-side row had
 * been evicted / a restart had dropped it. With the encapsulated start there is
 * no row to lose.
 *
 * The `wfs` token is `<strategyName>.<rawToken>`, so its prefix
 * (`encapsulated.` vs `store.`) reveals the active strategy. The trigger writes
 * the token to the response BODY as `wfs` (token config `{ write: "body",
 * name: "wfs" }`), so we read it straight off the `/auth/trigger` response.
 *
 * Boot the demo with `DEMO_MODE=test SEED=true pnpm dev` (BASE_URL defaults to
 * http://localhost:3001 in playwright.config.ts).
 */
import type { Page } from "@playwright/test";
import { expect, test } from "@playwright/test";

import {
  fillField,
  readFinishEnvelope,
  resetApp,
  submitForm,
  totp,
  USERS,
  waitForFormInput,
  wfUrl,
} from "./harness";

const LOGIN_WF = "auth/login/flow";

test.beforeEach(async ({ request }) => {
  await resetApp(request);
});

/**
 * Capture the `wfs` token from the trigger response produced by `action`. The
 * trigger writes the token to the response body top-level as `wfs`
 * (provider token config `{ write: "body", name: "wfs" }`), so a single field
 * read is enough — the prefix before the first `.` is the strategy name.
 */
async function triggerToken(page: Page, action: () => Promise<void>): Promise<string> {
  const [resp] = await Promise.all([
    page.waitForResponse(
      (r) => r.url().includes("/auth/trigger") && r.request().method() === "POST",
    ),
    action(),
  ]);
  const body = (await resp.json()) as { wfs?: string };
  return body.wfs ?? "";
}

/** Read `{ count }` off `GET /__test/wf-states/count`. */
async function wfStatesCount(
  request: import("@playwright/test").APIRequestContext,
): Promise<number> {
  const res = await request.get("/__test/wf-states/count");
  expect(res.status(), "wf-states/count endpoint mounted (run with DEMO_MODE=test)").toBe(200);
  return ((await res.json()) as { count: number }).count;
}

test.describe("LoginWorkflow / state strategy", () => {
  /**
   * WF-STRATEGY-ENCAP-START. The pre-validation phase is serverless: starting
   * the login wf (the SPA fires a `/auth/trigger` start on mount to fetch the
   * credentials form) issues an `encapsulated.`-prefixed token and persists NO
   * `wf_states` row. WHY: the root cause of the idle 410-GONE bug is that the
   * server held a losable row before the user proved any intent — the
   * encapsulated start removes that row entirely.
   */
  test("WF-STRATEGY-ENCAP-START: login starts encapsulated with zero server rows", async ({
    page,
    request,
  }) => {
    // Known-zero baseline regardless of reset ordering.
    const del = await request.delete("/__test/wf-states");
    expect(del.ok(), "wf-states truncate endpoint returns 2xx").toBe(true);

    // The SPA starts the wf on mount; the first /auth/trigger POST returns the
    // credentials form + the START token.
    const token = await triggerToken(page, async () => {
      await page.goto(wfUrl(LOGIN_WF, "minimal"));
    });

    expect(token, "trigger response carries the wfs token in the body").not.toBe("");
    expect(token.startsWith("encapsulated."), `token strategy prefix: ${token.split(".")[0]}`).toBe(
      true,
    );

    // No durable row was written for the pre-validation form fetch.
    expect(await wfStatesCount(request)).toBe(0);
  });

  /**
   * WF-STRATEGY-IDLE-SURVIVES-WIPE (the headline fix). A user reaches the login
   * form, idles, and meanwhile the `wf_states` table is wiped (row evicted /
   * server restarted). They then submit valid credentials and the login still
   * FINISHES with tokens — NOT a 410. WHY: the encapsulated state rode inside
   * the `wfs` token, so a wiped server store is irrelevant to resuming the
   * pre-validation phase. This is the exact regression the encapsulated-start
   * change was built to prevent — if the start ever reverts to a server-backed
   * strategy, the wipe below strands the user and this test fails.
   *
   * Reuses USERS.alice on variant `minimal` — the same MFA-disabled,
   * finishes-on-password-alone path as WF-LOGIN-001.
   */
  test("WF-STRATEGY-IDLE-SURVIVES-WIPE: idle login survives a wf_states wipe and still issues tokens", async ({
    page,
    request,
  }) => {
    await page.goto(wfUrl(LOGIN_WF, "minimal"));
    await waitForFormInput(page, "username");

    // Simulate the row being evicted / the server restarting while idle.
    const del = await request.delete("/__test/wf-states");
    expect(del.ok(), "wf-states truncate endpoint returns 2xx").toBe(true);

    await fillField(page, "username", USERS.alice.username);
    await fillField(page, "password", USERS.alice.password);
    await submitForm(page);

    // The login must FINISH with tokens — the wiped store didn't matter because
    // the pre-validation state was in the token.
    await expect(page.getByText("Workflow finished")).toBeVisible({ timeout: 15_000 });
    const envelope = (await readFinishEnvelope(page)) as {
      finished?: boolean;
      data?: { accessToken?: string };
    };
    expect(typeof envelope.data?.accessToken, "login survived the wipe and issued a token").toBe(
      "string",
    );
    expect((envelope.data?.accessToken ?? "").length).toBeGreaterThan(0);
  });

  /**
   * WF-STRATEGY-SWAP-TO-STORE. Once the user proves intent (valid credentials),
   * the workflow pauses on the MFA code prompt — and that pause is now durable:
   * the credentials submit's trigger response carries a `store.`-prefixed token
   * and a `wf_states` row exists. WHY: state becomes durable AND inspectable
   * exactly when it must survive a real cross-request wait (the user fetching
   * their TOTP code), proving the `swapStrategy("store")` fired end-to-end on
   * first validated input.
   *
   * Reuses USERS.grace on variant `mfa-totp` — the single-confirmed-TOTP user
   * that WF-LOGIN-008 / -013 drive: credentials validate, the flow pauses on
   * `MfaCodeForm` (the `code` input).
   */
  test("WF-STRATEGY-SWAP-TO-STORE: validated credentials swap to the durable store and persist a row", async ({
    page,
    request,
  }) => {
    const del = await request.delete("/__test/wf-states");
    expect(del.ok(), "wf-states truncate endpoint returns 2xx").toBe(true);

    await page.goto(wfUrl(LOGIN_WF, "mfa-totp"));
    await waitForFormInput(page, "username");
    await fillField(page, "username", USERS.grace.username);
    await fillField(page, "password", USERS.grace.password);

    // Capture the token from the CREDENTIALS submit — the response returns the
    // next form (the MFA code prompt) and the post-swap token.
    const token = await triggerToken(page, async () => {
      await page.getByRole("button", { name: "Sign in", exact: true }).click();
    });

    // The pause landed on MfaCodeForm (proves credentials validated, not an
    // error response).
    await waitForFormInput(page, "code");

    expect(token, "credentials-submit trigger response carries the wfs token").not.toBe("");
    expect(token.startsWith("store."), `token strategy prefix: ${token.split(".")[0]}`).toBe(true);

    // The post-validation pause persisted a durable row.
    expect(await wfStatesCount(request)).toBeGreaterThanOrEqual(1);
  });
});

test.describe("MFA enrollment / TOTP QR", () => {
  /**
   * WF-STRATEGY-TOTP-QR-RENDERS. Driving the forced-TOTP enrollment to
   * `EnrollConfirmForm` (required mode + single transport `totp` → auto-pick,
   * mirrors WF-LOGIN-033) must render a SCANNABLE QR plus the manual-entry
   * secret — not the raw `otpauth://` URI string. WHY: TOTP setup is only
   * usable if the user can either scan the QR or hand-type the base32 secret;
   * a regression that drops the `AsQrCode` render (or leaves the provisioned
   * `enrollSecret` / URI empty) would leave a blank field and break enrollment.
   *
   * AsQrCode DOM (from @atscript/vue-aooth as-qr-code component):
   *   - `.as-qr-code`        — AsFieldShell wrapper (field-class)
   *   - `.as-qr-code-stack`  — present only once a URI is bound
   *   - `.as-qr-code-svg`    — holds the rendered QR as inline <svg> (innerHTML)
   *   - `.as-qr-code-secret` — the base32 secret for manual entry
   *
   * Reuses USERS.alice on variant `mfa-enroll-required-totp` with a
   * `reset-mfa` clear — the exact setup WF-LOGIN-033 uses.
   */
  test("WF-STRATEGY-TOTP-QR-RENDERS: enrollment shows a scannable QR + manual secret", async ({
    page,
    request,
  }) => {
    // Clean 0-method user so the required-MFA policy force-enrols (mirror -033).
    const cleared = await request.post(`/__test/reset-mfa/${USERS.alice.username}`);
    expect(cleared.status()).toBe(201);

    await page.goto(wfUrl(LOGIN_WF, "mfa-enroll-required-totp"));
    await fillField(page, "username", USERS.alice.username);
    await fillField(page, "password", USERS.alice.password);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();

    // Auto-pick (single transport) lands straight on EnrollConfirmForm — `code`
    // is its signature field.
    await waitForFormInput(page, "code");

    // The QR component rendered its root + the per-URI stack.
    const qrRoot = page.locator(".as-qr-code").first();
    await expect(qrRoot).toBeVisible();
    await expect(qrRoot.locator(".as-qr-code-stack")).toBeVisible();

    // It drew an actual QR: the qrcode lib emits inline <svg> into .as-qr-code-svg.
    await expect(qrRoot.locator(".as-qr-code-svg svg")).toBeVisible();

    // And the manual-entry secret is shown and non-empty.
    const secretEl = qrRoot.locator(".as-qr-code-secret");
    await expect(secretEl).toBeVisible();
    const secretText = ((await secretEl.textContent()) ?? "").trim();
    expect(secretText.length, "manual-entry base32 secret is non-empty").toBeGreaterThan(0);

    // Cross-check: the manual secret equals the server-provisioned (unconfirmed)
    // TOTP method value, and computing a code against it confirms enrollment —
    // pins that the QR/secret render the REAL provisioned secret, not a stale
    // placeholder.
    const userRes = await request.get(`/__test/user/${USERS.alice.username}`);
    expect(userRes.status()).toBe(200);
    const userRec = (await userRes.json()) as {
      mfa: { methods: Array<{ name: string; confirmed: boolean; value: string }> };
    };
    const totpRow = userRec.mfa.methods.find((m) => m.name === "totp");
    expect(totpRow, "auto-pick provisioned an unconfirmed totp method").toBeDefined();
    expect(totpRow!.confirmed).toBe(false);
    expect(secretText, "rendered manual secret matches the provisioned secret").toBe(
      totpRow!.value,
    );

    await fillField(page, "code", totp(totpRow!.value));
    await submitForm(page);
    const envelope = (await readFinishEnvelope(page)) as { data?: { accessToken?: string } };
    expect(typeof envelope.data?.accessToken).toBe("string");
    expect((envelope.data?.accessToken ?? "").length).toBeGreaterThan(0);
  });
});
