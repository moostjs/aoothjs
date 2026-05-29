/**
 * Playwright coverage for the failed-login lockout POSTURE (`resolveLockout`
 * → three `AuthWfLockoutMode`s). The lockout MECHANISM (threshold counter,
 * permanent vs timed lock, auto-expiry) has vitest coverage in `@aooth/user`;
 * these specs pin the workflow-level policy end-to-end through the SPA:
 *
 *   - admin-only   → tripping the threshold locks PERMANENTLY (lockEnds === 0)
 *                    and completing recovery resets the password but DOES NOT
 *                    lift the lock (the account stays frozen — admin only).
 *   - self-service → locks permanently too, but completing recovery runs the
 *                    `unlock-account` step, so login works again afterward.
 *   - temporary    → locks with a TIMED expiry (lockEnds > 0) and recovery
 *                    does not lift it early (it auto-expires).
 *
 * The admin-only vs self-service split is the load-bearing behavioral
 * difference (recovery-unlocks-or-not); temporary is distinguished from the
 * two permanent modes by lockEnds > 0 (asserted via `/__test/user`, so we
 * never wait out a real timeout).
 *
 * The demo seeds `LOCKOUT_THRESHOLD=3`, so three wrong passwords trip the
 * lock. Each wrong submit is serialized on its `/auth/trigger` POST response
 * because the inline "Invalid credentials" banner is sticky across re-renders
 * and can't sequence the loop.
 */
import { type APIRequestContext, expect, type Page, test } from "@playwright/test";

import {
  fillField,
  readFinishEnvelope,
  resetApp,
  submitForm,
  USERS,
  waitForEmail,
  waitForFormInput,
  wfUrl,
} from "./harness";

const LOGIN_WF = "auth/login/flow";
const RECOVERY_WF = "auth/recovery/flow";
const ALICE_EMAIL = "alice@acme.test";
const NEW_PASSWORD = "Relocked1!A";

type AccountRec = { account: { locked: boolean; lockEnds: number } };

async function readAccount(request: APIRequestContext, username: string): Promise<AccountRec> {
  const res = await request.get(`/__test/user/${username}`);
  expect(res.status()).toBe(200);
  return (await res.json()) as AccountRec;
}

/** Trip the lockout: submit `threshold` (3) wrong passwords, serialized. */
async function tripLockout(page: Page, variant: string): Promise<void> {
  await page.goto(wfUrl(LOGIN_WF, variant));
  for (let i = 1; i <= 3; i++) {
    await fillField(page, "username", USERS.alice.username);
    await fillField(page, "password", "definitely-wrong");
    await Promise.all([
      page.waitForResponse(
        (r) => r.url().includes("/auth/trigger") && r.request().method() === "POST",
      ),
      page.getByRole("button", { name: "Sign in", exact: true }).click(),
    ]);
  }
}

/** Drive alice through recovery to NEW_PASSWORD under `variant`. */
async function resetViaRecovery(
  page: Page,
  request: APIRequestContext,
  variant: string,
): Promise<void> {
  await page.goto(wfUrl(RECOVERY_WF, variant));
  await waitForFormInput(page, "email", 15_000);
  await fillField(page, "email", ALICE_EMAIL);
  await submitForm(page);

  const email = await waitForEmail(request, (e) => e.kind === "recovery.pincode");
  await waitForFormInput(page, "code", 15_000);
  await fillField(page, "code", email.code as string);
  await submitForm(page);

  await waitForFormInput(page, "newPassword", 15_000);
  await fillField(page, "newPassword", NEW_PASSWORD);
  await fillField(page, "confirmPassword", NEW_PASSWORD);
  await submitForm(page);
  await expect(page.getByText("Workflow finished.")).toBeVisible({ timeout: 15_000 });
}

test.describe("Lockout posture (resolveLockout modes)", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  // admin-only: permanent lock; recovery resets the password but the account
  // stays frozen until an admin lifts it. A regression that ran unlock-account
  // for this mode (or downgraded the lock to timed) would silently turn an
  // admin-freeze into a self-service one.
  test("WF-LOGIN-LOCKOUT-ADMIN-ONLY: threshold → permanent lock; recovery resets password but stays locked", async ({
    page,
    request,
  }) => {
    await tripLockout(page, "lockout-admin-only");

    const locked = await readAccount(request, USERS.alice.username);
    expect(locked.account.locked, "3 wrong passwords trip the lock").toBe(true);
    expect(locked.account.lockEnds, "admin-only is permanent → lockEnds 0").toBe(0);

    // Recovery succeeds (the lock never gates recovery) and resets the password…
    await resetViaRecovery(page, request, "lockout-admin-only");

    // …but the account is STILL locked — admin-only does not self-service unlock.
    const after = await readAccount(request, USERS.alice.username);
    expect(after.account.locked, "admin-only: recovery must NOT unlock").toBe(true);

    // And a login with the freshly-reset password is still refused.
    await page.goto(wfUrl(LOGIN_WF, "lockout-admin-only"));
    await fillField(page, "username", USERS.alice.username);
    await fillField(page, "password", NEW_PASSWORD);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(page.getByText("Account locked, please try again later")).toBeVisible();
  });

  // self-service: permanent lock, but completing recovery runs unlock-account,
  // so login works again. This is the mode the user asked for ("recovery flow
  // kicks in to unlock").
  test("WF-LOGIN-LOCKOUT-SELF-SERVICE: threshold → permanent lock; recovery unlocks and login works again", async ({
    page,
    request,
  }) => {
    await tripLockout(page, "lockout-self-service");

    const locked = await readAccount(request, USERS.alice.username);
    expect(locked.account.locked).toBe(true);
    expect(locked.account.lockEnds, "self-service is permanent → lockEnds 0").toBe(0);

    await resetViaRecovery(page, request, "lockout-self-service");

    // unlock-account fired: the account is no longer locked.
    const after = await readAccount(request, USERS.alice.username);
    expect(after.account.locked, "self-service: recovery lifts the lock").toBe(false);

    // End-to-end proof: login with the reset password now issues tokens.
    await page.goto(wfUrl(LOGIN_WF, "lockout-self-service"));
    await fillField(page, "username", USERS.alice.username);
    await fillField(page, "password", NEW_PASSWORD);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    const envelope = (await readFinishEnvelope(page)) as { data?: { accessToken?: string } };
    expect(typeof envelope.data?.accessToken).toBe("string");
    expect((envelope.data?.accessToken ?? "").length).toBeGreaterThan(0);
  });

  // temporary: the lock is TIMED (lockEnds in the future), not permanent — the
  // mode override is absent so UserService's configured duration applies. This
  // is what distinguishes temporary from the two permanent modes without
  // waiting out the real timeout.
  test("WF-LOGIN-LOCKOUT-TEMPORARY: threshold → timed lock (lockEnds in the future, auto-expires)", async ({
    page,
    request,
  }) => {
    const before = Date.now();
    await tripLockout(page, "lockout-temporary");

    const locked = await readAccount(request, USERS.alice.username);
    expect(locked.account.locked).toBe(true);
    // lockEnds > 0 AND in the future ⇒ timed (not the permanent `0` of the
    // admin-only / self-service modes).
    expect(locked.account.lockEnds, "temporary → timed lock, not permanent").toBeGreaterThan(
      before,
    );
  });
});
