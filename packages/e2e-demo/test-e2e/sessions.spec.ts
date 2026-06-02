import { expect, test } from "@playwright/test";

import {
  fillField,
  loginViaUi,
  resetApp,
  submitForm,
  USERS,
  waitForFormInput,
  wfUrl,
} from "./harness";

// WHY: the "Active sessions" panel is the consumer-of-record feature this whole
// change exists for. These tests pin its three load-bearing guarantees against
// the REAL stack (atscript-db credential store, ARBAC-gated SessionsController):
//   1. listSessions collapses each login (access+refresh family) into ONE row,
//      carries the captured IP/UA metadata, and flags exactly the caller's own
//      session as `current`.
//   2. revokeSession kills exactly one device's family — others keep working.
//   3. revokeOtherSessions (?others=true) leaves only the caller's current
//      session, logging out every other device.
//
// Two sessions for one user are created by logging the same user in from two
// independent browser contexts (separate cookie jars = separate token families).
// API calls ride `page.request`, which shares the page's authenticated cookie jar.

interface SessionRow {
  sessionId: string;
  userId: string;
  createdAt: number;
  expiresAt: number;
  lastSeenAt?: number;
  current?: boolean;
  metadata?: { ip?: string; userAgent?: string };
}

test.describe("Active sessions (auth.sessions)", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("AS-001: lists one row per device with metadata + current flag", async ({
    page,
    browser,
  }) => {
    await loginViaUi(page, USERS.alice); // session 1 (this context)

    const ctx2 = await browser.newContext();
    const page2 = await ctx2.newPage();
    await loginViaUi(page2, USERS.alice); // session 2 (other device)

    const res = await page.request.get("/auth/sessions");
    expect(res.ok()).toBe(true);
    const sessions = (await res.json()) as SessionRow[];

    // Two logins = two sessions (access+refresh of each collapsed into one row).
    expect(sessions).toHaveLength(2);
    // Exactly one is the caller's current session.
    expect(sessions.filter((s) => s.current)).toHaveLength(1);
    // Login-time metadata (User-Agent) was captured and surfaced.
    const current = sessions.find((s) => s.current);
    expect(typeof current?.metadata?.userAgent).toBe("string");
    expect((current?.metadata?.userAgent ?? "").length).toBeGreaterThan(0);

    await ctx2.close();
  });

  test("AS-002: revoke a single session kills only that device", async ({ page, browser }) => {
    await loginViaUi(page, USERS.alice);
    const ctx2 = await browser.newContext();
    const page2 = await ctx2.newPage();
    await loginViaUi(page2, USERS.alice);

    const before = (await (await page.request.get("/auth/sessions")).json()) as SessionRow[];
    const other = before.find((s) => !s.current);
    expect(other).toBeTruthy();

    const del = await page.request.delete(`/auth/sessions/${other!.sessionId}`);
    expect(del.ok()).toBe(true);

    // The revoked device can no longer authenticate…
    const status2 = await page2.request.get("/auth/status");
    expect(status2.status()).toBe(401);
    // …while the caller's own session keeps working, now the only row.
    const after = (await (await page.request.get("/auth/sessions")).json()) as SessionRow[];
    expect(after).toHaveLength(1);
    expect(after[0].current).toBe(true);

    await ctx2.close();
  });

  test("AS-003: ?others=true logs out everywhere else, keeping current", async ({
    page,
    browser,
  }) => {
    await loginViaUi(page, USERS.alice);
    const ctx2 = await browser.newContext();
    const page2 = await ctx2.newPage();
    await loginViaUi(page2, USERS.alice);
    const ctx3 = await browser.newContext();
    const page3 = await ctx3.newPage();
    await loginViaUi(page3, USERS.alice);

    const del = await page.request.delete("/auth/sessions?others=true");
    expect(del.ok()).toBe(true);
    expect((await del.json()) as { revoked: number }).toEqual({ revoked: 2 });

    // Only the caller's current session survives.
    const after = (await (await page.request.get("/auth/sessions")).json()) as SessionRow[];
    expect(after).toHaveLength(1);
    expect(after[0].current).toBe(true);
    // Both other devices are logged out.
    expect((await page2.request.get("/auth/status")).status()).toBe(401);
    expect((await page3.request.get("/auth/status")).status()).toBe(401);

    await ctx2.close();
    await ctx3.close();
  });

  test("AS-004: a bare DELETE (no ?others) is rejected — that's what logout is for", async ({
    page,
  }) => {
    await loginViaUi(page, USERS.alice);
    const res = await page.request.delete("/auth/sessions");
    expect(res.status()).toBe(400);
  });

  test("AS-005: anonymous access to /auth/sessions is rejected (401)", async ({ request }) => {
    const res = await request.get("/auth/sessions");
    expect(res.status()).toBe(401);
  });

  test("AS-007: logout ends THIS device's whole family (refresh included), not just cookies", async ({
    page,
    browser,
  }) => {
    // The #2 footgun: the httpOnly refresh cookie lives on `/auth/refresh` and
    // is NOT sent to `/auth/logout`, so logout sees no refresh token. Pre-fix
    // the refresh credential lingered for its full TTL and the "logged-out"
    // session kept appearing in listSessions. Family-aware logout revokes the
    // whole family by sessionId.
    await loginViaUi(page, USERS.alice); // device A (will log out)
    const ctx2 = await browser.newContext();
    const page2 = await ctx2.newPage();
    await loginViaUi(page2, USERS.alice); // device B (independent observer)

    const before = (await (await page2.request.get("/auth/sessions")).json()) as SessionRow[];
    expect(before).toHaveLength(2);

    // Device A logs out with an empty body — and the refresh cookie's narrow
    // path keeps it off `/auth/logout`. Exactly the SPA case.
    const out = await page.request.post("/auth/logout", { data: {} });
    expect(out.ok()).toBe(true);

    // Device A is fully signed out.
    expect((await page.request.get("/auth/status")).status()).toBe(401);

    // Device B (separate cookie jar) now sees ONLY its own session — device A's
    // whole family, the lingering refresh included, is gone from listSessions.
    const after = (await (await page2.request.get("/auth/sessions")).json()) as SessionRow[];
    expect(after).toHaveLength(1);
    expect(after[0].current).toBe(true);

    await ctx2.close();
  });

  test("AS-006: changing password revokes OTHER sessions but keeps the current device", async ({
    page,
    browser,
  }) => {
    // B4: the shared revoke-sessions step runs revokeOtherSessions(current) for
    // change-password (vs revokeAllForUser for recovery), so the device that
    // changed the password stays signed in while every other device is kicked.
    await loginViaUi(page, USERS.alice); // current device
    const ctx2 = await browser.newContext();
    const page2 = await ctx2.newPage();
    await loginViaUi(page2, USERS.alice); // other device

    await page.goto(wfUrl("auth/change-password/flow"));
    await waitForFormInput(page, "currentPassword");
    await fillField(page, "currentPassword", USERS.alice.password);
    await fillField(page, "newPassword", "BrandNew2!Pass");
    await fillField(page, "confirmPassword", "BrandNew2!Pass");
    await submitForm(page);
    await expect(page.locator("text=Workflow finished")).toBeVisible({ timeout: 5000 });

    // The other device is logged out…
    expect((await page2.request.get("/auth/status")).status()).toBe(401);
    // …and the current device is still authenticated (token rotated in place).
    expect((await page.request.get("/auth/status")).status()).toBe(200);

    await ctx2.close();
  });
});
