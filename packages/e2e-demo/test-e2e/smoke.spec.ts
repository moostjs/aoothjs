import { expect, test } from "@playwright/test";

/**
 * Heartbeat for the e2e infra. Proves three things at once:
 *   1. The dev server is up at BASE_URL and the SPA root renders.
 *   2. `POST /__test/reset` re-seeds the DB and returns the unified envelope.
 *   3. `GET /__test/emails` returns an empty array immediately after reset.
 *
 * If this spec fails, every other Playwright spec will fail too — fix this
 * first.
 */
test("infra heartbeat: SPA renders + __test endpoints respond", async ({ page, request }) => {
  await page.goto("/");
  // The demo SPA lists every workflow on the landing page; "Login" is the
  // most stable anchor (present in every variant config).
  await expect(page.locator("body")).toContainText("Login");

  const resetRes = await request.post("/__test/reset");
  expect(resetRes.status()).toBe(201);
  const resetBody = (await resetRes.json()) as { ok: boolean; seeded: number };
  expect(resetBody.ok).toBe(true);
  expect(resetBody.seeded).toBeGreaterThan(0);

  const emailsRes = await request.get("/__test/emails");
  expect(emailsRes.status()).toBe(200);
  expect(await emailsRes.json()).toEqual([]);
});
