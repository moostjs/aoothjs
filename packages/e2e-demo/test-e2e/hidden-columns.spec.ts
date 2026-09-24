import { expect, test } from "@playwright/test";

import { bearerAuth, lazySuiteTokens } from "./harness";

/**
 * A scope projection hides a column from every query position, not just from
 * row payloads. `t1_eve` (viewer) reads `/tasks` under PROJ_TASK_VIEWER
 * (`internalNotes: 0`); seeded tasks 0 and 10 carry a confidential memo there.
 * Filtering or sorting on the hidden column must answer exactly like a column
 * that does not exist — with @atscript/moost-db 0.1.128–0.1.132 these requests
 * returned 200 and matched on the hidden values (a value oracle).
 * `t1_dave` (admin, no projection) keeps full use of the column.
 */
test.describe("HIDDEN-COL: projection-scoped columns are unknown fields in queries", () => {
  // Pure reads — one reset + lazily minted tokens serve the whole suite.
  const tokenFor = lazySuiteTokens();

  for (const query of [
    "internalNotes='Confidential project memo'",
    "internalNotes~=/^Conf/",
    "$exists=internalNotes",
    "(status='open'^internalNotes!='x')",
    "$sort=internalNotes",
  ]) {
    test(`HIDDEN-COL-001: viewer ?${query} → 400 Unknown field`, async ({ request }) => {
      const token = await tokenFor(request, "t1_eve");
      const res = await request.get(`/tasks/query?${query}`, { headers: bearerAuth(token) });
      expect(res.status()).toBe(400);
      expect(await res.json()).toMatchObject({ message: 'Unknown field "internalNotes"' });
    });
  }

  test("HIDDEN-COL-002: the hidden column answers like a nonexistent one", async ({ request }) => {
    const token = await tokenFor(request, "t1_eve");
    const hidden = await request.get("/tasks/query?internalNotes='x'", {
      headers: bearerAuth(token),
    });
    const missing = await request.get("/tasks/query?noSuchColumn='x'", {
      headers: bearerAuth(token),
    });
    expect(hidden.status()).toBe(400);
    expect(JSON.stringify(await hidden.json()).replaceAll("internalNotes", "noSuchColumn")).toBe(
      JSON.stringify(await missing.json()),
    );
  });

  test("HIDDEN-COL-003: visible columns still filter and sort for the viewer", async ({
    request,
  }) => {
    const token = await tokenFor(request, "t1_eve");
    const res = await request.get("/tasks/query?status!='x'&$sort=title", {
      headers: bearerAuth(token),
    });
    expect(res.status()).toBe(200);
    const rows = (await res.json()) as Array<Record<string, unknown>>;
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) expect(row).not.toHaveProperty("internalNotes");
  });

  test("HIDDEN-COL-004: an unscoped admin filters and sorts on the column", async ({ request }) => {
    const token = await tokenFor(request, "t1_dave");
    const res = await request.get(
      "/tasks/query?internalNotes='Confidential project memo'&$sort=internalNotes",
      { headers: bearerAuth(token) },
    );
    expect(res.status()).toBe(200);
    const rows = (await res.json()) as Array<{ internalNotes?: string }>;
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) expect(row.internalNotes).toBe("Confidential project memo");
  });
});
