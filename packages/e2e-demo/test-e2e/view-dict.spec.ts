import { expect, test } from "@playwright/test";

import { bearerAuth, mintToken, resetApp } from "./harness";

/**
 * Regression: a `@db.view` bound through the WRITABLE ARBAC controller chain
 * (`TaskDictController` = `@ReadableController(TaskDict)` over
 * `AsArbacDbController`). moost-db's `.table` getter throws for view-bound
 * controllers, so before the arbac-moost fix every read-side override that
 * touched `this.table` turned into HTTP 500:
 *   - `/meta` (applyMetaOverlay → metaAlwaysVisibleFields)
 *   - any filter/$select referencing a field (hasField → validateInsights)
 *
 * `t1_eve` is a pure viewer — the role grants tenant-scoped read on
 * `task-dict` (roles/viewer.ts) with no projection mask.
 */
test.describe("VIEW-DICT: view-bound ARBAC controller read surface", () => {
  // Every test here is a pure read, so one reset + one token serves the whole
  // suite (lazy because the `request` fixture is test-scoped). workers=1 keeps
  // this race-free.
  let eveToken: string | undefined;
  async function viewerToken(request: Parameters<typeof mintToken>[0]): Promise<string> {
    if (!eveToken) {
      await resetApp(request);
      eveToken = await mintToken(request, "t1_eve");
    }
    return eveToken;
  }

  test("VIEW-DICT-001: GET /task-dict/meta returns 200 with the view's field surface", async ({
    request,
  }) => {
    const token = await viewerToken(request);
    const res = await request.get("/task-dict/meta", { headers: bearerAuth(token) });
    expect(res.status()).toBe(200);
    const meta = (await res.json()) as {
      fields: Record<string, { filterable?: boolean }>;
      primaryKeys: string[];
    };
    expect(Object.keys(meta.fields)).toEqual(
      expect.arrayContaining(["id", "tenantId", "title", "status"]),
    );
    expect(meta.primaryKeys).toEqual(["id"]);
  });

  test("VIEW-DICT-002: query with filter + $select works (hasField goes through the readable)", async ({
    request,
  }) => {
    const token = await viewerToken(request);
    const res = await request.get("/task-dict/query?status='open'&$select=id,title", {
      headers: bearerAuth(token),
    });
    expect(res.status()).toBe(200);
    const rows = (await res.json()) as Array<{ id: string; title: string }>;
    expect(Array.isArray(rows)).toBe(true);
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      expect(typeof row.id).toBe("string");
      expect(typeof row.title).toBe("string");
    }
  });

  test("VIEW-DICT-003: unknown-field filter is a clean 400, not the .table view-guard 500", async ({
    request,
  }) => {
    const token = await viewerToken(request);
    const res = await request.get("/task-dict/query?nosuchfield='x'", {
      headers: bearerAuth(token),
    });
    expect(res.status()).toBe(400);
  });

  test("VIEW-DICT-004: tenant scope filter still applies on the view", async ({ request }) => {
    // Seed creates tasks in BOTH tenants; eve's viewer scope is tenant-filtered,
    // so her dict rows must collapse to a single tenantId.
    const eve = await viewerToken(request);
    const res = await request.get("/task-dict/query", { headers: bearerAuth(eve) });
    expect(res.status()).toBe(200);
    const rows = (await res.json()) as Array<{ tenantId: string }>;
    expect(rows.length).toBeGreaterThan(0);
    expect(new Set(rows.map((r) => r.tenantId)).size).toBe(1);
  });
});
