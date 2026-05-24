import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { buildTestApp, dbFindOne, expectAllInTenant, loginAndFetch, type TestApp } from "./harness";

interface TaskRow {
  id: string;
  tenantId: string;
  title: string;
  internalNotes?: string;
}

describe("ISO — read-only tenant isolation", () => {
  let app: TestApp;

  beforeAll(async () => {
    app = await buildTestApp();
  });
  afterAll(async () => {
    await app.close();
  });

  it("ISO-01 — list scoped to caller's tenant (alice → A; oscar → B)", async () => {
    const tenantA = app.fixtures.tenants["tenant-a"];
    const tenantB = app.fixtures.tenants["tenant-b"];

    const { fetch: aliceFetch } = await loginAndFetch(app, app.fixtures.users.t1_alice);
    const aRes = await aliceFetch("/tasks/query");
    expect(aRes.status).toBe(200);
    const aRows = (await aRes.json()) as TaskRow[];
    expect(aRows.length).toBeGreaterThan(0);
    expectAllInTenant(aRows, tenantA);

    const { fetch: oscarFetch } = await loginAndFetch(app, app.fixtures.users.t2_oscar);
    const bRes = await oscarFetch("/tasks/query");
    expect(bRes.status).toBe(200);
    const bRows = (await bRes.json()) as TaskRow[];
    expect(bRows.length).toBeGreaterThan(0);
    expectAllInTenant(bRows, tenantB);
  });

  it("ISO-02 — single-record fetch across tenant returns 404", async () => {
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_alice);
    const tB = app.fixtures.tasks.tenantB[0];
    const res = await fetch(`/tasks/one/${tB}`);
    expect(res.status).toBe(404);
  });

  it("ISO-03 — composite-key /one fetch scope-gated (cross-tenant id → 404)", async () => {
    // The seed's document model does not declare a composite unique index, so
    // we exercise the same `getOneComposite` route via the primary-key form
    // (`?id=<id>`). This still goes through `transformOne` (the scope filter),
    // which is what ISO-03 verifies.
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_alice);
    const docB = app.fixtures.documents.tenantB[0];
    const res = await fetch(`/documents/one?id=${docB}`);
    expect(res.status).toBe(404);
  });

  it("ISO-04 — pagination count respects scope (alice sees only tenant-A tasks)", async () => {
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_alice);
    const cnt = await fetch("/tasks/query?$count=true");
    expect(cnt.status).toBe(200);
    const total = (await cnt.json()) as number;
    expect(total).toBe(app.fixtures.tasks.tenantA.length);

    const pages = await fetch("/tasks/pages");
    expect(pages.status).toBe(200);
    const pBody = (await pages.json()) as { count: number; data: TaskRow[] };
    expect(pBody.count).toBe(app.fixtures.tasks.tenantA.length);
    expectAllInTenant(pBody.data, app.fixtures.tenants["tenant-a"]);
  });

  it("ISO-08 — superadmin sees rows from every tenant", async () => {
    const { fetch } = await loginAndFetch(app, app.fixtures.users._super);
    const res = await fetch("/tasks/query");
    expect(res.status).toBe(200);
    const rows = (await res.json()) as TaskRow[];
    const tenantIds = new Set(rows.map((r) => r.tenantId));
    expect(tenantIds.has(app.fixtures.tenants["tenant-a"])).toBe(true);
    expect(tenantIds.has(app.fixtures.tenants["tenant-b"])).toBe(true);
    expect(rows.length).toBe(app.fixtures.tasks.tenantA.length + app.fixtures.tasks.tenantB.length);
  });
});

describe("ISO — write isolation (mutations; isolated app per test)", () => {
  let app: TestApp;

  beforeAll(async () => {
    app = await buildTestApp();
  });
  afterAll(async () => {
    await app.close();
  });

  it("ISO-05 — PATCH cross-tenant by id MUST NOT modify (scope ANDed with body.id)", async () => {
    const tenantB = app.fixtures.tenants["tenant-b"];
    const tB = app.fixtures.tasks.tenantB[0];

    const before = (await dbFindOne(app, "tasks", { id: tB })) as TaskRow;
    expect(before.tenantId).toBe(tenantB);
    const originalTitle = before.title;

    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_dave);
    const res = await fetch("/tasks", {
      method: "PATCH",
      json: { id: tB, title: "ISO-05-pwned" },
    });

    const after = (await dbFindOne(app, "tasks", { id: tB })) as TaskRow;

    // SPEC: scope filter is ANDed with body.id; tenant-A admin cannot touch
    // tenant-B rows. The PATCH is rejected with 404 (out of scope).
    expect(res.status).toBe(404);
    expect(after.tenantId).toBe(tenantB);
    expect(after.title).toBe(originalTitle);
  });

  it("ISO-06 — DELETE cross-tenant by id MUST NOT delete (scope gates delete)", async () => {
    const tB = app.fixtures.tasks.tenantB[1];

    const before = await dbFindOne(app, "tasks", { id: tB });
    expect(before).toBeTruthy();

    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_dave);
    const res = await fetch(`/tasks/${tB}`, { method: "DELETE" });

    // SPEC: scope gates delete by tenant. Out-of-scope id rejected with 404.
    expect(res.status).toBe(404);
    const after = await dbFindOne(app, "tasks", { id: tB });
    expect(after).toBeTruthy();
  });

  it("ISO-07a — actions/new ignores body.tenantId; scope.set forces caller's tenant", async () => {
    const tenantA = app.fixtures.tenants["tenant-a"];
    const tenantB = app.fixtures.tenants["tenant-b"];
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_alice);

    const res = await fetch("/tasks/actions/new", {
      method: "POST",
      json: {
        input: {
          projectId: app.fixtures.projects["proj-a-1"],
          title: "ISO-07a alice-new",
          tenantId: tenantB,
        },
      },
    });
    expect([200, 201]).toContain(res.status);
    const body = (await res.json()) as { insertedId: string };
    const row = (await dbFindOne(app, "tasks", { id: body.insertedId })) as TaskRow;
    expect(row.tenantId).toBe(tenantA);
  });

  it("ISO-07b — bare POST /tasks ignores body.tenantId; scope.set forces caller's tenant", async () => {
    const tenantA = app.fixtures.tenants["tenant-a"];
    const tenantB = app.fixtures.tenants["tenant-b"];
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_dave);

    const res = await fetch("/tasks", {
      method: "POST",
      json: {
        projectId: app.fixtures.projects["proj-a-1"],
        title: "ISO-07b dave-bare",
        creatorUsername: "t1_dave",
        status: "open",
        tenantId: tenantB,
      },
    });
    expect([200, 201]).toContain(res.status);
    const body = (await res.json()) as { insertedId: string };
    const row = (await dbFindOne(app, "tasks", { id: body.insertedId })) as TaskRow;
    expect(row.tenantId).toBe(tenantA);
  });
});

// Without a filter-bound count, an attacker can infer cross-tenant table size
// by polling `$count=true` while side-channel events (e.g. a teammate's signup
// in another tenant) inflate the global count. Filter-bounded count must be
// invariant to inserts outside the caller's scope. Fresh app per test so the
// adversarial tenant-B inserts don't leak into the shared read-only suite.
describe("ISO — count is filter-bounded (adversarial cross-tenant inserts)", () => {
  let app: TestApp;

  beforeEach(async () => {
    app = await buildTestApp();
  });
  afterEach(async () => {
    await app.close();
  });

  it("ISO-04b — $count=true is filter-bounded, not table-bounded (adversarial cross-tenant inserts must not change alice's count)", async () => {
    const tenantB = app.fixtures.tenants["tenant-b"];
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_alice);

    const cntBefore = await fetch("/tasks/query?$count=true");
    expect(cntBefore.status).toBe(200);
    const before = (await cntBefore.json()) as number;
    // Pins the existing ISO-04 invariant — alice's count starts at her scope size.
    expect(before).toBe(app.fixtures.tasks.tenantA.length);

    // Adversarial inserts: tenant-B rows added DIRECTLY to the DB (bypassing
    // Moost/ARBAC, mirroring an out-of-band side channel like a signup).
    // Direct DB insert (option 2) is chosen over a superadmin POST so the
    // test measures table growth against alice's count without routing
    // through any scope/filter HTTP layer that could mask the leak.
    const tasksTbl = app.appHandle.appDb.tables.tasks as unknown as {
      insertOne: (row: Record<string, unknown>) => Promise<{ insertedId: string }>;
    };
    const decoyTitles = ["ISO-04b decoy 1", "ISO-04b decoy 2", "ISO-04b decoy 3"];
    const projectB = app.fixtures.projects["proj-b-1"];
    for (const title of decoyTitles) {
      await tasksTbl.insertOne({
        tenantId: tenantB,
        projectId: projectB,
        title,
        creatorUsername: "_decoy",
        status: "open",
      });
    }

    // Confirm a decoy actually landed in tenant-B — otherwise the
    // `after === before` assertion below would trivially pass for the wrong
    // reason (e.g. insertOne silently no-op'd). One check covers it; insertOne
    // resolving without throwing covers the rest.
    const landed = (await dbFindOne(app, "tasks", { title: decoyTitles[0] })) as TaskRow | null;
    expect(landed?.tenantId).toBe(tenantB);

    const cntAfter = await fetch("/tasks/query?$count=true");
    expect(cntAfter.status).toBe(200);
    const after = (await cntAfter.json()) as number;

    // Load-bearing: alice's count MUST NOT observe the 3 cross-tenant inserts.
    expect(after).toBe(before);
  });
});
