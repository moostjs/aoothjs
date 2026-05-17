import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { buildTestApp, dbUpdateOne, loginAndFetch, type TestApp } from "./harness";

interface ProjectRow {
  id: string;
  tenantId: string;
  visibility: "public" | "team" | "private";
  ownerUsername: string;
}

interface UserRow {
  id: string;
  username: string;
  email?: string;
  departmentId?: string;
  password?: unknown;
  mfa?: unknown;
  account?: unknown;
  secretNotes?: unknown;
}

describe("UNION — multi-role scope union", () => {
  let app: TestApp;

  beforeAll(async () => {
    app = await buildTestApp();
  });
  afterAll(async () => {
    await app.close();
  });

  it("UNION-01 — two scoped roles broaden filter (alice member+viewer on /projects)", async () => {
    const tenantA = app.fixtures.tenants["tenant-a"];
    const tenantB = app.fixtures.tenants["tenant-b"];
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_alice);
    const res = await fetch("/projects/query");
    expect(res.status).toBe(200);
    const rows = (await res.json()) as ProjectRow[];

    for (const r of rows) expect(r.tenantId).not.toBe(tenantB);

    const ids = new Set(rows.map((r) => r.id));
    // viewer broadens beyond member: viewer sees all tenant-A non-private,
    // member adds owned-by-self anywhere. Net for alice in tenant A:
    // proj-a-1 (public), proj-a-2 (team), proj-a-4 (team), proj-a-5 (public, alice-owned).
    expect(ids.has(app.fixtures.projects["proj-a-1"])).toBe(true);
    expect(ids.has(app.fixtures.projects["proj-a-2"])).toBe(true);
    expect(ids.has(app.fixtures.projects["proj-a-4"])).toBe(true);
    expect(ids.has(app.fixtures.projects["proj-a-5"])).toBe(true);
    expect(ids.has(app.fixtures.projects["proj-a-3"])).toBe(false);

    const aliceOwned = rows.filter((r) => r.ownerUsername === "t1_alice");
    expect(aliceOwned.length).toBeGreaterThan(0);
    for (const r of aliceOwned) expect(r.tenantId).toBe(tenantA);
  });

  it("UNION-02 — two scoped roles broaden field projection (member ∪ viewer on /users)", async () => {
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_alice);
    const res = await fetch("/users/query");
    expect(res.status).toBe(200);
    const rows = (await res.json()) as UserRow[];
    expect(rows.length).toBeGreaterThan(0);

    let sawEmail = false;
    for (const r of rows) {
      expect(r.id).toBeTruthy();
      expect(r.username).toBeTruthy();
      expect(r.password).toBeUndefined();
      expect(r.mfa).toBeUndefined();
      expect(r.account).toBeUndefined();
      expect(r.secretNotes).toBeUndefined();
      if (r.email !== undefined) sawEmail = true;
    }
    // Member's projection includes `email`; viewer's omits it. Union must
    // surface email on at least one row that has one in the seed.
    expect(sawEmail).toBe(true);
  });
});

describe("UNION-03 — explicit deny short-circuits union", () => {
  let app: TestApp;

  beforeEach(async () => {
    app = await buildTestApp();
    // alice already holds [member, viewer], both of which allow comments.query.
    // Layer commentsDeniedRole on top via dbUpdateOne (mirrors UNION-04's
    // pattern) so the union becomes [member, viewer, comments-denied].
    await dbUpdateOne(app, "users", {
      username: "t1_alice",
      roles: ["member", "viewer", "comments-denied"],
    });
  });
  afterEach(async () => {
    await app.close();
  });

  it("UNION-03 — comments-denied beats member+viewer allows on /comments/query", async () => {
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_alice);
    const res = await fetch("/comments/query");
    // SPEC: a deny rule for (comments, query) short-circuits the additive
    // union — even though member AND viewer each allow the same action,
    // any deny on the (resource, action) tuple wins.
    expect(res.status).toBe(403);
  });
});

describe("UNION-04 — superadmin overlapped with viewer", () => {
  let app: TestApp;

  beforeEach(async () => {
    app = await buildTestApp();
    await dbUpdateOne(app, "users", { username: "_super", roles: ["superadmin", "viewer"] });
  });
  afterEach(async () => {
    await app.close();
  });

  it("UNION-04 — superadmin + viewer still sees all tenants", async () => {
    const { fetch } = await loginAndFetch(app, app.fixtures.users._super);
    const res = await fetch("/tasks/query");
    expect(res.status).toBe(200);
    const rows = (await res.json()) as Array<{ tenantId: string }>;
    const tenantIds = new Set(rows.map((r) => r.tenantId));
    // SPEC: no-scope `allow` is universe; under multi-role union universe must
    // beat any scoped filter.
    expect(tenantIds.has(app.fixtures.tenants["tenant-a"])).toBe(true);
    expect(tenantIds.has(app.fixtures.tenants["tenant-b"])).toBe(true);
    expect(rows.length).toBe(app.fixtures.tasks.tenantA.length + app.fixtures.tasks.tenantB.length);
  });
});
