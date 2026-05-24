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

describe("UNION-05 — wildcard action deny short-circuits granular allows", () => {
  let app: TestApp;

  beforeEach(async () => {
    app = await buildTestApp();
    // Grace is a `member`: member grants `tasks.markDone` with
    // `scope.filter = { tenantId, assigneeUsername: self }` AND
    // `tasks.new` with `scope.set` that auto-assigns the new row to self.
    // Layer `tasks-write-denied` (a SINGLE `.deny("tasks", "*")` rule) on
    // top so the union becomes [member, tasks-write-denied].
    await dbUpdateOne(app, "users", {
      username: "t1_grace",
      roles: ["member", "tasks-write-denied"],
    });
    // Pre-load: reassign tenantA[0] to grace so her member-scope allow on
    // `tasks.markDone` WOULD match the row. The deny must beat the allow
    // even though the row-level filter is satisfied.
    const taskId = app.fixtures.tasks.tenantA[0];
    await dbUpdateOne(app, "tasks", { id: taskId, assigneeUsername: "t1_grace" });
  });
  afterEach(async () => {
    await app.close();
  });

  it("UNION-05 — wildcard `.deny('tasks', '*')` 403s both markDone (row-allow exists) and new (set-allow exists)", async () => {
    // Pins arbac-core's binary-deny contract: `deny` matches via
    // `_actionRegex.test(action)` and returns `{ allowed: false }`
    // BEFORE any scope is evaluated (arbac.ts:127-131). A future
    // regression that made deny scope-aware (allowing partial visibility)
    // would fail this test by letting grace's row-level allow on
    // markDone leak through.
    //
    // The `*` glob compiles to `[^.]*` (utils.ts:4), so ONE deny rule
    // matches MULTIPLE distinct actions — exercising the regex-matching
    // side of the contract, not just literal-string equality.
    const taskId = app.fixtures.tasks.tenantA[0];
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_grace);

    // markDone: grace's member scope.filter (assigneeUsername=self) is
    // satisfied by the pre-load — without deny, ACT-02 proves this returns 2xx.
    // With wildcard deny, the entry-gate must 403 before scope evaluation.
    const markDone = await fetch("/tasks/actions/markDone", {
      method: "POST",
      json: { ids: { id: taskId } },
    });
    expect(markDone.status).toBe(403);

    // new: grace's member scope.set would auto-assign self — without deny,
    // ACT-03 proves this returns 2xx. With wildcard deny, the SAME rule
    // (different action) must 403, proving the regex matched more than
    // just `markDone`.
    const newRes = await fetch("/tasks/actions/new", {
      method: "POST",
      json: {
        input: {
          projectId: app.fixtures.projects["proj-a-1"],
          title: "UNION-05 grace-new",
        },
      },
    });
    expect(newRes.status).toBe(403);
  });
});
