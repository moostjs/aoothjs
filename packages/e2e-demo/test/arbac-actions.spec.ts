import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { buildTestApp, dbFindOne, dbUpdateOne, loginAndFetch, type TestApp } from "./harness";

interface TaskRow {
  id: string;
  status: "open" | "in_progress" | "done";
  title: string;
  tenantId: string;
  assigneeUsername?: string;
  creatorUsername?: string;
}

/** Stub credential blobs used when seeding throw-away users via POST /users. */
function stubUserCreds(): Record<string, unknown> {
  return {
    password: { hash: "x", history: [], lastChanged: 0, isInitial: false },
    account: {
      active: true,
      locked: false,
      lockReason: "",
      lockEnds: 0,
      failedLoginAttempts: 0,
      lastLogin: 0,
    },
    mfa: { methods: [], defaultMethod: "", autoSend: false },
  };
}

describe("ACT — read-mostly per-action gating", () => {
  let app: TestApp;

  beforeAll(async () => {
    app = await buildTestApp();
  });
  afterAll(async () => {
    await app.close();
  });

  it("ACT-01 — viewer can read tasks (query/meta) but every write/delete → 403", async () => {
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_eve);

    expect((await fetch("/tasks/query")).status).toBe(200);
    expect((await fetch("/tasks/meta")).status).toBe(200);

    const post = await fetch("/tasks", {
      method: "POST",
      json: {
        tenantId: "x",
        projectId: app.fixtures.projects["proj-a-1"],
        title: "x",
        creatorUsername: "t1_eve",
        status: "open",
      },
    });
    expect(post.status).toBe(403);

    const tA = app.fixtures.tasks.tenantA[0];
    const patch = await fetch("/tasks", {
      method: "PATCH",
      json: { id: tA, title: "ACT-01 viewer-cannot-write" },
    });
    expect(patch.status).toBe(403);

    const put = await fetch("/tasks", {
      method: "PUT",
      json: {
        id: tA,
        tenantId: app.fixtures.tenants["tenant-a"],
        projectId: app.fixtures.projects["proj-a-1"],
        title: "x",
        creatorUsername: "t1_eve",
        status: "open",
      },
    });
    expect(put.status).toBe(403);

    const del = await fetch(`/tasks/${tA}`, { method: "DELETE" });
    expect(del.status).toBe(403);
  });

  it("ACT-04 — @ArbacPublic does NOT bypass auth-moost auth guard (no token → 401)", async () => {
    // /health/protected is decorated @ArbacPublic() ONLY (no @Public()). The
    // ARBAC interceptor short-circuits, but auth-moost's bearer guard still
    // demands a token.
    expect((await app.fetch("/health/protected")).status).toBe(401);

    const badAuth = await app.fetch("/health/protected", {
      headers: { Authorization: "Bearer not-a-real-jwt" },
    });
    expect(badAuth.status).toBe(401);

    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_eve);
    expect((await fetch("/health/protected")).status).toBe(200);
  });

  it("ACT-06 — `tasks.one` covers both /tasks/one/:id and /tasks/one?... (normalizeAutoCrudMethod)", async () => {
    // Tasks have no secondary unique index, so the composite-key route on
    // /tasks/one isn't exercisable for that resource. We instead use /users
    // (where `username` is `@db.index.unique`) to verify both the
    // primary-key path (`getOne`) and the composite-key path
    // (`getOneComposite`) collapse to the same ARBAC action `one`. Eve
    // (viewer) holds `users.one`; both routes must succeed.
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_eve);

    const targetId = app.fixtures.users.t1_dave.id;
    const byId = await fetch(`/users/one/${targetId}`);
    expect(byId.status).toBe(200);

    const byUsername = await fetch("/users/one?username=t1_dave");
    expect(byUsername.status).toBe(200);
    const row = (await byUsername.json()) as { id: string; username: string };
    expect(row.id).toBe(targetId);
  });

  it("ACT-07 — `users.remove` covers both DELETE /users/:id and DELETE /users?...", async () => {
    // Same parallel as ACT-06 but for delete. Tasks lack a secondary unique
    // index for `removeComposite`, so we again exercise /users. Only
    // superadmin holds `users.remove`; both DELETE shapes must reach the
    // table. Use rows we create on the fly so we don't perturb seeded users
    // referenced by other tests.
    const { fetch: supFetch } = await loginAndFetch(app, app.fixtures.users._super);
    const tenantA = app.fixtures.tenants["tenant-a"];

    const ins1 = await supFetch("/users", {
      method: "POST",
      json: {
        username: "act07_byid",
        email: "act07_byid@x.test",
        tenantId: tenantA,
        roles: ["guest"],
        ...stubUserCreds(),
      },
    });
    expect([200, 201]).toContain(ins1.status);
    const id1 = ((await ins1.json()) as { insertedId: string }).insertedId;

    const ins2 = await supFetch("/users", {
      method: "POST",
      json: {
        username: "act07_bycomposite",
        email: "act07_bycomposite@x.test",
        tenantId: tenantA,
        roles: ["guest"],
        ...stubUserCreds(),
      },
    });
    expect([200, 201]).toContain(ins2.status);

    // Primary-key DELETE — JS method `remove` → ARBAC action `remove`.
    const byId = await supFetch(`/users/${id1}`, { method: "DELETE" });
    expect([200, 202, 204]).toContain(byId.status);

    // Composite-key DELETE — JS method `removeComposite` → normalized to `remove`.
    const byComposite = await supFetch("/users?username=act07_bycomposite", { method: "DELETE" });
    expect([200, 202, 204]).toContain(byComposite.status);

    expect(await dbFindOne(app, "users", { id: id1 })).toBeFalsy();
    expect(await dbFindOne(app, "users", { username: "act07_bycomposite" })).toBeFalsy();
  });
});

describe("ACT — mutating per-action gating (fresh app per test)", () => {
  let app: TestApp;

  beforeEach(async () => {
    app = await buildTestApp();
  });
  afterEach(async () => {
    await app.close();
  });

  it("ACT-02 — member can `tasks.markDone` (200) but NOT `tasks.delete` (403)", async () => {
    // t1_grace is a member; first 5 tenant-A tasks are seeded with
    // assigneeUsername = "t1_bob". Grace's member scope on `markDone` is
    // `assigneeUsername = self`, so reassign one of those tasks to grace first.
    const taskId = app.fixtures.tasks.tenantA[0];
    await dbUpdateOne(app, "tasks", { id: taskId, assigneeUsername: "t1_grace" });

    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_grace);

    // markDone is `'row'`-level (uses `@DbActionID()` — single id, NOT array).
    // The action body envelope is `{ ids: { id: ... } }` for row-level.
    const markDone = await fetch("/tasks/actions/markDone", {
      method: "POST",
      json: { ids: { id: taskId } },
    });
    expect([200, 201, 202]).toContain(markDone.status);

    const after = (await dbFindOne(app, "tasks", { id: taskId })) as TaskRow;
    expect(after.status).toBe("done");

    const del = await fetch("/tasks/actions/delete", {
      method: "POST",
      json: { ids: { id: taskId } },
    });
    expect(del.status).toBe(403);
  });

  it("ACT-03 — action key is the @DbAction arg, not the JS method name (`newTask` → `tasks.new`)", async () => {
    // The handler is `newTask()` decorated `@DbAction("new", ...)`. Member's
    // privilege grants `tasks.new` (the @DbAction arg), NOT `tasks.newTask`.
    // A 200 response proves `atscript_db_action.name` wins over the JS method
    // name in `useArbac()`'s action resolution chain. Symmetrically,
    // `deleteTask` → `@DbAction("delete")`: admin holds `tasks.delete`, not
    // `tasks.deleteTask`.
    const { fetch: graceFetch } = await loginAndFetch(app, app.fixtures.users.t1_grace);
    const newRes = await graceFetch("/tasks/actions/new", {
      method: "POST",
      json: {
        input: {
          projectId: app.fixtures.projects["proj-a-1"],
          title: "ACT-03 grace-newTask",
        },
      },
    });
    expect([200, 201]).toContain(newRes.status);

    const insertedId = ((await newRes.json()) as { insertedId: string }).insertedId;
    const { fetch: daveFetch } = await loginAndFetch(app, app.fixtures.users.t1_dave);
    const delRes = await daveFetch("/tasks/actions/delete", {
      method: "POST",
      json: { ids: { id: insertedId } },
    });
    expect([200, 201, 202]).toContain(delRes.status);
  });

  it("ACT-05 — `disabled: perRow` predicate blocks markDone on already-done tasks (rejects, no mutation)", async () => {
    // Pre-condition: assign a tenantA task to grace and mark it done.
    const taskId = app.fixtures.tasks.tenantA[0];
    await dbUpdateOne(app, "tasks", { id: taskId, assigneeUsername: "t1_grace" });
    await dbUpdateOne(app, "tasks", { id: taskId, status: "done" });

    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_grace);
    const res = await fetch("/tasks/actions/markDone", {
      method: "POST",
      json: { ids: { id: taskId } },
    });
    // moost-db's onDisabledRows defaults to "reject" → 4xx (typically 400).
    // The exact status code (400 vs 422) is moost-db's choice; assert non-success only.
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);

    const row = (await dbFindOne(app, "tasks", { id: taskId })) as TaskRow;
    expect(row.status).toBe("done");
  });
});
