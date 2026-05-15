import { afterEach, beforeEach, describe, expect, it } from "vite-plus/test";

import { buildTestApp, dbFindOne, loginAndFetch, type TestApp } from "./harness";

interface UserRow {
  id: string;
  username?: string;
  email?: string;
  roles?: string[];
  tenantId?: string;
  secretNotes?: string;
}

interface TaskRow {
  id: string;
  tenantId: string;
  projectId: string;
  title: string;
  status: string;
  creatorUsername: string;
  assigneeUsername?: string;
  priority?: "low" | "medium" | "high";
  internalNotes?: string;
}

describe("WRITE — write-side enforcement (fresh app per test)", () => {
  let app: TestApp;

  beforeEach(async () => {
    app = await buildTestApp();
  });
  afterEach(async () => {
    await app.close();
  });

  it("WRITE-01 — admin's `users.update` allowedFields filters out `roles`; email survives", async () => {
    const bobId = app.fixtures.users.t1_bob.id;
    const before = (await dbFindOne(app, "users", { id: bobId })) as UserRow;
    expect(before.roles).toEqual(["member"]);

    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_dave);
    const patch = await fetch("/users", {
      method: "PATCH",
      json: { id: bobId, email: "newbob@acme.test", roles: ["admin"] },
    });
    expect([200, 202]).toContain(patch.status);

    const after = (await dbFindOne(app, "users", { id: bobId })) as UserRow;
    expect(after.email).toBe("newbob@acme.test");
    // `roles` is NOT in WRITEABLE_USER_FIELDS_ADMIN; the field is stripped by
    // applyAllowedFieldsAndSet before the SQL UPDATE — bob remains a member.
    expect(after.roles).toEqual(["member"]);
  });

  it("WRITE-02/03 — member's `tasks.new` forces tenantId/creatorUsername/assigneeUsername to caller (set wins over body)", async () => {
    const tenantA = app.fixtures.tenants["tenant-a"];
    const tenantB = app.fixtures.tenants["tenant-b"];

    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_grace);
    // The action's @InputForm(NewTaskForm) schema only declares
    // {projectId, title, description?, assigneeUsername?, priority?, dueDate?}.
    // Forcing `tenantId`/`creatorUsername` happens via scope.set on top of the
    // body's allowed keys; we only need to assign someone ELSE in the body
    // and check `set` overrides it.
    const res = await fetch("/tasks/actions/new", {
      method: "POST",
      json: {
        input: {
          projectId: app.fixtures.projects["proj-a-1"],
          title: "WRITE-02 grace-new",
          assigneeUsername: "t1_dave",
        },
      },
    });
    expect([200, 201]).toContain(res.status);
    const insertedId = ((await res.json()) as { insertedId: string }).insertedId;

    const row = (await dbFindOne(app, "tasks", { id: insertedId })) as TaskRow;
    expect(row.tenantId).toBe(tenantA);
    expect(row.creatorUsername).toBe("t1_grace");
    expect(row.assigneeUsername).toBe("t1_grace");
    // Member's `tasks.new` set also pins status to "open".
    expect(row.status).toBe("open");
    expect(row.tenantId).not.toBe(tenantB);
  });

  it("WRITE-04 — PUT /users (replace) honors the same allowedFields whitelist", async () => {
    const bobId = app.fixtures.users.t1_bob.id;
    const before = (await dbFindOne(app, "users", { id: bobId })) as UserRow;

    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_dave);
    const put = await fetch("/users", {
      method: "PUT",
      json: {
        id: bobId,
        username: before.username,
        email: "replaced@acme.test",
        // Try to escalate via PUT — must be filtered out.
        roles: ["admin", "superadmin"],
        tenantId: before.tenantId,
        secretNotes: "via PUT",
      },
    });
    // The request may 200/202 (replace succeeds with allowed fields) or 400
    // (.as validator rejects the partial replacement payload that lacks the
    // required nested credential blobs after stripping). Either is acceptable
    // for the purpose of THIS story; only the "no role escalation" bit is
    // load-bearing.
    const after = (await dbFindOne(app, "users", { id: bobId })) as UserRow;
    if (put.status >= 200 && put.status < 300) {
      expect(after.roles).toEqual(["member"]);
    } else {
      expect(put.status).toBeGreaterThanOrEqual(400);
      expect(put.status).toBeLessThan(500);
      // No partial mutation: the row is unchanged.
      expect(after.roles).toEqual(["member"]);
    }
  });

  it("WRITE-05 — bare POST /tasks (insert) accepts a single record per ARBAC scope (admin)", async () => {
    // Admin's `tasks.insert` rule has no `set` and no `allowedFields`, so the
    // body is honored as-is (still gated by the global ARBAC guard for the
    // insert action). Verifies the bare-insert path round-trips through
    // `onWrite("insert", data)` → `applyAllowedFieldsAndSet` without losing
    // schema-valid fields.
    const tenantA = app.fixtures.tenants["tenant-a"];
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_dave);
    const single = await fetch("/tasks", {
      method: "POST",
      json: {
        tenantId: tenantA,
        projectId: app.fixtures.projects["proj-a-1"],
        title: "WRITE-05 single",
        creatorUsername: "t1_dave",
        status: "open",
        priority: "high",
      },
    });
    expect([200, 201]).toContain(single.status);
    const singleId = ((await single.json()) as { insertedId: string }).insertedId;
    const r1 = (await dbFindOne(app, "tasks", { id: singleId })) as TaskRow;
    expect(r1.title).toBe("WRITE-05 single");
    expect(r1.priority).toBe("high");
  });

  it("WRITE-06 — denied write returns 403 with body that names the resource and action", async () => {
    // t1_alice is `[member, viewer]` — neither role grants `users.update`.
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_alice);
    const res = await fetch("/users", {
      method: "PATCH",
      json: { id: app.fixtures.users.t1_bob.id, email: "evil@x" },
    });
    expect(res.status).toBe(403);
    const text = (await res.text()).toLowerCase();
    // arbacAuthorizeInterceptor's message:
    //   `Insufficient privileges for action "${action}" on resource "${resource}"`
    expect(text).toContain("users");
    expect(text).toContain("update");
  });

  it("WRITE-07 — auto-set fields cannot be unset by a `null` in the body (set wins)", async () => {
    const tenantA = app.fixtures.tenants["tenant-a"];
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_grace);
    const res = await fetch("/tasks/actions/new", {
      method: "POST",
      json: {
        input: {
          projectId: app.fixtures.projects["proj-a-1"],
          title: "WRITE-07 grace-null-tenant",
          tenantId: null,
          creatorUsername: null,
          assigneeUsername: null,
        },
      },
    });
    expect([200, 201]).toContain(res.status);
    const insertedId = ((await res.json()) as { insertedId: string }).insertedId;

    const row = (await dbFindOne(app, "tasks", { id: insertedId })) as TaskRow;
    expect(row.tenantId).toBe(tenantA);
    expect(row.creatorUsername).toBe("t1_grace");
    expect(row.assigneeUsername).toBe("t1_grace");
  });
});
