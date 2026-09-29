import { type APIRequestContext, expect, test } from "@playwright/test";

import { bearerAuth as auth, mintToken, resetApp } from "./harness";

/**
 * ARBAC DB-controller hardening, end to end against the demo's real tables
 * (SQLite, real auth guard + ARBAC interceptor + AsArbacDbController):
 *
 * - action ids obey the action's scope (no IDOR through `@DbAction*`);
 * - WITH CHECK: a written row must still match the write scope's filter —
 *   403 + rollback, never a silent move out of scope;
 * - nested writes through nav props are refused unless the scope opts in;
 * - `checkRefs`: a task's `projectId` must name a project the caller can read;
 * - a tenant admin assigns only tenant roles (never `superadmin`);
 * - `$with` on an undeclared relation obeys the caller's OWN read policy on
 *   the related table (no grant → 400 Unknown relation);
 * - `/meta/form/:name` requires an action that renders the form;
 * - DB controllers fail closed: no grant → 403 (not `200 []`), and `@Public()`
 *   does not open them.
 *
 * Cast (seed.ts): tenant A — t1_dave admin (eng), t1_carol manager+viewer
 * (ops), t1_bob member (eng), t1_eve viewer, t1_frank guest; tenant B —
 * t2_olivia admin. Tasks inherit their project's department (proj-a-2 is ops).
 */

type Row = Record<string, unknown> & { id: string };

async function json<T>(res: { json(): Promise<unknown> }): Promise<T> {
  return (await res.json()) as T;
}

/** GET as `token`, asserting 200, returning the parsed rows. */
async function rows(request: APIRequestContext, token: string, url: string): Promise<Row[]> {
  const res = await request.get(url, { headers: auth(token) });
  expect(res.status(), `GET ${url}`).toBe(200);
  return json<Row[]>(res);
}

async function departmentIds(
  request: APIRequestContext,
  adminToken: string,
): Promise<{ eng: string; ops: string }> {
  const depts = await rows(request, adminToken, "/departments/query?$select=id,name");
  const byName = (name: string) => depts.find((d) => d.name === name)!.id;
  return { eng: byName("Engineering"), ops: byName("Operations") };
}

/** A tenant-A task in `departmentId`, read through the admin (full tenant view). */
async function taskIn(
  request: APIRequestContext,
  adminToken: string,
  departmentId: string,
  extra = "",
): Promise<Row> {
  const found = await rows(
    request,
    adminToken,
    `/tasks/query?departmentId='${departmentId}'${extra}&$select=id,title,status,projectId,assigneeUsername,departmentId&$limit=1`,
  );
  expect(found.length).toBe(1);
  return found[0];
}

async function adminReadTask(
  request: APIRequestContext,
  adminToken: string,
  id: string,
): Promise<Row> {
  const res = await request.get(`/tasks/one/${id}`, { headers: auth(adminToken) });
  expect(res.status()).toBe(200);
  return json<Row>(res);
}

test.describe("ARBAC-HARD: DB-controller hardening (actions, WITH CHECK, nested, $with, forms, fail-closed)", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  // ── Action IDOR ──────────────────────────────────────────────────────────

  test("ARBAC-HARD-001: another tenant's admin cannot run row actions on a task (404 like a missing id, no mutation)", async ({
    request,
  }) => {
    const dave = await mintToken(request, "t1_dave");
    const olivia = await mintToken(request, "t2_olivia");
    const { eng } = await departmentIds(request, dave);
    const victim = await taskIn(request, dave, eng, "&status='open'");

    const missing = await request.post("/tasks/actions/markDone", {
      headers: auth(olivia),
      data: { ids: { id: "00000000-0000-4000-8000-000000000000" } },
    });
    expect(missing.status()).toBe(404);
    const missingBody = await missing.json();

    for (const [action, input] of [
      ["markDone", undefined],
      ["markInProgress", undefined],
      ["archive", undefined],
      ["assign", { assigneeUsername: "t2_olivia" }],
      ["delete", undefined],
    ] as const) {
      const res = await request.post(`/tasks/actions/${action}`, {
        headers: auth(olivia),
        data: { ids: { id: victim.id }, ...(input && { input }) },
      });
      expect(res.status(), action).toBe(404);
      // Indistinguishable from a nonexistent id — no existence oracle.
      expect(await res.json(), action).toEqual(missingBody);
    }

    const after = await adminReadTask(request, dave, victim.id);
    expect(after.status).toBe("open");
    expect(after.assigneeUsername).toBe(victim.assigneeUsername);
  });

  test("ARBAC-HARD-002: cross-tenant CRUD by id — one / PATCH / DELETE all 404, row untouched", async ({
    request,
  }) => {
    const dave = await mintToken(request, "t1_dave");
    const olivia = await mintToken(request, "t2_olivia");
    const { eng } = await departmentIds(request, dave);
    const victim = await taskIn(request, dave, eng);

    expect((await request.get(`/tasks/one/${victim.id}`, { headers: auth(olivia) })).status()).toBe(
      404,
    );
    const patch = await request.patch("/tasks", {
      headers: auth(olivia),
      data: { id: victim.id, title: "pwned" },
    });
    expect(patch.status()).toBe(404);
    const del = await request.delete(`/tasks/${victim.id}`, { headers: auth(olivia) });
    expect(del.status()).toBe(404);

    expect((await adminReadTask(request, dave, victim.id)).title).toBe(victim.title);
  });

  test("ARBAC-HARD-003: a manager's row actions reach only own-department tasks", async ({
    request,
  }) => {
    const dave = await mintToken(request, "t1_dave");
    const carol = await mintToken(request, "t1_carol"); // manager, ops
    const { eng, ops } = await departmentIds(request, dave);
    const foreign = await taskIn(request, dave, eng, "&status='open'");
    const own = await taskIn(request, dave, ops, "&status='open'");

    // Readable (tenant-wide read) but not actionable: same 404 as a missing row.
    const denied = await request.post("/tasks/actions/markDone", {
      headers: auth(carol),
      data: { ids: { id: foreign.id } },
    });
    expect(denied.status()).toBe(404);
    expect((await adminReadTask(request, dave, foreign.id)).status).toBe("open");

    const allowed = await request.post("/tasks/actions/markDone", {
      headers: auth(carol),
      data: { ids: { id: own.id } },
    });
    expect(allowed.status()).toBe(201);
    expect((await adminReadTask(request, dave, own.id)).status).toBe("done");
  });

  test("ARBAC-HARD-005: $actions and GET /meta/actions/:id follow each action's own scope", async ({
    request,
  }) => {
    const dave = await mintToken(request, "t1_dave");
    const carol = await mintToken(request, "t1_carol"); // manager, ops: tenant read, ops actions
    const eve = await mintToken(request, "t1_eve"); // viewer: reads only, no task actions
    const olivia = await mintToken(request, "t2_olivia");
    const { eng, ops } = await departmentIds(request, dave);
    const foreign = await taskIn(request, dave, eng, "&status='open'");
    const own = await taskIn(request, dave, ops, "&status='open'");

    // $actions: readable tenant-wide, but markDone is offered on own-department rows only.
    const listed = await rows(
      request,
      carol,
      "/tasks/query?status='open'&$actions=true&$select=id,departmentId",
    );
    const actionsOf = (id: string) =>
      (listed.find((r) => r.id === id)?.$actions as string[] | undefined) ?? [];
    expect(actionsOf(own.id)).toContain("markDone");
    expect(actionsOf(foreign.id)).not.toContain("markDone");
    for (const r of listed) {
      expect((r.$actions as string[] | undefined) ?? [], String(r.departmentId)).toEqual(
        r.departmentId === ops ? expect.arrayContaining(["markDone"]) : [],
      );
    }

    // The per-row route: same answer, no row data; out-of-scope ≡ missing.
    const route = async (token: string, id: string) =>
      request.get(`/tasks/meta/actions/${id}`, { headers: auth(token) });
    const mine = await route(carol, own.id);
    expect(mine.status()).toBe(200);
    expect((await json<{ actions: string[] }>(mine)).actions).toContain("markDone");
    const theirs = await route(carol, foreign.id);
    const missing = await route(carol, "00000000-0000-4000-8000-000000000000");
    expect(theirs.status()).toBe(200);
    expect(await theirs.json()).toEqual({ actions: [] });
    expect(await missing.json()).toEqual({ actions: [] });
    // Another tenant's admin: nothing on tenant A's rows.
    expect(await (await route(olivia, own.id)).json()).toEqual({ actions: [] });
    // No row-level action grant at all → 403 (a read grant is not enough).
    expect((await route(eve, own.id)).status()).toBe(403);
  });

  test("ARBAC-HARD-004: an action the caller holds no grant on is 403 before any id lookup", async ({
    request,
  }) => {
    const dave = await mintToken(request, "t1_dave");
    const eve = await mintToken(request, "t1_eve"); // viewer: reads only, no task actions
    const { eng } = await departmentIds(request, dave);
    const task = await taskIn(request, dave, eng, "&status='open'");

    for (const id of [task.id, "00000000-0000-4000-8000-000000000000"]) {
      const res = await request.post("/tasks/actions/markDone", {
        headers: auth(eve),
        data: { ids: { id } },
      });
      // Same 403 for an existing and a missing id — no existence oracle.
      expect(res.status(), id).toBe(403);
    }
    const create = await request.post("/tasks/actions/new", {
      headers: auth(eve),
      data: { input: { projectId: task.projectId, title: "hard-004" } },
    });
    expect(create.status()).toBe(403);
    expect((await adminReadTask(request, dave, task.id)).status).toBe("open");
    expect(await rows(request, dave, "/tasks/query?title='hard-004'")).toEqual([]);
  });

  // ── WITH CHECK ───────────────────────────────────────────────────────────

  test("ARBAC-HARD-010: a manager cannot PATCH a task out of their department (403, rolled back)", async ({
    request,
  }) => {
    const dave = await mintToken(request, "t1_dave");
    const carol = await mintToken(request, "t1_carol");
    const { eng, ops } = await departmentIds(request, dave);
    const own = await taskIn(request, dave, ops);

    // In-scope edit works.
    const ok = await request.patch("/tasks", {
      headers: auth(carol),
      data: { id: own.id, title: "renamed in ops" },
    });
    expect(ok.status()).toBe(202);

    // Moving it out — alone, or together with another change — is refused and
    // the WHOLE update is rolled back (the title change does not stick either).
    for (const departmentId of [eng, null]) {
      const moved = await request.patch("/tasks", {
        headers: auth(carol),
        data: { id: own.id, departmentId, title: "moved" },
      });
      expect(moved.status(), `departmentId=${departmentId}`).toBe(403);
    }
    const after = await adminReadTask(request, dave, own.id);
    expect(after.departmentId).toBe(ops);
    expect(after.title).toBe("renamed in ops");

    // Out-of-scope rows are not even targetable (USING): 404, unchanged.
    const foreign = await taskIn(request, dave, eng);
    const res = await request.patch("/tasks", {
      headers: auth(carol),
      data: { id: foreign.id, departmentId: ops },
    });
    expect(res.status()).toBe(404);
    expect((await adminReadTask(request, dave, foreign.id)).departmentId).toBe(eng);
  });

  test("ARBAC-HARD-011: a manager's insert must land in their department (403 + nothing written otherwise)", async ({
    request,
  }) => {
    const dave = await mintToken(request, "t1_dave");
    const carol = await mintToken(request, "t1_carol");
    const { eng, ops } = await departmentIds(request, dave);
    const { projectId } = await taskIn(request, dave, ops);
    const task = (title: string, departmentId?: string) => ({
      projectId,
      title,
      creatorUsername: "t1_carol",
      status: "open",
      ...(departmentId && { departmentId }),
    });

    for (const [title, departmentId] of [
      ["hard-011 eng", eng],
      ["hard-011 none", undefined],
    ] as const) {
      const res = await request.post("/tasks", {
        headers: auth(carol),
        data: task(title, departmentId),
      });
      expect(res.status(), title).toBe(403);
    }
    // Bulk: one out-of-scope row rejects the whole batch.
    const bulk = await request.post("/tasks", {
      headers: auth(carol),
      data: [task("hard-011 bulk ops", ops), task("hard-011 bulk eng", eng)],
    });
    expect(bulk.status()).toBe(403);
    expect(await rows(request, dave, "/tasks/query?title~=/^hard-011/")).toEqual([]);

    const ok = await request.post("/tasks", {
      headers: auth(carol),
      data: task("hard-011 ops", ops),
    });
    expect(ok.status()).toBe(201);
    const written = await rows(request, dave, "/tasks/query?title~=/^hard-011/&$select=tenantId");
    expect(written.length).toBe(1);
  });

  test("ARBAC-HARD-012: the manager's 'New task' action places the task in their department", async ({
    request,
  }) => {
    const dave = await mintToken(request, "t1_dave");
    const carol = await mintToken(request, "t1_carol");
    const { ops } = await departmentIds(request, dave);
    // NewTaskForm carries no department — the scope's `set` supplies it.
    const { projectId } = await taskIn(request, dave, ops);
    const res = await request.post("/tasks/actions/new", {
      headers: auth(carol),
      data: { input: { projectId, title: "hard-012 via form" } },
    });
    expect(res.status()).toBe(201);
    const { insertedId } = await json<{ insertedId: string }>(res);
    const created = await adminReadTask(request, dave, insertedId);
    expect(created.departmentId).toBe(ops);
    expect(created.creatorUsername).toBe("t1_carol");
  });

  test("ARBAC-HARD-013: an admin cannot move a user into another tenant (403, unchanged)", async ({
    request,
  }) => {
    const dave = await mintToken(request, "t1_dave");
    const olivia = await mintToken(request, "t2_olivia");
    const [tenantB] = await rows(request, olivia, "/tenants/query?$select=id");
    const [bob] = await rows(request, dave, "/users/query?username='t1_bob'&$select=id,tenantId");

    // `tenantId` is in the admin's allowedFields — WITH CHECK is what keeps
    // the written row inside the admin's tenant.
    const res = await request.patch("/users", {
      headers: auth(dave),
      data: { id: bob.id, tenantId: tenantB.id },
    });
    expect(res.status()).toBe(403);
    const [after] = await rows(request, dave, `/users/query?id='${bob.id}'&$select=tenantId`);
    expect(after.tenantId).toBe(bob.tenantId);
  });

  test("ARBAC-HARD-014: a tenant admin assigns only tenant roles — never superadmin", async ({
    request,
  }) => {
    const dave = await mintToken(request, "t1_dave");
    const root = await mintToken(request, "_super");
    const [bob] = await rows(request, dave, "/users/query?username='t1_bob'&$select=id,roles");
    const assign = (token: string, roles: string[]) =>
      request.post("/users/actions/assignRoles", {
        headers: auth(token),
        data: { ids: { id: bob.id }, input: { roles } },
      });
    const rolesNow = async () =>
      (await rows(request, dave, `/users/query?id='${bob.id}'&$select=roles`))[0].roles;

    for (const roles of [["superadmin"], ["member", "superadmin"]]) {
      const res = await assign(dave, roles);
      expect(res.status(), roles.join()).toBe(403);
      expect(await res.json()).toMatchObject({
        message: 'Role "superadmin" cannot be assigned by your role',
      });
    }
    const unknown = await assign(dave, ["root"]);
    expect(unknown.status()).toBe(400);
    expect(await unknown.json()).toMatchObject({ message: 'Unknown role "root"' });
    expect(await rolesNow()).toEqual(bob.roles);

    // Tenant roles are assignable; the superadmin (privileged action) may assign any.
    expect((await assign(dave, ["member", "viewer"])).status()).toBe(201);
    expect(await rolesNow()).toEqual(["member", "viewer"]);
    expect((await assign(root, ["superadmin"])).status()).toBe(201);
    expect(await rolesNow()).toEqual(["superadmin"]);
  });

  test("ARBAC-HARD-015: a task's project must be one the caller can read (checkRefs → 403, nothing written)", async ({
    request,
  }) => {
    const dave = await mintToken(request, "t1_dave"); // admin, tenant A
    const carol = await mintToken(request, "t1_carol"); // manager, ops
    const bob = await mintToken(request, "t1_bob"); // member
    const olivia = await mintToken(request, "t2_olivia"); // admin, tenant B
    const { eng, ops } = await departmentIds(request, dave);
    const [foreign] = await rows(request, olivia, "/projects/query?$select=id&$limit=1");
    const [own] = await rows(request, dave, "/projects/query?name='Acme Public Site'&$select=id");
    // Private tenant-A project owned by dave: outside the member's projects read scope.
    const [secret] = await rows(request, dave, "/projects/query?name='Acme Secret Lab'&$select=id");
    const OUT = { message: 'Referenced row "projectId" is outside your scope' };
    const task = (title: string, projectId: string, departmentId = eng) => ({
      projectId,
      title,
      creatorUsername: "t1_dave",
      status: "open",
      departmentId,
    });

    // CRUD insert — single and bulk.
    const single = await request.post("/tasks", {
      headers: auth(dave),
      data: task("hard-015 foreign", foreign.id),
    });
    expect(single.status()).toBe(403);
    expect(await single.json()).toMatchObject(OUT);
    const bulk = await request.post("/tasks", {
      headers: auth(dave),
      data: [task("hard-015 bulk own", own.id), task("hard-015 bulk foreign", foreign.id)],
    });
    expect(bulk.status()).toBe(403);

    // CRUD update — only a patch touching the FK is checked.
    const victim = await taskIn(request, dave, eng);
    const moved = await request.patch("/tasks", {
      headers: auth(dave),
      data: { id: victim.id, projectId: foreign.id, title: "hard-015 moved" },
    });
    expect(moved.status()).toBe(403);
    const after = await adminReadTask(request, dave, victim.id);
    expect(after.projectId).toBe(victim.projectId);
    expect(after.title).toBe(victim.title);
    const renamed = await request.patch("/tasks", {
      headers: auth(dave),
      data: { id: victim.id, title: "renamed by 015" },
    });
    expect(renamed.status()).toBe(202);

    // The "New task" action, per role — the form's projectId is validated too.
    for (const [who, token, projectId] of [
      ["admin", dave, foreign.id],
      ["manager", carol, foreign.id],
      ["member", bob, foreign.id],
      ["member (private project)", bob, secret.id],
    ] as const) {
      const res = await request.post("/tasks/actions/new", {
        headers: auth(token),
        data: { input: { projectId, title: `hard-015 new ${who}` } },
      });
      expect(res.status(), who).toBe(403);
      expect(await res.json(), who).toMatchObject(OUT);
    }
    expect(await rows(request, dave, "/tasks/query?title~=/^hard-015/")).toEqual([]);

    // In-scope references still work.
    expect(
      (
        await request.post("/tasks", { headers: auth(dave), data: task("hard-015 own", own.id) })
      ).status(),
    ).toBe(201);
    const { projectId: opsProject } = await taskIn(request, dave, ops);
    for (const [who, token, projectId] of [
      ["admin", dave, own.id],
      ["manager", carol, opsProject],
      ["member", bob, own.id],
    ] as const) {
      const res = await request.post("/tasks/actions/new", {
        headers: auth(token),
        data: { input: { projectId, title: `hard-015 ok ${who}` } },
      });
      expect(res.status(), who).toBe(201);
    }
  });

  // ── Nested writes ────────────────────────────────────────────────────────

  test("ARBAC-HARD-020: nested writes through nav props are refused (403, nothing written)", async ({
    request,
  }) => {
    const dave = await mintToken(request, "t1_dave");
    const bob = await mintToken(request, "t1_bob");
    const { eng } = await departmentIds(request, dave);
    const [own] = await rows(
      request,
      bob,
      "/tasks/query?assigneeUsername='t1_bob'&$select=id,title&$limit=1",
    );
    const commentsBefore = (await rows(request, dave, `/comments/query?taskId='${own.id}'`)).length;

    // Member: own comment carrying a nested TO-parent patch of the task.
    const viaChild = await request.post("/comments", {
      headers: auth(bob),
      data: { taskId: own.id, body: "hard-020", task: { title: "hijacked" } },
    });
    expect(viaChild.status()).toBe(403);
    expect(await viaChild.json()).toMatchObject({
      message: 'Nested writes through "task" are not allowed',
    });

    // Admin: FROM-children through the parent, on update and on insert.
    const viaParent = await request.patch("/tasks", {
      headers: auth(dave),
      data: { id: own.id, comments: [{ body: "hard-020", authorUsername: "t1_eve" }] },
    });
    expect(viaParent.status()).toBe(403);
    const { projectId } = await taskIn(request, dave, eng);
    const insertWithChildren = await request.post("/tasks", {
      headers: auth(dave),
      data: {
        projectId,
        title: "hard-020 parent",
        creatorUsername: "t1_dave",
        status: "open",
        comments: [{ body: "hard-020", authorUsername: "t1_eve" }],
      },
    });
    expect(insertWithChildren.status()).toBe(403);

    expect((await adminReadTask(request, dave, own.id)).title).toBe(own.title);
    expect((await rows(request, dave, `/comments/query?taskId='${own.id}'`)).length).toBe(
      commentsBefore,
    );
    expect(await rows(request, dave, "/tasks/query?title='hard-020 parent'")).toEqual([]);

    // The flat write the nested one tried to smuggle is fine.
    const flat = await request.post("/comments", {
      headers: auth(bob),
      data: { taskId: own.id, body: "hard-020 flat" },
    });
    expect(flat.status()).toBe(201);
  });

  // ── $with relation policy ────────────────────────────────────────────────

  test("ARBAC-HARD-030: $with into a table the caller has no grant on → 400 Unknown relation, pruned from /meta", async ({
    request,
  }) => {
    const bob = await mintToken(request, "t1_bob"); // member: no `departments` grant
    const res = await request.get("/tasks/query?$with=department", { headers: auth(bob) });
    expect(res.status()).toBe(400);
    expect(await res.json()).toMatchObject({
      errors: [{ path: "$with", message: 'Unknown relation "department"' }],
    });

    const meta = await json<{ relations: Array<{ name: string }> }>(
      await request.get("/tasks/meta", { headers: auth(bob) }),
    );
    expect(meta.relations.map((r) => r.name)).toEqual(["comments"]);
  });

  test("ARBAC-HARD-031: with a grant on the target, $with joins rows under the caller's own policy there", async ({
    request,
  }) => {
    const carol = await mintToken(request, "t1_carol"); // manager: tenant-scoped departments read
    const joined = await rows(
      request,
      carol,
      "/tasks/query?$select=id,departmentId&$with=department&$limit=5",
    );
    expect(joined.length).toBe(5);
    const [me] = await rows(request, carol, "/users/query?username='t1_carol'&$select=tenantId");
    for (const row of joined) {
      const dept = row.department as { id: string; tenantId: string };
      expect(dept.id).toBe(row.departmentId);
      expect(dept.tenantId).toBe(me.tenantId);
    }
    const meta = await json<{ relations: Array<{ name: string }> }>(
      await request.get("/tasks/meta", { headers: auth(carol) }),
    );
    expect(meta.relations.map((r) => r.name).toSorted()).toEqual(["comments", "department"]);
  });

  test("ARBAC-HARD-032: joined rows are filtered and projected by the caller's read scope on the target", async ({
    request,
  }) => {
    const bob = await mintToken(request, "t1_bob"); // member: tasks = own (creator/assignee), no internalNotes
    const dave = await mintToken(request, "t1_dave");
    const ownTaskIds = new Set(
      (await rows(request, bob, "/tasks/query?$select=id")).map((t) => t.id),
    );
    const comments = await rows(request, bob, "/comments/query?$select=id,taskId&$with=task");
    expect(comments.length).toBeGreaterThan(0);
    let joinedCount = 0;
    let hiddenCount = 0;
    for (const c of comments) {
      const task = c.task as Row | null;
      if (ownTaskIds.has(c.taskId as string)) {
        joinedCount++;
        expect(task?.id).toBe(c.taskId);
        expect(task).not.toHaveProperty("internalNotes");
      } else {
        hiddenCount++;
        expect(task).toBeNull();
      }
    }
    expect(joinedCount).toBeGreaterThan(0);
    expect(hiddenCount).toBeGreaterThan(0);

    // The seeded memo exists on a task bob can join — only the projection hides it.
    const memo = await rows(
      request,
      dave,
      "/tasks/query?internalNotes='Confidential project memo'&$select=id",
    );
    expect(memo.some((t) => ownTaskIds.has(t.id))).toBe(true);
  });

  test("ARBAC-HARD-033: a declared `with.<rel>` sub-scope governs the join (viewer tasks → comments)", async ({
    request,
  }) => {
    const eve = await mintToken(request, "t1_eve");
    const [task] = await rows(request, eve, "/tasks/query?$select=id&$with=comments&$limit=1");
    const comments = task.comments as Row[];
    expect(comments.length).toBeGreaterThan(0);
    for (const c of comments) expect(c).not.toHaveProperty("tenantId");
    // Relations outside the viewer's `$with` whitelist stay gated (403, controls).
    const res = await request.get("/tasks/query?$with=department", { headers: auth(eve) });
    expect(res.status()).toBe(403);
  });

  // ── Form schema ──────────────────────────────────────────────────────────

  test("ARBAC-HARD-040: /meta/form/:name requires an action rendering the form", async ({
    request,
  }) => {
    const eve = await mintToken(request, "t1_eve"); // read-only
    const bob = await mintToken(request, "t1_bob"); // `new` only
    const carol = await mintToken(request, "t1_carol"); // `new` + `assign`
    const frank = await mintToken(request, "t1_frank"); // no tasks grant
    const form = (token: string, name: string) =>
      request.get(`/tasks/meta/form/${name}`, { headers: auth(token) });

    const unknown = await form(bob, "NoSuchForm");
    expect(unknown.status()).toBe(404);
    const unknownBody = JSON.stringify(await unknown.json());
    const denied = await form(eve, "NewTaskForm");
    expect(denied.status()).toBe(404);
    // Same answer as an unknown form (modulo the name) — no form-existence oracle.
    expect(JSON.stringify(await denied.json()).replace("NewTaskForm", "NoSuchForm")).toBe(
      unknownBody,
    );

    expect((await form(bob, "NewTaskForm")).status()).toBe(200);
    expect((await form(bob, "AssignTaskForm")).status()).toBe(404);
    expect((await form(carol, "AssignTaskForm")).status()).toBe(200);
    expect((await form(frank, "NewTaskForm")).status()).toBe(403);
  });

  // ── Fail closed ──────────────────────────────────────────────────────────

  test("ARBAC-HARD-050: no read grant → 403 on every read endpoint (not 200 [])", async ({
    request,
  }) => {
    const frank = await mintToken(request, "t1_frank"); // guest: users (self) only
    for (const url of ["/tasks/query", "/tasks/pages", "/tasks/meta", "/documents/query"]) {
      const res = await request.get(url, { headers: auth(frank) });
      expect(res.status(), url).toBe(403);
    }
    // The one grant the guest has still works — scoped to their own row.
    const self = await rows(request, frank, "/users/query");
    expect(self.map((u) => u.username)).toEqual(["t1_frank"]);
  });

  test("ARBAC-HARD-051: @Public() does not open an ARBAC DB controller", async ({ request }) => {
    const dave = await mintToken(request, "t1_dave");
    const eve = await mintToken(request, "t1_eve");
    for (const url of [
      "/public-documents/query",
      "/public-documents/pages",
      "/public-documents/meta",
    ]) {
      const res = await request.get(url);
      expect(res.status(), url).toBe(401);
    }
    const insert = await request.post("/public-documents", {
      data: { title: "hard-051", body: "x", classification: "public", ownerUsername: "anon" },
    });
    expect(insert.status()).toBe(401);
    expect(await rows(request, dave, "/documents/query?title='hard-051'")).toEqual([]);

    // An authenticated caller gets exactly their own scope, as on /documents.
    const viaPublic = await rows(request, eve, "/public-documents/query?$select=id,classification");
    const viaScoped = await rows(request, eve, "/documents/query?$select=id,classification");
    expect(viaPublic.length).toBeGreaterThan(0);
    expect(viaPublic).toEqual(viaScoped);
    for (const d of viaPublic) expect(d.classification).toBe("public");
  });
});
