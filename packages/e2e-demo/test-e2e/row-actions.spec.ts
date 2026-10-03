import { type APIRequestContext, expect, test } from "@playwright/test";

import { bearerAuth as auth, departmentIds, mintToken, resetApp, type Row, rows } from "./harness";

/**
 * Row actions across controllers, end to end (SQLite, real auth guard + ARBAC
 * interceptor):
 *
 * - the `task-dict` VIEW lists the tasks' row actions on its rows
 *   (`@DbActionsFrom`): each verdict is the tasks controller's, under the
 *   caller's grants on `tasks` — a grant on the view itself adds nothing, and
 *   executing always goes through `/tasks/actions/*`;
 * - query targets (`{ query }` instead of `{ ids }`): "every row matching the
 *   query" reaches only rows the caller can both list and act on; on the view
 *   (`/task-dict/delegated-actions/:name`) the tasks route re-authorizes every
 *   batch, so rows outside the caller's task grant are skipped, never run.
 *
 * Cast (seed.ts): tenant A — t1_dave admin, t1_carol manager+viewer (ops:
 * tenant-wide task read, ops-department task actions, task-dict read),
 * t1_eve viewer (task + task-dict read, no task actions); tenant B —
 * t2_olivia admin (no task-dict read).
 */

/** Tenant A's tasks as the admin sees them: id → { status, departmentId }. */
async function tenantTasks(
  request: APIRequestContext,
  adminToken: string,
): Promise<Map<string, { status: string; departmentId?: string }>> {
  const all = await rows(
    request,
    adminToken,
    "/tasks/query?$select=id,status,departmentId&$limit=1000",
  );
  return new Map(
    all.map((r) => [r.id, { status: r.status as string, departmentId: r.departmentId as string }]),
  );
}

type Tasks = Awaited<ReturnType<typeof tenantTasks>>;

/** Exactly the open tasks of department `ops` are done now; every other task is unchanged. */
function expectOnlyOpenOpsDone(before: Tasks, after: Tasks, ops: string): void {
  for (const [id, t] of before) {
    const done = t.status === "open" && t.departmentId === ops;
    expect(after.get(id)!.status, id).toBe(done ? "done" : t.status);
  }
}

const has = (r: Row, action: string) =>
  ((r.$actions as string[] | undefined) ?? []).includes(action);

test.describe("ROW-ACTIONS: view-delegated row actions and query targets", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("ROW-ACT-001: the view's rows carry the tasks' actions exactly where the tasks controller offers them", async ({
    request,
  }) => {
    const dave = await mintToken(request, "t1_dave");
    const carol = await mintToken(request, "t1_carol");
    const eve = await mintToken(request, "t1_eve");
    const { ops } = await departmentIds(request, dave);
    const tasks = await tenantTasks(request, dave);

    const viaView = await rows(
      request,
      carol,
      "/task-dict/query?$actions=true&$select=id,status&$limit=1000",
    );
    const viaSource = new Map(
      (await rows(request, carol, "/tasks/query?$actions=true&$select=id&$limit=1000")).map((r) => [
        r.id,
        r,
      ]),
    );
    expect(viaView.length).toBe(tasks.size);
    let offered = 0;
    for (const r of viaView) {
      const task = tasks.get(r.id)!;
      const expected = task.departmentId === ops && task.status !== "done";
      expect(has(r, "markDone"), r.id).toBe(expected);
      expect(has(r, "markDone"), r.id).toBe(has(viaSource.get(r.id)!, "markDone"));
      // Only the delegated subset — never the tasks' other actions.
      expect(has(r, "archive"), r.id).toBe(false);
      if (expected) offered++;
    }
    expect(offered).toBeGreaterThan(0);

    // A reader of the view without task actions: nothing delegated.
    const asViewer = await rows(request, eve, "/task-dict/query?$actions=true&$select=id");
    expect(asViewer.length).toBe(tasks.size);
    for (const r of asViewer) expect(has(r, "markDone") || has(r, "markDoneMany")).toBe(false);
  });

  test("ROW-ACT-002: /meta and GET /meta/actions/:id of the view answer as the tasks controller", async ({
    request,
  }) => {
    const dave = await mintToken(request, "t1_dave");
    const carol = await mintToken(request, "t1_carol");
    const eve = await mintToken(request, "t1_eve");
    const { ops } = await departmentIds(request, dave);
    const tasks = await tenantTasks(request, dave);
    const own = [...tasks].find(([, t]) => t.departmentId === ops && t.status === "open")![0];
    const foreign = [...tasks].find(([, t]) => t.departmentId !== ops && t.status === "open")![0];

    const meta = async (token: string) => {
      const res = await request.get("/task-dict/meta", { headers: auth(token) });
      expect(res.status()).toBe(200);
      return ((await res.json()) as { actions: Array<Record<string, unknown>> }).actions;
    };
    const carolMeta = await meta(carol);
    expect(carolMeta.map((a) => String(a.name)).toSorted()).toEqual(["markDone", "markDoneMany"]);
    expect(carolMeta.find((a) => a.name === "markDoneMany")).toMatchObject({
      owner: "/tasks",
      value: "/tasks/actions/markDoneMany",
      queryTarget: { maxRows: 500, url: "/task-dict/delegated-actions/markDoneMany" },
    });
    expect(await meta(eve)).toEqual([]);

    // The view answers the delegated subset of what the tasks route answers.
    const delegated = new Set(["markDone", "markDoneMany"]);
    for (const id of [own, foreign]) {
      const view = await request.get(`/task-dict/meta/actions/${id}`, { headers: auth(carol) });
      const source = await request.get(`/tasks/meta/actions/${id}`, { headers: auth(carol) });
      const fromSource = ((await source.json()) as { actions: string[] }).actions;
      const fromView = ((await view.json()) as { actions: string[] }).actions;
      expect(fromView.toSorted(), id).toEqual(
        fromSource.filter((a) => delegated.has(a)).toSorted(),
      );
      if (id === own) expect(fromView).toContain("markDone");
    }
    // No task action grant: nothing listed (the tasks route itself answers 403).
    const eveView = await request.get(`/task-dict/meta/actions/${own}`, { headers: auth(eve) });
    expect(await eveView.json()).toEqual({ actions: [] });
  });

  test("ROW-ACT-003: a query target on /tasks reaches only rows the caller can list AND act on", async ({
    request,
  }) => {
    const dave = await mintToken(request, "t1_dave");
    const carol = await mintToken(request, "t1_carol");
    const eve = await mintToken(request, "t1_eve");
    const { ops } = await departmentIds(request, dave);
    const before = await tenantTasks(request, dave);
    const openOps = [...before].filter(([, t]) => t.departmentId === ops && t.status === "open");
    expect(openOps.length).toBeGreaterThan(0);

    const url = "/tasks/actions/markDoneMany";
    const dry = await request.post(url, {
      headers: auth(carol),
      data: { query: { q: "status='open'", dryRun: true } },
    });
    expect(dry.status(), await dry.text()).toBe(201);
    expect(await dry.json()).toEqual({ matched: openOps.length });

    // No action grant on tasks: refused before anything resolves.
    const denied = await request.post(url, {
      headers: auth(eve),
      data: { query: { q: "status='open'" } },
    });
    expect(denied.status()).toBe(403);

    const run = await request.post(url, {
      headers: auth(carol),
      data: { query: { q: "status='open'", expectCount: openOps.length } },
    });
    expect(run.status(), await run.text()).toBe(201);
    expect(await run.json()).toMatchObject({ count: openOps.length });

    expectOnlyOpenOpsDone(before, await tenantTasks(request, dave), ops);
  });

  test("ROW-ACT-004: a query target on the view runs the tasks route per batch — out-of-grant rows skipped", async ({
    request,
  }) => {
    const dave = await mintToken(request, "t1_dave");
    const carol = await mintToken(request, "t1_carol");
    const { ops } = await departmentIds(request, dave);
    const before = await tenantTasks(request, dave);
    const open = [...before].filter(([, t]) => t.status === "open");
    const openOps = open.filter(([, t]) => t.departmentId === ops);

    const res = await request.post("/task-dict/delegated-actions/markDoneMany", {
      headers: auth(carol),
      data: { query: { q: "status='open'" } },
    });
    expect(res.status(), await res.text()).toBe(201);
    const summary = (await res.json()) as {
      matched: number;
      processed: number;
      skipped: Array<{ id: { id: string }; reason?: string }>;
      failed: unknown[];
    };
    expect(summary.matched).toBe(open.length);
    expect(summary.processed).toBe(openOps.length);
    expect(summary.failed).toEqual([]);
    expect(summary.skipped.map((s) => s.id.id).toSorted()).toEqual(
      open
        .filter(([, t]) => t.departmentId !== ops)
        .map(([id]) => id)
        .toSorted(),
    );

    expectOnlyOpenOpsDone(before, await tenantTasks(request, dave), ops);
  });

  test("ROW-ACT-005: the view's read grant alone runs nothing (403); no view read grant → 403", async ({
    request,
  }) => {
    const dave = await mintToken(request, "t1_dave");
    const eve = await mintToken(request, "t1_eve");
    const olivia = await mintToken(request, "t2_olivia");
    const before = await tenantTasks(request, dave);
    const url = "/task-dict/delegated-actions/markDoneMany";

    // eve reads the view but holds no task action: the source refuses it,
    // dry runs included.
    const dry = await request.post(url, {
      headers: auth(eve),
      data: { query: { q: "status='open'", dryRun: true } },
    });
    expect(dry.status()).toBe(403);
    const run = await request.post(url, {
      headers: auth(eve),
      data: { query: { q: "status='open'" } },
    });
    expect(run.status()).toBe(403);
    // Another tenant's admin cannot read the view at all.
    const foreign = await request.post(url, {
      headers: auth(olivia),
      data: { query: { q: "" } },
    });
    expect(foreign.status()).toBe(403);

    const after = await tenantTasks(request, dave);
    for (const [id, t] of before) expect(after.get(id)!.status, id).toBe(t.status);
  });
});
