// Per-action row scope: every `@DbAction` runs only on the rows its OWN
// grant reaches — `actionRowScope` returns the caller's filter for that
// action (custom-field `rowFilter` folded, attenuation conjoined). The
// action gate, `$actions` and `GET meta/actions/:id` all enforce it; the
// route needs no read grant, only some row-level action grant.
import { allowTableAction, allowTableOps, allowTableRead, defineRole } from "@aooth/arbac";
import type { TScopeFieldRules } from "@aooth/arbac";
import {
  AsDbController,
  DbAction,
  DbActionID,
  DbRowActions,
  TableController,
} from "@atscript/moost-db";
import { Get, Post } from "@moostjs/event-http";
import type { MoostHttp } from "@moostjs/event-http";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vite-plus/test";

import { listFieldRule } from "../../__testing__/scope-fields";
import type { FakeUserProvider } from "../../__testing__/user-provider";
import { ArbacResource } from "../../arbac.decorator";
import { getArbacMate } from "../../arbac.mate";
import { type ArbacDbScope, AsArbacDbController } from "../as-arbac-db-controller";
import { AsArbacDbReadableController } from "../as-arbac-db-readable-controller";
import { RpTask } from "./fixtures/rel-fixtures.as";
import { boot, createSpace, type Harness, seed, send } from "./relations-harness";

type AppScope = ArbacDbScope & { teams?: string[] };
type Attrs = { teams?: string[] };

const TEAMS: TScopeFieldRules<AppScope> = { teams: listFieldRule("teams", "tenant") };

const teamScope = (a: Attrs): AppScope => ({ teams: a.teams });
const ACTIONS = ["resolve", "close"];
const ROLES = [
  // Reads everything, may run no action.
  defineRole<Attrs, AppScope>()
    .id("leadership")
    .use(allowTableRead("tasks"), allowTableRead("rtasks"))
    .build(),
  // Actions on the caller's teams only — no read grant.
  defineRole<Attrs, AppScope>()
    .id("triage")
    .use(
      allowTableAction("tasks", ACTIONS, { scope: teamScope }),
      allowTableAction("rtasks", ACTIONS, { scope: teamScope }),
    )
    .build(),
  // Action-only principal whose action scope hides `title`.
  defineRole<Attrs, AppScope>()
    .id("peeker")
    .use(
      allowTableAction("tasks", ["peek"], {
        scope: () => ({ filter: { tenant: "a" }, projection: { title: 0 } }),
      }),
    )
    .build(),
  // Only the class-level `edit` entry (no handler method) + `/meta`.
  defineRole<Attrs, AppScope>()
    .id("editor")
    .use(
      allowTableAction("tasks", ["edit"], { scope: teamScope }),
      allowTableOps("tasks", ["meta"]),
    )
    .build(),
  // The same action on team "b".
  defineRole<Attrs, AppScope>()
    .id("triage-b")
    .use(allowTableAction("tasks", ["resolve"], { scope: () => ({ teams: ["b"] }) }))
    .build(),
];

let resolved: unknown[] = [];
let ownScopeWhileRunning: unknown = "unset";

@TableController(RpTask, "tasks")
@ArbacResource("tasks")
@DbRowActions({ edit: { label: "Edit", processor: "navigate", value: "/tasks/$1/edit" } })
class TasksController extends AsArbacDbController<typeof RpTask> {
  @Post("actions/resolve")
  @DbAction("resolve", { label: "Resolve" })
  async resolve(@DbActionID() id: unknown) {
    resolved.push(id);
    // Running the action itself: the row overlay already IS its grant.
    ownScopeWhileRunning = await this.actionRowScope("resolve");
    return { id };
  }

  // Always disabled; the reason would echo `title` if the gate loaded it.
  @Post("actions/peek")
  @DbAction("peek", {
    label: "Peek",
    requiredFields: ["title"],
    disabled: (rows: Array<{ title?: string }>) => rows.map((r) => `title=${String(r.title)}`),
  })
  peek(@DbActionID() id: unknown) {
    return { id };
  }

  // Probe (skips the authorize interceptor): the names allowedActions keeps.
  @Get("probe/allowed")
  @(getArbacMate().decorate("arbacPublic", true))
  probeAllowed() {
    return this.allowedActions(["resolve", "close", "peek", "edit"]);
  }

  // Probe (skips the authorize interceptor): the filters actionRowScope returns.
  @Get("probe/scopes")
  @(getArbacMate().decorate("arbacPublic", true))
  async probe() {
    const [resolveScope, closeScope, unknown] = await Promise.all([
      this.actionRowScope("resolve"),
      this.actionRowScope("close"),
      this.actionRowScope("nope"),
    ]);
    return { resolveScope, sameObject: resolveScope === closeScope, unknown };
  }

  @Post("actions/close")
  @DbAction("close", {
    label: "Close",
    requiredFields: ["title"],
    disabled: (rows: Array<{ title?: string }>) =>
      rows.map((r) => (r.title === "taskA2" ? "Already closed" : false)),
  })
  close(@DbActionID() id: unknown) {
    return { id };
  }
}

// A plain moost-db controller (no ARBAC prepareRequest) under the global
// ARBAC interceptor: its delegated handlers stay fail-closed.
@TableController(RpTask, "plain")
@ArbacResource("tasks")
class PlainTasksController extends AsDbController<typeof RpTask> {
  @Post("actions/resolve")
  @DbAction("resolve", { label: "Resolve" })
  resolve(@DbActionID() id: unknown) {
    return { id };
  }
}

// The read-only controller variant over the same table.
@TableController(RpTask, "rtasks")
@ArbacResource("rtasks")
class ReadableTasksController extends AsArbacDbReadableController<typeof RpTask> {
  @Post("actions/resolve")
  @DbAction("resolve", { label: "Resolve" })
  resolve(@DbActionID() id: unknown) {
    return { id };
  }
}

let h: Harness;
let http: MoostHttp;
let user: FakeUserProvider<Attrs>;
async function bootAs(roles: string[], attrs: Attrs = { teams: ["a"] }) {
  ({ http, user } = await boot(
    ROLES,
    [TasksController, ReadableTasksController, PlainTasksController],
    roles,
    {
      attrs,
      fields: TEAMS,
    },
  ));
}

const get = (path: string) => send(http, "GET", path);
const resolve = (id: number, ctrl = "tasks") =>
  send(http, "POST", `/${ctrl}/actions/resolve`, { ids: { id } });
/** Row id → its `$actions`. */
async function actionsByRow(ctrl = "tasks"): Promise<Record<number, string[] | undefined>> {
  const r = await get(`/${ctrl}/query?$actions=true&$sort=id`);
  expect(r.status, JSON.stringify(r.body)).toBe(200);
  return Object.fromEntries(
    (r.body as Array<{ id: number; $actions?: string[] }>).map((row) => [row.id, row.$actions]),
  );
}

beforeAll(async () => {
  h = await createSpace();
});
afterAll(() => h.close());
beforeEach(async () => {
  resolved = [];
  await seed(h);
});

// Seed: task 1 (tenant a, "taskA"), 2 (tenant b), 3 (tenant a, "taskA2").
describe("$actions and the action gate follow each action's own grant", () => {
  it("leadership + triage: resolve is offered and runs only on the team's rows", async () => {
    await bootAs(["leadership", "triage"]);
    const acts = await actionsByRow();
    expect(acts[1]).toEqual(expect.arrayContaining(["resolve", "close"]));
    expect(acts[2] ?? []).toEqual([]);
    expect(acts[3]).toContain("resolve");
    expect((await resolve(1)).status).toBe(201);
    const foreign = await resolve(2);
    const missing = await resolve(99);
    expect(foreign.status).toBe(404);
    expect(foreign.body).toEqual(missing.body);
    expect(resolved).toEqual([{ id: 1 }]);
  });

  it("a second team role unions: resolve on both teams, close still team a only", async () => {
    await bootAs(["leadership", "triage", "triage-b"]);
    const acts = await actionsByRow();
    expect(acts[2]).toEqual(["resolve"]);
    expect(acts[1]).toContain("close");
    expect((await resolve(2)).status).toBe(201);
    const close2 = await send(http, "POST", "/tasks/actions/close", { ids: { id: 2 } });
    expect(close2.status).toBe(404);
  });

  it("the read-only controller variant applies the same row scope", async () => {
    await bootAs(["leadership", "triage"]);
    const acts = await actionsByRow("rtasks");
    expect(acts[1]).toEqual(["resolve"]);
    expect(acts[2] ?? []).toEqual([]);
    expect((await resolve(2, "rtasks")).status).toBe(404);
    expect((await resolve(3, "rtasks")).status).toBe(201);
  });

  it("attenuation clips $actions and the gate", async () => {
    await bootAs(["leadership", "triage"], { teams: ["a", "b"] });
    expect((await actionsByRow())[2]).toContain("resolve");
    user.attenuation = { attrs: { teams: ["b"] } };
    const acts = await actionsByRow();
    expect(acts[1] ?? []).toEqual([]);
    expect(acts[2]).toContain("resolve");
    expect((await resolve(1)).status).toBe(404);
  });
});

describe("class-level row actions (no handler method) — one rule everywhere", () => {
  it("/meta, $actions and meta/actions scope the entry by its grant", async () => {
    await bootAs(["editor"]);
    const meta = (await get("/tasks/meta")).body;
    expect(meta.actions.map((a: { name: string }) => a.name)).toEqual(["edit"]);
    // Action-only (no read): the route is served and scoped by the grant.
    expect((await get("/tasks/meta/actions/1")).body).toEqual({ actions: ["edit"] });
    expect((await get("/tasks/meta/actions/2")).body).toEqual({ actions: [] });
    await bootAs(["leadership", "editor"]);
    const acts = await actionsByRow();
    expect(acts[1]).toEqual(["edit"]);
    expect(acts[2] ?? []).toEqual([]);
    expect(acts[3]).toEqual(["edit"]);
  });

  it("without its grant the entry is hidden from /meta, $actions and the route", async () => {
    await bootAs(["leadership", "triage"]);
    const acts = await actionsByRow();
    expect(acts[1]).not.toContain("edit");
    expect((await get("/tasks/meta/actions/1")).body.actions).not.toContain("edit");
  });
});

describe("actionRowScope", () => {
  it("equal grants share ONE filter object; no grant → match-nothing", async () => {
    await bootAs(["triage"]);
    const r = await get("/tasks/probe/scopes");
    expect(r.status).toBe(200);
    expect(r.body).toEqual({
      resolveScope: { tenant: { $in: ["a"] } },
      sameObject: true,
      unknown: { $or: [] },
    });
    await bootAs(["leadership"]);
    expect((await get("/tasks/probe/scopes")).body.resolveScope).toEqual({ $or: [] });
  });

  it("is undefined while the action itself runs (the row overlay already applies it)", async () => {
    await bootAs(["triage"]);
    ownScopeWhileRunning = "unset";
    expect((await resolve(1)).status).toBe(201);
    expect(ownScopeWhileRunning).toBeUndefined();
  });
});

describe("route authorization is delegated to prepareRequest (moost-db endpoint tag)", () => {
  it("the ARBAC controllers need no override stubs and are not public", async () => {
    const mate = getArbacMate();
    for (const ctrl of [TasksController, ReadableTasksController]) {
      for (const method of ["availableActionsById", "availableActions"]) {
        expect(mate.read(ctrl.prototype, method)?.arbacPublic, method).toBeUndefined();
      }
    }
    await bootAs(["triage"]);
    expect((await get("/tasks/meta/actions/1")).status).toBe(200);
  });

  it("a plain moost-db controller under the ARBAC interceptor stays fail-closed (403)", async () => {
    await bootAs(["triage", "leadership"]);
    expect((await get("/plain/meta/actions/1")).status).toBe(403);
    expect((await get("/plain/meta/actions?id=1")).status).toBe(403);
  });
});

describe("allowedActions answers per action, like the /meta overlay", () => {
  it("lists exactly the /meta overlay's row-level actions, for several roles", async () => {
    for (const roles of [
      ["leadership"],
      ["leadership", "triage"],
      ["leadership", "editor"],
      ["leadership", "peeker"],
      ["leadership", "triage-b"],
      ["leadership", "triage", "editor", "peeker"],
    ]) {
      await bootAs(roles);
      const meta = (await get("/tasks/meta")).body as {
        actions: Array<{ name: string; level: string }>;
      };
      const fromMeta = meta.actions
        .filter((a) => a.level === "row" || a.level === "rows")
        .map((a) => a.name)
        .toSorted();
      const allowed = (await get("/tasks/probe/allowed")).body as string[];
      expect(allowed.toSorted(), roles.join("+")).toEqual(fromMeta);
    }
  });

  it("$actions and the route no longer build the /meta overlay", async () => {
    await bootAs(["leadership", "triage"]);
    const overlay = vi.spyOn(
      TasksController.prototype as unknown as { applyMetaOverlay: () => unknown },
      "applyMetaOverlay",
    );
    try {
      expect((await actionsByRow())[1]).toContain("resolve");
      expect((await get("/tasks/meta/actions/1")).body.actions).toContain("resolve");
      expect(overlay).not.toHaveBeenCalled();
      await get("/tasks/meta");
      expect(overlay).toHaveBeenCalled();
    } finally {
      overlay.mockRestore();
    }
  });
});

describe("GET meta/actions/:id", () => {
  it("action-only grant: no read, but the route lists in-scope actions", async () => {
    await bootAs(["triage"]);
    expect((await get("/tasks/query")).status).toBe(403);
    expect((await get("/tasks/one/1")).status).toBe(403);
    const one = await get("/tasks/meta/actions/1");
    expect(one.status).toBe(200);
    expect(one.body.actions.toSorted()).toEqual(["close", "resolve"]);
    // Out of scope and unknown answer identically.
    const foreign = await get("/tasks/meta/actions/2");
    const missing = await get("/tasks/meta/actions/99");
    expect(foreign.status).toBe(200);
    expect(foreign.body).toEqual({ actions: [] });
    expect(missing.status).toBe(200);
    expect(missing.body).toEqual(foreign.body);
    // Composite form.
    expect((await get("/tasks/meta/actions?id=1")).body.actions).toContain("resolve");
    expect((await get("/tasks/meta/actions?id=2")).body).toEqual({ actions: [] });
    // The read-only variant.
    expect((await get("/rtasks/meta/actions/1")).body).toEqual({ actions: ["resolve"] });
    expect((await get("/rtasks/meta/actions/2")).body).toEqual({ actions: [] });
  });

  it("disabled reasons pass through", async () => {
    await bootAs(["triage"]);
    const r = await get("/tasks/meta/actions/3");
    expect(r.body).toEqual({ actions: ["resolve"], disabledReasons: { close: "Already closed" } });
  });

  it("field visibility is never wider than the granted actions' (no hidden column in reasons)", async () => {
    await bootAs(["peeker"]);
    const r = await get("/tasks/meta/actions/1");
    expect(r.status).toBe(200);
    expect(r.body).toEqual({ actions: [], disabledReasons: { peek: "title=undefined" } });
    expect(JSON.stringify(r.body)).not.toContain("taskA");
    // Rows still come from the action's own scope.
    expect((await get("/tasks/meta/actions/2")).body).toEqual({ actions: [] });
  });

  it("no row-level action grant → 403 (a read grant is not enough)", async () => {
    await bootAs(["leadership"]);
    expect((await get("/tasks/meta/actions/1")).status).toBe(403);
    expect((await get("/tasks/meta/actions?id=1")).status).toBe(403);
    await bootAs([]);
    expect((await get("/tasks/meta/actions/1")).status).toBe(403);
  });

  it("the read scope does not leak in: leadership + triage still answers per action", async () => {
    await bootAs(["leadership", "triage"]);
    expect((await get("/tasks/meta/actions/2")).body).toEqual({ actions: [] });
    expect((await get("/tasks/meta/actions/1")).body.actions).toContain("resolve");
  });

  it("attenuation clips the route", async () => {
    await bootAs(["triage"], { teams: ["a", "b"] });
    expect((await get("/tasks/meta/actions/2")).body.actions).toContain("resolve");
    user.attenuation = { attrs: { teams: ["a"] } };
    expect((await get("/tasks/meta/actions/2")).body).toEqual({ actions: [] });
    expect((await get("/tasks/meta/actions/1")).body.actions).toContain("resolve");
  });
});
