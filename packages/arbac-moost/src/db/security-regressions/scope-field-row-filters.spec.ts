// Custom scope fields that restrict ROWS: a registered `rowFilter` folds the
// field into each evaluated scope's `filter` (per scope, before the union
// and the attenuation conjunction), so every framework row path enforces it
// — reads, the action gate, write USING, the default WITH CHECK and `$with`
// inherited grants. Here the custom `teams` field maps onto `tenant`.
import { allowTableAction, allowTableRead, allowTableWrite, defineRole } from "@aooth/arbac";
import type { TScopeFieldRules } from "@aooth/arbac";
import { DbAction, DbActionID, TableController } from "@atscript/moost-db";
import { Get, Post } from "@moostjs/event-http";
import type { MoostHttp } from "@moostjs/event-http";
import { Controller } from "moost";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { listFieldRule } from "../../__testing__/scope-fields";
import type { FakeUserProvider } from "../../__testing__/user-provider";
import { useArbac } from "../../arbac.composables";
import { ArbacAction, ArbacResource } from "../../arbac.decorator";
import { type ArbacDbScope, AsArbacDbController } from "../as-arbac-db-controller";
import { RpTask, RpUser } from "./fixtures/rel-fixtures.as";
import { boot, createSpace, type Harness, one, seed, send } from "./relations-harness";

type AppScope = ArbacDbScope & { teams?: string[] };
type Attrs = { teams?: string[] };

let rowFilterCalls = 0;
const teamsRule = listFieldRule<AppScope>("teams", "tenant");
const TEAMS: TScopeFieldRules<AppScope> = {
  teams: {
    ...teamsRule,
    rowFilter(value, scope) {
      rowFilterCalls++;
      return teamsRule.rowFilter!(value, scope);
    },
  },
};

const teamScope = (a: Attrs): AppScope => ({ teams: a.teams });
const ROLES = [
  // Triage: the caller's teams (from attrs), reads + writes + one action.
  defineRole<Attrs, AppScope>()
    .id("triage")
    .use(
      allowTableWrite("tasks", { scope: teamScope }),
      allowTableAction("tasks", ["touch"], { scope: teamScope }),
      allowTableRead("users", { scope: teamScope }),
    )
    .build(),
  // A second team-scoped role, fixed to team "b".
  defineRole<Attrs, AppScope>()
    .id("triage-b")
    .use(allowTableRead("tasks", { scope: () => ({ teams: ["b"] }) }))
    .build(),
  // Leadership: no teams field — every row.
  defineRole<Attrs, AppScope>().id("leadership").use(allowTableRead("tasks")).build(),
  // An explicit check is left as written (here: disabled).
  defineRole<Attrs, AppScope>()
    .id("no-check")
    .use(allowTableWrite("tasks", { scope: (a) => ({ teams: a.teams, check: {} }) }))
    .build(),
];

@TableController(RpTask, "tasks")
@ArbacResource("tasks")
class TasksController extends AsArbacDbController<typeof RpTask> {
  @Post("actions/touch")
  @DbAction("touch", { label: "Touch" })
  touch(@DbActionID() id: unknown) {
    return { id };
  }
}

@TableController(RpUser, "users")
@ArbacResource("users")
class UsersController extends AsArbacDbController<typeof RpUser> {}

@Controller("app")
@ArbacResource("tasks")
class AppController {
  @Get("scopes")
  @ArbacAction("query")
  scopes() {
    return useArbac().getScopes<AppScope>();
  }
}

let h: Harness;
let http: MoostHttp;
let user: FakeUserProvider<Attrs>;
async function bootAs(roles: string[], attrs: Attrs = { teams: ["a"] }) {
  ({ http, user } = await boot(ROLES, [TasksController, UsersController, AppController], roles, {
    attrs,
    fields: TEAMS,
  }));
}

const get = (path: string) => send(http, "GET", path);
const ids = (rows: Array<{ id: number }>) => rows.map((r) => r.id).toSorted((a, b) => a - b);

beforeAll(async () => {
  h = await createSpace();
});
afterAll(() => h.close());
beforeEach(() => seed(h));

// Seed: task 1 (tenant a), task 2 (tenant b), task 3 (tenant a, owner bob of tenant b).
describe("rowFilter — reads and the action gate", () => {
  it("reads only the team's rows; the raw value stays on the scope", async () => {
    await bootAs(["triage"]);
    expect(ids((await get("/tasks/query")).body)).toEqual([1, 3]);
    expect((await get("/tasks/pages")).body).toMatchObject({ count: 2 });
    expect((await get("/tasks/one/2")).status).toBe(404);
    const [scope] = (await get("/app/scopes")).body;
    expect(scope.teams).toEqual(["a"]);
    expect(scope.filter).toEqual({ tenant: { $in: ["a"] } });
  });

  it("the action gate answers an out-of-team row like a missing one (404)", async () => {
    await bootAs(["triage"]);
    expect((await send(http, "POST", "/tasks/actions/touch", { ids: { id: 1 } })).status).toBe(201);
    const foreign = await send(http, "POST", "/tasks/actions/touch", { ids: { id: 2 } });
    const missing = await send(http, "POST", "/tasks/actions/touch", { ids: { id: 99 } });
    expect(foreign.status).toBe(404);
    expect(foreign.body).toEqual(missing.body);
  });

  it("unions across roles: leadership (no teams) ∪ triage = every row; two teams = both", async () => {
    await bootAs(["leadership", "triage"]);
    expect(ids((await get("/tasks/query")).body)).toEqual([1, 2, 3]);
    await bootAs(["triage", "triage-b"]);
    expect(ids((await get("/tasks/query")).body)).toEqual([1, 2, 3]);
    await bootAs(["triage-b"]);
    expect(ids((await get("/tasks/query")).body)).toEqual([2]);
  });

  it("an unregistered row rule is not applied (the field is then app-only)", async () => {
    await bootAs(["triage"], {});
    // `teams` absent → no restriction from the field.
    expect(ids((await get("/tasks/query")).body)).toEqual([1, 2, 3]);
  });

  it("rowFilter runs once per scope object, not per consumer", async () => {
    await bootAs(["triage-b"]);
    rowFilterCalls = 0;
    await get("/tasks/query");
    const perRequest = rowFilterCalls;
    await get("/tasks/query");
    expect(rowFilterCalls).toBe(perRequest * 2);
    expect(perRequest).toBeLessThanOrEqual(2);
  });
});

describe("rowFilter — writes", () => {
  it("USING: an out-of-team row cannot be updated (404), nothing written", async () => {
    await bootAs(["triage"]);
    const res = await send(http, "PATCH", "/tasks", { id: 2, title: "x" });
    expect(res.status).toBe(404);
    expect((await one(h, RpTask, { id: 2 })).title).toBe("taskB");
  });

  it("default WITH CHECK: moving a row out of the team is rejected (403), nothing written", async () => {
    await bootAs(["triage"]);
    expect((await send(http, "PATCH", "/tasks", { id: 1, title: "ok" })).status).toBe(202);
    const res = await send(http, "PATCH", "/tasks", { id: 1, tenant: "b" });
    expect(res.status).toBe(403);
    expect((await one(h, RpTask, { id: 1 })).tenant).toBe("a");
  });

  it("an explicit check is left as written (here `{}`: moving out is allowed; USING still applies)", async () => {
    await bootAs(["no-check"]);
    expect((await send(http, "PATCH", "/tasks", { id: 1, tenant: "b" })).status).toBe(202);
    expect((await one(h, RpTask, { id: 1 })).tenant).toBe("b");
    expect((await send(http, "PATCH", "/tasks", { id: 2, title: "x" })).status).toBe(404);
  });
});

describe("rowFilter — attenuation and relations", () => {
  it("both sides are folded, then conjoined", async () => {
    await bootAs(["triage"], { teams: ["a", "b"] });
    expect(ids((await get("/tasks/query")).body)).toEqual([1, 2, 3]);
    user.attenuation = { attrs: { teams: ["b"] } };
    expect(ids((await get("/tasks/query")).body)).toEqual([2]);
    const [scope] = (await get("/app/scopes")).body;
    expect(scope.teams).toEqual(["b"]);
    // A credential naming a team the user lacks gets nothing.
    await bootAs(["triage"], { teams: ["a"] });
    user.attenuation = { attrs: { teams: ["b"] } };
    expect((await get("/tasks/query")).body).toEqual([]);
  });

  it("the inherited `$with` grant on the related table is folded too", async () => {
    await bootAs(["triage"]);
    const r = await get("/tasks/query?$with=owner&$sort=id");
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    const rows = r.body as Array<Record<string, any>>;
    expect(rows.find((x) => x.id === 1)!.owner).toMatchObject({ id: 1, name: "alice" });
    // Task 3's owner bob is team b — outside the users grant's teams.
    expect(rows.find((x) => x.id === 3)!.owner ?? null).toBeNull();
  });
});
