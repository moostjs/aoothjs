// `$with` joins: the joined table's @db.writeOnly columns are sealed (in plain
// AsDbController too, whatever grant covers the join), and the P1
// inherit-target corners read-policy.integration.spec.ts does not pin:
// `controls.$with: false`, nav paths on the parent query, and an inherited
// level under a declared `with.<rel>`.
import { AsDbController, TableController } from "@atscript/moost-db";
import type { MoostHttp } from "@moostjs/event-http";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { readerRole } from "../../__testing__/http";
import { ArbacResource } from "../../arbac.decorator";
import { type ArbacDbScope, AsArbacDbController } from "../as-arbac-db-controller";
import { RpOrg, RpTask, RpUser } from "./fixtures/rel-fixtures.as";
import { boot, createSpace, type Harness, seed, send } from "./relations-harness";

const TENANT_A = { filter: { tenant: "a" } };
const role = (id: string, grants: Record<string, ArbacDbScope | undefined>) =>
  readerRole<ArbacDbScope>(id, grants);
const DECLARED_OWNER: ArbacDbScope = {
  ...TENANT_A,
  with: { owner: { filter: { tenant: "a" }, projection: { salary: 0 } } },
};

const ROLES = [
  // The users grant hides salary, not password (a writeOnly column).
  role("reader-a", {
    tasks: TENANT_A,
    users: { filter: { tenant: "a" }, projection: { salary: 0 } },
  }),
  role("reader-all", { tasks: TENANT_A, users: undefined, orgs: undefined, plain: undefined }),
  role("declared", { tasks: DECLARED_OWNER }),
  role("declared-orgs", {
    tasks: DECLARED_OWNER,
    orgs: { filter: { tenant: "a" }, projection: { budget: 0 } },
  }),
  role("tasks-only", { tasks: TENANT_A }),
  role("no-with", { tasks: { ...TENANT_A, controls: { $with: false } }, users: undefined }),
];

@TableController(RpTask, "tasks")
@ArbacResource("tasks")
class TasksController extends AsArbacDbController<typeof RpTask> {}

// Plain moost-db controller: the joined writeOnly seal needs no ARBAC.
@TableController(RpTask, "plain-tasks")
@ArbacResource("plain")
class PlainTasksController extends AsDbController<typeof RpTask> {}

@TableController(RpUser, "users")
@ArbacResource("users")
class UsersController extends AsArbacDbController<typeof RpUser> {}

@TableController(RpOrg, "orgs")
@ArbacResource("orgs")
class OrgsController extends AsArbacDbController<typeof RpOrg> {}

let h: Harness;
let http: MoostHttp;
let user: { roles: string[] };
beforeAll(async () => {
  h = await createSpace();
});
afterAll(() => h.close());
beforeEach(async () => {
  await seed(h);
  ({ http, user } = await boot(
    ROLES,
    [TasksController, UsersController, OrgsController, PlainTasksController],
    ["reader-all"],
  ));
});

type Row = Record<string, any>;
const byId = (rows: Row[], id: number) => rows.find((r) => r.id === id)!;

describe("@db.writeOnly columns of a joined table are sealed", () => {
  it.each<[role: string, path: string]>([
    ["reader-a", "/tasks"],
    ["reader-all", "/tasks"],
    ["declared", "/tasks"],
    ["reader-all", "/plain-tasks"],
  ])("%s: %s/query?$with=owner never returns password", async (roleId, path) => {
    user.roles = [roleId];
    const r = await send(http, "GET", `${path}/query?$with=owner&$sort=id`);
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(byId(r.body, 1).owner).toMatchObject({ id: 1, name: "alice" });
    for (const row of r.body as Row[]) expect(row.owner ?? {}).not.toHaveProperty("password");
    const single = await send(http, "GET", `${path}/one/3?$with=owner`);
    expect(single.status).toBe(200);
    expect(single.body.owner ?? {}).not.toHaveProperty("password");
  });

  it.each(["/tasks", "/plain-tasks"])(
    "%s: password cannot be selected, filtered or sorted inside $with",
    async (path) => {
      const sel = await send(http, "GET", `${path}/query?$with=owner($select=id,password)`);
      expect(sel.status).toBe(200);
      for (const row of sel.body as Row[]) expect(row.owner).toEqual({ id: row.ownerId });
      for (const [q, verb] of [
        ["$with=owner(password='pw-bob')", "Filtering"],
        ["$with=owner($sort=password)", "Sorting"],
      ]) {
        const r = await send(http, "GET", `${path}/query?${q}`);
        expect(r.status, q).toBe(400);
        expect(r.body, q).toMatchObject({
          message: `${verb} on field "owner.password" is not permitted — field is @db.writeOnly.`,
        });
      }
    },
  );
});

describe("$with inherit-target corners (P1)", () => {
  it("controls.$with: false → 403, even with a users grant", async () => {
    user.roles = ["no-with"];
    const r = await send(http, "GET", "/tasks/query?$with=owner");
    expect(r.status).toBe(403);
  });

  it.each([
    "owner.salary>100",
    "$sort=owner.salary",
    "$select=id,owner.salary",
    "$select=owner.tenant,count(*):n&$groupBy=owner.tenant",
  ])("no users grant: a nav path on the parent query (?%s) → 400", async (q) => {
    user.roles = ["tasks-only"];
    expect((await send(http, "GET", `/tasks/query?${q}`)).status).toBe(400);
  });

  it("an undeclared level under a declared with.owner follows the caller's own grant", async () => {
    user.roles = ["declared-orgs"];
    const r = await send(http, "GET", "/tasks/query?$with=owner($with=org)&$sort=id");
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    // Declared with.owner: tenant "a" only, no salary.
    expect(byId(r.body, 1).owner).toMatchObject({ id: 1, name: "alice" });
    expect(byId(r.body, 1).owner).not.toHaveProperty("salary");
    expect(byId(r.body, 3).owner).toBeNull();
    // Inherited org: the orgs grant's projection hides budget.
    expect(byId(r.body, 1).owner.org).toEqual({ id: 1, name: "orgA", tenant: "a" });
    expect((await send(http, "GET", "/tasks/query?$with=owner($with=org(budget>1))")).status).toBe(
      400,
    );
  });
});
