import {
  allowTableAction,
  allowTableOps,
  allowTableRead,
  allowTableWrite,
  defineRole,
} from "@aooth/arbac";
import type { TArbacRole } from "@aooth/arbac-core";
import { DbSpace } from "@atscript/db";
import { SchemaSync } from "@atscript/db/sync";
import { BetterSqlite3Driver, SqliteAdapter } from "@atscript/db-sqlite";
import {
  clearDbSpaces,
  DbAction,
  DbActionID,
  provideDbSpace,
  TableController,
} from "@atscript/moost-db";
import { Post } from "@moostjs/event-http";
import { clearGlobalWooks, Id } from "moost";
import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

import { bootArbacHttp } from "../__testing__/arbac-http";
import { readerRole } from "../__testing__/http";
import { FakeUserProvider } from "../__testing__/user-provider";
import { ArbacAction, ArbacResource } from "../arbac.decorator";
import { MoostArbac } from "../moost-arbac";
import { PolOrg, PolTask, PolUser } from "./__test__/fixtures/read-policy.as";
import { type ArbacDbScope, AsArbacDbController } from "./as-arbac-db-controller";

/**
 * The 0.1.72 read-side policy over real SQLite + HTTP:
 *
 * - `$with` inherit-target (P1): an undeclared relation's joined rows obey the
 *   caller's OWN grant on the related table — no grant → `Unknown relation`,
 *   byte-for-byte like a nonexistent one; a declared `with.<rel>` (any role)
 *   still wins, silent roles contribute nothing; `/meta` agrees.
 * - derived columns follow their source; SQL `@db.json` columns are atomic.
 * - `/meta` search surface pruning; crud op → handler action mapping.
 */

@TableController(PolTask, "tasks")
@ArbacResource("tasks")
class TasksController extends AsArbacDbController<typeof PolTask> {
  // The action id is the @DbAction name, never the method @Id (useArbac parity).
  @Post("actions/archive")
  @Id("legacy-archive")
  @DbAction("archive", { label: "Archive" })
  archive(@DbActionID() id: unknown) {
    return { id };
  }

  @Post("actions/flag")
  @DbAction("flag", { label: "Flag" })
  @ArbacAction("tasks.flag")
  flag(@DbActionID() id: unknown) {
    return { id };
  }
}

@TableController(PolUser, "users")
@ArbacResource("users")
class UsersController extends AsArbacDbController<typeof PolUser> {}

@TableController(PolOrg, "orgs")
@ArbacResource("orgs")
class OrgsController extends AsArbacDbController<typeof PolOrg> {}

let driver: BetterSqlite3Driver;

beforeAll(async () => {
  driver = new BetterSqlite3Driver(":memory:");
  const space = new DbSpace(() => new SqliteAdapter(driver));
  await new SchemaSync(space).run([PolOrg, PolUser, PolTask] as never);
  await space.getTable(PolOrg).insertMany([
    { id: 1, name: "orgA", tenant: "a", budget: 100 },
    { id: 2, name: "orgB", tenant: "b", budget: 999 },
  ]);
  await space.getTable(PolUser).insertMany([
    { id: 1, name: "alice", tenant: "a", salary: 10, orgId: 1 },
    { id: 2, name: "bob", tenant: "b", salary: 777, orgId: 2 },
    { id: 3, name: "carol", tenant: "a", salary: 20, orgId: 2 },
  ]);
  const home: [number, number] = [2.35, 48.85];
  await space.getTable(PolTask).insertMany([
    {
      id: 1,
      title: "t1",
      secretNote: "zebra",
      tenant: "a",
      ownerId: 1,
      settings: { apiKey: "K1", theme: "dark" },
      home,
    },
    {
      id: 2,
      title: "t2",
      secretNote: "lion",
      tenant: "a",
      ownerId: 2,
      settings: { apiKey: "K2", theme: "light" },
      home,
    },
    {
      id: 3,
      title: "t3",
      secretNote: "tiger",
      tenant: "a",
      ownerId: 3,
      settings: { apiKey: "K3", theme: "dark" },
      home,
    },
  ] as never);
  provideDbSpace(space);
});

afterAll(() => {
  clearDbSpaces();
  driver.close();
});

type Grants = Record<string, ArbacDbScope | undefined>;
type Get = (path: string) => Promise<{ status: number; body: any; text: string }>;

/** Boot with ONE role per entry of `roles`: resource → read scope (`undefined` = unscoped). */
async function boot(roles: Grants[], extra: Array<[string, string[]]> = []): Promise<Get> {
  const built = roles.map((grants, i) => readerRole<ArbacDbScope>(`r${i}`, grants));
  if (extra.length > 0) {
    let b = defineRole<object, ArbacDbScope>().id("extra");
    for (const [resource, actions] of extra) b = b.use(allowTableAction(resource, actions));
    built.push(b.build());
  }
  return bootRoles(built);
}

/** Boot with the given roles, all held by the caller. */
async function bootRoles(roles: Array<TArbacRole<object, ArbacDbScope>>): Promise<Get> {
  clearGlobalWooks();
  const arbac = new MoostArbac<object, ArbacDbScope>();
  const ids: string[] = [];
  for (const role of roles) {
    arbac.registerRole(role);
    ids.push(role.id);
  }
  const http = await bootArbacHttp({
    arbac,
    user: new FakeUserProvider("u1", ids),
    controllers: [TasksController, UsersController, OrgsController],
    authorize: true,
  });
  return async (path) => {
    const res = await http.request(path);
    const text = await res!.text();
    let body: unknown = text;
    try {
      body = JSON.parse(text);
    } catch {
      // keep text
    }
    return { status: res!.status, body, text };
  };
}

const TENANT_A = { filter: { tenant: "a" } } as const;
const USERS_A = { filter: { tenant: "a" }, projection: { salary: 0 } } as const;
const byId = (rows: Array<Record<string, any>>, id: number) => rows.find((r) => r.id === id)!;
const message = (name: string, available: string) =>
  `Unknown relation "${name}" in $with. Available relations: ${available}`;

describe("$with inherit-target policy (P1)", () => {
  it("an undeclared relation's rows obey the caller's own grant on the related table", async () => {
    const get = await boot([{ tasks: TENANT_A, users: USERS_A }]);
    const r = await get("/tasks/query?$with=owner&$sort=id&$select=id,ownerId");
    expect(r.status).toBe(200);
    expect(byId(r.body, 1).owner).toEqual({ id: 1, name: "alice", tenant: "a", orgId: 1 });
    // bob is tenant b — outside the users grant → the join is empty.
    expect(byId(r.body, 2).owner).toBeNull();
    const one = await get("/tasks/one/2?$with=owner");
    expect(one.status).toBe(200);
    expect(one.body.owner).toBeNull();
  });

  it("a field the related grant hides is unknown inside the $with sub-query", async () => {
    const get = await boot([{ tasks: TENANT_A, users: USERS_A }]);
    for (const [hidden, missing] of [
      ["$with=owner(salary>1)", "$with=owner(nope>1)"],
      ["$with=owner($sort=salary)", "$with=owner($sort=nope)"],
      ["$with=owner($select=salary)", "$with=owner($select=nope)"],
    ]) {
      const h = await get(`/tasks/query?${hidden}`);
      const m = await get(`/tasks/query?${missing}`);
      expect(h.status, hidden).toBe(400);
      expect(h.text.replaceAll("salary", "nope"), hidden).toBe(m.text);
    }
  });

  it("no grant on the related table → Unknown relation, like a nonexistent one", async () => {
    for (const tasks of [TENANT_A, undefined]) {
      const get = await boot([{ tasks }]);
      const hidden = await get("/tasks/query?$with=owner(salary>1)");
      const missing = await get("/tasks/query?$with=nope(salary>1)");
      expect(hidden.status).toBe(400);
      expect(hidden.body).toMatchObject({
        message: expect.stringContaining('Unknown relation "owner"'),
      });
      expect(hidden.text.replaceAll("owner", "nope")).toBe(missing.text);
      expect((await get("/tasks/one/1?$with=owner")).status).toBe(400);
    }
  });

  it("applies at every nesting level", async () => {
    const noOrgs = await boot([{ tasks: TENANT_A, users: USERS_A }]);
    const hidden = await noOrgs("/tasks/query?$with=owner($with=org)");
    expect(hidden.status).toBe(400);
    expect(hidden.body).toMatchObject({
      message: 'Unknown relation "org" in $with. Available relations: (none)',
    });

    const get = await boot([
      { tasks: TENANT_A, users: USERS_A, orgs: { filter: { tenant: "a" } } },
    ]);
    const r = await get("/tasks/query?$with=owner($with=org)&$sort=id");
    expect(r.status).toBe(200);
    expect(byId(r.body, 1).owner.org).toMatchObject({ id: 1, name: "orgA" });
    // carol (tenant a) belongs to orgB (tenant b) — outside the orgs grant.
    expect(byId(r.body, 3).owner).toMatchObject({ id: 3 });
    expect(byId(r.body, 3).owner.org).toBeNull();
  });

  it("the Unknown relation 400 lists the relations the caller can use — never hidden ones", async () => {
    const scoped = await boot([{ tasks: TENANT_A, users: USERS_A }]);
    expect((await scoped("/tasks/query?$with=nope")).body).toMatchObject({
      message: message("nope", "owner"),
    });
    // Nested level: users → org is hidden (no orgs grant), so nothing is listed.
    expect((await scoped("/tasks/query?$with=owner($with=nope)")).body).toMatchObject({
      message: message("nope", "(none)"),
    });
    const withOrgs = await boot([{ tasks: TENANT_A, users: USERS_A, orgs: TENANT_A }]);
    expect((await withOrgs("/tasks/query?$with=owner($with=nope)")).body).toMatchObject({
      message: message("nope", "org"),
    });
    // No users grant: `owner` is hidden — neither listed nor distinguishable.
    const tasksOnly = await boot([{ tasks: TENANT_A }]);
    const missing = await tasksOnly("/tasks/query?$with=nope");
    expect(missing.body).toMatchObject({ message: message("nope", "(none)") });
    const hidden = await tasksOnly("/tasks/query?$with=owner");
    expect(hidden.text.replaceAll("owner", "nope")).toBe(missing.text);
  });

  it("a declared with.<rel> wins over the related grant; silent roles contribute nothing", async () => {
    const declaring: Grants = {
      tasks: { ...TENANT_A, with: { owner: { projection: { salary: 0, tenant: 0 } } } },
    };
    // A second role with an UNRESTRICTED users grant, silent on `with`.
    const get = await boot([declaring, { tasks: TENANT_A, users: undefined }]);
    const r = await get("/tasks/query?$with=owner&$sort=id");
    expect(r.status).toBe(200);
    // Declared sub-scope has no row filter → bob is joined, without salary / tenant.
    expect(byId(r.body, 2).owner).toEqual({ id: 2, name: "bob", orgId: 2 });
    expect((await get("/tasks/query?$with=owner(salary>1)")).status).toBe(400);
    // …and the declared sub-scope is silent on `org` → org follows the orgs grant (none).
    expect((await get("/tasks/query?$with=owner($with=org)")).status).toBe(400);
  });

  it("/meta: relations, nav types and FK refs follow the same rule", async () => {
    const none = await boot([{ tasks: TENANT_A }]);
    const hidden = (await none("/tasks/meta")).body;
    expect(hidden.relations).toEqual([]);
    expect(hidden.type.type.props).not.toHaveProperty("owner");
    // The FK names a table the caller cannot read → its ref is stripped.
    expect(hidden.type.type.props.ownerId.ref).toBeUndefined();

    const scoped = await boot([{ tasks: TENANT_A, users: USERS_A }]);
    const meta = (await scoped("/tasks/meta")).body;
    expect(meta.relations.map((r: { name: string }) => r.name)).toEqual(["owner"]);
    const owner = meta.type.type.props.owner.type.props;
    expect(Object.keys(owner).toSorted()).toEqual(["id", "name", "orgId", "tenant"]);
    expect(meta.type.type.props.ownerId.ref).toMatchObject({ field: "id" });
    // Inside the joined type too: users.orgId → orgs (no grant) loses its ref.
    expect(owner.orgId.ref).toBeUndefined();

    const all = await boot([{ tasks: undefined, users: undefined, orgs: undefined }]);
    const full = (await all("/tasks/meta")).body;
    expect(Object.keys(full.type.type.props.owner.type.props)).toContain("salary");
    expect(full.type.type.props.owner.type.props.org.type.props).toHaveProperty("budget");
  });
});

describe("derived columns follow their source", () => {
  it.each([
    ["exclusion", { settings: 0 }],
    ["whitelist", { id: 1, title: 1, apiKeyCopy: 1 }],
  ] as const)("%s hiding the JSON source hides apiKeyCopy everywhere", async (_n, projection) => {
    const get = await boot([{ tasks: { projection } }]);
    const rows = await get("/tasks/query?$sort=id");
    expect(rows.status).toBe(200);
    for (const row of rows.body) {
      expect(row).not.toHaveProperty("apiKeyCopy");
      expect(row).not.toHaveProperty("settings");
    }
    const f = await get("/tasks/query?apiKeyCopy='K1'");
    expect(f.status).toBe(400);
    expect(f.body).toMatchObject({ message: 'Unknown field "apiKeyCopy"' });
    const meta = (await get("/tasks/meta")).body;
    expect(meta.fields).not.toHaveProperty("apiKeyCopy");
    expect(meta.type.type.props).not.toHaveProperty("apiKeyCopy");
  });

  it("a visible source keeps the derived column", async () => {
    const get = await boot([{ tasks: { projection: { secretNote: 0 } } }]);
    const r = await get("/tasks/query?apiKeyCopy='K1'&$select=id,apiKeyCopy");
    expect(r.status).toBe(200);
    expect(r.body).toEqual([{ id: 1, apiKeyCopy: "K1" }]);
  });
});

describe("SQL @db.json columns are atomic", () => {
  it("a hidden JSON leaf hides the whole column (rows, filters, /meta)", async () => {
    const get = await boot([{ tasks: { projection: { "settings.apiKey": 0 } } }]);
    const rows = await get("/tasks/query?$sort=id");
    expect(rows.status).toBe(200);
    expect(rows.body[0]).not.toHaveProperty("settings");
    expect(rows.body[0]).not.toHaveProperty("apiKeyCopy");
    expect(rows.body[0]).toMatchObject({ id: 1, title: "t1" });
    for (const q of ["$select=settings", "settings.theme='dark'", "$exists=settings"]) {
      const r = await get(`/tasks/query?${q}`);
      expect(r.status, q).toBe(400);
      expect(r.body, q).toMatchObject({
        message: expect.stringMatching(/^Unknown field "settings/),
      });
    }
    const meta = (await get("/tasks/meta")).body;
    expect(meta.fields).not.toHaveProperty("settings");
    expect(meta.type.type.props).not.toHaveProperty("settings");
  });

  it("a whitelisted JSON leaf alone does not reveal the column (fail closed, still executable)", async () => {
    const get = await boot([{ tasks: { projection: { id: 1, title: 1, "settings.theme": 1 } } }]);
    const rows = await get("/tasks/query?$sort=id");
    expect(rows.status).toBe(200);
    expect(rows.body[0]).toEqual({ id: 1, title: "t1" });
    expect((await get("/tasks/one/1")).body).toEqual({ id: 1, title: "t1" });
  });

  it("a whole-column grant is unaffected", async () => {
    const get = await boot([{ tasks: { projection: { id: 1, settings: 1 } } }]);
    const rows = await get("/tasks/query?$sort=id");
    expect(rows.body[0]).toEqual({ id: 1, settings: { apiKey: "K1", theme: "dark" } });
  });
});

describe("/meta search surface", () => {
  it("drops indexes over hidden fields and recomputes the flags + control lists", async () => {
    const full = (await (await boot([{ tasks: undefined }]))("/tasks/meta")).body;
    expect(full.searchIndexes.length).toBeGreaterThan(0);
    expect(full.crud.query).toContain("index");

    const noNote = (
      await (
        await boot([{ tasks: { projection: { secretNote: 0 } } }])
      )("/tasks/meta")
    ).body;
    expect(noNote.searchIndexes).toEqual([]);
    expect(JSON.stringify(noNote)).not.toContain("secretNote");
    // The @db.column.searchable fallback (tenant) still searches.
    expect(noNote.searchable).toBe(true);
    expect(noNote.crud.query).toContain("search");
    expect(noNote.crud.query).not.toContain("index");

    const nothing = (
      await (
        await boot([{ tasks: { projection: { secretNote: 0, tenant: 0 } } }])
      )("/tasks/meta")
    ).body;
    expect(nothing.searchable).toBe(false);
    expect(nothing.crud.query).not.toContain("search");
    expect(nothing.crud.pages).not.toContain("search");
  });

  it("geo: a hidden geo column drops geoSearchable and crud.geo", async () => {
    const full = (await (await boot([{ tasks: undefined }]))("/tasks/meta")).body;
    const hidden = (await (await boot([{ tasks: { projection: { home: 0 } } }]))("/tasks/meta"))
      .body;
    expect(full.geoSearchable).toBe(true);
    {
      expect(full.crud).toHaveProperty("geo");
      expect(hidden.geoSearchable).toBe(false);
      expect(hidden.crud).not.toHaveProperty("geo");
    }
  });
});

describe("/meta crud ops map to their handler actions", () => {
  it("one ← getOne / getOneComposite, remove ← remove / removeComposite", async () => {
    const get = await boot([], [["tasks", ["meta", "getOneComposite", "removeComposite"]]]);
    const meta = (await get("/tasks/meta")).body;
    expect(Object.keys(meta.crud).toSorted()).toEqual(["one", "remove"]);
  });

  it("an action is authorized by its @DbAction name (never the method @Id)", async () => {
    const byName = await boot([], [["tasks", ["meta", "archive", "tasks.flag"]]]);
    const names = (await byName("/tasks/meta")).body.actions.map((a: { name: string }) => a.name);
    expect(names.toSorted()).toEqual(["archive", "flag"]);
    const byId = await boot([], [["tasks", ["meta", "legacy-archive", "flag"]]]);
    expect((await byId("/tasks/meta")).body.actions).toEqual([]);
  });
});

const factoryRole = (use: ReturnType<typeof allowTableRead<object, ArbacDbScope>>) =>
  defineRole<object, ArbacDbScope>().id("factory").use(use).build();

describe("/meta crud ops follow the table-op factories", () => {
  it("allowTableRead alone → crud.one / query / pages, and GET one/:id serves", async () => {
    const get = await bootRoles([factoryRole(allowTableRead("tasks"))]);
    const meta = (await get("/tasks/meta")).body;
    expect(Object.keys(meta.crud)).toEqual(expect.arrayContaining(["one", "query", "pages"]));
    for (const op of ["insert", "update", "replace", "remove"]) {
      expect(meta.crud).not.toHaveProperty(op);
    }
    const one = await get("/tasks/one/1");
    expect(one.status).toBe(200);
    expect(one.body).toMatchObject({ id: 1, title: "t1" });
    expect((await get("/tasks/one?id=1")).status).toBe(200);
  });

  it("allowTableWrite → every crud op, including remove", async () => {
    const get = await bootRoles([factoryRole(allowTableWrite("tasks"))]);
    const meta = (await get("/tasks/meta")).body;
    expect(Object.keys(meta.crud)).toEqual(
      expect.arrayContaining(["one", "query", "pages", "insert", "update", "replace", "remove"]),
    );
  });

  it("allowTableOps with remove (no read) → crud.remove, not the read ops", async () => {
    const get = await bootRoles([factoryRole(allowTableOps("tasks", ["meta", "remove"]))]);
    const meta = (await get("/tasks/meta")).body;
    expect(Object.keys(meta.crud).toSorted()).toEqual(["remove"]);
    expect((await get("/tasks/one/1")).status).toBe(403);
  });
});
