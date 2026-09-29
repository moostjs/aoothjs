import { DbSpace } from "@atscript/db";
import { clearDbSpaces, provideDbSpace, TableController } from "@atscript/moost-db";
import { clearGlobalWooks } from "moost";
import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

import { bootArbacHttp } from "../__testing__/arbac-http";
import { loadMemoryAdapter, readerRole } from "../__testing__/http";
import { FakeUserProvider } from "../__testing__/user-provider";
import { ArbacResource } from "../arbac.decorator";
import { MoostArbac } from "../moost-arbac";
import { PolOrg, PolTask, PolUser } from "./__test__/fixtures/read-policy.as";
import { type ArbacDbScope, AsArbacDbController } from "./as-arbac-db-controller";

/**
 * The adapter-specific half of read-policy.integration.spec.ts: on a
 * document-style adapter (`@atscript/db-memory`) a `@db.json` column's
 * sub-paths ARE addressable, so a scope keeps sub-path precision there (the
 * SQL adapters treat the column atomically). Derived columns still follow
 * their source.
 */

@TableController(PolTask, "mem-tasks")
@ArbacResource("tasks")
class TasksController extends AsArbacDbController<typeof PolTask> {}

@TableController(PolUser, "mem-users")
@ArbacResource("users")
class UsersController extends AsArbacDbController<typeof PolUser> {}

beforeAll(async () => {
  const MemoryAdapter = await loadMemoryAdapter();
  const space = new DbSpace(() => new MemoryAdapter());
  for (const t of [PolOrg, PolUser, PolTask]) await space.getTable(t as never).ensureTable();
  await space.getTable(PolUser).insertMany([
    { id: 1, name: "alice", tenant: "a", salary: 10 },
    { id: 2, name: "bob", tenant: "b", salary: 777 },
  ]);
  await space.getTable(PolTask).insertMany([
    {
      id: 1,
      title: "t1",
      secretNote: "zebra",
      tenant: "a",
      ownerId: 2,
      settings: { apiKey: "K1", theme: "dark" },
      home: [2.35, 48.85],
    },
  ] as never);
  provideDbSpace(space);
});

afterAll(() => clearDbSpaces());

async function boot(grants: Record<string, ArbacDbScope | undefined>) {
  clearGlobalWooks();
  const arbac = new MoostArbac<object, ArbacDbScope>();
  arbac.registerRole(readerRole("r", grants));
  const http = await bootArbacHttp({
    arbac,
    user: new FakeUserProvider("u1", ["r"]),
    controllers: [TasksController, UsersController],
    authorize: true,
  });
  return async (path: string) => {
    const res = await http.request(path);
    return { status: res!.status, body: (await res!.json()) as any };
  };
}

describe("memory adapter: JSON sub-paths stay precise", () => {
  it("a hidden JSON leaf hides only that leaf (and the derived copy of it)", async () => {
    const get = await boot({ tasks: { projection: { "settings.apiKey": 0 } } });
    const rows = await get("/mem-tasks/query");
    expect(rows.status).toBe(200);
    expect(rows.body[0].settings).toEqual({ theme: "dark" });
    expect(rows.body[0]).not.toHaveProperty("apiKeyCopy");
    expect((await get("/mem-tasks/query?settings.theme='dark'&$select=id")).body).toEqual([
      { id: 1 },
    ]);
    const hidden = await get("/mem-tasks/query?settings.apiKey='K1'");
    expect(hidden.status).toBe(400);
    expect(hidden.body).toMatchObject({ message: 'Unknown field "settings.apiKey"' });
    const meta = (await get("/mem-tasks/meta")).body;
    expect(Object.keys(meta.type.type.props.settings.type.props)).toEqual(["theme"]);
    expect(meta.type.type.props).not.toHaveProperty("apiKeyCopy");
  });
});

describe("memory adapter: $with inherit-target", () => {
  it("joined rows follow the caller's own users grant; none → Unknown relation", async () => {
    const scoped = await boot({ tasks: undefined, users: { filter: { tenant: "a" } } });
    const r = await scoped("/mem-tasks/query?$with=owner");
    expect(r.status).toBe(200);
    expect(r.body[0].owner).toBeNull();

    const none = await boot({ tasks: undefined });
    const hidden = await none("/mem-tasks/query?$with=owner");
    expect(hidden.status).toBe(400);
  });
});
