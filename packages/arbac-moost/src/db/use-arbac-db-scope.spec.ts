import { allowTableRead, allowTableWrite, defineRole } from "@aooth/arbac";
import type { TArbacEvalResult } from "@aooth/arbac-core";
import type { AtscriptDbTable } from "@atscript/db";
import { DbSpace } from "@atscript/db";
import { BetterSqlite3Driver, SqliteAdapter } from "@atscript/db-sqlite";
import { Body, Get, type MoostHttp, Post } from "@moostjs/event-http";
import { clearGlobalWooks, Controller, Param } from "moost";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { bootArbacHttp } from "../__testing__/arbac-http";
import { FakeUserProvider } from "../__testing__/user-provider";
import { ArbacAction, ArbacResource } from "../arbac.decorator";
import { getArbacMate } from "../arbac.mate";
import { MoostArbac } from "../moost-arbac";
import { KeyedDoc } from "./__test__/fixtures/keyed-doc.as";
import { RpSlug } from "./security-regressions/fixtures/rel-fixtures.as";
import type { ArbacDbScope } from "./as-arbac-db-controller";
import { useArbacDbScope } from "./use-arbac-db-scope";

/**
 * `useArbacDbScope()` in custom routes over a real SQLite table: the merged
 * row filter is CONJOINED with the caller's extra filter (a spread would let
 * `{ owner: "u2" }` replace the scope's `owner: "u1"`), ids are verified in
 * scope with one count, and a route without cached scopes evaluates lazily
 * and fails closed.
 */

const ownerRole = defineRole<object, ArbacDbScope>()
  .id("owner")
  .use(
    allowTableWrite("keyed", {
      scope: () => ({ filter: { owner: "u1" }, set: { owner: "u1" }, projection: { code: 0 } }),
    }),
  )
  .build();
const checkedRole = defineRole<object, ArbacDbScope>()
  .id("checked")
  .use(
    allowTableRead("keyed", {
      scope: () => ({ filter: { owner: "u2" }, check: { title: "b" }, set: { title: "x" } }),
    }),
  )
  .build();
const noCheckRole = defineRole<object, ArbacDbScope>()
  .id("no-check")
  .use(allowTableRead("keyed", { scope: () => ({ filter: { owner: "u1" }, check: {} }) }))
  .build();
const adminRole = defineRole<object, ArbacDbScope>()
  .id("admin")
  .use(allowTableWrite("keyed"))
  .build();
/** A scope predicate that returns nothing — contributes no scope. */
const voidRole = defineRole<object, ArbacDbScope>()
  .id("void")
  .use(allowTableRead("keyed", { scope: () => undefined as unknown as ArbacDbScope }))
  .build();

const slugRole = defineRole<object, ArbacDbScope>()
  .id("slugs")
  .use(allowTableWrite("slugs", { scope: () => ({ filter: { tenant: "t1" } }) }))
  .build();

let driver: BetterSqlite3Driver;
let table: AtscriptDbTable<typeof KeyedDoc>;
let slugs: AtscriptDbTable<typeof RpSlug>;

const Public = () => getArbacMate().decorate("arbacPublic", true);

@Controller("custom")
@ArbacResource("keyed")
class CustomController {
  @Get("rows")
  @ArbacAction("query")
  async rows() {
    const scope = await useArbacDbScope<typeof KeyedDoc>();
    // Asks for u2's rows — the scope must keep them out.
    return table.findMany({
      filter: scope.filter({ owner: "u2" }),
      controls: { $sort: { id: 1 }, $select: ["id"] },
    } as never);
  }

  @Get("overlay")
  @ArbacAction("query")
  async overlay() {
    const scope = await useArbacDbScope();
    return {
      filter: scope.filter(),
      extra: scope.filter({ id: 1 }),
      set: scope.set(),
      check: scope.check(),
      count: scope.scopes.length,
    };
  }

  @Get("assert/:ids")
  @ArbacAction("update")
  async assert(@Param("ids") ids: string) {
    const scope = await useArbacDbScope();
    await scope.assertRowsInScope(
      table,
      ids.split(",").map((id) => (/^\d+$/.test(id) ? Number(id) : id)),
    );
    return { ok: true };
  }

  @Get("slugs/:ids")
  @ArbacResource("slugs")
  @ArbacAction("update")
  async slugs(@Param("ids") ids: string) {
    const scope = await useArbacDbScope();
    await scope.assertRowsInScope(slugs, ids.split(","));
    return { ok: true };
  }

  @Post("write/insert")
  @ArbacAction("insert")
  async writeInsert(@Body() row: Record<string, unknown>) {
    const scope = await useArbacDbScope<typeof KeyedDoc>();
    await table.insertOne(row, scope.writeOptions(table));
    return { ok: true };
  }

  @Post("write/update")
  @ArbacAction("update")
  async writeUpdate(@Body() patch: Record<string, unknown>) {
    const scope = await useArbacDbScope<typeof KeyedDoc>();
    const r = await table.updateOne(patch, scope.writeOptions(table));
    return { matched: r.matchedCount };
  }

  @Post("write/remove/:id")
  @ArbacAction("remove")
  async writeRemove(@Param("id") id: string) {
    const scope = await useArbacDbScope<typeof KeyedDoc>();
    const r = await table.deleteOne(Number(id), scope.removeOptions(table));
    return { deleted: r.deletedCount };
  }

  @Get("public")
  @ArbacAction("query")
  @Public()
  async publicRoute() {
    const scope = await useArbacDbScope();
    return { filter: scope.filter(), count: scope.scopes.length };
  }
}

/** Allows every request with an EMPTY scope list — the fail-closed edge. */
class ScopelessArbac extends MoostArbac<object, ArbacDbScope> {
  override evaluate(): Promise<TArbacEvalResult<ArbacDbScope>> {
    return Promise.resolve({ allowed: true, scopes: [] });
  }
}

/** Allows every request WITHOUT a scopes list (a scope-agnostic evaluator). */
class ScopeAgnosticArbac extends MoostArbac<object, ArbacDbScope> {
  override evaluate(): Promise<TArbacEvalResult<ArbacDbScope>> {
    return Promise.resolve({ allowed: true });
  }
}

beforeAll(async () => {
  driver = new BetterSqlite3Driver(":memory:");
  const space = new DbSpace(() => new SqliteAdapter(driver));
  table = space.getTable(KeyedDoc);
  await table.ensureTable();
  await table.insertMany([
    { id: 1, code: "K1", title: "a", owner: "u1" },
    { id: 2, code: "K2", title: "b", owner: "u2" },
    { id: 3, code: "K3", title: "c", owner: "u1" },
  ]);
  slugs = space.getTable(RpSlug);
  await slugs.ensureTable();
  // "a" is one row's PK AND another row's unique slug — both in scope.
  await slugs.insertMany([
    { id: "a", slug: "s-a", tenant: "t1", title: "A", version: 1 },
    { id: "z", slug: "a", tenant: "t1", title: "Z", version: 1 },
    { id: "o", slug: "s-o", tenant: "t2", title: "O", version: 1 },
  ]);
});

afterAll(() => {
  driver.close();
});

describe("useArbacDbScope", () => {
  let user: FakeUserProvider;
  let http: MoostHttp;

  async function boot(authorize: boolean, arbac = new MoostArbac<object, ArbacDbScope>()) {
    clearGlobalWooks();
    for (const role of [ownerRole, checkedRole, noCheckRole, adminRole, voidRole, slugRole]) {
      arbac.registerRole(role);
    }
    user = new FakeUserProvider("u1", []);
    http = await bootArbacHttp({ arbac, user, controllers: [CustomController], authorize });
  }

  async function get(path: string): Promise<{ status: number; body: unknown }> {
    const res = await http.request(`/custom/${path}`);
    return { status: res!.status, body: await res!.json() };
  }

  describe("with scopes cached by the authorize interceptor", () => {
    beforeEach(() => boot(true));

    it("conjoins the extra filter with the scope filter — never spreads it", async () => {
      user.roles = ["owner"];
      expect(await get("rows")).toStrictEqual({ status: 200, body: [] });
      user.roles = ["admin"];
      expect(await get("rows")).toStrictEqual({ status: 200, body: [{ id: 2 }] });
    });

    it("exposes the merged filter, set and check (check defaults to filter)", async () => {
      user.roles = ["owner"];
      expect((await get("overlay")).body).toStrictEqual({
        filter: { owner: "u1" },
        extra: { $and: [{ owner: "u1" }, { id: 1 }] },
        set: { owner: "u1" },
        check: { owner: "u1" },
        count: 1,
      });
    });

    it("unions filters and checks across roles; later set overrides win", async () => {
      user.roles = ["owner", "checked"];
      expect((await get("overlay")).body).toStrictEqual({
        filter: { owner: { $in: ["u1", "u2"] } },
        extra: { $and: [{ owner: { $in: ["u1", "u2"] } }, { id: 1 }] },
        set: { owner: "u1", title: "x" },
        check: { $or: [{ owner: "u1" }, { title: "b" }] },
        count: 2,
      });
    });

    it("treats check: {} as no check", async () => {
      user.roles = ["no-check"];
      expect((await get("overlay")).body).toMatchObject({ filter: { owner: "u1" }, check: {} });
    });

    it("returns {} filters for an unrestricted scope", async () => {
      user.roles = ["admin"];
      expect((await get("overlay")).body).toStrictEqual({
        filter: {},
        extra: { id: 1 },
        set: {},
        check: {},
        count: 1,
      });
    });

    describe("assertRowsInScope", () => {
      it("passes when every id is in scope (duplicates count once)", async () => {
        user.roles = ["owner"];
        expect(await get("assert/1,3")).toStrictEqual({ status: 200, body: { ok: true } });
        expect(await get("assert/1,1,3")).toStrictEqual({ status: 200, body: { ok: true } });
      });

      it("404s when any id is out of scope or missing", async () => {
        user.roles = ["owner"];
        for (const ids of ["2", "1,2", "99", "1,99"]) {
          const { status, body } = await get(`assert/${ids}`);
          expect(status, ids).toBe(404);
          expect(body, ids).toMatchObject({ message: "Not found" });
        }
      });

      it("does not identify rows through a scope-hidden unique key", async () => {
        user.roles = ["owner"];
        expect((await get("assert/K1")).status).toBe(404);
        user.roles = ["admin"];
        expect((await get("assert/K1")).status).toBe(200);
      });

      it("resolves each id to exactly ONE row (PK first) — an ambiguous id cannot mask a missing one", async () => {
        // Regression: ids were resolved with the `$or` of every identification,
        // so "a" matched two rows (PK "a" + slug "a") and the count of 2 hid
        // that "missing" names no row at all.
        user.roles = ["slugs"];
        expect((await get("slugs/a,missing")).status).toBe(404);
        expect((await get("slugs/a,z")).status).toBe(200);
        expect((await get("slugs/a")).status).toBe(200);
        // Out of scope by PK → 404, like a missing row.
        expect((await get("slugs/o")).status).toBe(404);
      });

      it("still verifies existence for an unrestricted scope", async () => {
        user.roles = ["admin"];
        expect((await get("assert/1,2,3")).status).toBe(200);
        expect((await get("assert/1,99")).status).toBe(404);
      });
    });
  });

  describe("writeOptions() / removeOptions() — handler writes get the CRUD enforcement", () => {
    beforeEach(() => boot(true));

    const post = async (path: string, body?: unknown) => {
      const res = await http.request(`/custom/${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      return { status: res!.status, body: await res!.json() };
    };

    it("WITH CHECK: an inserted row outside the scope's check is rejected and rolled back", async () => {
      user.roles = ["owner"];
      const bad = await post("write/insert", { id: 50, code: "K50", title: "x", owner: "u2" });
      expect(bad.status).toBe(403);
      expect(await table.count({ filter: { id: 50 } })).toBe(0);
      const ok = await post("write/insert", { id: 51, code: "K51", title: "x", owner: "u1" });
      expect(ok.status).toBe(201);
      await table.deleteOne(51);
    });

    it("USING: an update of an out-of-scope row is a 404; an in-scope one passes", async () => {
      user.roles = ["owner"];
      expect((await post("write/update", { id: 2, title: "hijack" })).status).toBe(404);
      expect((await table.findById(2))?.title).toBe("b");
      expect(await post("write/update", { id: 1, title: "a" })).toMatchObject({
        status: 201,
        body: { matched: 1 },
      });
    });

    it("WITH CHECK on update: moving a row out of the scope is rejected", async () => {
      user.roles = ["owner"];
      expect((await post("write/update", { id: 1, owner: "u2" })).status).toBe(403);
      expect((await table.findById(1))?.owner).toBe("u1");
    });

    it("removeOptions: an out-of-scope row is not deleted (404)", async () => {
      user.roles = ["owner"];
      expect((await post("write/remove/2")).status).toBe(404);
      expect(await table.count({ filter: { id: 2 } })).toBe(1);
    });
  });

  describe("without cached scopes (lazy evaluation)", () => {
    it("evaluates the route's resource/action when the interceptor did not run", async () => {
      await boot(false);
      user.roles = ["owner"];
      expect(await get("rows")).toStrictEqual({ status: 200, body: [] });
      expect((await get("overlay")).body).toMatchObject({ filter: { owner: "u1" } });
    });

    it("403s on a deny", async () => {
      await boot(false);
      user.roles = [];
      expect((await get("overlay")).status).toBe(403);
      // `checked` grants read only — `update` is denied.
      user.roles = ["checked"];
      expect((await get("assert/2")).status).toBe(403);
    });

    it("evaluates on a public route too — `arbacPublic` skips the interceptor, not the scope", async () => {
      await boot(true);
      user.roles = [];
      expect((await get("public")).status).toBe(403);
      user.roles = ["owner"];
      expect(await get("public")).toStrictEqual({
        status: 200,
        body: { filter: { owner: "u1" }, count: 1 },
      });
    });

    it("403s when an allowed evaluation carries no scopes (the unified empty-scope rule)", async () => {
      // Deliberate 0.1.72 change: `allowed` with an EMPTY scope list is a deny
      // (fail closed) — not a scoped grant that matches nothing.
      await boot(false, new ScopelessArbac());
      user.roles = ["admin"];
      expect((await get("overlay")).status).toBe(403);
      expect((await get("rows")).status).toBe(403);
      expect((await get("assert/1")).status).toBe(403);
    });

    it("treats an allowed evaluation WITHOUT a scopes list as unrestricted", async () => {
      await boot(false, new ScopeAgnosticArbac());
      user.roles = [];
      expect((await get("overlay")).body).toStrictEqual({
        filter: {},
        extra: { id: 1 },
        set: {},
        check: {},
        count: 1,
      });
    });

    it("drops a scope predicate that returned nothing (fail closed for that rule)", async () => {
      await boot(false);
      user.roles = ["void", "owner"];
      expect((await get("overlay")).body).toMatchObject({ filter: { owner: "u1" }, count: 1 });
      user.roles = ["void"];
      expect((await get("overlay")).status).toBe(403);
    });
  });
});
