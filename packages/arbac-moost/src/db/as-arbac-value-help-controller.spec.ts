import { allowTableOps, allowTableRead, defineRole } from "@aooth/arbac";
import type { ValueHelpQuery } from "@atscript/moost-db";
import type { MoostHttp } from "@moostjs/event-http";
import { clearGlobalWooks, Controller, Inherit, Moost } from "moost";
import { describe, expect, it } from "vite-plus/test";

import { bootArbacHttp } from "../__testing__/arbac-http";
import { FakeUserProvider } from "../__testing__/user-provider";
import { ArbacResource } from "../arbac.decorator";
import { getArbacMate } from "../arbac.mate";
import { MoostArbac } from "../moost-arbac";
import { ScopedDoc } from "./__test__/fixtures/scoped-doc.as";
import type { ArbacDbScope } from "./as-arbac-db-controller";
import {
  AsArbacJsonValueHelpController,
  AsArbacValueHelpController,
} from "./as-arbac-value-help-controller";

/**
 * ARBAC value-help controllers over HTTP: the same scope contract as the DB
 * controllers (row filter, projection, hidden-field gate, controls gates,
 * `/meta` pruning, fail-closed `prepareRequest`), granted by the standard
 * table READ actions.
 */

type Row = { id: number; title: string; status: string; secret: string; rank: number };
const ROWS: Row[] = [
  { id: 1, title: "Alpha", status: "open", secret: "tok-one", rank: 1 },
  { id: 2, title: "Beta", status: "locked", secret: "tok-two", rank: 2 },
  { id: 3, title: "Gamma", status: "open", secret: "tok-three", rank: 3 },
];

const SCOPE = (): ArbacDbScope => ({
  filter: { status: "open" },
  projection: { secret: 0, rank: 0 },
});

const roles = [
  defineRole<object, ArbacDbScope>()
    .id("reader")
    .use(allowTableRead("vh", { scope: SCOPE }))
    .build(),
  defineRole<object, ArbacDbScope>()
    .id("whitelist")
    .use(allowTableRead("vh", { scope: () => ({ projection: { title: 1 } }) }))
    .build(),
  defineRole<object, ArbacDbScope>()
    .id("no-search")
    .use(allowTableRead("vh", { scope: () => ({ controls: { $search: false } }) }))
    .build(),
  defineRole<object, ArbacDbScope>().id("admin").use(allowTableRead("vh")).build(),
  defineRole<object, ArbacDbScope>()
    .id("meta-only")
    .use(allowTableOps("vh", ["meta"]))
    .build(),
];

@Inherit()
@Controller("vh")
@ArbacResource("vh")
class VhController extends AsArbacJsonValueHelpController<typeof ScopedDoc> {
  constructor(app: Moost) {
    super(ScopedDoc, ROWS, app, "vh");
  }
}

// `@Public()` (auth-moost) writes this flag — it skips the authorize
// interceptor but must NOT skip the value-help controller's own evaluation.
@Inherit()
@Controller("pub")
@ArbacResource("vh")
@(getArbacMate().decorate("arbacPublic", true))
class PublicVhController extends AsArbacJsonValueHelpController<typeof ScopedDoc> {
  constructor(app: Moost) {
    super(ScopedDoc, ROWS, app, "pub");
  }
}

// Bring-your-own-source variant: records what the scoped seams hand `query`.
const seen: ValueHelpQuery<Row>[] = [];
@Inherit()
@Controller("custom")
@ArbacResource("vh")
class CustomVhController extends AsArbacValueHelpController<typeof ScopedDoc> {
  constructor(app: Moost) {
    super(ScopedDoc, "custom", app);
  }
  protected async query(q: ValueHelpQuery<Row>) {
    seen.push(q);
    return { data: [] as Row[], count: 0 };
  }
  protected async getOne(id: string | number) {
    return ROWS.find((r) => String(r.id) === String(id)) ?? null;
  }
}

async function boot(userRoles: string[], authorize = true) {
  clearGlobalWooks();
  const arbac = new MoostArbac<object, ArbacDbScope>();
  for (const role of roles) arbac.registerRole(role);
  const http: MoostHttp = await bootArbacHttp({
    arbac,
    user: new FakeUserProvider("u1", userRoles),
    controllers: [VhController, PublicVhController, CustomVhController],
    authorize,
  });
  return async (path: string) => {
    // Paths default to the `vh` controller; `pub/…` / `custom/…` address the others.
    const res = await http.request(/^(pub|custom)\//.test(path) ? `/${path}` : `/vh/${path}`);
    return { status: res!.status, body: (await res!.json()) as any };
  };
}

const ids = (body: Row[]) => body.map((r) => r.id);

describe("AsArbacJsonValueHelpController — allowTableRead grants the value-help routes", () => {
  it("serves /query, /pages, /one and /meta to an unscoped table-read grant", async () => {
    const get = await boot(["admin"]);
    const q = await get("query");
    expect(q.status).toBe(200);
    expect(q.body).toEqual(ROWS);
    const p = await get("pages?$size=2");
    expect(p.status).toBe(200);
    expect(p.body).toMatchObject({ count: 3, pages: 2 });
    expect((await get("one/2")).body).toEqual(ROWS[1]);
    expect((await get("one?id=2")).body).toEqual(ROWS[1]);
    const meta = await get("meta");
    expect(meta.status).toBe(200);
    expect(Object.keys(meta.body.fields)).toEqual(["id", "title", "status", "secret", "rank"]);
    expect(Object.keys(meta.body.crud)).toEqual(expect.arrayContaining(["query", "pages"]));
  });

  it("/meta crud.one follows the allowTableRead grant (runGetOne → getOne)", async () => {
    const get = await boot(["admin"]);
    for (const path of ["meta", "custom/meta"]) {
      const meta = await get(path);
      expect(meta.status, path).toBe(200);
      expect(Object.keys(meta.body.crud), path).toEqual(
        expect.arrayContaining(["query", "pages", "one"]),
      );
    }
    expect((await get("custom/one/2")).status).toBe(200);
    // A meta-only grant advertises no read op.
    const metaOnly = (await (await boot(["meta-only"]))("meta")).body;
    expect(metaOnly.crud).not.toHaveProperty("one");
    expect(metaOnly.crud).not.toHaveProperty("query");
  });
});

describe("AsArbacJsonValueHelpController — row scope", () => {
  it("conjoins the scope filter into /query and /pages", async () => {
    const get = await boot(["reader"]);
    expect(ids((await get("query")).body)).toEqual([1, 3]);
    // A request filter cannot widen the scope (never spread over it).
    expect(ids((await get("query?status='locked'")).body)).toEqual([]);
    expect((await get("pages")).body).toMatchObject({ count: 2 });
  });

  it("answers 404 for a row outside the scope on both /one routes", async () => {
    const get = await boot(["reader"]);
    expect((await get("one/1")).status).toBe(200);
    expect((await get("one/2")).status).toBe(404);
    expect((await get("one?id=2")).status).toBe(404);
  });
});

describe("AsArbacJsonValueHelpController — column scope", () => {
  it("strips hidden columns from every read", async () => {
    const get = await boot(["reader"]);
    expect((await get("query")).body).toEqual([
      { id: 1, title: "Alpha", status: "open" },
      { id: 3, title: "Gamma", status: "open" },
    ]);
    expect((await get("pages")).body.data[0]).toEqual({ id: 1, title: "Alpha", status: "open" });
    expect((await get("one/1")).body).toEqual({ id: 1, title: "Alpha", status: "open" });
    expect((await get("query?$select=title")).body).toEqual([
      { title: "Alpha" },
      { title: "Gamma" },
    ]);
  });

  it("keeps the PK under an inclusion-scope projection", async () => {
    const get = await boot(["whitelist"]);
    expect((await get("query")).body).toEqual(ROWS.map(({ id, title }) => ({ id, title })));
    expect((await get("one/2")).body).toEqual({ id: 2, title: "Beta" });
    expect((await get("query?$select=title")).body[0]).toEqual({ title: "Alpha" });
  });

  it.each([
    ["filter", "query?secret='tok-two'"],
    ["sort", "query?$sort=rank"],
    ["select", "query?$select=secret"],
    ["pages filter", "pages?rank>1"],
  ])("rejects a hidden field in %s like an unknown one", async (_label, path) => {
    const get = await boot(["reader"]);
    const res = await get(path);
    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/Unknown field "(secret|rank)"/);
  });

  it("never matches $search against a hidden field", async () => {
    const admin = await boot(["admin"]);
    expect(ids((await admin("query?$search=tok-two")).body)).toEqual([2]);
    const reader = await boot(["whitelist"]);
    expect((await reader("query?$search=tok-two")).body).toEqual([]);
    expect(ids((await reader("query?$search=beta")).body)).toEqual([2]);
  });

  it("prunes /meta fields, type and the searchable flag", async () => {
    const get = await boot(["reader"]);
    const meta = (await get("meta")).body;
    expect(Object.keys(meta.fields)).toEqual(["id", "title", "status"]);
    expect(Object.keys(meta.type.type.props)).toEqual(["id", "title", "status"]);
    expect(meta.searchable).toBe(true);
    const whitelist = (await (await boot(["whitelist"]))("meta")).body;
    expect(Object.keys(whitelist.fields)).toEqual(["id", "title"]);
  });

  it("enforces scope control gates", async () => {
    const get = await boot(["no-search"]);
    expect((await get("query")).status).toBe(200);
    expect((await get("query?$search=alpha")).status).toBe(403);
  });
});

describe("AsArbacJsonValueHelpController — fail closed", () => {
  it("denies an ungranted principal with 403 on every route", async () => {
    const get = await boot([]);
    for (const path of ["query", "pages", "one/1", "one?id=1", "meta"]) {
      expect((await get(path)).status).toBe(403);
    }
  });

  it("serves /meta but not the data routes to a meta-only grant", async () => {
    const get = await boot(["meta-only"]);
    expect((await get("meta")).status).toBe(200);
    expect((await get("query")).status).toBe(403);
    expect((await get("one/1")).status).toBe(403);
  });

  it("evaluates in prepareRequest when no authorize interceptor is wired", async () => {
    const scoped = await boot(["reader"], false);
    expect((await scoped("query")).body).toEqual([
      { id: 1, title: "Alpha", status: "open" },
      { id: 3, title: "Gamma", status: "open" },
    ]);
    expect((await scoped("one/2")).status).toBe(404);
    expect((await scoped("query?$sort=secret")).status).toBe(400);
    const none = await boot([], false);
    expect((await none("query")).status).toBe(403);
    expect((await none("one/1")).status).toBe(403);
    expect((await none("meta")).status).toBe(403);
  });

  it("does not let arbacPublic bypass the controller's evaluation", async () => {
    const none = await boot([]);
    expect((await none("pub/query")).status).toBe(403);
    expect((await none("pub/one/1")).status).toBe(403);
    const scoped = await boot(["reader"]);
    expect(ids((await scoped("pub/query")).body)).toEqual([1, 3]);
    expect((await scoped("pub/query")).body[0]).not.toHaveProperty("secret");
  });
});

describe("AsArbacValueHelpController (custom source)", () => {
  it("hands query the scoped filter and restricted projection", async () => {
    seen.length = 0;
    const get = await boot(["reader"]);
    expect((await get("custom/query?title='Alpha'&$select=title,secret")).status).toBe(400);
    expect((await get("custom/query?title='Alpha'&$select=title,status")).status).toBe(200);
    expect(seen).toHaveLength(1);
    expect(seen[0].filter).toEqual({ $and: [{ status: "open" }, { title: "Alpha" }] });
    expect(seen[0].controls.$select).toEqual({ title: 1, status: 1 });
    await get("custom/query");
    expect(seen[1].filter).toEqual({ status: "open" });
    expect(seen[1].controls.$select).toEqual({ secret: 0, rank: 0 });
  });

  it("applies the overlay to getOne rows and denies ungranted principals", async () => {
    const get = await boot(["reader"]);
    expect((await get("custom/one/1")).body).toEqual({ id: 1, title: "Alpha", status: "open" });
    expect((await get("custom/one/2")).status).toBe(404);
    const none = await boot([]);
    expect((await none("custom/query")).status).toBe(403);
  });
});
