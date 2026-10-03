import type { AggregateControls, FilterExpr, UniqueryControls } from "@atscript/db";
import { DbSpace } from "@atscript/db";
import { BetterSqlite3Driver, SqliteAdapter } from "@atscript/db-sqlite";
import {
  clearDbSpaces,
  provideDbSpace,
  ReadableController,
  TableController,
  type ValueHelpQuery,
  type ValueHelpSelect,
} from "@atscript/moost-db";
import { Get, type MoostHttp } from "@moostjs/event-http";
import { clearGlobalWooks, Controller, Inherit, Moost } from "moost";
import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

import { bootArbacHttp } from "../__testing__/arbac-http";
import { readerRole, request } from "../__testing__/http";
import { FakeUserProvider } from "../__testing__/user-provider";
import { ArbacAction, ArbacResource } from "../arbac.decorator";
import { MoostArbac } from "../moost-arbac";
import { ScopedDoc } from "./__test__/fixtures/scoped-doc.as";
import { type ArbacDbScope, AsArbacDbController } from "./as-arbac-db-controller";
import { AsArbacDbReadableController } from "./as-arbac-db-readable-controller";
import {
  AsArbacJsonValueHelpController,
  AsArbacValueHelpController,
} from "./as-arbac-value-help-controller";
import { useArbacDbScope } from "./use-arbac-db-scope";

/**
 * Async subclass overrides of the ARBAC controllers' `transformFilter` /
 * `transformProjection`. moost-db types these hooks `X | Promise<X>` and
 * awaits them; the ARBAC overrides compute synchronously but must keep that
 * contract, or an app's `protected async transformFilter(f) { … await
 * super.transformFilter(f) … }` fails inheritance (TS2416). The classes below
 * are the compile-time check (`vp lint` type-checks spec files); the tests
 * pin that the async filter and the ARBAC scope filter BOTH apply — ordinary
 * reads, built-in `$groupBy` reads and a custom aggregate route.
 */

type Row = { id: number; title: string; status: string; secret: string; rank: number };
const ROWS: Row[] = [
  { id: 1, title: "a", status: "open", secret: "s1", rank: 1 },
  { id: 2, title: "b", status: "open", secret: "s2", rank: 5 },
  { id: 3, title: "c", status: "done", secret: "s3", rank: 1 },
  { id: 4, title: "d", status: "open", secret: "s4", rank: 2 },
];

// Scope: `status = open` (rows 1, 2, 4), `secret` hidden.
// Async override: `rank <= 2` (rows 1, 3, 4). Both → rows 1 and 4.
const reader = readerRole<ArbacDbScope>("reader", {
  "async-docs": { filter: { status: "open" }, projection: { secret: 0 } },
});

/** A bounded async lookup (e.g. a per-tenant setting fetched from another service). */
async function lookupMaxRank(): Promise<number> {
  await new Promise((resolve) => setTimeout(resolve, 1));
  return 2;
}

/** The async part of every override below: `filter ∧ rank <= <looked-up max>`. */
async function withRankBound(filter: FilterExpr): Promise<FilterExpr> {
  return { $and: [filter, { rank: { $lte: await lookupMaxRank() } }] };
}

type TSelect = UniqueryControls["$select"];

const STATS_CONTROLS: AggregateControls = {
  $groupBy: ["status"],
  $select: ["status", { $fn: "count", $field: "*", $as: "n" }],
};

@TableController(ScopedDoc, "async-docs")
@ArbacResource("async-docs")
class AsyncDocsController extends AsArbacDbController<typeof ScopedDoc> {
  protected override async transformFilter(filter: FilterExpr): Promise<FilterExpr> {
    return withRankBound(await super.transformFilter(filter));
  }

  protected override async transformProjection(projection?: TSelect): Promise<TSelect | undefined> {
    await lookupMaxRank();
    return super.transformProjection(projection);
  }

  /** Custom grouped read: resolves the scopes, then goes through the (async) hook. */
  @Get("stats")
  @ArbacAction("query")
  async stats() {
    await useArbacDbScope();
    return this.readable.aggregate({
      filter: await this.transformFilter({}),
      controls: STATS_CONTROLS,
    });
  }
}

@ReadableController(ScopedDoc, "async-docs-view")
@ArbacResource("async-docs")
class AsyncDocsReadableController extends AsArbacDbReadableController<typeof ScopedDoc> {
  protected override async transformFilter(filter: FilterExpr): Promise<FilterExpr> {
    return withRankBound(await super.transformFilter(filter));
  }

  protected override async transformProjection(projection?: TSelect): Promise<TSelect | undefined> {
    await lookupMaxRank();
    return super.transformProjection(projection);
  }

  @Get("stats")
  @ArbacAction("query")
  async stats() {
    await useArbacDbScope();
    return this.readable.aggregate({
      filter: await this.transformFilter({}),
      controls: STATS_CONTROLS,
    });
  }
}

@Inherit()
@Controller("async-vh")
@ArbacResource("async-docs")
class AsyncJsonVhController extends AsArbacJsonValueHelpController<typeof ScopedDoc> {
  constructor(app: Moost) {
    super(ScopedDoc, ROWS, app, "async-vh");
  }

  protected override async transformFilter(filter: FilterExpr): Promise<FilterExpr> {
    return withRankBound(await super.transformFilter(filter));
  }

  protected override async transformProjection(
    select: ValueHelpSelect<Row> | undefined,
  ): Promise<ValueHelpSelect<Row> | undefined> {
    await lookupMaxRank();
    return super.transformProjection(select);
  }
}

// Bring-your-own-source variant: records the filter the seams hand `query`.
const seen: ValueHelpQuery<Row>[] = [];
@Inherit()
@Controller("async-byo")
@ArbacResource("async-docs")
class AsyncByoVhController extends AsArbacValueHelpController<typeof ScopedDoc> {
  constructor(app: Moost) {
    super(ScopedDoc, "async-byo", app);
  }

  protected override async transformFilter(filter: FilterExpr): Promise<FilterExpr> {
    return withRankBound(await super.transformFilter(filter));
  }

  protected async query(q: ValueHelpQuery<Row>) {
    seen.push(q);
    return { data: [] as Row[], count: 0 };
  }

  protected async getOne(id: string | number) {
    return ROWS.find((r) => String(r.id) === String(id)) ?? null;
  }
}

let driver: BetterSqlite3Driver;

beforeAll(async () => {
  driver = new BetterSqlite3Driver(":memory:");
  const space = new DbSpace(() => new SqliteAdapter(driver));
  const table = space.getTable(ScopedDoc);
  await table.ensureTable();
  await table.insertMany(ROWS);
  provideDbSpace(space);
});

afterAll(() => {
  clearDbSpaces();
  driver.close();
});

async function boot() {
  clearGlobalWooks();
  const arbac = new MoostArbac<object, ArbacDbScope>();
  arbac.registerRole(reader);
  const http: MoostHttp = await bootArbacHttp({
    arbac,
    user: new FakeUserProvider("u1", ["reader"]),
    controllers: [
      AsyncDocsController,
      AsyncDocsReadableController,
      AsyncJsonVhController,
      AsyncByoVhController,
    ],
    authorize: true,
  });
  return (path: string) => request(http, "GET", path);
}

const ids = (body: Array<{ id: number }>) => body.map((r) => r.id);

describe.each([
  ["AsArbacDbController", "/async-docs"],
  ["AsArbacDbReadableController", "/async-docs-view"],
])("%s — async transformFilter / transformProjection override", (_name, base) => {
  it("ordinary reads apply the async filter AND the scope filter + projection", async () => {
    const get = await boot();
    const q = await get(`${base}/query?$sort=id`);
    expect(q.status).toBe(200);
    expect(q.body).toEqual([
      { id: 1, title: "a", status: "open", rank: 1 },
      { id: 4, title: "d", status: "open", rank: 2 },
    ]);
    // A request filter cannot widen either one.
    expect(ids((await get(`${base}/query?status='done'`)).body)).toEqual([]);
    expect(ids((await get(`${base}/query?rank>2`)).body)).toEqual([]);
    expect((await get(`${base}/pages`)).body).toMatchObject({ count: 2 });
    expect((await get(`${base}/query?$count=true`)).body).toBe(2);
  });

  it("/one answers 404 outside either filter", async () => {
    const get = await boot();
    expect((await get(`${base}/one/1`)).status).toBe(200);
    expect((await get(`${base}/one/2`)).status).toBe(404); // in scope, rank 5
    expect((await get(`${base}/one/3`)).status).toBe(404); // rank 1, out of scope
  });

  it("built-in $groupBy reads count only rows passing both filters", async () => {
    const get = await boot();
    const r = await get(`${base}/query?$select=status,count(*):n&$groupBy=status`);
    expect(r.status).toBe(200);
    expect(r.body).toEqual([{ status: "open", n: 2 }]);
  });

  it("a custom aggregate route awaiting transformFilter gets both filters", async () => {
    const get = await boot();
    const r = await get(`${base}/stats`);
    expect(r.status).toBe(200);
    expect(r.body).toEqual([{ status: "open", n: 2 }]);
  });
});

describe("ARBAC value-help controllers — async transformFilter override", () => {
  it("AsArbacJsonValueHelpController applies the async filter AND the scope", async () => {
    const get = await boot();
    const q = await get("/async-vh/query");
    expect(q.status).toBe(200);
    expect(q.body).toEqual([
      { id: 1, title: "a", status: "open", rank: 1 },
      { id: 4, title: "d", status: "open", rank: 2 },
    ]);
    expect((await get("/async-vh/pages")).body).toMatchObject({ count: 2 });
    expect((await get("/async-vh/one/1")).status).toBe(200);
    expect((await get("/async-vh/one/2")).status).toBe(404);
    expect((await get("/async-vh/one/3")).status).toBe(404);
  });

  it("AsArbacValueHelpController hands query() the async filter AND the scope", async () => {
    seen.length = 0;
    const get = await boot();
    expect((await get("/async-byo/query")).status).toBe(200);
    const filter = JSON.stringify(seen[0]?.filter);
    expect(filter).toContain('"status":"open"');
    expect(filter).toContain('"rank":{"$lte":2}');
  });
});
