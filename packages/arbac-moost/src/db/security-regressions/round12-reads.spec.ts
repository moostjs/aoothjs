// Read-side features of atscript-db 0.1.148 under ARBAC: `/meta.fields[*].groupable`
// and `ui.valueHelp` dictionary bindings in the `/meta` overlay, `@DbDecorations`
// columns, aggregate expressions / first-last / `$rowOrder`.
import { allowTableAction, allowTableRead, defineRole } from "@aooth/arbac";
import {
  DbAction,
  DbActionID,
  DbDecorations,
  InputForm,
  TableController,
} from "@atscript/moost-db";
import type { TDbDecorateContext } from "@atscript/moost-db";
import type { MoostHttp } from "@moostjs/event-http";
import { Post } from "@moostjs/event-http";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { ArbacResource } from "../../arbac.decorator";
import { type ArbacDbScope, AsArbacDbController } from "../as-arbac-db-controller";
import {
  R12Decorations,
  R12Dict,
  R12DictForm,
  R12Item,
  R12NestedForm,
} from "./fixtures/round12-fixtures.as";
import { readerRole, request } from "../../__testing__/http";
import { boot } from "./relations-harness";
import { createR12Space, type R12Space } from "./round12-harness";

@TableController(R12Dict as never, "r12-dicts")
@ArbacResource("dicts")
class DictsController extends AsArbacDbController<typeof R12Dict> {}

@TableController(R12Item as never, "items")
@ArbacResource("items")
class ItemsController extends AsArbacDbController<typeof R12Item> {}

@TableController(R12Item as never, "decorated")
@ArbacResource("decorated")
@DbDecorations(R12Decorations as never, { requires: { ownerName: ["ownerId"] } })
class DecoratedController extends AsArbacDbController<typeof R12Item> {
  protected decorateRows(rows: Record<string, unknown>[], ctx: TDbDecorateContext) {
    if (!ctx.decorations.has("ownerName")) return;
    for (const row of rows) row.ownerName = `owner-${String(row.ownerId)}`;
  }
}

@TableController(R12Item as never, "form-items")
@ArbacResource("formitems")
class FormItemsController extends AsArbacDbController<typeof R12Item> {
  @Post("actions/tag")
  @DbAction("tag", { label: "tag" })
  tag(@DbActionID() _id: unknown, @InputForm(R12DictForm as never) _input: unknown) {
    return { ok: true };
  }

  @Post("actions/nested")
  @DbAction("nested", { label: "nested" })
  nested(@DbActionID() _id: unknown, @InputForm(R12NestedForm as never) _input: unknown) {
    return { ok: true };
  }
}

type Grants = Record<string, ArbacDbScope | undefined>;
let space: R12Space;
let http: MoostHttp;

async function bootGrants(grants: Grants) {
  ({ http } = await boot(
    [readerRole("reader", grants)],
    [DictsController, ItemsController, DecoratedController, FormItemsController],
    ["reader"],
  ));
}
const get = (path: string) => request(http, "GET", path);

beforeAll(async () => {
  space = await createR12Space();
});
afterAll(() => space.close());
beforeEach(() => space.seed());

const groupableFields = (meta: any): string[] =>
  Object.entries<any>(meta.fields)
    .filter(([, f]) => f.groupable)
    .map(([p]) => p)
    .toSorted();

describe("/meta.fields[*].groupable follows controls.$groupBy", () => {
  it("no policy: the flag is served as moost-db builds it", async () => {
    await bootGrants({ items: undefined });
    const meta = (await get("/items/meta")).body;
    expect(groupableFields(meta)).toEqual(expect.arrayContaining(["owner", "status", "rank"]));
  });

  it("$groupBy: false drops it everywhere (and the query answers 403)", async () => {
    await bootGrants({ items: { controls: { $groupBy: false } } });
    const meta = (await get("/items/meta")).body;
    expect(meta.fields.status).toBeDefined();
    expect(groupableFields(meta)).toEqual([]);
    // every aggregate / arithmetic `$select` is `$groupBy` use: no aggregate surface
    expect(Object.values<any>(meta.fields).some((f) => f.numeric || f.bucketable)).toBe(false);
    expect(meta.aggregateFns).toBeUndefined();
    expect(meta.aggregateExpressions).toBeUndefined();
    expect(meta.bucketUnits).toBeUndefined();
    expect(meta.crud.query).not.toContain("groupBy");
    const r = await get("/items/query?$select=status,count(*):n&$groupBy=status");
    expect(r.status).toBe(403);
  });

  it("a whitelist keeps it only on the listed paths, mirroring the 403 gate", async () => {
    await bootGrants({ items: { controls: { $groupBy: ["status"] } } });
    const meta = (await get("/items/meta")).body;
    expect(groupableFields(meta)).toEqual(["status"]);
    expect(meta.fields.owner.groupable).toBeUndefined();
    // ungrouped aggregates and arithmetic stay allowed under a whitelist
    expect(meta.fields.rank.numeric).toBe(true);
    expect(meta.aggregateFns).toContain("sum");
    expect(meta.crud.query).toContain("groupBy");
    expect((await get("/items/query?$select=status,count(*):n&$groupBy=status")).status).toBe(200);
    expect((await get("/items/query?$select=owner,count(*):n&$groupBy=owner")).status).toBe(403);
  });

  it("a hidden field is gone from /meta and its $groupBy is 400", async () => {
    await bootGrants({ items: { projection: { rank: 0 } } });
    const meta = (await get("/items/meta")).body;
    expect(meta.fields.rank).toBeUndefined();
    const r = await get("/items/query?$select=rank,count(*):n&$groupBy=rank");
    expect(r.status).toBe(400);
    expect(r.text).toContain('Unknown field \\"rank\\"');
  });

  it("$sort: false → nothing sortable in /meta (and $sort is 403); $nulls stays for $rowOrder", async () => {
    await bootGrants({ items: { controls: { $sort: false } } });
    const meta = (await get("/items/meta")).body;
    expect(Object.values<any>(meta.fields).some((f) => f.sortable)).toBe(false);
    expect(meta.crud.query).not.toContain("sort");
    expect(meta.crud.pages).not.toContain("sort");
    expect(meta.crud.pages).not.toContain("nulls");
    expect((await get("/items/query?$sort=rank")).status).toBe(403);
    // NULL placement of a `$rowOrder` key is still usable: advertised and served
    expect(meta.crud.query).toContain("nulls");
    expect(meta.nullsPlacement).toBe(true);
    const r = await get(
      "/items/query?$select=status,first(rank):f&$groupBy=status&$rowOrder=-createdAt:last",
    );
    expect(r.status).toBe(200);
  });

  // moost-db adds the decoration `fields` entries AFTER `applyMetaOverlay`, so
  // the overlay cannot gate them: this holds only while moost-db serves them
  // `sortable: false` (fails if a decoration ever becomes sortable).
  it("$sort: false → no decoration field is sortable either", async () => {
    await bootGrants({ decorated: { controls: { $sort: false } } });
    const meta = (await get("/decorated/meta")).body;
    expect(meta.fields.ownerName).toMatchObject({ decoration: true });
    expect(Object.values<any>(meta.fields).some((f) => f.sortable)).toBe(false);
  });

  it("each read op follows its own policy: an unscoped getOne grant re-advertises nothing", async () => {
    ({ http } = await boot(
      [
        readerRole("reader", { items: { controls: { $groupBy: false, $sort: false } } }),
        defineRole<object, ArbacDbScope>()
          .id("lookup")
          .use(allowTableAction("items", "getOne"))
          .build(),
      ],
      [DictsController, ItemsController, DecoratedController, FormItemsController],
      ["reader", "lookup"],
    ));
    const meta = (await get("/items/meta")).body;
    expect(groupableFields(meta)).toEqual([]);
    expect(meta.aggregateFns).toBeUndefined();
    expect(Object.values<any>(meta.fields).some((f) => f.sortable)).toBe(false);
    expect(meta.crud.query).not.toContain("groupBy");
    expect((await get("/items/query?$select=status,count(*):n&$groupBy=status")).status).toBe(403);
  });

  it("$sort and $groupBy false → no NULL placement in /meta", async () => {
    await bootGrants({ items: { controls: { $sort: false, $groupBy: false } } });
    const meta = (await get("/items/meta")).body;
    expect(meta.nullsPlacement).toBeUndefined();
    expect(meta.crud.query).not.toContain("nulls");
    expect(meta.crud.query).not.toContain("rowOrder");
  });

  // moost-db's `/query` gives an ungrouped aggregate (aggregate `$select`, no
  // `$groupBy`) `$groupBy: []` before `validateControls` runs.
  describe("an ungrouped aggregate counts as $groupBy use", () => {
    const sumRank = "/items/query?$select=sum(rank):total";

    it("$groupBy: false → 403", async () => {
      await bootGrants({ items: { controls: { $groupBy: false } } });
      expect((await get(sumRank)).status).toBe(403);
    });

    it("a whitelist allows it (no column grouped on)", async () => {
      await bootGrants({ items: { controls: { $groupBy: ["status"] } } });
      const r = await get(sumRank);
      expect(r.status).toBe(200);
      expect(r.body).toEqual([{ total: 15 }]);
    });

    it("an aggregate over a hidden field is still 400", async () => {
      await bootGrants({ items: { projection: { rank: 0 } } });
      const r = await get(sumRank);
      expect(r.status).toBe(400);
      expect(r.text).toContain('Unknown field \\"rank\\"');
    });
  });
});

const binding = (meta: any, prop: string) => meta.type.type.props[prop]?.metadata?.["ui.valueHelp"];

describe("ui.valueHelp bindings in /meta.type", () => {
  it("a readable dictionary keeps the binding unchanged", async () => {
    await bootGrants({ items: undefined, dicts: undefined });
    const meta = (await get("/items/meta")).body;
    for (const prop of ["color", "pinned", "filtered"])
      expect(binding(meta, prop), prop).toBeDefined();
    expect(binding(meta, "color")).toMatchObject({ field: "code" });
    // A row scope on the dictionary hides no field the binding names: nothing changes.
    await bootGrants({ items: undefined, dicts: { filter: { region: "eu" } } });
    expect((await get("/items/meta")).body.type).toEqual(meta.type);
  });

  it("a dictionary the caller cannot read drops every binding to it", async () => {
    await bootGrants({ items: undefined });
    const meta = (await get("/items/meta")).body;
    expect(meta.type.type.props.color).toBeDefined();
    for (const prop of ["color", "pinned", "filtered"])
      expect(binding(meta, prop), prop).toBeUndefined();
  });

  it("a binding whose committed field or filter field is hidden on the dictionary is dropped", async () => {
    await bootGrants({ items: undefined, dicts: { projection: { secretCode: 0 } } });
    const meta = (await get("/items/meta")).body;
    // `color` commits `code`, filters on `region`: both visible.
    expect(binding(meta, "color")).toMatchObject({ field: "code" });
    // `pinned` commits the hidden `secretCode`; `filtered` filters on it.
    expect(binding(meta, "pinned")).toBeUndefined();
    expect(binding(meta, "filtered")).toBeUndefined();
  });
});

describe("@DbDecorations under a read scope", () => {
  it("a scope hiding the source column hides the decoration everywhere", async () => {
    await bootGrants({ decorated: { projection: { ownerId: 0 } } });
    const meta = (await get("/decorated/meta")).body;
    expect(meta.fields.ownerName).toBeUndefined();
    expect(meta.fields.ownerId).toBeUndefined();
    const sel = await get("/decorated/query?$select=ownerName");
    expect(sel.status).toBe(400);
    expect(sel.text).toContain('Unknown field \\"ownerName\\"');
    // The hidden-source answer is the unknown-field answer — no oracle.
    const unknown = await get("/decorated/query?$select=nope");
    expect(sel.body.message.replace("ownerName", "nope")).toBe(unknown.body.message);
    const rows = (await get("/decorated/query?$sort=id")).body as Array<Record<string, unknown>>;
    expect(rows).toHaveLength(3);
    for (const row of rows) {
      expect(row).not.toHaveProperty("ownerName");
      expect(row).not.toHaveProperty("ownerId");
    }
  });

  it("a visible scope serves the decoration; the source column is not in the row unless selected", async () => {
    await bootGrants({ decorated: undefined });
    const meta = (await get("/decorated/meta")).body;
    expect(meta.fields.ownerName).toMatchObject({ decoration: true });
    const rows = (await get("/decorated/query?$select=id,ownerName&$sort=id")).body;
    expect(rows).toEqual([
      { id: 1, ownerName: "owner-1" },
      { id: 2, ownerName: "owner-1" },
      { id: 3, ownerName: "owner-2" },
    ]);
    const all = (await get("/decorated/query?$sort=id")).body as Array<Record<string, unknown>>;
    expect(all[0]).toMatchObject({ id: 1, ownerName: "owner-1", ownerId: 1 });
    // Selecting only the decoration: the widened source is stripped again (the id stays).
    const only = (await get("/decorated/query?$select=ownerName&$sort=id")).body as Array<
      Record<string, unknown>
    >;
    expect(only.map((r) => Object.keys(r))).toEqual([0, 1, 2].map(() => ["id", "ownerName"]));
    // A decoration is never a filter / sort key.
    expect((await get("/decorated/query?ownerName=owner-1")).status).toBe(400);
  });

  it("a row scope still bounds the rows the decoration is computed for", async () => {
    await bootGrants({ decorated: { filter: { owner: "u2" } } });
    const rows = (await get("/decorated/query?$select=id,ownerName")).body;
    expect(rows).toEqual([{ id: 3, ownerName: "owner-2" }]);
  });
});

describe("aggregate expressions, first / last and $rowOrder obey the field gates", () => {
  const SCOPE_HIDE_RANK: ArbacDbScope = { projection: { rank: 0 } };

  it.each([
    // row-level operand of an aggregate
    ["$select=status,sum(rank*2):s&$groupBy=status", "rank"],
    ["$select=status,sum(createdAt%2Brank):s&$groupBy=status", "rank"],
    // first / last field
    ["$select=status,first(rank):f&$groupBy=status&$rowOrder=createdAt", "rank"],
    ["$select=status,last(rank):f&$groupBy=status&$rowOrder=createdAt", "rank"],
  ])("hidden operand ?%s → 400 Unknown field", async (query, field) => {
    await bootGrants({ items: SCOPE_HIDE_RANK });
    const r = await get(`/items/query?${query}`);
    expect(r.status, r.text).toBe(400);
    expect(r.text).toContain(`Unknown field \\"${field}\\"`);
  });

  it("a hidden $rowOrder key → 400 Unknown field", async () => {
    await bootGrants({ items: SCOPE_HIDE_RANK });
    const r = await get(
      "/items/query?$select=status,first(createdAt):f&$groupBy=status&$rowOrder=rank",
    );
    expect(r.status, r.text).toBe(400);
    expect(r.text).toContain('Unknown field \\"rank\\"');
  });

  it("a group-level expression cannot reach a hidden column either", async () => {
    await bootGrants({ items: SCOPE_HIDE_RANK });
    const r = await get("/items/query?$select=status,max(rank):m,expr(m*2):x&$groupBy=status");
    expect(r.status, r.text).toBe(400);
  });

  it("visible operands compute over in-scope rows only", async () => {
    await bootGrants({ items: { filter: { owner: "u1" } } });
    const sum = await get("/items/query?$select=status,sum(rank*2):s&$groupBy=status");
    expect(sum.status, sum.text).toBe(200);
    expect(sum.body).toEqual([{ status: "open", s: 12 }]);
    const fl = await get(
      "/items/query?$select=status,first(color):a,last(color):b&$groupBy=status&$rowOrder=createdAt",
    );
    expect(fl.status, fl.text).toBe(200);
    expect(fl.body).toEqual([{ status: "open", a: "red", b: "blue" }]);
  });

  it("$rowOrder is a policy-gatable control: false denies it", async () => {
    await bootGrants({ items: { controls: { $rowOrder: false } } });
    const r = await get(
      "/items/query?$select=status,first(color):a&$groupBy=status&$rowOrder=createdAt",
    );
    expect(r.status).toBe(403);
    expect(r.text).toContain("$rowOrder");
    // Other aggregates stay open.
    expect((await get("/items/query?$select=status,count(*):n&$groupBy=status")).status).toBe(200);
  });
});

describe("/meta/form/:name applies the ref / ui.valueHelp overlay", () => {
  const formBinding = (form: any, prop: string) =>
    form.type.props[prop]?.metadata?.["ui.valueHelp"];

  async function bootForm(dicts: ArbacDbScope | undefined | null) {
    const roles = [
      defineRole<object, ArbacDbScope>()
        .id("reader")
        .use(
          allowTableRead("formitems"),
          allowTableAction("formitems", ["tag", "nested"]),
          ...(dicts === null
            ? []
            : [allowTableRead("dicts", dicts ? { scope: () => dicts } : undefined)]),
        )
        .build(),
    ];
    ({ http } = await boot(
      roles,
      [DictsController, ItemsController, DecoratedController, FormItemsController],
      ["reader"],
    ));
  }

  it("a readable dictionary keeps the form's bindings and ref", async () => {
    await bootForm(undefined);
    const r = await get("/form-items/meta/form/R12DictForm");
    expect(r.status, r.text).toBe(200);
    expect(formBinding(r.body, "color")).toMatchObject({ field: "code" });
    expect(formBinding(r.body, "pinned")).toBeDefined();
    expect(r.body.type.props.dictId.ref).toBeDefined();
  });

  it("an unreadable dictionary strips the form's bindings and ref", async () => {
    await bootForm(null);
    const r = await get("/form-items/meta/form/R12DictForm");
    expect(r.status, r.text).toBe(200);
    expect(r.body.type.props.color).toBeDefined();
    for (const prop of ["color", "pinned"]) expect(formBinding(r.body, prop), prop).toBeUndefined();
    expect(r.body.type.props.dictId.ref).toBeUndefined();
  });

  it("a binding naming a field hidden on the dictionary is stripped", async () => {
    await bootForm({ projection: { secretCode: 0 } });
    const r = await get("/form-items/meta/form/R12DictForm");
    expect(formBinding(r.body, "color")).toMatchObject({ field: "code" });
    expect(formBinding(r.body, "pinned")).toBeUndefined();
  });

  it("strips bindings nested in union and tuple members (was kept: only props/of walked)", async () => {
    const pick = (form: any, path: Array<string | number>) =>
      path.reduce((n: any, k) => (typeof k === "number" ? n.type.items[k] : n.type.props[k]), form)
        .metadata?.["ui.valueHelp"];
    await bootForm(undefined);
    const open = await get("/form-items/meta/form/R12NestedForm");
    expect(open.status, open.text).toBe(200);
    expect(pick(open.body, ["either", 0, "pick"])).toBeDefined();
    expect(pick(open.body, ["pair", 0, "pick"])).toBeDefined();
    await bootForm(null);
    const r = await get("/form-items/meta/form/R12NestedForm");
    expect(r.status, r.text).toBe(200);
    expect(pick(r.body, ["either", 0, "pick"])).toBeUndefined();
    expect(pick(r.body, ["pair", 0, "pick"])).toBeUndefined();
    expect(r.body.type.props.note).toBeDefined();
  });
});
