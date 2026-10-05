// Read-side features of atscript-db 0.1.148 under ARBAC: `/meta.fields[*].groupable`
// and `ui.valueHelp` dictionary bindings in the `/meta` overlay, `@DbDecorations`
// columns, aggregate expressions / first-last / `$rowOrder`.
import { DbDecorations, TableController } from "@atscript/moost-db";
import type { TDbDecorateContext } from "@atscript/moost-db";
import type { MoostHttp } from "@moostjs/event-http";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { ArbacResource } from "../../arbac.decorator";
import { type ArbacDbScope, AsArbacDbController } from "../as-arbac-db-controller";
import { R12Decorations, R12Dict, R12Item } from "./fixtures/round12-fixtures.as";
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

type Grants = Record<string, ArbacDbScope | undefined>;
let space: R12Space;
let http: MoostHttp;

async function bootGrants(grants: Grants) {
  ({ http } = await boot(
    [readerRole("reader", grants)],
    [DictsController, ItemsController, DecoratedController],
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
    const r = await get("/items/query?$select=status,count(*):n&$groupBy=status");
    expect(r.status).toBe(403);
  });

  it("a whitelist keeps it only on the listed paths, mirroring the 403 gate", async () => {
    await bootGrants({ items: { controls: { $groupBy: ["status"] } } });
    const meta = (await get("/items/meta")).body;
    expect(groupableFields(meta)).toEqual(["status"]);
    expect(meta.fields.owner.groupable).toBeUndefined();
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
