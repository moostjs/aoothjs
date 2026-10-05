// An insert needs the insert grant, and every submitted row — conflicting or
// not — must pass the grant's write check, BEFORE the write: a forbidden row
// is a 403, never a duplicate-key 409 (no existence probe), in plain POST and
// in `POST /?$onConflict=ignore` (atscript-db 0.1.148) alike. Ignore mode
// never widens a grant.
import { allowTableOps, allowTableRead, defineRole } from "@aooth/arbac";
import { TableController } from "@atscript/moost-db";
import type { TDbRequestContext } from "@atscript/moost-db";
import type { MoostHttp } from "@moostjs/event-http";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { ArbacResource } from "../../arbac.decorator";
import { type ArbacDbScope, AsArbacDbController } from "../as-arbac-db-controller";
import { R12Code } from "./fixtures/round12-fixtures.as";
import { boot, send } from "./relations-harness";
import { createR12Space, type R12Space } from "./round12-harness";

const ROLES = [
  // Inserts into tenant a only (the default write check is the grant's filter).
  defineRole<object, ArbacDbScope>()
    .id("insert-a")
    .use(allowTableOps("codes", ["insert"], { scope: () => ({ filter: { tenant: "a" } }) }))
    .build(),
  // The check reads a column the database generates (the row may omit it).
  defineRole<object, ArbacDbScope>()
    .id("insert-generated")
    .use(allowTableOps("codes", ["insert"], { scope: () => ({ filter: { id: { $gt: 0 } } }) }))
    .build(),
  // Reads, but holds no insert grant.
  defineRole<object, ArbacDbScope>().id("read-only").use(allowTableRead("codes")).build(),
];

const seen: Array<string | undefined> = [];

@TableController(R12Code as never, "codes")
@ArbacResource("codes")
class CodesController extends AsArbacDbController<typeof R12Code> {
  protected async prepareRequest(ctx: TDbRequestContext): Promise<void> {
    if (ctx.endpoint === "insert") seen.push(ctx.onConflict);
    await super.prepareRequest(ctx);
  }
}

let space: R12Space;
let http: MoostHttp;
async function bootAs(role: string) {
  ({ http } = await boot(ROLES, [CodesController], [role]));
}
const post = (path: string, body: unknown) => send(http, "POST", path, body);
const ids = async () =>
  (await space.rows(R12Code)).map((r) => r.id as number).toSorted((a, b) => a - b);

beforeAll(async () => {
  space = await createR12Space();
});
afterAll(() => space.close());
beforeEach(async () => {
  await space.seed();
  seen.length = 0;
});

describe("POST ?$onConflict=ignore under ARBAC", () => {
  it("the mode reaches prepareRequest, so a controller can see (and refuse) it", async () => {
    await bootAs("insert-a");
    await post("/codes?$onConflict=ignore", { id: 10, code: "T-10", tenant: "a", title: "x" });
    await post("/codes", { id: 11, code: "T-11", tenant: "a", title: "y" });
    expect(seen).toEqual(["ignore", undefined]);
  });

  it("a permitted row inserts; a permitted row that conflicts is skipped, not refused", async () => {
    await bootAs("insert-a");
    const fresh = await post("/codes?$onConflict=ignore", {
      id: 10,
      code: "T-10",
      tenant: "a",
      title: "x",
    });
    expect(fresh.status, JSON.stringify(fresh.body)).toBeLessThan(300);
    expect(fresh.body).toMatchObject({ conflict: false });
    // Same primary key as an existing row of tenant a.
    const dup = await post("/codes?$onConflict=ignore", {
      id: 1,
      code: "T-DUP",
      tenant: "a",
      title: "dup",
    });
    expect(dup.status, JSON.stringify(dup.body)).toBeLessThan(300);
    expect(dup.body).toMatchObject({ conflict: true });
    expect(await ids()).toEqual([1, 2, 10]);
  });

  it("a row the caller may not insert is refused (403), conflicting or not", async () => {
    await bootAs("insert-a");
    // Fresh row of another tenant.
    const fresh = await post("/codes?$onConflict=ignore", {
      id: 20,
      code: "T-20",
      tenant: "b",
      title: "x",
    });
    expect(fresh.status).toBe(403);
    // Would conflict with tenant b's existing row: still 403, so ignore mode
    // is no existence probe on rows outside the grant.
    const dup = await post("/codes?$onConflict=ignore", {
      id: 2,
      code: "T-OTHER",
      tenant: "b",
      title: "x",
    });
    expect(dup.status).toBe(403);
    expect(await ids()).toEqual([1, 2]);
  });

  it("a batch with one forbidden row is refused whole", async () => {
    await bootAs("insert-a");
    const r = await post("/codes?$onConflict=ignore", [
      { id: 30, code: "T-30", tenant: "a", title: "ok" },
      { id: 31, code: "T-31", tenant: "b", title: "nope" },
    ]);
    expect(r.status).toBe(403);
    expect(await ids()).toEqual([1, 2]);
  });

  it("no insert grant → 403, with or without the mode", async () => {
    await bootAs("read-only");
    const row = { id: 40, code: "T-40", tenant: "a", title: "x" };
    expect((await post("/codes?$onConflict=ignore", row)).status).toBe(403);
    expect((await post("/codes", row)).status).toBe(403);
    expect(await ids()).toEqual([1, 2]);
  });
});

describe("a permitted row colliding with another tenant's unique value", () => {
  // Accepted disclosure: the unique index is global, so an in-scope row whose
  // unique value matches ANOTHER tenant's row reports the conflict. Per-tenant
  // uniqueness needs per-tenant unique indexes (atscript-db api/crud#insert-ignore).
  it("answers conflict:true in ignore mode and 409 in plain mode, writing nothing", async () => {
    await bootAs("insert-a");
    const row = { id: 90, code: "T-OTHER", tenant: "a", title: "x" };
    const ignored = await post("/codes?$onConflict=ignore", row);
    expect(ignored.status, JSON.stringify(ignored.body)).toBeLessThan(300);
    expect(ignored.body).toMatchObject({ conflict: true });
    const plain = await post("/codes", row);
    expect(plain.status).toBe(409);
    expect(await ids()).toEqual([1, 2]);
  });
});

describe("plain POST refuses a forbidden row before the write", () => {
  it("a forbidden duplicate answers 403, a permitted one still 409", async () => {
    await bootAs("insert-a");
    // Tenant b's existing row: no 409 existence oracle.
    const forbidden = await post("/codes", { id: 2, code: "T-X", tenant: "b", title: "x" });
    expect(forbidden.status).toBe(403);
    // Same unique code as tenant b's row, in a forbidden tenant.
    const byUnique = await post("/codes", { id: 50, code: "T-OTHER", tenant: "b", title: "x" });
    expect(byUnique.status).toBe(403);
    // Tenant a's own row: the caller may see it, so the conflict is reported.
    const permitted = await post("/codes", { id: 1, code: "T-DUP", tenant: "a", title: "x" });
    expect(permitted.status).toBe(409);
    expect(await ids()).toEqual([1, 2]);
  });

  it("a forbidden fresh row answers 403 and writes nothing", async () => {
    await bootAs("insert-a");
    const r = await post("/codes", { id: 60, code: "T-60", tenant: "b", title: "x" });
    expect(r.status).toBe(403);
    expect(await ids()).toEqual([1, 2]);
  });

  it("a check on a column the row omits is not refused up front", async () => {
    await bootAs("insert-generated");
    // `id` is generated by the database: the post-write check decides.
    const r = await post("/codes", { code: "T-70", tenant: "a", title: "x" });
    expect(r.status, JSON.stringify(r.body)).toBeLessThan(300);
    expect(await ids()).toHaveLength(3);
    // An explicit value outside the check is still refused.
    const bad = await post("/codes", { id: -5, code: "T-71", tenant: "a", title: "x" });
    expect(bad.status).toBe(403);
    expect(await ids()).toHaveLength(3);
  });

  it("ignore mode fails closed where the row omits a checked column", async () => {
    await bootAs("insert-generated");
    const r = await post("/codes?$onConflict=ignore", {
      code: "T-80",
      tenant: "a",
      title: "x",
    });
    expect(r.status).toBe(403);
    expect(await ids()).toEqual([1, 2]);
  });
});
