import { allowTableWrite, defineRole } from "@aooth/arbac";
import { DbSpace } from "@atscript/db";
import { clearDbSpaces, provideDbSpace, TableController } from "@atscript/moost-db";
import type { MoostHttp } from "@moostjs/event-http";
import { clearGlobalWooks } from "moost";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { bootArbacHttp } from "../__testing__/arbac-http";
import { loadMemoryAdapter } from "../__testing__/http";
import { FakeUserProvider } from "../__testing__/user-provider";
import { ArbacResource } from "../arbac.decorator";
import { MoostArbac } from "../moost-arbac";
import { type ArbacDbScope, AsArbacDbController } from "./as-arbac-db-controller";
import { WrDoc } from "./write-fixtures.as";

/**
 * WITH CHECK on an adapter WITHOUT real transactions (`@atscript/db-memory`:
 * `withTransaction` is a pass-through, so a post-write check could not roll
 * back). The ARBAC controller validates BEFORE the write, in memory: full
 * rows (insert / replace) as-is, update patches over their pre-image when
 * every checked field is untouched or a plain SET — anything it cannot
 * decide is a 403 (fail closed) and nothing is written.
 */

const writer = (id: string, scope: ArbacDbScope) =>
  defineRole<object, ArbacDbScope>()
    .id(id)
    .use(allowTableWrite("mem-docs", { scope: () => scope }))
    .build();

const ROLES = [
  writer("writer", { filter: { tenant: "a" } }),
  writer("status-check", {
    filter: { tenant: "a" },
    check: { status: { $in: ["draft", "open"] } },
  }),
  writer("nested-check", { filter: { tenant: "a" }, check: { "settings.locked": { $ne: "yes" } } }),
  writer("regex-check", { filter: { tenant: "a" }, check: { title: { $regex: "^ok" } } }),
  writer("rel-check", { filter: { tenant: "a" }, check: { owner: { $some: { tenant: "a" } } } }),
];

@TableController(WrDoc, "mem-docs")
@ArbacResource("mem-docs")
class MemDocsController extends AsArbacDbController<typeof WrDoc> {}

let space: DbSpace;
let http: MoostHttp;

beforeAll(async () => {
  const MemoryAdapter = await loadMemoryAdapter();
  space = new DbSpace(() => new MemoryAdapter());
  await space.getTable(WrDoc).ensureTable();
  provideDbSpace(space);
});

afterAll(() => clearDbSpaces());

const docs = () => space.getTable(WrDoc);
const doc = (id: number) => docs().findOne({ filter: { id }, controls: {} });

async function boot(roles: string[]): Promise<void> {
  clearGlobalWooks();
  const arbac = new MoostArbac<object, ArbacDbScope>();
  for (const r of ROLES) arbac.registerRole(r);
  http = await bootArbacHttp({
    arbac,
    user: new FakeUserProvider("u1", roles),
    controllers: [MemDocsController],
    authorize: true,
  });
}

async function send(method: string, body: unknown): Promise<{ status: number; body: any }> {
  const res = await http.request("/mem-docs", {
    method,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res!.status, body: await res!.json() };
}

beforeEach(async () => {
  await docs().deleteMany({ id: { $gt: 0 } });
  await docs().insertMany([
    { id: 1, title: "ok1", tenant: "a", status: "open", settings: { theme: "t", locked: "no" } },
    { id: 2, title: "b1", tenant: "b", status: "open" },
  ]);
  await boot(["writer"]);
});

describe("non-transactional WITH CHECK (validated before the write)", () => {
  it("the adapter really is non-transactional", async () => {
    const adapter = docs().getAdapter();
    await adapter.withTransaction(async () => {
      expect(adapter.isInTransaction()).toBe(false);
    });
  });

  it("POST / POST [] of a foreign row → 403, nothing written", async () => {
    expect((await send("POST", { id: 10, title: "x", tenant: "b" })).status).toBe(403);
    const batch = await send("POST", [
      { id: 11, title: "ok", tenant: "a" },
      { id: 12, title: "x", tenant: "b" },
    ]);
    expect(batch.status).toBe(403);
    expect(await doc(10)).toBeNull();
    expect(await doc(11)).toBeNull();
  });

  it("PUT with a foreign image → 403, untouched", async () => {
    expect((await send("PUT", { id: 1, title: "m", tenant: "b" })).status).toBe(403);
    expect(await doc(1)).toMatchObject({ tenant: "a", title: "ok1" });
  });

  it("PATCH moving the row out (plain SET of a checked field) → 403, untouched", async () => {
    const res = await send("PATCH", { id: 1, tenant: "b" });
    expect(res.status).toBe(403);
    expect(res.body.message).toBe("Row outside your write scope");
    expect(await doc(1)).toMatchObject({ tenant: "a" });
  });

  it("PATCH of unchecked fields and in-scope SETs pass", async () => {
    expect((await send("PATCH", { id: 1, title: "renamed" })).status).toBeLessThan(300);
    expect((await send("PATCH", { id: 1, tenant: "a" })).status).toBeLessThan(300);
    expect((await send("POST", { id: 13, title: "ok", tenant: "a" })).status).toBe(201);
    expect(await doc(1)).toMatchObject({ title: "renamed" });
  });

  it("USING still applies: an out-of-scope PATCH → 404", async () => {
    expect((await send("PATCH", { id: 2, title: "x" })).status).toBe(404);
  });

  it("an explicit check is evaluated over pre-image + patch", async () => {
    await boot(["status-check"]);
    expect((await send("PATCH", { id: 1, status: "closed" })).status).toBe(403);
    expect((await send("PATCH", { id: 1, title: "x" })).status).toBeLessThan(300);
    expect(await doc(1)).toMatchObject({ status: "open", title: "x" });
  });

  it("a nested object patch over a checked path cannot be decided → 403", async () => {
    await boot(["nested-check"]);
    const res = await send("PATCH", { id: 1, settings: { theme: "dark" } });
    expect(res.status).toBe(403);
    expect(await doc(1)).toMatchObject({ settings: { theme: "t" } });
    expect((await send("PATCH", { id: 1, title: "fine" })).status).toBeLessThan(300);
  });

  it("an operator the in-memory evaluator does not model fails closed", async () => {
    await boot(["regex-check"]);
    expect((await send("PATCH", { id: 1, title: "ok2" })).status).toBe(403);
    expect((await send("POST", { id: 14, title: "ok", tenant: "a" })).status).toBe(403);
    expect(await doc(14)).toBeNull();
  });

  it("a relational check needs the related rows — fails closed (403), nothing written", async () => {
    await boot(["rel-check"]);
    expect((await send("PATCH", { id: 1, title: "rel" })).status).toBe(403);
    expect((await send("POST", { id: 15, title: "ok", tenant: "a" })).status).toBe(403);
    expect(await doc(15)).toBeNull();
    expect(await doc(1)).not.toMatchObject({ title: "rel" });
  });
});
