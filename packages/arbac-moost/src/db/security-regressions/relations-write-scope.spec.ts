// Write-scope edge cases not covered by write-scope.integration.spec.ts:
// PK-first resolution of an ambiguous scalar id (a string PK next to a string
// unique key), the 409 disambiguation never reading an out-of-scope row,
// USING on a mixed bulk PUT, a top-level `set` pin, and dotted payload keys
// against an `allowedFields` whitelist.
import { allowTableWrite, defineRole } from "@aooth/arbac";
import { TableController } from "@atscript/moost-db";
import type { MoostHttp } from "@moostjs/event-http";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { ArbacResource } from "../../arbac.decorator";
import { type ArbacDbScope, AsArbacDbController } from "../as-arbac-db-controller";
import { RpSlug, RpTask } from "./fixtures/rel-fixtures.as";
import { all, boot, createSpace, type Harness, one, seed, send } from "./relations-harness";

const tasks = (id: string, extra: ArbacDbScope) =>
  defineRole<object, ArbacDbScope>()
    .id(id)
    .use(allowTableWrite("tasks", { scope: () => ({ filter: { tenant: "a" }, ...extra }) }))
    .build();

const ROLES = [
  defineRole<object, ArbacDbScope>()
    .id("writer")
    .use(allowTableWrite("tasks", { scope: () => ({ filter: { tenant: "a" } }) }))
    .use(allowTableWrite("slugs", { scope: () => ({ filter: { tenant: "a" } }) }))
    .build(),
  defineRole<object, ArbacDbScope>().id("unrestricted").use(allowTableWrite("slugs")).build(),
  tasks("dotted", { allowedFields: ["title", "profile.name"] }),
  tasks("parent", { allowedFields: ["title", "profile"] }),
  tasks("set-tenant", { set: { tenant: "a" } }),
];

@TableController(RpTask, "tasks")
@ArbacResource("tasks")
class TasksController extends AsArbacDbController<typeof RpTask> {}

@TableController(RpSlug, "slugs")
@ArbacResource("slugs")
class SlugsController extends AsArbacDbController<typeof RpSlug> {}

let h: Harness;
let http: MoostHttp;
let user: { roles: string[] };
beforeAll(async () => {
  h = await createSpace();
});
afterAll(() => h.close());
beforeEach(async () => {
  await seed(h);
  ({ http, user } = await boot(ROLES, [TasksController, SlugsController], ["writer"]));
});

const task = (id: number) => one(h, RpTask, { id });
const slug = (id: string) => one(h, RpSlug, { id });

// rp_slugs: { id: "zz-b", slug: "abc", tenant: "b" } (lower rowid),
//           { id: "abc",  slug: "a-own", tenant: "a" }
describe("a scalar id naming one row's PK and another row's unique key", () => {
  it.each(["writer", "unrestricted"])(
    "%s: DELETE removes the primary-key row, never the unique-key row",
    async (roleId) => {
      user.roles = [roleId];
      const res = await send(http, "DELETE", "/slugs/abc");
      expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
      expect(await slug("abc")).toBeNull();
      expect(await slug("zz-b")).toMatchObject({ slug: "abc", title: "B-row" });
    },
  );

  it("once no PK matches, the unique-key row is out of scope → 404, untouched", async () => {
    await h.table(RpSlug).deleteOne("abc");
    expect(await slug("abc")).toBeNull();
    const res = await send(http, "DELETE", "/slugs/abc");
    expect(res.status).toBe(404);
    expect(await slug("zz-b")).toMatchObject({ title: "B-row" });
  });

  it("GET /one resolves the primary-key row", async () => {
    user.roles = ["unrestricted"];
    const res = await send(http, "GET", "/slugs/one/abc");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ id: "abc", title: "A-row" });
  });

  it("a stale-version 409 reports the in-scope row's version, never the out-of-scope row's", async () => {
    // Bump the foreign row's version so the two rows are distinguishable.
    for (const title of ["b1", "b2", "b3"]) {
      await h.table(RpSlug).updateOne({ id: "zz-b", title });
    }
    const foreign = (await slug("zz-b")) as { version: number };
    const own = (await slug("abc")) as { version: number };
    expect(foreign.version).not.toBe(own.version);
    const before = await all(h, RpSlug);
    // Own PK "abc" + slug "abc" (the foreign row's unique key) + a stale version.
    const res = await send(http, "PATCH", "/slugs", {
      id: "abc",
      slug: "abc",
      version: 12345,
      title: "x",
    });
    expect(res.status).toBe(409);
    expect(res.body.currentVersion).toBe(own.version);
    expect(await all(h, RpSlug)).toEqual(before);
  });
});

describe("USING on bulk replace", () => {
  it("a bulk PUT with one out-of-scope row → 404, nothing written", async () => {
    const res = await send(http, "PUT", "/tasks", [
      { id: 1, title: "partial?", tenant: "a" },
      { id: 2, title: "pwn", tenant: "b" },
    ]);
    expect(res.status).toBe(404);
    expect(await task(1)).toMatchObject({ title: "taskA" });
    expect(await task(2)).toMatchObject({ title: "taskB" });
  });
});

describe("allowedFields / set", () => {
  it("a top-level `set` pins the column on PATCH", async () => {
    user.roles = ["set-tenant"];
    const res = await send(http, "PATCH", "/tasks", { id: 1, title: "t", tenant: "b" });
    expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
    expect(await task(1)).toMatchObject({ title: "t", tenant: "a" });
  });

  it.each<[role: string, key: string, status: number]>([
    // Not whitelisted → stripped; the remaining empty patch is a no-op.
    ["dotted", "profile.tenant", 202],
    // Whitelisted (as a leaf or under its parent) → kept, and atscript-db
    // refuses dotted payload keys.
    ["dotted", "profile.name", 400],
    ["parent", "profile.tenant", 400],
  ])("%s: a dotted payload key %s never writes a leaf", async (roleId, key, status) => {
    user.roles = [roleId];
    const res = await send(http, "PATCH", "/tasks", { id: 1, [key]: "b" });
    expect(res.status, JSON.stringify(res.body)).toBe(status);
    expect(await task(1)).toMatchObject({ profile: { name: "pa", tenant: "a" } });
  });
});
