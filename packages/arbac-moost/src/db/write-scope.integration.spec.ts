import { allowTableAction, allowTableRead, allowTableWrite, defineRole } from "@aooth/arbac";
import { DbSpace } from "@atscript/db";
import { BetterSqlite3Driver, SqliteAdapter } from "@atscript/db-sqlite";
import {
  clearDbSpaces,
  DbAction,
  DbActionID,
  InputForm,
  provideDbSpace,
  ReadableController,
  TableController,
} from "@atscript/moost-db";
import type { MoostHttp } from "@moostjs/event-http";
import { Post } from "@moostjs/event-http";
import { clearGlobalWooks, Inherit } from "moost";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { bootArbacHttp } from "../__testing__/arbac-http";
import { request } from "../__testing__/http";
import { FakeUserProvider } from "../__testing__/user-provider";
import { ArbacAction, ArbacResource } from "../arbac.decorator";
import { getArbacMate } from "../arbac.mate";
import { MoostArbac } from "../moost-arbac";
import { type ArbacDbScope, AsArbacDbController } from "./as-arbac-db-controller";
import { AsArbacDbReadableController } from "./as-arbac-db-readable-controller";
import { WrDoc, WrNote, WrSignForm, WrUser } from "./write-fixtures.as";

/**
 * The 0.1.72 write pipeline over HTTP against a real SQLite table:
 * fail-closed `prepareRequest`, USING (pre-image in the scope filter, inside
 * the transaction), WITH CHECK (`check`, default `filter`, after the write,
 * rolled back), `nestedWrites` opt-in, path-aware `allowedFields` / `set`,
 * OCC preserved under a whitelist, `/meta/form` authorization, and `check`
 * conjunction under credential attenuation.
 */

const tenantA = (extra: ArbacDbScope = {}): ArbacDbScope => ({ filter: { tenant: "a" }, ...extra });
const writer = (id: string, scope: () => ArbacDbScope) =>
  defineRole<object, ArbacDbScope>().id(id).use(allowTableWrite("wr-docs", { scope })).build();

const ROLES = [
  writer("writer", () => tenantA()),
  writer("no-check", () => tenantA({ check: {} })),
  writer("status-check", () => tenantA({ check: { status: { $in: ["draft", "open"] } } })),
  writer("nested-notes", () => tenantA({ nestedWrites: ["notes"] })),
  writer("whitelist", () =>
    tenantA({ allowedFields: ["title", "profile.name", "settings.theme"] }),
  ),
  writer("set-dotted", () => tenantA({ set: { "profile.tenant": "a", "settings.locked": "yes" } })),
  writer("unrestricted", () => ({})),
  // Two roles: the union of their filters / checks / nestedWrites applies.
  writer("writer-b", () => ({ filter: { tenant: "b" }, nestedWrites: ["owner"] })),
  defineRole<object, ArbacDbScope>().id("reader").use(allowTableRead("wr-docs")).build(),
  defineRole<object, ArbacDbScope>()
    .id("signer")
    .use(allowTableRead("wr-docs"), allowTableAction("wr-docs", ["doc.sign"]))
    .build(),
];

@Inherit()
class DocsBase extends AsArbacDbController<typeof WrDoc> {
  @Post("actions/sign")
  @DbAction("sign", { label: "sign" })
  @ArbacAction("doc.sign")
  sign(@DbActionID() id: unknown, @InputForm(WrSignForm) input: unknown) {
    return { id, input };
  }
}

@TableController(WrDoc, "wr-docs")
@ArbacResource("wr-docs")
class DocsController extends DocsBase {}

// `@Public()` (auth-moost) writes this flag; the interceptor skips it, the
// DB controller's prepareRequest does not.
@TableController(WrDoc, "wr-docs-public")
@ArbacResource("wr-docs")
@(getArbacMate().decorate("arbacPublic", true))
class PublicDocsController extends DocsBase {}

@ReadableController(WrDoc, "wr-docs-view")
@ArbacResource("wr-docs")
class DocsReadableController extends AsArbacDbReadableController<typeof WrDoc> {}

let driver: BetterSqlite3Driver;
let space: DbSpace;

beforeAll(async () => {
  driver = new BetterSqlite3Driver(":memory:");
  space = new DbSpace(() => new SqliteAdapter(driver));
  for (const t of [WrUser, WrDoc, WrNote]) await space.getTable(t as never).ensureTable();
  provideDbSpace(space);
});

afterAll(() => {
  clearDbSpaces();
  driver.close();
});

const docs = () => space.getTable(WrDoc);
const doc = (id: number) => docs().findOne({ filter: { id }, controls: {} });
const one = (t: unknown, id: number) =>
  space.getTable(t as never).findOne({ filter: { id }, controls: {} } as never);

async function reseed(): Promise<void> {
  for (const t of [WrNote, WrDoc, WrUser]) {
    driver.exec(`DELETE FROM "${(space.getTable(t as never) as { tableName: string }).tableName}"`);
  }
  await space.getTable(WrUser).insertMany([
    { id: 1, name: "alice", tenant: "a" },
    { id: 2, name: "bob", tenant: "b" },
  ]);
  await docs().insertMany([
    { id: 1, title: "a1", tenant: "a", status: "open", profile: { name: "pa", tenant: "a" } },
    { id: 2, title: "b1", tenant: "b", status: "open", ownerId: 2 },
    { id: 3, title: "a2", tenant: "a", status: "draft" },
  ]);
  await space.getTable(WrNote).insertMany([{ id: 1, body: "n1", tenant: "a", docId: 1 }]);
}

type Res = { status: number; body: any };
let user: FakeUserProvider;
let http: MoostHttp;

async function boot(roles: string[], authorize = true): Promise<void> {
  clearGlobalWooks();
  const arbac = new MoostArbac<object, ArbacDbScope>();
  for (const r of ROLES) arbac.registerRole(r);
  user = new FakeUserProvider("u1", roles);
  http = await bootArbacHttp({
    arbac,
    user,
    controllers: [DocsController, PublicDocsController, DocsReadableController],
    authorize,
  });
}

function send(method: string, path: string, body?: unknown): Promise<Res> {
  return request(http, method, path, body);
}

beforeEach(async () => {
  await reseed();
  await boot(["writer"]);
});

describe("A1 fail-closed prepareRequest", () => {
  const ENDPOINTS: Array<[method: string, path: string, body?: unknown]> = [
    ["GET", "query"],
    ["GET", "pages"],
    ["GET", "one/1"],
    ["GET", "meta"],
    ["POST", "", { id: 9, title: "x", tenant: "a" }],
    ["PATCH", "", { id: 1, title: "x" }],
    ["PUT", "", { id: 1, title: "x", tenant: "a" }],
    ["DELETE", "1"],
  ];

  it.each([true, false])(
    "no grant → 403 on every endpoint (authorize interceptor: %s)",
    async (authorize) => {
      await boot([], authorize);
      for (const [method, path, body] of ENDPOINTS) {
        const res = await send(method, `/wr-docs${path ? `/${path}` : ""}`, body);
        expect(res.status, `${method} ${path}`).toBe(403);
      }
      for (const path of ["query", "one/1", "meta"]) {
        expect((await send("GET", `/wr-docs-view/${path}`)).status, path).toBe(403);
      }
      expect(await doc(1)).toMatchObject({ title: "a1" });
    },
  );

  it("`@Public()` does not bypass an ARBAC DB controller", async () => {
    await boot([]);
    expect((await send("PATCH", "/wr-docs-public", { id: 1, title: "x" })).status).toBe(403);
    expect((await send("DELETE", "/wr-docs-public/1")).status).toBe(403);
    expect((await send("GET", "/wr-docs-public/query")).status).toBe(403);
    expect(await doc(1)).toMatchObject({ title: "a1" });
  });

  it("`@Public()` with a grant: scopes evaluated by prepareRequest are enforced", async () => {
    const res = await send("PATCH", "/wr-docs-public", { id: 2, title: "x" });
    expect(res.status).toBe(404);
    expect((await send("PATCH", "/wr-docs-public", { id: 1, title: "ok" })).status).toBeLessThan(
      300,
    );
  });
});

describe("A2 USING — the pre-image must be in the scope filter", () => {
  it.each<[string, string, unknown]>([
    ["PATCH", "/wr-docs", { id: 2, title: "pwn" }],
    ["PUT", "/wr-docs", { id: 2, title: "pwn", tenant: "a" }],
    ["DELETE", "/wr-docs/2", undefined],
  ])("%s of an out-of-scope row → 404, untouched", async (method, path, body) => {
    const res = await send(method, path, body);
    expect(res.status).toBe(404);
    expect(await doc(2)).toMatchObject({ title: "b1", tenant: "b" });
  });

  it("out-of-scope and missing rows answer identically", async () => {
    const out = await send("PATCH", "/wr-docs", { id: 2, title: "x" });
    const missing = await send("PATCH", "/wr-docs", { id: 99, title: "x" });
    expect(out).toEqual(missing);
  });

  it("bulk PATCH with one out-of-scope row → 404, nothing written", async () => {
    const res = await send("PATCH", "/wr-docs", [
      { id: 1, title: "partial?" },
      { id: 2, title: "pwn" },
    ]);
    expect(res.status).toBe(404);
    expect(await doc(1)).toMatchObject({ title: "a1" });
  });

  it("duplicate in-scope ids in a bulk PATCH are deduped (not a 404)", async () => {
    const res = await send("PATCH", "/wr-docs", [
      { id: 1, title: "x" },
      { id: 1, title: "y" },
    ]);
    expect(res.status).toBeLessThan(300);
  });

  it("DELETE of an in-scope row succeeds", async () => {
    expect((await send("DELETE", "/wr-docs/3")).status).toBeLessThan(300);
    expect(await doc(3)).toBeNull();
  });

  it("an unrestricted scope skips USING", async () => {
    await boot(["unrestricted"]);
    expect((await send("PATCH", "/wr-docs", { id: 2, title: "ok" })).status).toBeLessThan(300);
  });
});

describe("A2 WITH CHECK — written rows must match `check` (default `filter`)", () => {
  it("POST of a foreign-tenant row → 403, not inserted", async () => {
    const res = await send("POST", "/wr-docs", { id: 10, title: "x", tenant: "b" });
    expect(res.status).toBe(403);
    expect(res.body.message).toBe("Row outside your write scope");
    expect(await doc(10)).toBeNull();
  });

  it("POST [] with one foreign row → 403, the whole batch rolled back", async () => {
    const res = await send("POST", "/wr-docs", [
      { id: 11, title: "ok", tenant: "a" },
      { id: 12, title: "x", tenant: "b" },
    ]);
    expect(res.status).toBe(403);
    expect(await doc(11)).toBeNull();
    expect(await doc(12)).toBeNull();
  });

  it("PATCH moving an in-scope row out of scope → 403, rolled back", async () => {
    const res = await send("PATCH", "/wr-docs", { id: 1, tenant: "b" });
    expect(res.status).toBe(403);
    expect(await doc(1)).toMatchObject({ tenant: "a" });
  });

  it("bulk PATCH / PUT moving rows out → 403, rolled back", async () => {
    expect(
      (
        await send("PATCH", "/wr-docs", [
          { id: 1, title: "m1" },
          { id: 3, tenant: "b" },
        ])
      ).status,
    ).toBe(403);
    expect(
      (
        await send("PUT", "/wr-docs", [
          { id: 1, title: "m1", tenant: "a" },
          { id: 3, title: "m3", tenant: "b" },
        ])
      ).status,
    ).toBe(403);
    expect(await doc(1)).toMatchObject({ title: "a1" });
    expect(await doc(3)).toMatchObject({ tenant: "a", title: "a2" });
  });

  it("PUT replacing an in-scope row with a foreign image → 403", async () => {
    const res = await send("PUT", "/wr-docs", { id: 1, title: "moved", tenant: "b" });
    expect(res.status).toBe(403);
    expect(await doc(1)).toMatchObject({ tenant: "a", title: "a1" });
  });

  it("in-scope writes pass", async () => {
    expect((await send("POST", "/wr-docs", { id: 13, title: "ok", tenant: "a" })).status).toBe(201);
    expect((await send("PATCH", "/wr-docs", { id: 1, title: "ok" })).status).toBeLessThan(300);
  });

  it("`check: {}` opts out (the pre-image filter still applies)", async () => {
    await boot(["no-check"]);
    expect((await send("PATCH", "/wr-docs", { id: 1, tenant: "b" })).status).toBeLessThan(300);
    expect(await doc(1)).toMatchObject({ tenant: "b" });
    expect((await send("PATCH", "/wr-docs", { id: 2, title: "x" })).status).toBe(404);
  });

  it("an explicit `check` replaces the filter default", async () => {
    await boot(["status-check"]);
    expect((await send("PATCH", "/wr-docs", { id: 1, status: "closed" })).status).toBe(403);
    // `check` does not mention tenant: moving the row out passes WITH CHECK.
    expect((await send("PATCH", "/wr-docs", { id: 3, tenant: "b" })).status).toBeLessThan(300);
  });

  it("checks are unioned across roles", async () => {
    await boot(["writer", "writer-b"]);
    expect((await send("PATCH", "/wr-docs", { id: 1, tenant: "b" })).status).toBeLessThan(300);
    expect((await send("PATCH", "/wr-docs", { id: 3, tenant: "c" })).status).toBe(403);
  });
});

describe("A3 nested writes (P2)", () => {
  it.each<[string, unknown]>([
    ["POST", { id: 20, title: "t", tenant: "a", notes: [{ id: 50, body: "x", tenant: "b" }] }],
    ["POST", { id: 21, title: "t", tenant: "a", owner: { id: 60, name: "m", tenant: "b" } }],
    ["PATCH", { id: 1, owner: { name: "pwned" } }],
    ["PATCH", { id: 1, notes: { $update: [{ id: 1, body: "x" }] } }],
    ["PUT", { id: 1, title: "t", tenant: "a", notes: [{ id: 51, body: "x", tenant: "a" }] }],
  ])("%s through a nav prop → 403 by default", async (method, body) => {
    const res = await send(method, "/wr-docs", body);
    expect(res.status).toBe(403);
    expect(res.body.message).toMatch(/^Nested writes through "(notes|owner)" are not allowed$/);
    expect(await one(WrNote, 50)).toBeNull();
    expect(await one(WrUser, 60)).toBeNull();
  });

  it("bulk: one row with a nav key rejects the batch", async () => {
    const res = await send("POST", "/wr-docs", [
      { id: 22, title: "t", tenant: "a" },
      { id: 23, title: "t", tenant: "a", owner: { id: 61, name: "m", tenant: "a" } },
    ]);
    expect(res.status).toBe(403);
    expect(await doc(22)).toBeNull();
  });

  it("an unrestricted scope does not imply nested writes", async () => {
    await boot(["unrestricted"]);
    const res = await send("PATCH", "/wr-docs", { id: 1, owner: { name: "x" } });
    expect(res.status).toBe(403);
  });

  it("`nestedWrites` opts a relation in (parent authority)", async () => {
    await boot(["nested-notes"]);
    const res = await send("POST", "/wr-docs", {
      id: 24,
      title: "t",
      tenant: "a",
      notes: [{ id: 52, body: "x", tenant: "a" }],
    });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    expect(await one(WrNote, 52)).toMatchObject({ docId: 24 });
    // Only the listed relation.
    expect((await send("PATCH", "/wr-docs", { id: 1, owner: { name: "x" } })).status).toBe(403);
  });

  it("`nestedWrites` is unioned across roles", async () => {
    await boot(["nested-notes", "writer-b"]);
    const res = await send("PATCH", "/wr-docs", { id: 2, owner: { name: "bobby" } });
    expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
    expect(await one(WrUser, 2)).toMatchObject({ name: "bobby" });
  });
});

describe("A10 allowedFields / set", () => {
  it("a dotted whitelist entry keeps just that branch of a nested object", async () => {
    await boot(["whitelist"]);
    const res = await send("POST", "/wr-docs", {
      id: 31,
      title: "t",
      tenant: "a",
      status: "closed",
      profile: { name: "n", tenant: "b" },
    });
    expect(res.status, JSON.stringify(res.body)).toBe(400); // `tenant` stripped → required
    const ok = await send("PUT", "/wr-docs", {
      id: 1,
      title: "t",
      tenant: "a",
      status: "closed",
      profile: { name: "n", tenant: "b" },
    });
    // `tenant` is not whitelisted either: a full-row write without it is invalid.
    expect(ok.status, JSON.stringify(ok.body)).toBe(400);
  });

  it("PATCH: a dotted entry under a merge block writes only that leaf", async () => {
    await docs().updateOne({ id: 1, settings: { theme: "light", locked: "no" } });
    await boot(["whitelist"]);
    const res = await send("PATCH", "/wr-docs", {
      id: 1,
      title: "t",
      status: "closed",
      settings: { theme: "dark", locked: "yes" },
    });
    expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
    expect(await doc(1)).toMatchObject({
      title: "t",
      status: "open",
      settings: { theme: "dark", locked: "no" },
    });
  });

  it("PATCH: a partially whitelisted REPLACE block is dropped (it would clear the other leaves)", async () => {
    await boot(["whitelist"]);
    const res = await send("PATCH", "/wr-docs", { id: 1, profile: { name: "new" } });
    expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
    expect(await doc(1)).toMatchObject({ profile: { name: "pa", tenant: "a" } });
  });

  it("the version column survives a whitelist — a stale PATCH is a 409", async () => {
    await boot(["whitelist"]);
    const res = await send("PATCH", "/wr-docs", { id: 1, version: 999, title: "lost" });
    expect(res.status).toBe(409);
    expect(await doc(1)).toMatchObject({ title: "a1" });
    const current = (await doc(1))!.version;
    const ok = await send("PATCH", "/wr-docs", { id: 1, version: current, title: "won" });
    expect(ok.status).toBeLessThan(300);
  });

  it("a dotted `set` key sets the nested path (merged into the payload's object)", async () => {
    await boot(["set-dotted"]);
    const ins = await send("POST", "/wr-docs", {
      id: 30,
      title: "t",
      tenant: "a",
      profile: { name: "n", tenant: "b" },
    });
    expect(ins.status, JSON.stringify(ins.body)).toBe(201);
    expect(await doc(30)).toMatchObject({
      profile: { name: "n", tenant: "a" },
      settings: { locked: "yes" },
    });
    const nested = await send("PATCH", "/wr-docs", { id: 1, profile: { name: "m", tenant: "b" } });
    expect(nested.status, JSON.stringify(nested.body)).toBeLessThan(300);
    expect(await doc(1)).toMatchObject({ profile: { name: "m", tenant: "a" } });
  });

  it("PATCH: a dotted `set` adds a merge block, never a replace block the patch lacks", async () => {
    await docs().updateOne({ id: 1, settings: { theme: "light", locked: "no" } });
    await boot(["set-dotted"]);
    const res = await send("PATCH", "/wr-docs", { id: 1, title: "x" });
    expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
    expect(await doc(1)).toMatchObject({
      title: "x",
      profile: { name: "pa", tenant: "a" },
      settings: { theme: "light", locked: "yes" },
    });
  });
});

describe("A9 /meta/form/:name", () => {
  it("a principal without the form's action gets the unknown-form 404", async () => {
    await boot(["reader"]);
    const res = await send("GET", "/wr-docs/meta/form/WrSignForm");
    expect(res.status).toBe(404);
    const unknown = await send("GET", "/wr-docs/meta/form/Nope");
    expect(JSON.stringify(res.body)).toBe(
      JSON.stringify(unknown.body).replace("Nope", "WrSignForm"),
    );
  });

  it("a principal allowed to run the action (by its @ArbacAction id) gets the form", async () => {
    await boot(["signer"]);
    const res = await send("GET", "/wr-docs/meta/form/WrSignForm");
    expect(res.status).toBe(200);
    expect(JSON.stringify(res.body)).toContain("note");
  });
});

describe("attenuation conjoins `check`", () => {
  it("a credential narrowing the scope cannot write outside either side's check", async () => {
    await boot(["unrestricted", "writer"]);
    user.attenuation = { roles: ["writer"] };
    expect((await send("PATCH", "/wr-docs", { id: 1, tenant: "b" })).status).toBe(403);
    expect((await send("POST", "/wr-docs", { id: 40, title: "x", tenant: "b" })).status).toBe(403);
    expect((await send("POST", "/wr-docs", { id: 41, title: "x", tenant: "a" })).status).toBe(201);
  });
});
