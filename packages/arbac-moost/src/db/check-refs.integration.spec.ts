import { allowTableAction, allowTableRead, allowTableWrite, defineRole } from "@aooth/arbac";
import type { TArbacRole } from "@aooth/arbac-core";
import { DbSpace } from "@atscript/db";
import { BetterSqlite3Driver, SqliteAdapter } from "@atscript/db-sqlite";
import { clearDbSpaces, provideDbSpace, TableController } from "@atscript/moost-db";
import { Body, type MoostHttp, Post } from "@moostjs/event-http";
import { clearGlobalWooks } from "moost";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { bootArbacHttp } from "../__testing__/arbac-http";
import { request } from "../__testing__/http";
import { FakeUserProvider } from "../__testing__/user-provider";
import { ArbacResource } from "../arbac.decorator";
import { MoostArbac } from "../moost-arbac";
import { type ArbacDbScope, AsArbacDbController } from "./as-arbac-db-controller";
import { useArbacDbScope } from "./use-arbac-db-scope";
import { WrDoc, WrNote, WrUser } from "./write-fixtures.as";

/**
 * `ArbacDbScope.checkRefs` over HTTP against a real SQLite table: an FK the
 * write sets must reference a row the caller can READ on the target table
 * (its own `query` grant there, via the target's ARBAC DB controller).
 * Fixture: `wr_docs.ownerId → wr_users.id` (TO relation `owner`),
 * `wr_notes.docId → wr_docs.id`.
 */

const TENANT_A = { filter: { tenant: "a" } };
const docsWriter = (
  id: string,
  extra: ArbacDbScope,
  usersRead = true,
): TArbacRole<object, ArbacDbScope> => {
  const b = defineRole<object, ArbacDbScope>()
    .id(id)
    .use(allowTableWrite("wr-docs", { scope: () => ({ ...TENANT_A, ...extra }) }));
  return (usersRead ? b.use(allowTableRead("wr-users", { scope: () => TENANT_A })) : b).build();
};

const ROLES = [
  docsWriter("by-field", { checkRefs: ["ownerId"] }),
  docsWriter("by-relation", { checkRefs: ["owner"] }),
  docsWriter("all", { checkRefs: true }),
  docsWriter("plain", {}),
  docsWriter("no-users-grant", { checkRefs: ["ownerId"] }, false),
  ...[
    ["custom", { checkRefs: ["owner"] }],
    ["custom-plain", {}],
  ].map(([id, extra]) =>
    defineRole<object, ArbacDbScope>()
      .id(id as string)
      .use(
        allowTableAction("wr-docs", "customInsert", {
          scope: () => ({ ...TENANT_A, ...(extra as ArbacDbScope) }),
        }),
        allowTableRead("wr-users", { scope: () => TENANT_A }),
      )
      .build(),
  ),
  defineRole<object, ArbacDbScope>()
    .id("notes")
    .use(
      allowTableWrite("wr-notes", { scope: () => ({ ...TENANT_A, checkRefs: ["docId"] }) }),
      allowTableRead("wr-docs", { scope: () => TENANT_A }),
    )
    .build(),
];

@TableController(WrDoc, "wr-docs")
@ArbacResource("wr-docs")
class DocsController extends AsArbacDbController<typeof WrDoc> {
  // A handler-side insert — `useArbacDbScope().assertRefsInScope` runs the same check.
  @Post("custom-insert")
  async customInsert(@Body() row: Record<string, unknown>) {
    const scope = await useArbacDbScope<typeof WrDoc>();
    await scope.assertRefsInScope(this.table, [row]);
    await this.table.insertOne({ ...row, ...scope.set() });
    return { ok: true };
  }
}

// Only booted without UsersController: its app has no ARBAC controller for wr_users.
@TableController(WrDoc, "wr-docs-orphan")
@ArbacResource("wr-docs")
class OrphanDocsController extends AsArbacDbController<typeof WrDoc> {}

@TableController(WrUser, "wr-users")
@ArbacResource("wr-users")
class UsersController extends AsArbacDbController<typeof WrUser> {}

@TableController(WrNote, "wr-notes")
@ArbacResource("wr-notes")
class NotesController extends AsArbacDbController<typeof WrNote> {}

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

async function reseed(): Promise<void> {
  for (const t of [WrNote, WrDoc, WrUser]) {
    driver.exec(`DELETE FROM "${(space.getTable(t as never) as { tableName: string }).tableName}"`);
  }
  await space.getTable(WrUser).insertMany([
    { id: 1, name: "alice", tenant: "a" },
    { id: 2, name: "bob", tenant: "b" },
    { id: 3, name: "carol", tenant: "a" },
  ]);
  await docs().insertMany([
    { id: 1, title: "a1", tenant: "a", ownerId: 1 },
    { id: 2, title: "b1", tenant: "b", ownerId: 2 },
    // In scope, but already pointing at a foreign owner (legacy data).
    { id: 3, title: "a2", tenant: "a", ownerId: 2 },
  ]);
}

type Res = { status: number; body: any };
let http: MoostHttp;

async function boot(roles: string[], extra: Function[] = [UsersController]): Promise<void> {
  clearGlobalWooks();
  const arbac = new MoostArbac<object, ArbacDbScope>();
  for (const r of ROLES) arbac.registerRole(r);
  http = await bootArbacHttp({
    arbac,
    user: new FakeUserProvider("u1", roles),
    controllers: extra.includes(OrphanDocsController)
      ? extra
      : [DocsController, NotesController, ...extra],
    authorize: true,
  });
}

function send(method: string, path: string, body?: unknown): Promise<Res> {
  return request(http, method, path, body);
}

const OUT = 'Referenced row "ownerId" is outside your scope';

beforeEach(async () => {
  await reseed();
  await boot(["by-field"]);
});

describe("checkRefs — insert / replace", () => {
  it("an FK to a row outside the caller's target read scope → 403, not inserted", async () => {
    const res = await send("POST", "/wr-docs", { id: 10, title: "x", tenant: "a", ownerId: 2 });
    expect(res.status).toBe(403);
    expect(res.body.message).toBe(OUT);
    expect(await doc(10)).toBeNull();
  });

  it("a missing target row answers the same 403", async () => {
    const res = await send("POST", "/wr-docs", { id: 10, title: "x", tenant: "a", ownerId: 99 });
    expect(res.status).toBe(403);
    expect(res.body.message).toBe(OUT);
  });

  it("in-scope, null and absent FKs pass", async () => {
    for (const [id, ownerId] of [
      [10, 1],
      [11, null],
      [12, undefined],
    ] as const) {
      const res = await send("POST", "/wr-docs", { id, title: "ok", tenant: "a", ownerId });
      expect(res.status, String(ownerId)).toBe(201);
    }
  });

  it("bulk insert: one out-of-scope reference rejects the batch (one count, deduped)", async () => {
    const bad = await send("POST", "/wr-docs", [
      { id: 10, title: "ok", tenant: "a", ownerId: 1 },
      { id: 11, title: "x", tenant: "a", ownerId: 2 },
    ]);
    expect(bad.status).toBe(403);
    expect(await doc(10)).toBeNull();
    const ok = await send("POST", "/wr-docs", [
      { id: 10, title: "ok", tenant: "a", ownerId: 1 },
      { id: 11, title: "ok", tenant: "a", ownerId: 1 },
      { id: 12, title: "ok", tenant: "a", ownerId: 3 },
    ]);
    expect(ok.status).toBe(201);
  });

  it("PUT (replace) is checked like an insert", async () => {
    const res = await send("PUT", "/wr-docs", { id: 1, title: "a1", tenant: "a", ownerId: 2 });
    expect(res.status).toBe(403);
    expect(await doc(1)).toMatchObject({ ownerId: 1 });
    const ok = await send("PUT", "/wr-docs", { id: 1, title: "a1", tenant: "a", ownerId: 3 });
    expect(ok.status).toBeLessThan(300);
  });
});

describe("checkRefs — update", () => {
  it("a patch touching the FK is checked", async () => {
    const res = await send("PATCH", "/wr-docs", { id: 1, ownerId: 2 });
    expect(res.status).toBe(403);
    expect(res.body.message).toBe(OUT);
    expect(await doc(1)).toMatchObject({ ownerId: 1 });
    expect((await send("PATCH", "/wr-docs", { id: 1, ownerId: 3 })).status).toBeLessThan(300);
    expect((await send("PATCH", "/wr-docs", { id: 1, ownerId: null })).status).toBeLessThan(300);
  });

  it("a patch not touching the FK is not checked (the stored reference is left alone)", async () => {
    const res = await send("PATCH", "/wr-docs", { id: 3, title: "renamed" });
    expect(res.status).toBeLessThan(300);
    expect(await doc(3)).toMatchObject({ title: "renamed", ownerId: 2 });
  });

  it("bulk PATCH: one out-of-scope reference rejects the batch", async () => {
    const res = await send("PATCH", "/wr-docs", [
      { id: 1, title: "t1" },
      { id: 3, ownerId: 2 },
    ]);
    expect(res.status).toBe(403);
    expect(await doc(1)).toMatchObject({ title: "a1" });
  });
});

describe("checkRefs — configuration and union", () => {
  it("a TO relation name and `true` designate the same FK", async () => {
    for (const role of ["by-relation", "all"]) {
      await boot([role]);
      const res = await send("PATCH", "/wr-docs", { id: 1, ownerId: 2 });
      expect(res.status, role).toBe(403);
      expect(res.body.message, role).toBe(OUT);
    }
  });

  it("no check without the flag", async () => {
    await boot(["plain"]);
    expect((await send("PATCH", "/wr-docs", { id: 1, ownerId: 2 })).status).toBeLessThan(300);
  });

  it("no read grant on the target → 403 for any set reference; null still passes", async () => {
    await boot(["no-users-grant"]);
    const res = await send("PATCH", "/wr-docs", { id: 1, ownerId: 3 });
    expect(res.status).toBe(403);
    expect(res.body.message).toBe(OUT);
    expect((await send("PATCH", "/wr-docs", { id: 1, ownerId: null })).status).toBeLessThan(300);
  });

  it("no ARBAC controller registered for the target → 403", async () => {
    await boot(["by-field"], [OrphanDocsController]);
    const res = await send("PATCH", "/wr-docs-orphan", { id: 1, ownerId: 1 });
    expect(res.status).toBe(403);
    expect(res.body.message).toBe(OUT);
  });

  it("union: enforced only when EVERY write scope enables it", async () => {
    // `plain` grants unconstrained FK writes — the union is unconstrained.
    await boot(["by-field", "plain"]);
    expect((await send("PATCH", "/wr-docs", { id: 1, ownerId: 2 })).status).toBeLessThan(300);
    // Both enable it (by field name / by `true`) → enforced.
    await reseed();
    await boot(["by-field", "all"]);
    expect((await send("PATCH", "/wr-docs", { id: 1, ownerId: 2 })).status).toBe(403);
  });

  it("the target scope is the caller's own read scope on that resource", async () => {
    await boot(["notes"]);
    const ok = await send("POST", "/wr-notes", { id: 1, body: "n", tenant: "a", docId: 1 });
    expect(ok.status).toBe(201);
    const bad = await send("POST", "/wr-notes", { id: 2, body: "n", tenant: "a", docId: 2 });
    expect(bad.status).toBe(403);
    expect(bad.body.message).toBe('Referenced row "docId" is outside your scope');
  });
});

describe("checkRefs — useArbacDbScope().assertRefsInScope (handler-side inserts)", () => {
  it("checks the FKs the handler's scopes enforce", async () => {
    await boot(["custom"]);
    const bad = await send("POST", "/wr-docs/custom-insert", {
      id: 20,
      title: "x",
      tenant: "a",
      ownerId: 2,
    });
    expect(bad.status).toBe(403);
    expect(bad.body.message).toBe(OUT);
    expect(await doc(20)).toBeNull();
    for (const ownerId of [1, null]) {
      const id = ownerId ? 21 : 22;
      const ok = await send("POST", "/wr-docs/custom-insert", {
        id,
        title: "ok",
        tenant: "a",
        ownerId,
      });
      expect(ok.status, String(ownerId)).toBe(201);
    }
  });

  it("no check when the scopes do not enable it", async () => {
    await boot(["custom-plain"]);
    const res = await send("POST", "/wr-docs/custom-insert", {
      id: 20,
      title: "x",
      tenant: "a",
      ownerId: 2,
    });
    expect(res.status).toBe(201);
  });
});
