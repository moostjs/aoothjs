import {
  allowTableAction,
  allowTableOps,
  allowTableRead,
  allowTableWrite,
  defineRole,
} from "@aooth/arbac";
import type { TDbWriteAction } from "@atscript/db";
import { DbSpace } from "@atscript/db";
import { BetterSqlite3Driver, SqliteAdapter } from "@atscript/db-sqlite";
import { AsDbController, clearDbSpaces, provideDbSpace, TableController } from "@atscript/moost-db";
import type { MoostHttp } from "@moostjs/event-http";
import { Body, Delete, Get, Patch, Put, Url } from "@moostjs/event-http";
import { clearGlobalWooks, defineBeforeInterceptor, Intercept, Param } from "moost";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { bootArbacHttp } from "../__testing__/arbac-http";
import { FakeUserProvider } from "../__testing__/user-provider";
import { ArbacAction, ArbacResource } from "../arbac.decorator";
import type { AoothArbacClaims } from "../attenuation";
import { MoostArbac } from "../moost-arbac";
import { RbPair } from "./__test__/fixtures/read-back.as";
import { ScopedDoc } from "./__test__/fixtures/scoped-doc.as";
import { type ArbacDbScope, AsArbacDbController } from "./as-arbac-db-controller";
import {
  cachedRequestScopes,
  isInsertIgnoreRequest,
  readBackUnderReadGrant,
} from "./request-scopes";

/**
 * `Prefer: return=representation` on an opted-in ARBAC DB controller: the
 * insert's read-back (`row`) is exactly what `GET /one/:id` answers the
 * caller — authorized by the caller's grant on the `/one` handler, with that
 * grant's projection and row filter — never the insert grant's view. A
 * denied read-back answers the plain insert result (the insert stands).
 */

const hideSecret = () => ({ projection: { secret: 0 as const } });

const insertOnly = defineRole<object, ArbacDbScope>()
  .id("insert-only")
  .use(allowTableOps("rb", ["insert"]))
  .build();
// Unrestricted insert, but the read grant hides `secret`.
const insertHidden = defineRole<object, ArbacDbScope>()
  .id("insert-hidden")
  .use(allowTableOps("rb", ["insert"]))
  .use(allowTableRead("rb", { scope: hideSecret }))
  .build();
// Unrestricted insert, but the read grant sees only open rows.
const insertOpenOnly = defineRole<object, ArbacDbScope>()
  .id("insert-open-only")
  .use(allowTableOps("rb", ["insert"]))
  .use(allowTableRead("rb", { scope: () => ({ filter: { status: "open" } }) }))
  .build();
const full = defineRole<object, ArbacDbScope>().id("full").use(allowTableWrite("rb")).build();
// The composite table: insert plus `getOne` only (no `getOneComposite`), and
// insert plus a read grant hiding `secret`.
const pairsNoComposite = defineRole<object, ArbacDbScope>()
  .id("pairs-no-composite")
  .use(allowTableOps("rb-pairs", ["insert"]), () => [{ resource: "rb-pairs", action: "getOne" }])
  .build();
const pairsHidden = defineRole<object, ArbacDbScope>()
  .id("pairs-hidden")
  .use(allowTableOps("rb-pairs", ["insert"]))
  .use(allowTableRead("rb-pairs", { scope: hideSecret }))
  .build();

// Every write op, plus a read grant hiding `secret`.
const writerHidden = defineRole<object, ArbacDbScope>()
  .id("writer-hidden")
  .use(allowTableOps("rb", ["insert", "update", "replace", "remove"]))
  .use(allowTableRead("rb", { scope: hideSecret }))
  .build();
// Full read on `getOne`, but `readOne` (a method-level `@ArbacAction`) hides `secret`.
const readOneHidden = defineRole<object, ArbacDbScope>()
  .id("readone-hidden")
  .use(allowTableOps("rb", ["insert"]), allowTableRead("rb"))
  .use(allowTableAction("rb", "readOne", { scope: hideSecret }))
  .build();
// Full read on `rb`, but `rb-other.getOne` (a method-level `@ArbacResource`) hides `secret`.
const otherHidden = defineRole<object, ArbacDbScope>()
  .id("other-hidden")
  .use(allowTableOps("rb", ["insert"]), allowTableRead("rb"))
  .use(allowTableAction("rb-other", "getOne", { scope: hideSecret }))
  .build();
// The read grant's scope predicate throws.
const readThrows = defineRole<object, ArbacDbScope>()
  .id("read-throws")
  .use(allowTableOps("rb", ["insert"]))
  .use(
    allowTableRead("rb", {
      scope: () => {
        throw new Error("scope predicate failed");
      },
    }),
  )
  .build();

/** What the hooks saw, per request — for the scope-restoration test. */
let seen: {
  write?: ArbacDbScope[];
  readBack?: ArbacDbScope[];
  after?: ArbacDbScope[];
  ignoreDuringReadBack?: boolean;
  ignoreAfter?: boolean;
} = {};

@TableController(ScopedDoc, "rb")
@ArbacResource("rb")
class OptedInController extends AsArbacDbController<typeof ScopedDoc> {
  protected returnRepresentation(): boolean {
    return true;
  }

  protected onWrite(action: TDbWriteAction, data: unknown): unknown {
    seen.write = cachedRequestScopes();
    return super.onWrite(action, data);
  }

  protected transformProjection(
    projection?: Parameters<AsArbacDbController["transformProjection"]>[0],
  ) {
    seen.readBack = cachedRequestScopes();
    seen.ignoreDuringReadBack = isInsertIgnoreRequest();
    return super.transformProjection(projection);
  }

  protected async _readRepresentation(id: unknown) {
    const row = await super._readRepresentation(id);
    seen.after = cachedRequestScopes();
    seen.ignoreAfter = isInsertIgnoreRequest();
    return row;
  }
}

// Same table and resource, NOT opted in.
@TableController(ScopedDoc, "rb-plain")
@ArbacResource("rb")
class PlainController extends AsArbacDbController<typeof ScopedDoc> {}

// Same table, opted in, but its read-back skips the ARBAC override (calls
// moost-db's directly): the `"one"` request under the insert handler must
// not be served under the insert grant.
@TableController(ScopedDoc, "rb-bypass")
@ArbacResource("rb")
class BypassController extends AsArbacDbController<typeof ScopedDoc> {
  protected returnRepresentation(): boolean {
    return true;
  }

  protected _readRepresentation(id: unknown) {
    return AsDbController.prototype["_readRepresentation"].call(this, id) as ReturnType<
      AsArbacDbController<typeof ScopedDoc>["_readRepresentation"]
    >;
  }
}

// `getOne` overridden: its BODY redacts classified rows. The read-back runs it.
@TableController(ScopedDoc, "rb-redact")
@ArbacResource("rb")
class RedactController extends AsArbacDbController<typeof ScopedDoc> {
  protected returnRepresentation(): boolean {
    return true;
  }

  @Get("one/:id")
  async getOne(@Param("id") id: string, @Url() url: string) {
    const row = (await super.getOne(id, url)) as { id?: number; status?: string };
    return row?.status === "classified" ? ({ id: row.id } as never) : (row as never);
  }
}

// `getOne` with a method-level interceptor: a direct call would skip it → no read-back.
@TableController(ScopedDoc, "rb-intercepted")
@ArbacResource("rb")
class InterceptedController extends AsArbacDbController<typeof ScopedDoc> {
  protected returnRepresentation(): boolean {
    return true;
  }

  @Get("one/:id")
  @Intercept(defineBeforeInterceptor(() => {}))
  async getOne(@Param("id") id: string, @Url() url: string) {
    return super.getOne(id, url);
  }
}

// `getOne` authorized as `rb.readOne` (method-level `@ArbacAction`).
@TableController(ScopedDoc, "rb-readone")
@ArbacResource("rb")
class ReadOneController extends AsArbacDbController<typeof ScopedDoc> {
  protected returnRepresentation(): boolean {
    return true;
  }

  @Get("one/:id")
  @ArbacAction("readOne")
  async getOne(@Param("id") id: string, @Url() url: string) {
    return super.getOne(id, url);
  }
}

// `getOne` authorized as `rb-other.getOne` (method-level `@ArbacResource`).
@TableController(ScopedDoc, "rb-other-res")
@ArbacResource("rb")
class OtherResourceController extends AsArbacDbController<typeof ScopedDoc> {
  protected returnRepresentation(): boolean {
    return true;
  }

  @Get("one/:id")
  @ArbacResource("rb-other")
  async getOne(@Param("id") id: string, @Url() url: string) {
    return super.getOne(id, url);
  }
}

// Write overrides reading after the write — refused (403) since 0.2.4: the
// read would run under the WRITE grant.
@TableController(ScopedDoc, "rb-writes")
@ArbacResource("rb")
class WriteReadsController extends AsArbacDbController<typeof ScopedDoc> {
  @Patch("")
  async update(@Body() payload: { id: number }) {
    await super.update(payload);
    return this.getOne(String(payload.id), "");
  }

  @Put("")
  async replace(@Body() payload: { id: number }) {
    await super.replace(payload);
    return this.getOne(String(payload.id), "");
  }

  @Delete(":id")
  async remove(@Param("id") id: string) {
    await super.remove(id);
    return this.getOne(id, "");
  }
}

// A write override listing rows after the write — refused the same way.
@TableController(ScopedDoc, "rb-writes-query")
@ArbacResource("rb")
class WriteQueriesController extends AsArbacDbController<typeof ScopedDoc> {
  @Patch("")
  async update(@Body() payload: unknown) {
    await super.update(payload);
    return this.query("");
  }
}

// The migration: read the written row back under the read grant.
@TableController(ScopedDoc, "rb-migrated")
@ArbacResource("rb")
class MigratedController extends AsArbacDbController<typeof ScopedDoc> {
  @Patch("")
  async update(@Body() payload: { id: number }) {
    await super.update(payload);
    const { id } = payload;
    return { row: (await readBackUnderReadGrant(id, () => this.getOne(String(id), ""))) ?? null };
  }
}

// A composite key's read-back is the `GET /one?…` read (`getOneComposite`).
@TableController(RbPair, "rb-pairs")
@ArbacResource("rb-pairs")
class PairsController extends AsArbacDbController<typeof RbPair> {
  protected returnRepresentation(): boolean {
    return true;
  }
}

let driver: BetterSqlite3Driver;
let space: DbSpace;

beforeAll(async () => {
  driver = new BetterSqlite3Driver(":memory:");
  space = new DbSpace(() => new SqliteAdapter(driver));
  await space.getTable(ScopedDoc).ensureTable();
  await space.getTable(RbPair).ensureTable();
  provideDbSpace(space);
});

afterAll(() => {
  clearDbSpaces();
  driver.close();
});

let http: MoostHttp;

const ROLES = [
  insertOnly,
  insertHidden,
  insertOpenOnly,
  full,
  pairsNoComposite,
  pairsHidden,
  writerHidden,
  readOneHidden,
  otherHidden,
  readThrows,
];

async function boot(roles: string[], attenuation?: AoothArbacClaims): Promise<void> {
  clearGlobalWooks();
  const arbac = new MoostArbac<object, ArbacDbScope>();
  for (const r of ROLES) arbac.registerRole(r);
  const user = new FakeUserProvider("u1", roles);
  user.attenuation = attenuation;
  http = await bootArbacHttp({
    arbac,
    user,
    controllers: [
      OptedInController,
      PlainController,
      BypassController,
      RedactController,
      InterceptedController,
      ReadOneController,
      OtherResourceController,
      WriteReadsController,
      WriteQueriesController,
      MigratedController,
      PairsController,
    ],
    authorize: true,
  });
}

interface Res {
  status: number;
  body: any;
  applied: string | null;
}

async function call(method: string, path: string, body?: unknown, prefer = true): Promise<Res> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (prefer) headers.prefer = "return=representation";
  const res = (await http.request(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  }))!;
  const text = await res.text();
  return {
    status: res.status,
    body: text ? JSON.parse(text) : text,
    applied: res.headers.get("preference-applied"),
  };
}

const stored = (id: number) => space.getTable(ScopedDoc).findOne({ filter: { id }, controls: {} });
const doc = (id: number, status = "open") => ({
  id,
  title: `t${id}`,
  status,
  secret: `s${id}`,
  rank: id,
});
/** `doc(id)` as a read grant hiding `secret` answers it. */
const visible = (id: number, status = "open") => ({ id, title: `t${id}`, status, rank: id });

const get = (path: string) => call("GET", path, undefined, false);

/** The plain insert result: no `row`, no `Preference-Applied`. */
function expectPlain(res: Res, insertedId: unknown): void {
  expect(res.status).toBe(201);
  expect(res.body).toEqual({ insertedId });
  expect(res.applied).toBeNull();
}

beforeEach(() => {
  driver.exec(`DELETE FROM "scoped_docs"`);
  driver.exec(`DELETE FROM "read_back_pairs"`);
  seen = {};
});

describe("AsArbacDbController — insert read-back under the caller's read grant", () => {
  it("an insert-only role gets the plain result; the row is stored", async () => {
    await boot(["insert-only"]);
    const res = await call("POST", "/rb", doc(1));
    expectPlain(res, 1);
    expect(await stored(1)).toMatchObject({ id: 1, secret: "s1" });
    // The same caller's GET /one is a 403 — the read-back answers like it.
    expect((await get("/rb/one/1")).status).toBe(403);
  });

  it("a read projection hiding a field hides it in the row", async () => {
    await boot(["insert-hidden"]);
    const res = await call("POST", "/rb", doc(2));
    expect(res.status).toBe(201);
    expect(res.applied).toBe("return=representation");
    expect(res.body.row).toEqual(visible(2));
    expect((await get("/rb/one/2")).body).toEqual(res.body.row);
  });

  it("a read row filter excluding the new row → no row", async () => {
    await boot(["insert-open-only"]);
    const res = await call("POST", "/rb", doc(3, "done"));
    expectPlain(res, 3);
    expect(await stored(3)).toMatchObject({ id: 3, status: "done" });
    // Inside the read filter → the row.
    const open = await call("POST", "/rb", doc(4));
    expect(open.body.row).toEqual(doc(4));
  });

  it("a full read grant → row equals GET /one/:id", async () => {
    await boot(["full"]);
    const res = await call("POST", "/rb", doc(5));
    expect(res.status).toBe(201);
    expect(res.applied).toBe("return=representation");
    expect(res.body.insertedId).toBe(5);
    const one = await get("/rb/one/5");
    expect(one.status).toBe(200);
    expect(res.body.row).toEqual(one.body);
    expect(res.body.row).toEqual(doc(5));
  });

  it("without opting in, Prefer is ignored", async () => {
    await boot(["full"]);
    const res = await call("POST", "/rb-plain", doc(6));
    expectPlain(res, 6);
  });

  it("the insert's scopes are back in place after the read-back", async () => {
    await boot(["insert-hidden"]);
    const res = await call("POST", "/rb?$onConflict=ignore", doc(7));
    expect(res.body.row).toEqual(visible(7));
    expect(seen.write).toBeDefined();
    // During the read-back: the read grant (projection hides `secret`).
    expect(seen.readBack).not.toBe(seen.write);
    expect(seen.readBack).toEqual([{ projection: { secret: 0 } }]);
    expect(seen.ignoreDuringReadBack).toBe(false);
    // After it: the very insert scopes, ignore mode included.
    expect(seen.after).toBe(seen.write);
    expect(seen.ignoreAfter).toBe(true);
  });

  it("a read-back that skips the ARBAC override is denied, not served under the insert grant", async () => {
    await boot(["insert-hidden"]);
    const res = await call("POST", "/rb-bypass", doc(8));
    expectPlain(res, 8);
    expect(await stored(8)).toMatchObject({ id: 8, secret: "s8" });
  });

  it("a composite id reads back through getOneComposite's grant", async () => {
    await boot(["pairs-no-composite"]);
    const denied = await call("POST", "/rb-pairs", { left: 1, right: 2, label: "p", secret: "x" });
    expectPlain(denied, { left: 1, right: 2 });
    expect(
      await space.getTable(RbPair).findOne({ filter: { left: 1, right: 2 }, controls: {} }),
    ).toMatchObject({ label: "p", secret: "x" });

    await boot(["pairs-hidden"]);
    const res = await call("POST", "/rb-pairs", { left: 3, right: 4, label: "q", secret: "y" });
    expect(res.status).toBe(201);
    expect(res.applied).toBe("return=representation");
    expect(res.body.insertedId).toEqual({ left: 3, right: 4 });
    expect(res.body.row).toEqual({ left: 3, right: 4, label: "q" });
    const one = await get("/rb-pairs/one?left=3&right=4");
    expect(one.status).toBe(200);
    expect(one.body).toEqual(res.body.row);
  });
});

describe("AsArbacDbController — the read-back is the /one handler", () => {
  it("an overridden getOne body runs: its redaction applies to row", async () => {
    await boot(["full"]);
    const res = await call("POST", "/rb-redact", doc(20, "classified"));
    expect(res.status).toBe(201);
    expect(res.body.row).toEqual({ id: 20 });
    expect((await get("/rb-redact/one/20")).body).toEqual({ id: 20 });
    expect((await call("POST", "/rb-redact", doc(21))).body.row).toEqual(doc(21));
  });

  it("method-level interceptors on getOne → plain result", async () => {
    await boot(["full"]);
    const res = await call("POST", "/rb-intercepted", doc(22));
    expectPlain(res, 22);
  });

  it("a method-level @ArbacAction on getOne decides the read grant", async () => {
    await boot(["readone-hidden"]);
    const res = await call("POST", "/rb-readone", doc(23));
    expect(res.body.row).toEqual(visible(23));
    expect((await get("/rb-readone/one/23")).body).toEqual(visible(23));
  });

  it("a method-level @ArbacResource on getOne decides the read grant", async () => {
    await boot(["other-hidden"]);
    const res = await call("POST", "/rb-other-res", doc(24));
    expect(res.body.row).toEqual(visible(24));
    expect((await get("/rb-other-res/one/24")).body).toEqual(visible(24));
  });

  it("credential attenuation narrows the read-back like GET /one", async () => {
    await boot(["full", "insert-hidden"], { roles: ["insert-hidden"] });
    const res = await call("POST", "/rb", doc(25));
    expect(res.body.row).toEqual(visible(25));
    expect((await get("/rb/one/25")).body).toEqual(visible(25));
  });

  it("a failing read-grant evaluation → 201 without row, nothing echoed", async () => {
    await boot(["read-throws"]);
    const res = await call("POST", "/rb", doc(26));
    expectPlain(res, 26);
    expect(await stored(26)).toMatchObject({ id: 26 });
  });

  it("$onConflict=ignore on an existing row → no read-back", async () => {
    await space.getTable(ScopedDoc).insertOne(doc(27));
    await boot(["full"]);
    const res = await call("POST", "/rb?$onConflict=ignore", { ...doc(27), title: "other" });
    expect(res.status).toBe(201);
    expect(res.body).toEqual({ conflict: true });
    expect(res.applied).toBeNull();
  });
});

describe("AsArbacDbController — reads under a write handler", () => {
  beforeEach(async () => {
    await space.getTable(ScopedDoc).insertOne(doc(30));
    await boot(["writer-hidden"]);
  });

  it.each([
    ["PATCH", "/rb-writes", { id: 30, title: "changed" }],
    ["PUT", "/rb-writes", { ...doc(30), title: "changed" }],
    ["DELETE", "/rb-writes/30", undefined],
  ])(
    "%s override calling this.getOne → 403 (the write is committed)",
    async (method, path, body) => {
      const res = await call(method, path, body, false);
      expect(res.status).toBe(403);
      const row = await stored(30);
      if (method === "DELETE") expect(row).toBeNull();
      else expect(row).toMatchObject({ title: "changed" });
    },
  );

  it("an update override calling this.query → 403", async () => {
    const res = await call("PATCH", "/rb-writes-query", { id: 30, title: "changed" }, false);
    expect(res.status).toBe(403);
  });

  it("readBackUnderReadGrant(id, () => this.getOne(…)) under update → the read grant's row", async () => {
    const res = await call("PATCH", "/rb-migrated", { id: 30, title: "changed" }, false);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ row: { ...visible(30), title: "changed" } });
  });
});
