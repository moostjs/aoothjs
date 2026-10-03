import { allowTableAction, allowTableRead, defineRole } from "@aooth/arbac";
import { DbSpace } from "@atscript/db";
import { BetterSqlite3Driver, SqliteAdapter } from "@atscript/db-sqlite";
import {
  clearDbSpaces,
  DbAction,
  DbActionID,
  DbActionIDs,
  DbActionRow,
  DbActionRows,
  InputForm,
  provideDbSpace,
  TableController,
} from "@atscript/moost-db";
import type { MoostHttp } from "@moostjs/event-http";
import { Post } from "@moostjs/event-http";
import { clearGlobalWooks, Inherit } from "moost";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { bootArbacHttp } from "../../__testing__/arbac-http";
import { FakeUserProvider } from "../../__testing__/user-provider";
import { ArbacResource } from "../../arbac.decorator";
import { getArbacMate } from "../../arbac.mate";
import { MoostArbac } from "../../moost-arbac";
import { type ArbacDbScope, AsArbacDbController } from "../as-arbac-db-controller";
import { useArbacDbScope } from "../use-arbac-db-scope";
import { ActDoc, ApproveForm } from "./fixtures/actions-doc.as";

/**
 * Security regressions — `@DbAction` handlers on an ARBAC DB controller.
 *
 * Principal u1 (`actor`) holds `filter: { owner: "u1" }, projection: { secret: 0 }`
 * on reads and on every action. Rows 2 and 3 belong to u2 (out of scope; row 2
 * is `locked`); row 4 is in scope but its `secret` (`LOCKME`) is hidden.
 *
 * Not repeated here (covered elsewhere):
 * - no-grant CRUD (`POST` / `PATCH` / `PUT` / `DELETE` / reads) → 403 with and
 *   without the interceptor, `@Public()` not bypassing CRUD, and the unknown-form
 *   404 for a reader without the form's action → `write-scope.integration.spec.ts`;
 * - `/meta` dropping ungranted actions → `read-policy.integration.spec.ts`;
 * - hidden columns with the interceptor wired → `hidden-columns.integration.spec.ts`.
 */

const ACTIONS = [
  "approve",
  "peek",
  "gated",
  "gatedSecret",
  "bulk",
  "bulkGated",
  "bulkSkip",
  "purge",
  "purgeScoped",
  "formAction",
];
const SCOPE = (): ArbacDbScope => ({ filter: { owner: "u1" }, projection: { secret: 0 } });

const ROLES = [
  defineRole<object, ArbacDbScope>()
    .id("actor")
    .use(
      allowTableRead("acts", { scope: SCOPE }),
      allowTableAction("acts", ACTIONS, { scope: SCOPE }),
    )
    .build(),
  // Read-only principal: no action grant at all.
  defineRole<object, ArbacDbScope>().id("reader").use(allowTableRead("acts")).build(),
  // Unscoped read, row-scoped actions (owner u1 only).
  defineRole<object, ArbacDbScope>()
    .id("wide-read")
    .use(
      allowTableRead("acts"),
      allowTableAction("acts", ACTIONS, { scope: () => ({ filter: { owner: "u1" } }) }),
    )
    .build(),
  // One action grant, no read grant.
  defineRole<object, ArbacDbScope>()
    .id("act-only")
    .use(allowTableAction("acts", ["formAction"]))
    .build(),
];

const lockedVerdict = (rows: Array<{ status: string }>) =>
  rows.map((r) => (r.status === "locked" ? `Row is locked (status=${r.status})` : false));

/** Invocations of the table-level `purge` handler (it consults no scope itself). */
let purgeRuns = 0;

@Inherit()
class ActsBase extends AsArbacDbController<typeof ActDoc> {
  // Typical handler shape: mutate the row the id names.
  @Post("actions/approve")
  @DbAction("approve", { label: "approve" })
  async approve(@DbActionID() id: { id: number }) {
    const r = await this.table.updateOne({ id: id.id, status: "approved" });
    return { id, matched: r.matchedCount };
  }

  // Row param, no gate — the thin interceptor path.
  @Post("actions/peek")
  @DbAction("peek", { label: "peek", requiredFields: ["owner", "status", "secret"] })
  peek(@DbActionRow() row: unknown) {
    return { row };
  }

  @Post("actions/gated")
  @DbAction("gated", { label: "gated", requiredFields: ["status"], disabled: lockedVerdict })
  gated(@DbActionRow() row: unknown) {
    return { row };
  }

  // Gate over a column the principal's projection hides.
  @Post("actions/gatedSecret")
  @DbAction("gatedSecret", {
    label: "gatedSecret",
    requiredFields: ["secret"],
    disabled: (rows: Array<{ secret?: string }>) =>
      rows.map((r) => (r.secret === "LOCKME" ? `blocked: secret=${r.secret}` : false)),
  })
  gatedSecret(@DbActionRow() row: unknown) {
    return { row };
  }

  @Post("actions/bulk")
  @DbAction("bulk", { label: "bulk", requiredFields: ["owner", "secret"] })
  bulk(@DbActionIDs() ids: unknown, @DbActionRows() rows: unknown) {
    return { ids, rows };
  }

  @Post("actions/bulkGated")
  @DbAction("bulkGated", {
    label: "bulkGated",
    requiredFields: ["status"],
    disabled: lockedVerdict,
  })
  bulkGated(@DbActionRows() rows: unknown) {
    return { rows };
  }

  @Post("actions/bulkSkip")
  @DbAction("bulkSkip", {
    label: "bulkSkip",
    requiredFields: ["status", "owner"],
    disabled: lockedVerdict,
    onDisabledRows: "skip",
  })
  bulkSkip(@DbActionRows() rows: unknown) {
    return { rows };
  }

  // Table-level: no id, no scope consulted by the framework.
  @Post("actions/purge")
  @DbAction("purge", { label: "purge" })
  async purge() {
    purgeRuns++;
    return {
      unscopedCount: await this.readable.count({ filter: {} }),
      scopedCount: await this.readable.count({ filter: await this.transformFilter({}) }),
    };
  }

  // Table-level, opting in through the documented composable.
  @Post("actions/purgeScoped")
  @DbAction("purgeScoped", { label: "purgeScoped" })
  async purgeScoped() {
    const scope = await useArbacDbScope();
    return { scopedCount: await this.readable.count({ filter: scope.filter() }) };
  }

  @Post("actions/formAction")
  @DbAction("formAction", { label: "formAction" })
  formAction(@DbActionID() id: unknown, @InputForm(ApproveForm) input: unknown) {
    return { id, input };
  }
}

@TableController(ActDoc, "acts")
@ArbacResource("acts")
class ActsController extends ActsBase {}

// `@Public()` (auth-moost) writes this flag; the authorize interceptor skips it.
@TableController(ActDoc, "acts-public")
@ArbacResource("acts")
@(getArbacMate().decorate("arbacPublic", true))
class PublicActsController extends ActsBase {}

let driver: BetterSqlite3Driver;
let space: DbSpace;

const SEED = [
  { id: 1, owner: "u1", status: "open", secret: "s1" },
  { id: 2, owner: "u2", status: "locked", secret: "s2" },
  { id: 3, owner: "u2", status: "open", secret: "s3" },
  { id: 4, owner: "u1", status: "open", secret: "LOCKME" },
];

beforeAll(async () => {
  driver = new BetterSqlite3Driver(":memory:");
  space = new DbSpace(() => new SqliteAdapter(driver));
  await space.getTable(ActDoc).ensureTable();
  provideDbSpace(space);
});

afterAll(() => {
  clearDbSpaces();
  driver.close();
});

async function reseed(): Promise<void> {
  const t = space.getTable(ActDoc);
  await t.deleteMany({ id: { $gt: 0 } });
  await t.insertMany(SEED);
  purgeRuns = 0;
}

async function rowById(id: number) {
  return space.getTable(ActDoc).findOne({ filter: { id }, controls: {} } as never);
}

async function expectSeeded(...ids: number[]): Promise<void> {
  for (const id of ids) expect(await rowById(id), `row ${id}`).toEqual(SEED[id - 1]);
}

type Res = { status: number; body: any };
type Call = (method: string, path: string, body?: unknown) => Promise<Res>;

function client(http: MoostHttp, prefix: string): Call {
  return async (method, path, body) => {
    const res = await http.request(path ? `/${prefix}/${path}` : `/${prefix}`, {
      method,
      headers: body === undefined ? undefined : { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res!.text();
    let parsed: unknown = text;
    try {
      parsed = JSON.parse(text);
    } catch {
      // keep text
    }
    return { status: res!.status, body: parsed };
  };
}

async function boot(roles: string[], authorize = true) {
  clearGlobalWooks();
  const arbac = new MoostArbac<object, ArbacDbScope>();
  for (const role of ROLES) arbac.registerRole(role);
  const http = await bootArbacHttp({
    arbac,
    user: new FakeUserProvider("u1", roles),
    controllers: [ActsController, PublicActsController],
    authorize,
  });
  return { call: client(http, "acts"), callPublic: client(http, "acts-public") };
}

const ROW_NOT_FOUND = {
  statusCode: 404,
  message: "Row not found for action identifier",
  error: "Not Found",
};
const disabledFor = (action: string, ids: number[]) => ({
  name: "ActionDisabledError",
  message: `Action "${action}" is disabled for ${ids.length} of the selected rows`,
  statusCode: 409,
  action,
  ids: ids.map((id) => ({ id })),
  error: "Conflict",
});

beforeEach(reseed);

// Invariant: an action identifier addresses rows through the controller's row
// overlay (`transformOne({})`, here the ARBAC action-scope filter). A row
// outside it is indistinguishable from a nonexistent one — same status, same
// body, same slot — for id-only, row-loading, gated and bulk handlers.
describe("@DbAction ids and rows stay inside the action scope", () => {
  let call: Call;
  beforeEach(async () => {
    ({ call } = await boot(["actor"]));
  });

  it("an out-of-scope @DbActionID answers the missing-id 404 and the row is untouched", async () => {
    expect((await call("GET", "one/3")).status).toBe(404);
    const foreign = await call("POST", "actions/approve", { ids: { id: 3 } });
    const missing = await call("POST", "actions/approve", { ids: { id: 99 } });
    expect(foreign).toEqual({ status: 404, body: ROW_NOT_FOUND });
    expect(foreign).toEqual(missing);
    await expectSeeded(3);
  });

  it("a @DbActionID + @InputForm handler rejects an out-of-scope id the same way", async () => {
    const res = await call("POST", "actions/formAction", { ids: { id: 3 }, input: { note: "x" } });
    expect(res).toEqual({ status: 404, body: ROW_NOT_FOUND });
  });

  it("@DbActionRow never loads an out-of-scope row", async () => {
    const foreign = await call("POST", "actions/peek", { ids: { id: 3 } });
    expect(foreign).toEqual({ status: 404, body: ROW_NOT_FOUND });
    expect(foreign).toEqual(await call("POST", "actions/peek", { ids: { id: 99 } }));
  });

  it("@DbActionRow of an in-scope row never carries a scope-hidden column", async () => {
    const res = await call("POST", "actions/peek", { ids: { id: 4 } });
    expect(res).toEqual({ status: 201, body: { row: { id: 4, owner: "u1", status: "open" } } });
  });

  it("row-level gate: missing, out-of-scope locked and out-of-scope open ids are indistinguishable", async () => {
    const missing = await call("POST", "actions/gated", { ids: { id: 99 } });
    expect(missing).toEqual({ status: 404, body: ROW_NOT_FOUND });
    expect(await call("POST", "actions/gated", { ids: { id: 2 } })).toEqual(missing);
    expect(await call("POST", "actions/gated", { ids: { id: 3 } })).toEqual(missing);
  });

  it("@DbActionIDs / @DbActionRows: out-of-scope ids fail exactly like missing ids", async () => {
    const foreign = await call("POST", "actions/bulk", { ids: [{ id: 1 }, { id: 2 }, { id: 3 }] });
    expect(foreign).toEqual({ status: 409, body: disabledFor("bulk", [2, 3]) });
    const missing = await call("POST", "actions/bulk", {
      ids: [{ id: 1 }, { id: 98 }, { id: 99 }],
    });
    expect(missing).toEqual({ status: 409, body: disabledFor("bulk", [98, 99]) });
    // In-scope rows load without the hidden column.
    const inScope = await call("POST", "actions/bulk", { ids: [{ id: 1 }, { id: 4 }] });
    expect(inScope).toEqual({
      status: 201,
      body: {
        ids: [{ id: 1 }, { id: 4 }],
        rows: [
          { id: 1, owner: "u1" },
          { id: 4, owner: "u1" },
        ],
      },
    });
  });

  it("rows-level reject mode: an out-of-scope row never reveals its disabled reason", async () => {
    const res = await call("POST", "actions/bulkGated", {
      ids: [{ id: 1 }, { id: 2 }, { id: 3 }, { id: 99 }],
    });
    // Foreign locked (2), foreign open (3) and missing (99) share one reason-less shape.
    expect(res).toEqual({ status: 409, body: disabledFor("bulkGated", [2, 3, 99]) });
  });

  it("rows-level skip mode: out-of-scope rows are skipped like missing ones", async () => {
    const foreign = await call("POST", "actions/bulkSkip", {
      ids: [{ id: 1 }, { id: 2 }, { id: 3 }],
    });
    expect(foreign).toEqual({
      status: 201,
      body: { rows: [{ id: 1, status: "open", owner: "u1" }] },
    });
    const missing = await call("POST", "actions/bulkSkip", {
      ids: [{ id: 1 }, { id: 98 }, { id: 99 }],
    });
    expect(missing).toEqual(foreign);
  });

  it("an action scope narrower than the read scope still binds the action", async () => {
    ({ call } = await boot(["wide-read"]));
    expect((await call("GET", "one/3")).status).toBe(200);
    expect(await call("POST", "actions/peek", { ids: { id: 3 } })).toEqual({
      status: 404,
      body: ROW_NOT_FOUND,
    });
    expect((await call("POST", "actions/approve", { ids: { id: 3 } })).status).toBe(404);
    await expectSeeded(3);
  });

  it("a table-level handler reads the action scope through transformFilter", async () => {
    const res = await call("POST", "actions/purge");
    expect(res).toEqual({ status: 201, body: { unscopedCount: 4, scopedCount: 2 } });
  });

  it("a principal without the action grant is refused before any row load", async () => {
    ({ call } = await boot(["reader"]));
    expect((await call("POST", "actions/gated", { ids: { id: 2 } })).status).toBe(403);
    expect((await call("POST", "actions/approve", { ids: { id: 1 } })).status).toBe(403);
    await expectSeeded(1, 2);
  });
});

// Invariant: `requiredFields` never widen a read or an action row with a column
// the controller's `hasField` hides, and `disabled` verdicts see such a column
// as absent — neither `$disabledReasons`, the `$actions` list nor a 409 can
// leak its value.
describe("disabled verdicts and requiredFields never see scope-hidden columns", () => {
  let call: Call;
  beforeEach(async () => {
    ({ call } = await boot(["actor"]));
  });

  it("$actions widening does not return hidden columns", async () => {
    const res = await call("GET", "query?$actions=true&$sort=id");
    expect(res.status).toBe(200);
    expect(res.body.map((r: any) => r.id)).toEqual([1, 4]);
    for (const row of res.body) expect(row).not.toHaveProperty("secret");
    const one = await call("GET", "one/4?$actions=true");
    expect(one.status).toBe(200);
    expect(one.body).not.toHaveProperty("secret");
  });

  it("a verdict over a hidden column yields no reason and no enabled/disabled oracle", async () => {
    const res = await call("GET", "query?$actions=true&$sort=id");
    for (const row of res.body) {
      expect(row.$actions, `row ${row.id}`).toContain("gatedSecret");
      expect(row, `row ${row.id}`).not.toHaveProperty("$disabledReasons");
    }
    const one = await call("GET", "one/4?$actions=true");
    expect(one.body.$actions).toContain("gatedSecret");
    expect(one.body).not.toHaveProperty("$disabledReasons");
  });

  it("invoking the action evaluates the same blind verdict (no 409 carrying the hidden value)", async () => {
    const res = await call("POST", "actions/gatedSecret", { ids: { id: 4 } });
    expect(res).toEqual({ status: 201, body: { row: { id: 4 } } });
  });

  it("$actions lists nothing to a principal without action grants", async () => {
    ({ call } = await boot(["reader"]));
    const res = await call("GET", "query?$actions=true&$sort=id");
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(4);
    for (const row of res.body) expect(row.$actions ?? []).toEqual([]);
  });
});

// Invariant: `/meta/form/:name` needs the `metaForm` grant (resolved by
// `prepareRequest` when the interceptor did not run) AND a grant on one of the
// form's actions (`authorizeForm` — its 404 is pinned in write-scope.integration).
describe("/meta/form/:name stays behind the metaForm grant", () => {
  it("an action grant alone does not open the form", async () => {
    const { call } = await boot(["act-only"]);
    expect((await call("GET", "meta/form/ApproveForm")).status).toBe(403);
  });

  it("no grant: 403 without the interceptor and on a @Public() controller", async () => {
    const bare = await boot([], false);
    expect((await bare.call("GET", "meta/form/ApproveForm")).status).toBe(403);
    const wired = await boot([], true);
    expect((await wired.callPublic("GET", "meta/form/ApproveForm")).status).toBe(403);
  });
});

// Invariant: with no authorize interceptor (or on a `@Public()` controller,
// which the interceptor skips) the ARBAC DB controllers' `prepareRequest`
// (endpoint "action") still evaluates the action being run before any
// row loads — no grant is a 403 and nothing is written; a grant still binds
// the action to its own scope (the row overlay).
describe("@DbAction routes fail closed without the authorize interceptor", () => {
  it("no grant: every id-bearing action is a 403 and nothing is written", async () => {
    const { call, callPublic } = await boot([], false);
    expect((await call("POST", "actions/approve", { ids: { id: 2 } })).status).toBe(403);
    expect((await call("POST", "actions/peek", { ids: { id: 1 } })).status).toBe(403);
    expect((await call("POST", "actions/bulk", { ids: [{ id: 1 }] })).status).toBe(403);
    expect((await callPublic("POST", "actions/approve", { ids: { id: 1 } })).status).toBe(403);
    await expectSeeded(1, 2);
  });

  it("@Public() controller with the interceptor wired: no grant → 403, nothing written", async () => {
    const { callPublic } = await boot([], true);
    expect((await callPublic("POST", "actions/approve", { ids: { id: 2 } })).status).toBe(403);
    expect((await callPublic("POST", "actions/peek", { ids: { id: 1 } })).status).toBe(403);
    await expectSeeded(1, 2);
  });

  it("a read grant without the action grant is refused the same way", async () => {
    const { call } = await boot(["reader"], false);
    expect((await call("POST", "actions/approve", { ids: { id: 1 } })).status).toBe(403);
    await expectSeeded(1);
  });

  it("a scoped actor still acts only inside its action scope", async () => {
    const { call } = await boot(["actor"], false);
    expect((await call("POST", "actions/approve", { ids: { id: 3 } })).status).toBe(404);
    await expectSeeded(3);
    const own = await call("POST", "actions/approve", { ids: { id: 1 } });
    expect(own).toEqual({ status: 201, body: { id: { id: 1 }, matched: 1 } });
    expect(await rowById(1)).toMatchObject({ status: "approved" });
  });

  it("a table-level handler opting in via useArbacDbScope() is refused with 403", async () => {
    const bare = await boot([], false);
    expect((await bare.call("POST", "actions/purgeScoped")).status).toBe(403);
    const wired = await boot([], true);
    expect((await wired.callPublic("POST", "actions/purgeScoped")).status).toBe(403);
    const actor = await boot(["actor"], false);
    expect(await actor.call("POST", "actions/purgeScoped")).toEqual({
      status: 201,
      body: { scopedCount: 2 },
    });
  });

  // A table-level `@DbAction` (no id / row params): moost-db still runs
  // `prepareRequest` (endpoint "action") before it — that is what refuses it.
  it("a table-level handler that consults no scope is still refused (403, never run)", async () => {
    const bare = await boot([], false);
    expect((await bare.call("POST", "actions/purge")).status).toBe(403);
    const wired = await boot([], true);
    expect((await wired.callPublic("POST", "actions/purge")).status).toBe(403);
    expect(purgeRuns).toBe(0);
  });
});

// Invariant: without the interceptor the column scope still applies — the
// scopes are resolved in `prepareRequest` before projection / `hasField` run
// (they never fall back to "unrestricted").
describe("a scoped reader keeps its column scope without the authorize interceptor", () => {
  let call: Call;
  beforeEach(async () => {
    ({ call } = await boot(["actor"], false));
  });

  it("/query strips the hidden column and keeps the row filter", async () => {
    const res = await call("GET", "query?$sort=id");
    expect(res).toEqual({
      status: 200,
      body: [
        { id: 1, owner: "u1", status: "open" },
        { id: 4, owner: "u1", status: "open" },
      ],
    });
  });

  it.each(["secret='LOCKME'", "$sort=secret"])("?%s → 400 Unknown field", async (query) => {
    const res = await call("GET", `query?${query}`);
    expect(res.status).toBe(400);
    expect(res.body.message).toBe('Unknown field "secret"');
  });

  it("/one/:id strips the hidden column and keeps the row overlay", async () => {
    expect(await call("GET", "one/1")).toEqual({
      status: 200,
      body: { id: 1, owner: "u1", status: "open" },
    });
    expect((await call("GET", "one/3")).status).toBe(404);
  });
});
