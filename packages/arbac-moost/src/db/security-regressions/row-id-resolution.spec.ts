// `resolveRowIds` (moost-db 0.1.148) under ARBAC, and the scope-first action
// gate. The hook maps an alias to a canonical id BEFORE the row is read, so
// the permission layer must answer an alias of an out-of-scope row exactly
// like an id that names nothing — the alias must never become an oracle.
import { allowTableAction, allowTableRead, allowTableWrite, defineRole } from "@aooth/arbac";
import {
  DbAction,
  DbActionID,
  DbActionIDs,
  TableController,
  type TDbRowIdInput,
  type TDbRowIdsContext,
} from "@atscript/moost-db";
import { Post } from "@moostjs/event-http";
import type { MoostHttp } from "@moostjs/event-http";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { ArbacResource } from "../../arbac.decorator";
import { type ArbacDbScope, AsArbacDbController } from "../as-arbac-db-controller";
import { R12Code } from "./fixtures/round12-fixtures.as";
import { boot, send } from "./relations-harness";
import { createR12Space, type R12Space } from "./round12-harness";

const tenant = (t: string) => (): ArbacDbScope => ({ filter: { tenant: t } });

const ROLES = [
  // Everything on tenant a: reads, writes, both actions.
  defineRole<object, ArbacDbScope>()
    .id("tenant-a")
    .use(
      allowTableWrite("codes", { scope: tenant("a") }),
      allowTableAction("codes", ["ping", "bulk"], { scope: tenant("a") }),
    )
    .build(),
  // The same, with the unique `code` key hidden from the caller.
  defineRole<object, ArbacDbScope>()
    .id("code-hidden")
    .use(allowTableRead("codes", { scope: () => ({ projection: { code: 0 } }) }))
    .build(),
  // Holds nothing on `codes`.
  defineRole<object, ArbacDbScope>().id("nobody").use(allowTableRead("elsewhere")).build(),
  // Action grants WITHOUT a row filter / with one (no read grant).
  defineRole<object, ArbacDbScope>()
    .id("ping-any")
    .use(allowTableAction("scoped", ["ping"]))
    .build(),
  defineRole<object, ArbacDbScope>()
    .id("ping-a")
    .use(allowTableAction("scoped", ["ping"], { scope: tenant("a") }))
    .build(),
  // Reads every tenant, may `ping` only tenant a: the action scope differs from the read overlay.
  defineRole<object, ArbacDbScope>()
    .id("read-all-ping-a")
    .use(allowTableRead("scoped"), allowTableAction("scoped", ["ping"], { scope: tenant("a") }))
    .build(),
];

/** The alias table the hook consults: old key → canonical id (scalar or identification). */
const ALIASES: Record<string, TDbRowIdInput> = {
  "T-OLD": "T-NEW",
  "B-OLD": "T-OTHER",
  "HIDDEN-OLD": { code: "T-NEW" },
};
const hookCalls: Array<{ ids: readonly TDbRowIdInput[]; ctx: TDbRowIdsContext }> = [];
let pinged: unknown[] = [];
let bulked: unknown[] = [];

@TableController(R12Code as never, "codes")
@ArbacResource("codes")
class CodesController extends AsArbacDbController<typeof R12Code> {
  protected resolveRowIds(ids: readonly TDbRowIdInput[], ctx: TDbRowIdsContext) {
    hookCalls.push({ ids, ctx });
    return ids.map((id) => {
      const key = typeof id === "object" ? id.code : id;
      const to = typeof key === "string" ? ALIASES[key] : undefined;
      if (to === undefined) return id;
      return typeof id === "object" && typeof to === "string" ? { code: to } : to;
    });
  }

  @Post("actions/ping")
  @DbAction("ping", { label: "Ping" })
  ping(@DbActionID() id: unknown) {
    pinged.push(id);
    return { id };
  }

  @Post("actions/bulk")
  @DbAction("bulk", { label: "Bulk" })
  bulk(@DbActionIDs() ids: unknown[]) {
    bulked.push(ids);
    return { ids };
  }
}

// No `resolveRowIds`: the plain scope-first action gate.
@TableController(R12Code as never, "scoped")
@ArbacResource("scoped")
class ScopedCodesController extends AsArbacDbController<typeof R12Code> {
  @Post("actions/ping")
  @DbAction("ping", { label: "Ping" })
  ping(@DbActionID() id: unknown) {
    pinged.push(id);
    return { id };
  }
}

let space: R12Space;
let http: MoostHttp;
async function bootAs(...roles: string[]) {
  ({ http } = await boot(ROLES, [CodesController, ScopedCodesController], roles));
}
const get = (path: string) => send(http, "GET", path);
const post = (path: string, body?: unknown) => send(http, "POST", path, body);
const del = (path: string) => send(http, "DELETE", path);

beforeAll(async () => {
  space = await createR12Space();
});
afterAll(() => space.close());
beforeEach(async () => {
  await space.seed();
  hookCalls.length = 0;
  pinged = [];
  bulked = [];
  space.resetQueries();
});

describe("no grant → 403 before the hook runs", () => {
  it("answers 403 on every id-addressed route and never calls resolveRowIds", async () => {
    await bootAs("nobody");
    const answers = [
      await get("/codes/one/T-OLD"),
      await get("/codes/one?code=T-OLD"),
      await del("/codes/T-OLD"),
      await get("/codes/meta/actions/T-OLD"),
      await post("/codes/actions/ping", { ids: { code: "T-OLD" } }),
      await post("/codes/actions/bulk", { ids: [{ code: "T-OLD" }] }),
    ];
    expect(answers.map((r) => r.status)).toEqual([403, 403, 403, 403, 403, 403]);
    expect(hookCalls).toEqual([]);
  });
});

describe("an alias of an out-of-scope row answers like a nonexistent id", () => {
  // "B-OLD" → tenant b's row (out of scope); "NOPE" names nothing at all.
  it("/one, scalar and ?field= forms", async () => {
    await bootAs("tenant-a");
    const own = await get("/codes/one/T-OLD");
    expect(own.status).toBe(200);
    expect(own.body).toMatchObject({ id: 1, code: "T-NEW" });
    for (const [alias, missing] of [
      ["/codes/one/B-OLD", "/codes/one/NOPE"],
      ["/codes/one?code=B-OLD", "/codes/one?code=NOPE"],
    ]) {
      const a = await get(alias);
      const m = await get(missing);
      expect(a.status).toBe(404);
      expect(a.status).toBe(m.status);
      expect(a.body).toEqual(m.body);
      expect(JSON.stringify(a.body)).not.toContain("T-OTHER");
    }
  });

  it("DELETE removes nothing for an out-of-scope alias, the canonical row for an own one", async () => {
    await bootAs("tenant-a");
    const a = await del("/codes/B-OLD");
    const m = await del("/codes/NOPE");
    expect(a.status).toBe(m.status);
    expect(a.body).toEqual(m.body);
    expect(
      (await space.rows(R12Code)).map((r) => r.id as number).toSorted((a, b) => a - b),
    ).toEqual([1, 2]);
    expect((await del("/codes/T-OLD")).status).toBeLessThan(300);
    expect((await space.rows(R12Code)).map((r) => r.id)).toEqual([2]);
  });

  it("GET /meta/actions/:id", async () => {
    await bootAs("tenant-a");
    const own = await get("/codes/meta/actions/T-OLD");
    expect(own.body.actions.toSorted()).toEqual(["bulk", "ping"]);
    const a = await get("/codes/meta/actions/B-OLD");
    const m = await get("/codes/meta/actions/NOPE");
    expect(a.status).toBe(m.status);
    expect(a.body).toEqual(m.body);
    expect(a.body).toEqual({ actions: [] });
  });

  it("a 'row' action", async () => {
    await bootAs("tenant-a");
    const own = await post("/codes/actions/ping", { ids: { code: "T-OLD" } });
    expect(own.status).toBe(201);
    // The handler received the RESOLVED id; the response is the handler's.
    expect(pinged).toEqual([{ code: "T-NEW" }]);
    const a = await post("/codes/actions/ping", { ids: { code: "B-OLD" } });
    const m = await post("/codes/actions/ping", { ids: { code: "NOPE" } });
    expect(a.status).toBe(404);
    expect(a.status).toBe(m.status);
    // Both bodies echo the id the client sent, never the canonical one.
    expect(JSON.stringify(a.body)).not.toContain("T-OTHER");
    expect(JSON.stringify(a.body).replace("B-OLD", "NOPE")).toBe(JSON.stringify(m.body));
    expect(pinged).toHaveLength(1);
  });
});

describe("a 'rows' refusal carries the id the client sent", () => {
  it("names the old id, never the canonical key; nothing runs", async () => {
    await bootAs("tenant-a");
    const r = await post("/codes/actions/bulk", { ids: [{ code: "T-OLD" }, { code: "B-OLD" }] });
    expect(r.status).toBeGreaterThanOrEqual(400);
    const text = JSON.stringify(r.body);
    expect(text).toContain("B-OLD");
    expect(text).not.toContain("T-OTHER");
    expect(bulked).toEqual([]);
    // In-scope aliases alone run, with the resolved ids.
    const ok = await post("/codes/actions/bulk", { ids: [{ code: "T-OLD" }] });
    expect(ok.status).toBe(201);
    expect(bulked).toEqual([[{ code: "T-NEW" }]]);
  });
});

describe("a server bug is a 500", () => {
  it("a unique key the caller cannot see, returned by the hook, fails the request", async () => {
    await bootAs("code-hidden");
    const r = await get("/codes/one/HIDDEN-OLD");
    expect(r.status).toBe(500);
    expect(JSON.stringify(r.body)).not.toContain("T-NEW");
  });
});

describe("hook context", () => {
  it("receives the purpose and the request's row overlay", async () => {
    await bootAs("tenant-a");
    await get("/codes/one/T-OLD");
    expect(hookCalls).toHaveLength(1);
    expect(hookCalls[0].ctx.purpose).toBe("one");
    expect(hookCalls[0].ctx.overlay).toEqual({ tenant: "a" });
  });
});

describe("the action gate asks the scope first (no row load unless it restricts)", () => {
  it("a grant without a row filter reaches the handler on a missing id", async () => {
    await bootAs("ping-any");
    const r = await post("/scoped/actions/ping", { ids: { id: 99 } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    expect(pinged).toEqual([{ id: 99 }]);
    expect(space.queries()).toBe(0);
  });

  it("a grant with a row filter answers 404 for a missing id and an out-of-scope id alike", async () => {
    await bootAs("ping-a");
    const missing = await post("/scoped/actions/ping", { ids: { id: 99 } });
    const foreign = await post("/scoped/actions/ping", { ids: { id: 2 } });
    expect(missing.status).toBe(404);
    expect(foreign.status).toBe(404);
    expect(foreign.body).toEqual(missing.body);
    expect(pinged).toEqual([]);
    expect((await post("/scoped/actions/ping", { ids: { id: 1 } })).status).toBe(201);
  });

  it("an action scope that differs from the read overlay costs one query", async () => {
    await bootAs("read-all-ping-a");
    space.resetQueries();
    const r = await post("/scoped/actions/ping", { ids: { id: 1 } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    expect(space.queries()).toBe(1);
    expect((await post("/scoped/actions/ping", { ids: { id: 2 } })).status).toBe(404);
  });
});
