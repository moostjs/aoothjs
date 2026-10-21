// A rule scope that returns `null` / `undefined` grants nothing: every path
// must deny (403) without leaking rows, fields or internal error text — the
// authorize interceptor on a plain route, an attenuated credential, the DB
// controller reads / writes and `/meta`.
import { allowTableWrite, defineRole, defineTableAccess } from "@aooth/arbac";
import { TableController } from "@atscript/moost-db";
import { Get, type MoostHttp } from "@moostjs/event-http";
import { clearGlobalWooks, Controller } from "moost";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { bootArbacHttp } from "../../__testing__/arbac-http";
import { FakeUserProvider } from "../../__testing__/user-provider";
import { useArbac } from "../../arbac.composables";
import { ArbacAction, ArbacAuthorize, ArbacResource } from "../../arbac.decorator";
import { MoostArbac } from "../../moost-arbac";
import { type ArbacDbScope, AsArbacDbController } from "../as-arbac-db-controller";
import { RpTask } from "./fixtures/rel-fixtures.as";
import { boot, createSpace, type Harness, seed, send } from "./relations-harness";

type Attrs = { tenant?: string };

@Controller("orders")
class OrdersController {
  @Get("list")
  @ArbacResource("orders")
  @ArbacAction("read")
  @ArbacAuthorize()
  list() {
    return { ran: true, scopes: useArbac().getScopes() };
  }
}

const member = () =>
  defineRole<Attrs, { filter: object }>()
    .id("member")
    .allow("orders", "read", (a) => (a.tenant ? { filter: { tenant: a.tenant } } : null))
    .build();

async function bootOrders(attrs: Attrs, attenuation?: FakeUserProvider<Attrs>["attenuation"]) {
  clearGlobalWooks();
  const arbac = new MoostArbac<Attrs, object>();
  arbac.registerRole(member());
  const user = new FakeUserProvider<Attrs>("u1", ["member"], attrs);
  user.attenuation = attenuation;
  return bootArbacHttp({ arbac, user, controllers: [OrdersController] });
}

describe("nullish scope on a plain authorized route", () => {
  it("denies with 403 and never runs the handler", async () => {
    const res = await (await bootOrders({})).request("/orders/list");
    expect(res?.status).toBe(403);
    expect(await res?.text()).not.toContain("ran");
  });

  it("an attenuated credential is denied with 403, not a 401 with an error message", async () => {
    const res = await (await bootOrders({}, { attrs: {} })).request("/orders/list");
    expect(res?.status).toBe(403);
    expect(await res?.text()).not.toMatch(/Cannot|undefined|null to object/);
  });

  it("an attenuation whose narrowed scope is nullish is denied too", async () => {
    const http = await bootOrders({ tenant: "a" }, { attrs: { tenant: "" } });
    const res = await http.request("/orders/list");
    expect(res?.status).toBe(403);
  });

  it("a non-null scope still allows", async () => {
    const res = await (await bootOrders({ tenant: "a" })).request("/orders/list");
    expect(res?.status).toBe(200);
    expect(await res?.json()).toEqual({ ran: true, scopes: [{ filter: { tenant: "a" } }] });
  });
});

describe("nullish scope on a DB controller", () => {
  @TableController(RpTask, "tasks")
  @ArbacResource("tasks")
  class TasksController extends AsArbacDbController<typeof RpTask> {}

  const ROLES = [
    defineRole<object, ArbacDbScope>()
      .id("nullish-reader")
      .use(defineTableAccess("tasks", { read: true, scope: () => null }))
      .build(),
    defineRole<object, ArbacDbScope>()
      .id("nullish-writer")
      .use(allowTableWrite("tasks", { scope: () => undefined }))
      .build(),
  ];

  let h: Harness;
  let http: MoostHttp;
  beforeAll(async () => {
    h = await createSpace();
  });
  afterAll(() => h.close());
  beforeEach(() => seed(h));

  it.each(["nullish-reader", "nullish-writer"])(
    "%s: reads, /meta and writes are 403",
    async (role) => {
      ({ http } = await boot(ROLES, [TasksController], [role]));
      for (const path of ["/tasks/query", "/tasks/pages", "/tasks/one/1", "/tasks/meta"]) {
        const res = await send(http, "GET", path);
        expect(res.status, path).toBe(403);
        expect(JSON.stringify(res.body), path).not.toContain("taskA");
      }
      const write = await send(http, "PATCH", "/tasks", { id: 1, title: "pwned" });
      expect(write.status).toBe(403);
      expect(await h.table(RpTask).findOne({ filter: { id: 1 }, controls: {} })).toMatchObject({
        title: "taskA",
      });
    },
  );

  it("an attenuated credential with a nullish scope is 403 on the DB controller", async () => {
    let user: FakeUserProvider<{ tenant?: string }>;
    ({ http, user } = await boot<{ tenant?: string }>(
      [
        defineRole<{ tenant?: string }, ArbacDbScope>()
          .id("tenant-reader")
          .use(
            defineTableAccess<{ tenant?: string }, ArbacDbScope>("tasks", {
              read: true,
              scope: (a) => (a.tenant ? { filter: { tenant: a.tenant } } : null),
            }),
          )
          .build(),
      ],
      [TasksController],
      ["tenant-reader"],
      { attrs: { tenant: "a" } },
    ));
    user.attenuation = { attrs: { tenant: "" } };
    const res = await send(http, "GET", "/tasks/query");
    expect(res.status).toBe(403);
    expect(JSON.stringify(res.body)).not.toContain("taskA");
  });
});
