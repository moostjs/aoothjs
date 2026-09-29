// Credential attenuation × the `$with` inherit-target policy: a relation
// only ONE side declares `with.<rel>` for must also obey the silent side's
// INHERITED policy (the caller's own grant on the related table) — the
// conjunction never lets a credential's declared sub-scope stand alone as
// parent authority.
import { allowTableRead, defineRole } from "@aooth/arbac";
import { TableController } from "@atscript/moost-db";
import type { MoostHttp } from "@moostjs/event-http";
import { clearGlobalWooks } from "moost";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { bootArbacHttp } from "../../__testing__/arbac-http";
import { FakeUserProvider } from "../../__testing__/user-provider";
import { ArbacResource } from "../../arbac.decorator";
import { MoostArbac } from "../../moost-arbac";
import { type ArbacDbScope, AsArbacDbController } from "../as-arbac-db-controller";
import { RpTask, RpUser } from "./fixtures/rel-fixtures.as";
import { createSpace, type Harness, seed, send } from "./relations-harness";

type Attrs = { wide?: boolean };

// Declares `with.owner` (unrestricted, parent authority) only when the
// `wide` attr is set — the user lacks it; a credential claims it.
const role = defineRole<Attrs, ArbacDbScope>()
  .id("cond")
  .use(
    allowTableRead("tasks", {
      scope: (a) =>
        a.wide ? { filter: { tenant: "a" }, with: { owner: {} } } : { filter: { tenant: "a" } },
    }),
    allowTableRead("users", {
      scope: () => ({ filter: { tenant: "a" }, projection: { salary: 0 } }),
    }),
  )
  .build();

@TableController(RpTask, "tasks")
@ArbacResource("tasks")
class TasksController extends AsArbacDbController<typeof RpTask> {}

@TableController(RpUser, "users")
@ArbacResource("users")
class UsersController extends AsArbacDbController<typeof RpUser> {}

let h: Harness;
let http: MoostHttp;
let user: FakeUserProvider;
beforeAll(async () => {
  h = await createSpace();
});
afterAll(() => h.close());
beforeEach(async () => {
  await seed(h);
  clearGlobalWooks();
  const arbac = new MoostArbac<Attrs, ArbacDbScope>();
  arbac.registerRole(role);
  user = new FakeUserProvider("u1", ["cond"], {});
  http = await bootArbacHttp({
    arbac,
    user,
    controllers: [TasksController, UsersController],
    authorize: true,
  });
});

type Row = Record<string, any>;

describe("attenuation: a one-sided with.<rel> is conjoined with the inherited target grant", () => {
  for (const [label, attenuation] of [
    ["plain user", undefined],
    ["credential claiming the attr", { attrs: { wide: true } }],
  ] as const) {
    it(`${label}: joined owners never exceed the user's own users grant`, async () => {
      user.attenuation = attenuation;
      const r = await send(http, "GET", "/tasks/query?$with=owner&$sort=id");
      expect(r.status, JSON.stringify(r.body)).toBe(200);
      const rows = r.body as Row[];
      // Task 1: tenant-a owner alice — salary hidden by the users grant.
      const t1 = rows.find((x) => x.id === 1)!;
      expect(t1.owner).toMatchObject({ id: 1, name: "alice" });
      expect(t1.owner).not.toHaveProperty("salary");
      // Task 3: in scope, but owned by tenant-b bob — outside the users grant.
      expect(rows.find((x) => x.id === 3)!.owner ?? null).toBeNull();
      // The hidden column is unknown in the $with sub-query.
      const probe = await send(http, "GET", "/tasks/query?$with=owner(salary>1)");
      expect(probe.status).toBe(400);
    });
  }
});
