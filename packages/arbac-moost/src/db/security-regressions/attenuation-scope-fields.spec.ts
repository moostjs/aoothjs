// Credential attenuation × custom (declaration-merged) scope fields: the
// conjunction builds ONE composite scope, so a custom field must be combined
// by a registered rule — never dropped (a dropped field reads as absent,
// i.e. unrestricted under the app's own union rule → fail OPEN).
import { allowTableRead, defineRole } from "@aooth/arbac";
import type { TScopeFieldRules } from "@aooth/arbac";
import { TableController } from "@atscript/moost-db";
import { Get } from "@moostjs/event-http";
import type { MoostHttp } from "@moostjs/event-http";
import { Controller } from "moost";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vite-plus/test";

import { listFieldRule, unionListField } from "../../__testing__/scope-fields";
import type { FakeUserProvider } from "../../__testing__/user-provider";
import { useArbac } from "../../arbac.composables";
import { ArbacAction, ArbacResource } from "../../arbac.decorator";
import { MoostArbac } from "../../moost-arbac";
import { type ArbacDbScope, AsArbacDbController } from "../as-arbac-db-controller";
import { RpTask, RpUser } from "./fixtures/rel-fixtures.as";
import { all, boot, createSpace, type Harness, seed, send } from "./relations-harness";

// The app's custom field: tenants a row may belong to; absent = unrestricted.
type AppScope = ArbacDbScope & { tenants?: string[] };
type Attrs = { tenants: string[]; wide?: boolean };

const TENANTS_RULE: TScopeFieldRules<AppScope> = { tenants: listFieldRule("tenants") };

const role = defineRole<Attrs, AppScope>()
  .id("regional")
  .use(
    allowTableRead("tasks", {
      scope: (a) => ({
        tenants: a.tenants,
        // A `with` sub-scope carrying the custom field (both passes declare it).
        with: { tags: { tenants: a.tenants } },
        // One-sided `with.owner` (credential only) → conjoined at resolution
        // with the caller's own users grant, which carries the field too.
        ...(a.wide && { with: { tags: { tenants: a.tenants }, owner: {} } }),
      }),
    }),
    allowTableRead("users", { scope: (a) => ({ tenants: a.tenants }) }),
  )
  .build();

@TableController(RpTask, "tasks")
@ArbacResource("tasks")
class TasksController extends AsArbacDbController<typeof RpTask> {}

@TableController(RpUser, "users")
@ArbacResource("users")
class UsersController extends AsArbacDbController<typeof RpUser> {}

let h: Harness;

// An app handler applying the custom field with its own rule.
@Controller("app")
@ArbacResource("tasks")
class AppController {
  @Get("tasks")
  @ArbacAction("query")
  async tasks() {
    const scopes = useArbac().getScopes<AppScope>() ?? [];
    const tenants = unionListField(scopes, "tenants");
    const rows = await all(h, RpTask);
    return {
      ids: rows.filter((r) => !tenants || tenants.has(r.tenant)).map((r) => r.id),
      scopes,
    };
  }
}

let http: MoostHttp;
let user: FakeUserProvider<Attrs>;
async function bootWith(fields?: TScopeFieldRules<AppScope>) {
  ({ http, user } = await boot<Attrs, AppScope>(
    [role],
    [TasksController, UsersController, AppController],
    ["regional"],
    { attrs: { tenants: ["a", "b"] }, fields },
  ));
}

beforeAll(async () => {
  h = await createSpace();
});
afterAll(() => h.close());
beforeEach(() => seed(h));

describe("custom scope fields under attenuation", () => {
  it("non-attenuated: the app receives the raw scope list", async () => {
    await bootWith();
    const r = await send(http, "GET", "/app/tasks");
    expect(r.status).toBe(200);
    expect(r.body.ids.toSorted((a: number, b: number) => a - b)).toEqual([1, 2, 3]);
    expect(r.body.scopes).toEqual([
      { tenants: ["a", "b"], with: { tags: { tenants: ["a", "b"] } } },
    ]);
  });

  it("with a registered rule the composite carries the conjoined value (also in `with`)", async () => {
    await bootWith(TENANTS_RULE);
    user.attenuation = { attrs: { tenants: ["a", "c"] } };
    const r = await send(http, "GET", "/app/tasks");
    expect(r.status).toBe(200);
    expect(r.body.ids.toSorted((a: number, b: number) => a - b)).toEqual([1, 3]);
    expect(r.body.scopes).toHaveLength(1);
    expect(r.body.scopes[0].tenants).toEqual(["a"]);
    expect(r.body.scopes[0].with.tags.tenants).toEqual(["a"]);
    expect((await send(http, "GET", "/tasks/query")).status).toBe(200);
  });

  // A configuration error: a generic 500 (no field names / hints to the
  // client), details logged server-side — never served unrestricted.
  it("without a rule the request fails with a generic 500 — never served unrestricted", async () => {
    await bootWith();
    user.attenuation = { attrs: { tenants: ["a"] } };
    const logged = vi.spyOn(console, "error").mockImplementation(() => {});
    for (const path of ["/app/tasks", "/tasks/query", "/tasks/one/2"]) {
      const r = await send(http, "GET", path);
      expect(r.status, path).toBe(500);
      expect(JSON.stringify(r.body), path).not.toContain("tenants");
      expect(JSON.stringify(r.body), path).not.toContain("registerScopeFields");
      expect(r.body, path).not.toHaveProperty("ids");
    }
    // The details are logged server-side — once (the first failing evaluation in this file).
    const details = logged.mock.calls.filter((c) => String(c).includes('Scope field "tenants"'));
    logged.mockRestore();
    expect(details).toHaveLength(1);
  });

  it("a one-sided with.<rel> conjoined with the inherited grant uses the same rules", async () => {
    await bootWith(TENANTS_RULE);
    user.attenuation = { attrs: { tenants: ["a"], wide: true } };
    const r = await send(http, "GET", "/tasks/query?$with=owner&$sort=id");
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    await bootWith();
    user.attenuation = { attrs: { tenants: ["a"], wide: true } };
    const denied = await send(http, "GET", "/tasks/query?$with=owner&$sort=id");
    expect(denied.status).toBe(500);
    expect(JSON.stringify(denied.body)).not.toContain("tenants");
  });
});

describe("MoostArbac.registerScopeFields", () => {
  it("rejects built-in keys, missing conjoin and a conflicting re-registration", () => {
    const arbac = new MoostArbac<object, AppScope>();
    expect(() => arbac.registerScopeFields({ filter: { conjoin: () => undefined } })).toThrow(
      /built-in/,
    );
    expect(() => arbac.registerScopeFields({ x: {} as never })).toThrow(/conjoin/);
    arbac.registerScopeFields(TENANTS_RULE).registerScopeFields(TENANTS_RULE);
    expect(() => arbac.registerScopeFields({ tenants: { conjoin: () => undefined } })).toThrow(
      /already registered/,
    );
    expect(Object.keys(arbac.getScopeFields())).toEqual(["tenants"]);
  });

  it("is atomic: one invalid rule registers nothing", () => {
    const arbac = new MoostArbac<object, AppScope>();
    const ok = listFieldRule<AppScope>("regions");
    expect(() => arbac.registerScopeFields({ regions: ok, check: ok })).toThrow(/built-in/);
    expect(arbac.getScopeFields()).toEqual({});
  });

  it("warns once about a custom scope key without a rule, at evaluation", async () => {
    const arbac = new MoostArbac<object, AppScope & { label?: string }>();
    arbac.registerRole({
      id: "r",
      rules: [{ resource: "x", action: "a", scope: () => ({ label: "t", tenants: ["a"] }) }],
    });
    arbac.registerScopeFields(TENANTS_RULE);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      for (let i = 0; i < 3; i++) {
        await arbac.evaluate({ resource: "x", action: "a" }, { id: "u", roles: ["r"], attrs: {} });
      }
      const calls = warn.mock.calls.filter((c) => String(c[0]).includes('"label"'));
      expect(calls).toHaveLength(1);
      expect(warn.mock.calls.some((c) => String(c[0]).includes('"tenants"'))).toBe(false);
    } finally {
      warn.mockRestore();
    }
  });
});
