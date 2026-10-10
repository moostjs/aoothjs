// `/meta` HTTP caching through the ARBAC projection memo: a memoized
// projection must survive moost-db's later `/meta` steps (decorations, the
// index-visibility narrowing of an overridden `hasField`, the own-mount path)
// as an identity-stable object, so the response is served from JSON
// serialized once, with a weak ETag and `304` on a matching `If-None-Match`.
// Different decisions never share an ETag; `metaHttpCaching() → false` sends none.
import { allowTableRead, defineRole } from "@aooth/arbac";
import type { TArbacRole } from "@aooth/arbac-core";
import { AsDbController, DbDecorations, TableController } from "@atscript/moost-db";
import { MoostHttp } from "@moostjs/event-http";
import { clearGlobalWooks, Controller, Inherit, Moost } from "moost";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vite-plus/test";

import { bootArbacHttp } from "../../__testing__/arbac-http";
import { FakeUserProvider } from "../../__testing__/user-provider";
import { ArbacResource } from "../../arbac.decorator";
import { MoostArbac } from "../../moost-arbac";
import { type ArbacDbScope, AsArbacDbController } from "../as-arbac-db-controller";
import { AsArbacJsonValueHelpController } from "../as-arbac-value-help-controller";
import { ActDoc } from "./fixtures/actions-doc.as";
import { ReadAccount, ReadDept } from "./fixtures/read-fixtures.as";
import { RpOrg, RpTag, RpTask, RpTaskTag, RpUser } from "./fixtures/rel-fixtures.as";
import { R12Decorations, R12Dict, R12Item } from "./fixtures/round12-fixtures.as";
import { createSpace, type Harness } from "./relations-harness";

// (a) no decorations, no search index (the index gate still runs: `hasField` is overridden)
@TableController(RpTask, "tasks")
@ArbacResource("tasks")
class TasksController extends AsArbacDbController<typeof RpTask> {}

@TableController(RpUser, "users")
@ArbacResource("users")
class UsersController extends AsArbacDbController<typeof RpUser> {}

// (b) declared decorations
@TableController(R12Item as never, "decorated")
@ArbacResource("decorated")
@DbDecorations(R12Decorations as never, { requires: { ownerName: ["ownerId"] } })
class DecoratedController extends AsArbacDbController<typeof R12Item> {}

// (c) a full-text index reading a field a scope can hide (+ geo, writeOnly)
@TableController(ReadAccount as never, "accounts")
@ArbacResource("accounts")
class AccountsController extends AsArbacDbController {}

// (d) an ARBAC value-help controller (no index / decoration step)
@Inherit()
@Controller("vh")
@ArbacResource("vh")
class VhController extends AsArbacJsonValueHelpController<typeof ActDoc> {
  constructor(app: Moost) {
    super(ActDoc, [{ id: 1, owner: "u1", status: "open", secret: "s1" }], app, "vh");
  }
}

// HTTP caching opted out
@TableController(RpTask, "tasks-nocache")
@ArbacResource("tasks")
class TasksNoCacheController extends AsArbacDbController<typeof RpTask> {
  protected override metaHttpCaching() {
    return false as const;
  }
}

@Inherit()
@Controller("vh-nocache")
@ArbacResource("vh")
class VhNoCacheController extends AsArbacJsonValueHelpController<typeof ActDoc> {
  constructor(app: Moost) {
    super(ActDoc, [{ id: 1, owner: "u1", status: "open", secret: "s1" }], app, "vh-nocache");
  }

  protected override metaHttpCaching() {
    return false as const;
  }
}

// Baseline: a plain moost-db controller (no ARBAC).
@TableController(RpOrg, "plain-orgs")
class PlainOrgsController extends AsDbController<typeof RpOrg> {}

const ROLES: Array<TArbacRole<object, ArbacDbScope>> = [
  defineRole<object, ArbacDbScope>()
    .id("admin")
    .use(
      allowTableRead("tasks"),
      allowTableRead("users"),
      allowTableRead("decorated"),
      allowTableRead("accounts"),
      allowTableRead("vh"),
    )
    .build(),
  defineRole<object, ArbacDbScope>()
    .id("viewer")
    .use(
      allowTableRead("tasks", { scope: () => ({ projection: { title: 1 } }) }),
      allowTableRead("decorated", { scope: () => ({ projection: { ownerId: 0 } }) }),
      allowTableRead("accounts", { scope: () => ({ projection: { secretNote: 0 } }) }),
      allowTableRead("vh", { scope: () => ({ projection: { secret: 0 } }) }),
    )
    .build(),
];

let h: Harness;
let http: MoostHttp;
let user: FakeUserProvider<object>;

beforeAll(async () => {
  h = await createSpace([
    RpOrg,
    RpUser,
    RpTag,
    RpTask,
    RpTaskTag,
    R12Dict,
    R12Item,
    ReadDept,
    ReadAccount,
  ]);
});
afterAll(() => h.close());
beforeEach(async () => {
  clearGlobalWooks();
  const arbac = new MoostArbac<object, ArbacDbScope>();
  for (const r of ROLES) arbac.registerRole(r);
  user = new FakeUserProvider<object>("u1", ["admin"]);
  http = await bootArbacHttp({
    arbac,
    user,
    controllers: [
      TasksController,
      UsersController,
      DecoratedController,
      AccountsController,
      VhController,
      TasksNoCacheController,
      VhNoCacheController,
    ],
    authorize: true,
  });
  vi.spyOn(console, "warn").mockImplementation(() => {});
});
afterEach(() => {
  vi.restoreAllMocks();
});

/** `JSON.stringify` calls on a `/meta` envelope (has `crud` + `fields`) while `fn` runs. */
async function metaSerializations<T>(fn: () => Promise<T>): Promise<[T, number]> {
  const original = JSON.stringify;
  let count = 0;
  const spy = vi.spyOn(JSON, "stringify").mockImplementation(((
    value: unknown,
    ...rest: never[]
  ) => {
    if (value && typeof value === "object" && "crud" in value && "fields" in value) count++;
    return original(value, ...rest);
  }) as typeof JSON.stringify);
  try {
    return [await fn(), count];
  } finally {
    spy.mockRestore();
  }
}

async function get(path: string, etag?: string) {
  const res = (await http.request(path, {
    headers: etag ? { "if-none-match": etag } : undefined,
  }))!;
  return { status: res.status, etag: res.headers.get("etag") ?? undefined, text: await res.text() };
}

/**
 * Three requests as the current principal (the memo skips an envelope's first
 * sight), then a conditional one with the last ETag.
 */
async function settle(path: string) {
  const first = await get(path);
  await get(path);
  const [third, serialized] = await metaSerializations(() => get(path));
  const conditional = await get(path, third.etag);
  return { first, third, serialized, conditional };
}

const CASES = [
  ["(a) no decorations, no search index", "/tasks/meta"],
  ["(b) decorations", "/decorated/meta"],
  ["(c) search indexes subject to visibility", "/accounts/meta"],
  ["(d) value-help", "/vh/meta"],
] as const;

describe("/meta HTTP caching through the ARBAC memo", () => {
  for (const [label, path] of CASES) {
    it(`${label}: same role → serialized once, same ETag, 304`, async () => {
      for (const roles of [["admin"], ["viewer"]]) {
        user.roles = roles;
        const { first, third, serialized, conditional } = await settle(path);
        expect(third.text).toBe(first.text);
        expect(third.etag, roles.join()).toMatch(/^W\/"/);
        expect(serialized, roles.join()).toBe(0);
        expect(conditional.status, roles.join()).toBe(304);
        expect(conditional.etag).toBe(third.etag);
      }
    });

    it(`${label}: different roles never share a body or an ETag`, async () => {
      user.roles = ["admin"];
      const admin = (await settle(path)).third;
      user.roles = ["viewer"];
      const viewer = await settle(path);
      expect(viewer.third.text).not.toBe(admin.text);
      expect(viewer.third.etag).not.toBe(admin.etag);
      // the admin's tag is no validator for the viewer's bytes
      expect((await get(path, admin.etag)).status).toBe(200);
      user.roles = ["admin"];
      const back = await get(path, admin.etag);
      expect(back.status).toBe(304);
    });
  }

  it("the viewer's /meta really is narrowed (decoration, search index)", async () => {
    user.roles = ["viewer"];
    const decorated = JSON.parse((await get("/decorated/meta")).text);
    expect(decorated.fields.ownerName).toBeUndefined();
    const accounts = JSON.parse((await get("/accounts/meta")).text);
    expect(accounts.searchIndexes.map((i: { name: string }) => i.name)).not.toContain("txt_idx");
    user.roles = ["admin"];
    const full = JSON.parse((await get("/accounts/meta")).text);
    expect(full.searchIndexes.map((i: { name: string }) => i.name)).toContain("txt_idx");
  });
});

describe("metaHttpCaching() → false", () => {
  for (const path of ["/tasks-nocache/meta", "/vh-nocache/meta"]) {
    it(`${path}: no ETag, never 304`, async () => {
      for (const roles of [["admin"], ["viewer"]]) {
        user.roles = roles;
        const { first, third, conditional } = await settle(path);
        expect(third.text).toBe(first.text);
        expect(third.etag, roles.join()).toBeUndefined();
        expect((await get(path, 'W/"x", *')).status).toBe(200);
        expect(conditional.status).toBe(200);
      }
    });
  }
});

describe("baseline: plain moost-db controller", () => {
  it("serialized once, same ETag, 304", async () => {
    clearGlobalWooks();
    const app = new Moost();
    const plain = new MoostHttp();
    app.adapter(plain);
    app.registerControllers(PlainOrgsController);
    await app.init();
    http = plain;
    const { first, third, serialized, conditional } = await settle("/plain-orgs/meta");
    expect(third.text).toBe(first.text);
    expect(third.etag).toMatch(/^W\/"/);
    expect(serialized).toBe(0);
    expect(conditional.status).toBe(304);
  });
});
