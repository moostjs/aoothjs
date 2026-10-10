// `/meta` projection memo (0.1.78): grants are evaluated per request, the
// pruning by their decisions is memoized per envelope + decision record.
// Never a cross-role / cross-attr / cross-credential hit; unkeyable decisions
// (a one-sided INHERITED_CONJUNCTION sub-scope, a function-valued scope piece)
// are not memoized; memo on and off serve byte-identical bodies.
import { allowTableAction, allowTableRead, allowTableWrite, defineRole } from "@aooth/arbac";
import type { TArbacRole } from "@aooth/arbac-core";
import type { TMetaResponse } from "@atscript/db";
import { TableController } from "@atscript/moost-db";
import type { MoostHttp } from "@moostjs/event-http";
import { clearGlobalWooks } from "moost";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vite-plus/test";

import { bootArbacHttp } from "../../__testing__/arbac-http";
import { FakeUserProvider } from "../../__testing__/user-provider";
import { ArbacResource } from "../../arbac.decorator";
import { MoostArbac } from "../../moost-arbac";
import { type ArbacDbScope, AsArbacDbController } from "../as-arbac-db-controller";
import { RpNote, RpOrg, RpProject, RpTask, RpUser } from "./fixtures/rel-fixtures.as";
import { createSpace, type Harness, seed } from "./relations-harness";

type Attrs = { level?: string; wide?: boolean };

const tasksRead = (scope: (a: Attrs) => ArbacDbScope) =>
  allowTableRead<Attrs, ArbacDbScope>("tasks", { scope });

const ROLES: Array<TArbacRole<Attrs, ArbacDbScope>> = [
  defineRole<Attrs, ArbacDbScope>()
    .id("admin")
    .use(
      allowTableRead("tasks"),
      allowTableWrite("tasks"),
      allowTableRead("users"),
      allowTableRead("orgs"),
    )
    .build(),
  defineRole<Attrs, ArbacDbScope>()
    .id("viewer")
    .use(
      tasksRead(() => ({
        filter: { tenant: "a" },
        projection: { title: 1, ownerId: 1, owner: 1 },
      })),
      allowTableRead("users", { scope: () => ({ projection: { salary: 0, password: 0 } }) }),
    )
    .build(),
  defineRole<Attrs, ArbacDbScope>()
    .id("member")
    .use(tasksRead(() => ({ filter: { tenant: "a" }, projection: { title: 1, tenant: 1 } })))
    .build(),
  // Attr-dependent projection: two users holding this role see different fields.
  defineRole<Attrs, ArbacDbScope>()
    .id("attr")
    .use(
      tasksRead((a) => ({
        filter: { tenant: "a" },
        projection: (a.level === "hi" ? { title: 1, profile: 1 } : { title: 1 }) as Record<
          string,
          1
        >,
      })),
    )
    .build(),
  // `with.owner` only under the `wide` attr — a credential claiming it makes
  // the sub-scope one-sided (INHERITED_CONJUNCTION).
  defineRole<Attrs, ArbacDbScope>()
    .id("cond")
    .use(
      tasksRead((a) =>
        a.wide ? { filter: { tenant: "a" }, with: { owner: {} } } : { filter: { tenant: "a" } },
      ),
      allowTableRead("users", { scope: () => ({ projection: { salary: 0 } }) }),
    )
    .build(),
  // Same root grant, different declared `with.owner` sub-scope (below the root only).
  defineRole<Attrs, ArbacDbScope>()
    .id("w-hidden")
    .use(
      tasksRead(() => ({ with: { owner: { projection: { salary: 0 } } } })),
      allowTableRead("users"),
    )
    .build(),
  defineRole<Attrs, ArbacDbScope>()
    .id("w-open")
    .use(
      tasksRead(() => ({ with: { owner: {} } })),
      allowTableRead("users"),
    )
    .build(),
  // Same fields either way; `$sort` denied under the `lo` level only.
  defineRole<Attrs, ArbacDbScope>()
    .id("ctl")
    .use(
      tasksRead((a) =>
        a.level === "lo"
          ? { filter: { tenant: "a" }, controls: { $sort: false } }
          : { filter: { tenant: "a" } },
      ),
    )
    .build(),
  // Same union policy either way; `$sort` denied on `query` (lo) or on `pages` (hi).
  defineRole<Attrs, ArbacDbScope>()
    .id("ctl-op")
    .use(
      allowTableAction<Attrs, ArbacDbScope>("tasks", "query", {
        scope: (a) => ({
          filter: { tenant: "a" },
          ...(a.level === "lo" && { controls: { $sort: false } }),
        }),
      }),
      allowTableAction<Attrs, ArbacDbScope>("tasks", ["pages", "getOne", "meta"], {
        scope: (a) => ({
          filter: { tenant: "a" },
          ...(a.level === "hi" && { controls: { $sort: false } }),
        }),
      }),
    )
    .build(),
  // Notes reference projects (a `ref` with no nav prop): readable or not.
  defineRole<Attrs, ArbacDbScope>()
    .id("notes-proj")
    .use(allowTableRead("notes"), allowTableRead("projects"))
    .build(),
  defineRole<Attrs, ArbacDbScope>().id("notes-only").use(allowTableRead("notes")).build(),
  // A function-valued (custom) scope piece.
  defineRole<Attrs, ArbacDbScope>()
    .id("fn")
    .use(
      tasksRead(
        () =>
          ({
            filter: { tenant: "a" },
            projection: { title: 1 },
            tag: () => "x",
          }) as unknown as ArbacDbScope,
      ),
    )
    .build(),
];

const served: TMetaResponse[] = [];

@TableController(RpTask, "tasks")
@ArbacResource("tasks")
class TasksController extends AsArbacDbController<typeof RpTask> {
  protected override async applyMetaOverlay(meta: TMetaResponse): Promise<TMetaResponse> {
    const out = await super.applyMetaOverlay(meta);
    served.push(out);
    return out;
  }
}

@TableController(RpUser, "users")
@ArbacResource("users")
class UsersController extends AsArbacDbController<typeof RpUser> {}

@TableController(RpOrg, "orgs")
@ArbacResource("orgs")
class OrgsController extends AsArbacDbController<typeof RpOrg> {}

@TableController(RpProject, "projects")
@ArbacResource("projects")
class ProjectsController extends AsArbacDbController<typeof RpProject> {}

@TableController(RpNote, "notes")
@ArbacResource("notes")
class NotesController extends AsArbacDbController<typeof RpNote> {}

let h: Harness;
let http: MoostHttp;
let arbac: MoostArbac<Attrs, ArbacDbScope>;
let user: FakeUserProvider<Attrs>;
const attrs: Attrs = {};

beforeAll(async () => {
  h = await createSpace();
});
afterAll(() => h.close());
beforeEach(async () => {
  await seed(h);
  clearGlobalWooks();
  arbac = new MoostArbac<Attrs, ArbacDbScope>();
  for (const r of ROLES) arbac.registerRole(r);
  for (const k of Object.keys(attrs)) delete attrs[k as keyof Attrs];
  user = new FakeUserProvider<Attrs>("u1", ["admin"], attrs);
  http = await bootArbacHttp({
    arbac,
    user,
    controllers: [
      TasksController,
      UsersController,
      OrgsController,
      ProjectsController,
      NotesController,
    ],
    authorize: true,
  });
  served.length = 0;
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

/** One "cookie jar": carries the last ETag as If-None-Match, like a browser. */
function jar() {
  let etag: string | undefined;
  let last = "";
  return async (path = "/tasks/meta") => {
    const res = (await http.request(path, {
      headers: etag ? { "if-none-match": etag } : undefined,
    }))!;
    const text = await res.text();
    if (res.status === 304) {
      // A 304 is only ever right when the bytes would be the same.
      expect(res.headers.get("etag")).toBe(etag);
      return { status: 304, text: last, etag };
    }
    expect(res.status, text).toBe(200);
    etag = res.headers.get("etag") ?? undefined;
    last = text;
    return { status: res.status, text, etag };
  };
}

/** The body the same principal gets with the memo off (a fresh pruning). */
async function unmemoized(path = "/tasks/meta"): Promise<string> {
  arbac.setMetaMemo(false);
  try {
    const res = (await http.request(path))!;
    return await res.text();
  } finally {
    arbac.setMetaMemo({});
  }
}

const fieldsOf = (text: string) =>
  Object.keys((JSON.parse(text) as TMetaResponse).fields).toSorted();

describe("/meta projection memo", () => {
  it("memoizes per decision: the same principal gets the same frozen object", async () => {
    user.roles = ["viewer"];
    const a = jar();
    const first = await a();
    await a();
    await a();
    expect(served).toHaveLength(3);
    expect(served[1]).toBe(served[2]); // memoized from the second sight on
    expect(Object.isFrozen(served[2])).toBe(true);
    expect(first.text).toBe(await unmemoized());
  });

  it("admin → viewer → admin in one jar: each switch serves the right body", async () => {
    const a = jar();
    user.roles = ["admin"];
    const admin1 = await a();
    await a();
    user.roles = ["viewer"];
    const viewer = await a();
    expect(viewer.status).toBe(200);
    expect(viewer.text).not.toBe(admin1.text);
    expect(fieldsOf(viewer.text)).not.toContain("tenant");
    expect(viewer.text).toBe(await unmemoized());
    user.roles = ["admin"];
    const admin2 = await a();
    expect(admin2.text).toBe(admin1.text);
    expect(fieldsOf(admin2.text)).toContain("tenant");
  });

  it("full vs attenuated credential: different bodies; a carried ETag never masks the change", async () => {
    user.roles = ["admin", "member"];
    const a = jar();
    const full = await a();
    await a();
    user.attenuation = { roles: ["member"] };
    const narrowed = await a();
    expect(narrowed.status).toBe(200);
    expect(narrowed.text).not.toBe(full.text);
    expect(fieldsOf(narrowed.text)).toEqual(["id", "tenant", "title"]);
    expect(narrowed.text).toBe(await unmemoized());
    user.attenuation = undefined;
    expect((await a()).text).toBe(full.text);
  });

  it("an admin role edit between two requests with the same token shows at once", async () => {
    user.roles = ["member"];
    const a = jar();
    const before = await a();
    await a();
    arbac.registerRole(
      defineRole<Attrs, ArbacDbScope>()
        .id("member")
        .use(tasksRead(() => ({ filter: { tenant: "a" }, projection: { title: 1, profile: 1 } })))
        .build(),
    );
    const after = await a();
    expect(after.status).toBe(200);
    expect(after.text).not.toBe(before.text);
    expect(fieldsOf(after.text)).toContain("profile.name");
    expect(fieldsOf(after.text)).not.toContain("tenant");
    // the user-role assignment changes too
    user.roles = ["viewer"];
    expect((await a()).text).toBe(await unmemoized());
  });

  it("two users with the same role but attr-dependent projections never share a projection", async () => {
    user.roles = ["attr"];
    const a = jar();
    attrs.level = "hi";
    const hi = await a();
    await a();
    attrs.level = "lo";
    const lo = await a();
    expect(lo.status).toBe(200);
    expect(fieldsOf(hi.text)).toContain("profile.name");
    expect(fieldsOf(lo.text)).not.toContain("profile.name");
    expect(lo.text).toBe(await unmemoized());
    attrs.level = "hi";
    expect((await a()).text).toBe(hi.text);
  });

  it("the controls policy is part of the decision (same fields, `$sort` denied or not)", async () => {
    user.roles = ["ctl"];
    const a = jar();
    attrs.level = "hi";
    const open = await a();
    await a();
    attrs.level = "lo";
    const denied = await a();
    expect(denied.status).toBe(200);
    const sortable = (text: string) =>
      Object.values((JSON.parse(text) as TMetaResponse).fields).some((f) => f.sortable);
    expect(sortable(open.text)).toBe(true);
    expect(sortable(denied.text)).toBe(false);
    expect(fieldsOf(denied.text)).toEqual(fieldsOf(open.text));
    expect(denied.text).toBe(await unmemoized());
    attrs.level = "hi";
    expect((await a()).text).toBe(open.text);
  });

  it("each read op's policy is part of the decision (same union, `$sort` denied on another op)", async () => {
    user.roles = ["ctl-op"];
    const a = jar();
    const crud = (text: string) => (JSON.parse(text) as TMetaResponse).crud;
    attrs.level = "lo";
    await a();
    const lo = await a();
    attrs.level = "hi";
    const hi = await a();
    expect(crud(lo.text).query).not.toContain("sort");
    expect(crud(lo.text).pages).toContain("sort");
    expect(crud(hi.text).query).toContain("sort");
    expect(crud(hi.text).pages).not.toContain("sort");
    expect(hi.text).toBe(await unmemoized());
    attrs.level = "lo";
    expect((await a()).text).toBe(lo.text);
  });

  it("declared with.<rel> sub-scopes that differ below the root never share a projection", async () => {
    const a = jar();
    user.roles = ["w-hidden"];
    const hidden = await a();
    await a();
    user.roles = ["w-open"];
    const open = await a();
    expect(open.status).toBe(200);
    expect(open.text).not.toBe(hidden.text);
    expect(open.text).toBe(await unmemoized());
    user.roles = ["w-hidden"];
    expect((await a()).text).toBe(hidden.text);
    expect(hidden.text).toBe(await unmemoized());
  });

  it("a ref target's readability (ref only, no nav prop) is part of the decision", async () => {
    const a = jar();
    user.roles = ["notes-proj"];
    const withRef = await a("/notes/meta");
    await a("/notes/meta");
    user.roles = ["notes-only"];
    const noRef = await a("/notes/meta");
    expect(noRef.status).toBe(200);
    expect(noRef.text).not.toBe(withRef.text);
    expect(noRef.text).toBe(await unmemoized("/notes/meta"));
    user.roles = ["notes-proj"];
    expect((await a("/notes/meta")).text).toBe(withRef.text);
  });

  it("a one-sided INHERITED_CONJUNCTION sub-scope is not memoized (and matches memo off)", async () => {
    user.roles = ["cond"];
    user.attenuation = { attrs: { wide: true } };
    const a = jar();
    const r1 = await a();
    const r2 = await a();
    const r3 = await a();
    expect(new Set(served).size).toBe(3);
    expect(served.some((m) => Object.isFrozen(m))).toBe(false);
    expect(r2.text).toBe(r1.text);
    expect(r3.text).toBe(await unmemoized());
  });

  it("a function-valued scope piece is not memoized (and matches memo off)", async () => {
    user.roles = ["fn"];
    for (let i = 0; i < 3; i++) await http.request("/tasks/meta");
    expect(new Set(served).size).toBe(3);
    expect(served.some((m) => Object.isFrozen(m))).toBe(false);
    const res = (await http.request("/tasks/meta"))!;
    expect(await res.text()).toBe(await unmemoized());
  });

  it("re-login with the same role reuses the projection (a 304 is allowed)", async () => {
    user.roles = ["viewer"];
    const a = jar();
    const first = await a();
    await a();
    const again = jar(); // a fresh login, same role
    const second = await again();
    expect(second.text).toBe(first.text);
    expect(served.at(-1)).toBe(served.at(-2));
  });

  it("setMetaMemo(false) prunes per request; { max } bounds the variants per envelope", async () => {
    arbac.setMetaMemo(false);
    user.roles = ["viewer"];
    for (let i = 0; i < 3; i++) await http.request("/tasks/meta");
    expect(new Set(served).size).toBe(3);
    expect(arbac.getMetaMemoMax()).toBe(0);
    arbac.setMetaMemo({ max: 1 });
    served.length = 0;
    for (const roles of [["viewer"], ["viewer"], ["member"], ["member"], ["viewer"]]) {
      user.roles = roles;
      await http.request("/tasks/meta");
    }
    // viewer, viewer(memo), member (evicts viewer), member(memo), viewer (recomputed)
    expect(served[1]).not.toBe(served[0]);
    expect(served[3]).toBe(served[2]);
    expect(served[4]).not.toBe(served[1]);
  });

  it("differential fuzz: memo on and off serve byte-identical bodies", async () => {
    let seed = 7;
    const next = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
    const ids = ["admin", "viewer", "member", "attr", "cond", "fn", "w-hidden", "w-open"];
    const paths = ["/tasks/meta", "/users/meta", "/orgs/meta", "/notes/meta"];
    for (let i = 0; i < 80; i++) {
      user.roles = [
        ...ids.filter(() => next() < 0.4),
        ...(next() < 0.5 ? ["notes-proj"] : ["notes-only"]),
      ];
      attrs.level = next() < 0.5 ? "hi" : "lo";
      const r = next();
      user.attenuation =
        r < 0.2
          ? { roles: user.roles.filter(() => next() < 0.5) }
          : r < 0.3
            ? { attrs: { wide: true } }
            : undefined;
      const path = paths[Math.floor(next() * paths.length)];
      const on1 = await (await http.request(path))!.text();
      const on2 = await (await http.request(path))!.text();
      const off = await unmemoized(path);
      expect(on1, `${user.roles.join(",")}|${JSON.stringify(user.attenuation)}|${path}`).toBe(off);
      expect(on2).toBe(off);
    }
  });
});
