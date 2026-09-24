import { allowTableRead, allowTableWrite, defineRole } from "@aooth/arbac";
import { DbSpace } from "@atscript/db";
import { BetterSqlite3Driver, SqliteAdapter } from "@atscript/db-sqlite";
import {
  clearDbSpaces,
  provideDbSpace,
  ReadableController,
  TableController,
} from "@atscript/moost-db";
import type { MoostHttp } from "@moostjs/event-http";
import { clearGlobalWooks } from "moost";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { bootArbacHttp } from "../__testing__/arbac-http";
import { FakeUserProvider } from "../__testing__/user-provider";
import { ArbacResource } from "../arbac.decorator";
import type { AoothArbacClaims } from "../attenuation";
import { MoostArbac } from "../moost-arbac";
import { KeyedDoc } from "./__test__/fixtures/keyed-doc.as";
import { NestedDoc } from "./__test__/fixtures/nested-doc.as";
import { RelAuthor, RelDoc, RelOrg } from "./__test__/fixtures/related-doc.as";
import { ScopedDoc } from "./__test__/fixtures/scoped-doc.as";
import { type ArbacDbScope, AsArbacDbController } from "./as-arbac-db-controller";
import { AsArbacDbReadableController } from "./as-arbac-db-readable-controller";

/**
 * Column scopes against the REAL moost-db gate — the regression tripwire for
 * moost-db's `hasField` contract. A real controller over a real SQLite table,
 * driven over HTTP with the authorize interceptor wired globally: a
 * projection-scoped role referencing a hidden column anywhere in a query must
 * get the 400 `Unknown field "x"` a nonexistent column gets, never a filtered
 * or sorted result (a value oracle, even with `$select` values stripped).
 * Against moost-db 0.1.128–0.1.132 every hidden case here returns 200 — see
 * docs/moost/db-controllers.md "Column-scope security floor".
 *
 * The `$with` suite below extends the floor to JOINED fields: a column a
 * `with.<rel>` sub-scope hides must be just as unknown inside a `$with`
 * sub-query (filter / `$sort` / `$select`), nested relations included.
 * Through arbac-moost 0.1.67 those paths passed `hasField` unchecked — the
 * related row appeared or vanished with the hidden value (a value oracle).
 */

// `secret` and `rank` are hidden from the scoped role.
const scopedRole = defineRole<object, ArbacDbScope>()
  .id("scoped")
  .use(allowTableRead("docs", { scope: () => ({ projection: { secret: 0, rank: 0 } }) }))
  .build();
// The same columns hidden through an inclusion whitelist.
const whitelistRole = defineRole<object, ArbacDbScope>()
  .id("whitelist")
  .use(allowTableRead("docs", { scope: () => ({ projection: { id: 1, title: 1, status: 1 } }) }))
  .build();
const adminRole = defineRole<object, ArbacDbScope>()
  .id("admin")
  .use(allowTableRead("docs"))
  .build();

@TableController(ScopedDoc, "docs")
@ArbacResource("docs")
class DocsController extends AsArbacDbController<typeof ScopedDoc> {}

@ReadableController(ScopedDoc, "docs-view")
@ArbacResource("docs")
class DocsReadableController extends AsArbacDbReadableController<typeof ScopedDoc> {}

const HIDDEN_CASES: Array<[query: string, field: string]> = [
  ["$select=title,secret", "secret"],
  ["$select=-secret", "secret"],
  ["secret='x'", "secret"],
  ["secret!='x'", "secret"],
  ["secret~=/^./", "secret"],
  ["rank>1", "rank"],
  ["$exists=secret", "secret"],
  ["$!exists=secret", "secret"],
  ["(title='a'^secret='b')", "secret"],
  ["status='open'&(title='a'^!(rank>1))", "rank"],
  ["$sort=secret", "secret"],
  ["$sort=-rank", "rank"],
  ["$select=secret,count(*):n&$groupBy=secret", "secret"],
  ["$select=status,sum(rank):s&$groupBy=status", "rank"],
  ["$select=status,max(secret):m&$groupBy=status", "secret"],
];

const VISIBLE_QUERIES = [
  "",
  "title='a'",
  "status!='x'&title~=/^./",
  "$exists=title",
  "(title='a'^status='open')",
  "$sort=-title",
  "$select=id,title",
  "$select=status,count(*):n&$groupBy=status&$having=n>0",
];

// `with` grants: the author's `salary` and the author's org's `budget` are
// hidden from the joined rows. Exclusion and inclusion forms must agree.
const relExcludeRole = defineRole<object, ArbacDbScope>()
  .id("rel-exclude")
  .use(
    allowTableRead("rel-docs", {
      scope: () => ({
        projection: { secret: 0 },
        with: {
          author: { projection: { salary: 0 }, with: { org: { projection: { budget: 0 } } } },
        },
      }),
    }),
  )
  .build();
// Inclusion whitelists that never name the related PKs — `author.id` /
// `author.org.id` stay visible anyway (the related table's own identifiers).
const relIncludeRole = defineRole<object, ArbacDbScope>()
  .id("rel-include")
  .use(
    allowTableRead("rel-docs", {
      scope: () => ({
        projection: { id: 1, title: 1, authorId: 1 },
        with: {
          author: {
            projection: { name: 1, orgId: 1 },
            with: { org: { projection: { name: 1 } } },
          },
        },
      }),
    }),
  )
  .build();
// No `with` grant: silence wins — the joined rows are unrestricted.
const relSilentRole = defineRole<object, ArbacDbScope>()
  .id("rel-silent")
  .use(allowTableRead("rel-docs", { scope: () => ({ projection: { secret: 0 } }) }))
  .build();
const relAdminRole = defineRole<object, ArbacDbScope>()
  .id("rel-admin")
  .use(allowTableRead("rel-docs"))
  .build();

@TableController(RelDoc, "rel-docs")
@ArbacResource("rel-docs")
class RelDocsController extends AsArbacDbController<typeof RelDoc> {}

@ReadableController(RelDoc, "rel-docs-view")
@ArbacResource("rel-docs")
class RelDocsReadableController extends AsArbacDbReadableController<typeof RelDoc> {}

const HIDDEN_RELATED_CASES: Array<[query: string, field: string]> = [
  ["$with=author(salary>100)&$sort=id", "author.salary"],
  ["$with=author(salary<100)&$sort=id", "author.salary"],
  ["$with=author(name='b'^salary>100)", "author.salary"],
  ["$with=author($sort=salary)", "author.salary"],
  ["$with=author($sort=-salary)", "author.salary"],
  ["$with=author($select=salary)", "author.salary"],
  ["$with=author($select=name,salary)", "author.salary"],
  ["$with=author($select=-salary)", "author.salary"],
  ["$with=author($with=org(budget>1))", "author.org.budget"],
  ["$with=author($with=org($sort=budget))", "author.org.budget"],
  ["$with=author($with=org($select=budget))", "author.org.budget"],
  ["author.salary>1", "author.salary"],
];

const VISIBLE_RELATED_QUERIES = [
  "$with=author",
  "$with=author(name='b')",
  "$with=author($sort=name)",
  "$with=author($select=name)",
  "$with=author(id>0)",
  "$with=author($select=id)",
  "$with=author($with=org)",
  "$with=author($with=org(name='o'))",
  "$with=author($with=org($select=id,name))",
];

// `$select` ∩ scope projection over a nested object `a: { b, c }`.
const selIncludeRole = defineRole<object, ArbacDbScope>()
  .id("sel-include")
  .use(allowTableRead("nested", { scope: () => ({ projection: { id: 1, title: 1, "a.b": 1 } }) }))
  .build();
const selExcludeRole = defineRole<object, ArbacDbScope>()
  .id("sel-exclude")
  .use(allowTableRead("nested", { scope: () => ({ projection: { "a.c": 0 } }) }))
  .build();
// A whole nested object hidden by its parent key.
const selParentExcludeRole = defineRole<object, ArbacDbScope>()
  .id("sel-parent-exclude")
  .use(allowTableRead("nested", { scope: () => ({ projection: { a: 0 } }) }))
  .build();

@TableController(NestedDoc, "nested")
@ArbacResource("nested")
class NestedController extends AsArbacDbController<typeof NestedDoc> {}

@ReadableController(NestedDoc, "nested-view")
@ArbacResource("nested")
class NestedReadableController extends AsArbacDbReadableController<typeof NestedDoc> {}

// [role, $select query, expected row] — the row every endpoint must return.
const SELECT_CASES: Array<[role: string, query: string, row: Record<string, unknown>]> = [
  ["sel-include", "$select=a", { id: 1, a: { b: "B" } }],
  ["sel-include", "$select=title", { id: 1, title: "t" }],
  ["sel-include", "$select=a.b", { id: 1, a: { b: "B" } }],
  ["sel-include", "$select=-title", { id: 1, a: { b: "B" } }],
  ["sel-include", "$select=-a", { id: 1, title: "t" }],
  ["sel-include", "", { id: 1, title: "t", a: { b: "B" } }],
  ["sel-exclude", "$select=a", { id: 1, a: { b: "B" } }],
  ["sel-exclude", "$select=title", { id: 1, title: "t" }],
  ["sel-exclude", "$select=-title", { id: 1, a: { b: "B" } }],
  ["sel-exclude", "$select=-a", { id: 1, title: "t" }],
  ["sel-exclude", "", { id: 1, title: "t", a: { b: "B" } }],
  ["sel-parent-exclude", "", { id: 1, title: "t" }],
  ["sel-parent-exclude", "$select=title", { id: 1, title: "t" }],
  ["sel-parent-exclude", "$select=-title", { id: 1 }],
];

// Writes addressing a row by a unique key the scope hides. The row filter makes
// the ARBAC in-scope pre-check run; the projection hides the unique `code`.
const keyedScopedRole = defineRole<object, ArbacDbScope>()
  .id("keyed-scoped")
  .use(
    allowTableWrite("keyed", {
      scope: () => ({ filter: { owner: "u1" }, projection: { code: 0 } }),
    }),
  )
  .build();
// No row filter: the ARBAC pre-check is skipped, moost-db resolves the id.
const keyedProjectionRole = defineRole<object, ArbacDbScope>()
  .id("keyed-projection")
  .use(allowTableWrite("keyed", { scope: () => ({ projection: { code: 0 } }) }))
  .build();
const keyedAdminRole = defineRole<object, ArbacDbScope>()
  .id("keyed-admin")
  .use(allowTableWrite("keyed"))
  .build();

@TableController(KeyedDoc, "keyed")
@ArbacResource("keyed")
class KeyedController extends AsArbacDbController<typeof KeyedDoc> {}

// Attenuation: the scope's projection is picked by the `view` attribute; a
// credential narrows it through `attrs` overrides (restrict-only).
type ViewAttrs = { view: string };
const VIEW_PROJECTIONS: Record<string, Record<string, 0 | 1>> = {
  full: { id: 1, title: 1, a: 1 },
  nestedWhitelist: { id: 1, "a.b": 1 },
  nestedExclusion: { "a.c": 0 },
  parentExclusion: { a: 0 },
  disjoint: { "a.b": 1 },
  titleOnly: { id: 1, title: 1 },
};
const viewRole = defineRole<ViewAttrs, ArbacDbScope>()
  .id("view")
  .use(
    allowTableRead<ViewAttrs, ArbacDbScope>("nested", {
      scope: (attrs) => ({ projection: VIEW_PROJECTIONS[attrs.view] }),
    }),
  )
  .build();

class AttenuatedUser extends FakeUserProvider<ViewAttrs> {
  public attenuation: AoothArbacClaims | undefined;
  override getAttenuation(): AoothArbacClaims | undefined {
    return this.attenuation;
  }
}

// One database for the file: token-bound controllers resolve their table from
// the registered space once per class, so the space must outlive every app.
let driver: BetterSqlite3Driver;

beforeAll(async () => {
  driver = new BetterSqlite3Driver(":memory:");
  const space = new DbSpace(() => new SqliteAdapter(driver));
  const table = space.getTable(ScopedDoc);
  await table.ensureTable();
  await table.insertMany([
    { id: 1, title: "a", status: "open", secret: "s3cr3t", rank: 5 },
    { id: 2, title: "b", status: "done", secret: "hidden", rank: 1 },
  ]);
  for (const t of [RelOrg, RelAuthor, RelDoc]) await space.getTable(t).ensureTable();
  await space.getTable(RelOrg).insertMany([{ id: 1, name: "o", budget: 900 }]);
  await space.getTable(RelAuthor).insertMany([
    { id: 1, name: "a", salary: 50, orgId: 1 },
    { id: 2, name: "b", salary: 500, orgId: 1 },
  ]);
  await space.getTable(RelDoc).insertMany([
    { id: 1, title: "t1", secret: "x", authorId: 1 },
    { id: 2, title: "t2", secret: "y", authorId: 2 },
  ]);
  const nested = space.getTable(NestedDoc);
  await nested.ensureTable();
  await nested.insertMany([{ id: 1, title: "t", a: { b: "B", c: "C" } }]);
  const keyed = space.getTable(KeyedDoc);
  await keyed.ensureTable();
  await keyed.insertMany([
    { id: 1, code: "K1", title: "a", owner: "u1" },
    { id: 2, code: "K2", title: "b", owner: "u2" },
  ]);
  provideDbSpace(space);
});

afterAll(() => {
  clearDbSpaces();
  driver.close();
});

describe.each([
  ["AsArbacDbController", "docs"],
  ["AsArbacDbReadableController", "docs-view"],
])("%s: projection-scoped columns through the real moost-db gate", (_name, prefix) => {
  let user: FakeUserProvider;
  let http: MoostHttp;

  beforeEach(async () => {
    clearGlobalWooks();
    const arbac = new MoostArbac<object, ArbacDbScope>();
    for (const role of [scopedRole, whitelistRole, adminRole]) arbac.registerRole(role);
    user = new FakeUserProvider("u1", []);
    http = await bootArbacHttp({
      arbac,
      user,
      controllers: [DocsController, DocsReadableController],
      authorize: true,
    });
  });

  async function get(query: string): Promise<{ status: number; body: unknown }> {
    const res = await http.request(`/${prefix}/query${query ? `?${query}` : ""}`);
    return { status: res!.status, body: await res!.json() };
  }

  describe("projection-scoped role", () => {
    beforeEach(() => {
      user.roles = ["scoped"];
    });

    it.each(HIDDEN_CASES)("?%s → 400 Unknown field", async (query, field) => {
      const { status, body } = await get(query);
      expect(status, query).toBe(400);
      expect(body, query).toMatchObject({ message: `Unknown field "${field}"` });
    });

    it.each(VISIBLE_QUERIES)("visible columns still pass: ?%s", async (query) => {
      const { status } = await get(query);
      expect(status, query).toBe(200);
    });

    it("plain reads keep hidden values stripped", async () => {
      const { status, body } = await get("$sort=id");
      expect(status).toBe(200);
      for (const row of body as Array<Record<string, unknown>>) {
        expect(row).not.toHaveProperty("secret");
        expect(row).not.toHaveProperty("rank");
      }
    });
  });

  it.each(["scoped", "whitelist"])(
    "role %s: a hidden column answers byte-for-byte like a nonexistent one",
    async (role) => {
      user.roles = [role];
      const hidden = await get("secret='x'");
      const missing = await get("nope='x'");
      expect(hidden.status).toBe(400);
      expect(JSON.stringify(hidden.body).replaceAll("secret", "nope")).toBe(
        JSON.stringify(missing.body),
      );
    },
  );

  describe("unscoped role", () => {
    beforeEach(() => {
      user.roles = ["admin"];
    });

    it.each(HIDDEN_CASES)("?%s → 200", async (query) => {
      const { status } = await get(query);
      expect(status, query).toBe(200);
    });

    it("sees and filters by the columns the scoped role cannot", async () => {
      const { body } = await get("secret='s3cr3t'&$sort=-rank");
      expect(body).toEqual([{ id: 1, title: "a", status: "open", secret: "s3cr3t", rank: 5 }]);
    });
  });
});

describe.each([
  ["AsArbacDbController", "rel-docs"],
  ["AsArbacDbReadableController", "rel-docs-view"],
])("%s: `with`-scoped related columns through the real moost-db gate", (_name, prefix) => {
  let user: FakeUserProvider;
  let http: MoostHttp;

  beforeEach(async () => {
    clearGlobalWooks();
    const arbac = new MoostArbac<object, ArbacDbScope>();
    for (const role of [relExcludeRole, relIncludeRole, relSilentRole, relAdminRole]) {
      arbac.registerRole(role);
    }
    user = new FakeUserProvider("u1", []);
    http = await bootArbacHttp({
      arbac,
      user,
      controllers: [RelDocsController, RelDocsReadableController],
      authorize: true,
    });
  });

  async function get(path: string): Promise<{ status: number; body: unknown }> {
    const res = await http.request(`/${prefix}/${path}`);
    return { status: res!.status, body: await res!.json() };
  }

  describe.each(["rel-exclude", "rel-include"])("role %s", (role) => {
    beforeEach(() => {
      user.roles = [role];
    });

    it.each(HIDDEN_RELATED_CASES)("?%s → 400 Unknown field", async (query, field) => {
      const { status, body } = await get(`query?${query}`);
      expect(status, query).toBe(400);
      expect(body, query).toMatchObject({ message: `Unknown field "${field}"` });
    });

    it.each(VISIBLE_RELATED_QUERIES)("visible related fields still pass: ?%s", async (query) => {
      const { status } = await get(`query?${query}`);
      expect(status, query).toBe(200);
    });

    it.each([
      ["$with=author(salary>1)", "$with=author(nope>1)", "salary"],
      ["$with=author($sort=salary)", "$with=author($sort=nope)", "salary"],
      ["$with=author($select=salary)", "$with=author($select=nope)", "salary"],
      ["$with=author($with=org(budget>1))", "$with=author($with=org(nope>1))", "budget"],
    ])("?%s answers byte-for-byte like ?%s", async (hiddenQuery, missingQuery, field) => {
      const hidden = await get(`query?${hiddenQuery}`);
      const missing = await get(`query?${missingQuery}`);
      expect(hidden.status).toBe(400);
      expect(JSON.stringify(hidden.body).replaceAll(field, "nope")).toBe(
        JSON.stringify(missing.body),
      );
    });

    it("visible related filters work and hidden related values stay stripped", async () => {
      const { status, body } = await get("query?$with=author(name='b'&$with=org)&$sort=id");
      expect(status).toBe(200);
      const rows = body as Array<Record<string, unknown>>;
      expect(rows.map((r) => r.author === null)).toEqual([true, false]);
      const author = rows[1].author as Record<string, unknown>;
      expect(author).toMatchObject({ id: 2, name: "b" });
      expect(author).not.toHaveProperty("salary");
      expect(author.org).toMatchObject({ id: 1, name: "o" });
      expect(author.org).not.toHaveProperty("budget");
    });

    it("/one/:id with $with: hidden related field → 400, visible → 200", async () => {
      const hidden = await get("one/2?$with=author(salary>100)");
      expect(hidden.status).toBe(400);
      expect(hidden.body).toMatchObject({ message: 'Unknown field "author.salary"' });
      const visible = await get("one/2?$with=author(name='b')");
      expect(visible.status).toBe(200);
      expect((visible.body as { author: unknown }).author).toMatchObject({ id: 2, name: "b" });
    });

    it("/meta prunes the with-granted nav type by its sub-scope (hasField parity)", async () => {
      const { status, body } = await get("meta");
      expect(status).toBe(200);
      type Node = { type: { props?: Record<string, Node> } };
      const meta = body as { type: Node; relations: Array<{ name: string }> };
      const props = meta.type.type.props!;
      expect(props).not.toHaveProperty("secret");
      expect(meta.relations.map((r) => r.name)).toEqual(["author"]);
      const authorProps = props.author.type.props!;
      expect(Object.keys(authorProps).toSorted()).toEqual(["id", "name", "org", "orgId"]);
      const orgProps = authorProps.org.type.props!;
      expect(Object.keys(orgProps).toSorted()).toEqual(["id", "name"]);
    });
  });

  it("no with grant (silence wins): joined rows are unrestricted, so are their paths", async () => {
    user.roles = ["rel-silent"];
    const { status, body } = await get("query?$with=author(salary>100)&$sort=id");
    expect(status).toBe(200);
    expect((body as Array<{ author: unknown }>).map((r) => r.author === null)).toEqual([
      true,
      false,
    ]);
  });

  it("unscoped role: related columns filter, sort and select normally", async () => {
    user.roles = ["rel-admin"];
    for (const query of HIDDEN_RELATED_CASES.map(([q]) => q).filter((q) => q.includes("$with"))) {
      const { status } = await get(`query?${query}`);
      expect(status, query).toBe(200);
    }
    const { body } = await get("meta");
    const authorProps = (
      body as { type: { type: { props: Record<string, { type: { props: object } }> } } }
    ).type.type.props.author.type.props;
    expect(authorProps).toHaveProperty("salary");
  });
});

describe.each([
  ["AsArbacDbController", "nested"],
  ["AsArbacDbReadableController", "nested-view"],
])("%s: user $select narrows to its intersection with the scope projection", (_name, prefix) => {
  let user: FakeUserProvider;
  let http: MoostHttp;

  beforeEach(async () => {
    clearGlobalWooks();
    const arbac = new MoostArbac<object, ArbacDbScope>();
    for (const role of [selIncludeRole, selExcludeRole, selParentExcludeRole]) {
      arbac.registerRole(role);
    }
    user = new FakeUserProvider("u1", []);
    http = await bootArbacHttp({
      arbac,
      user,
      controllers: [NestedController, NestedReadableController],
      authorize: true,
    });
  });

  async function get(path: string): Promise<{ status: number; body: unknown }> {
    const res = await http.request(`/${prefix}/${path}`);
    return { status: res!.status, body: await res!.json() };
  }

  it.each(SELECT_CASES)("%s ?%s → only the visible intersection", async (role, query, row) => {
    user.roles = [role];
    const qs = query ? `?${query}` : "";
    const list = await get(`query${qs}`);
    expect(list.status, "query").toBe(200);
    expect(list.body, "query").toEqual([row]);
    const pages = await get(`pages${qs}`);
    expect(pages.status, "pages").toBe(200);
    expect((pages.body as { data: unknown }).data, "pages").toEqual([row]);
    const one = await get(`one/1${qs}`);
    expect(one.status, "one").toBe(200);
    expect(one.body, "one").toEqual(row);
  });
});

describe("credential attenuation never widens the projection (real gate)", () => {
  async function bootAs(
    userView: string,
    credView: string,
  ): Promise<(path: string) => Promise<{ status: number; body: unknown }>> {
    clearGlobalWooks();
    const arbac = new MoostArbac<ViewAttrs, ArbacDbScope>();
    arbac.registerRole(viewRole);
    const user = new AttenuatedUser("u1", ["view"], { view: userView });
    user.attenuation = { attrs: { view: credView } };
    const http = await bootArbacHttp({
      arbac,
      user,
      controllers: [NestedController],
      authorize: true,
    });
    return async (path) => {
      const res = await http.request(`/nested/${path}`);
      return { status: res!.status, body: await res!.json() };
    };
  }

  it.each([
    // [user view, credential view, expected row]
    ["full", "nestedWhitelist", { id: 1, a: { b: "B" } }],
    ["nestedWhitelist", "full", { id: 1, a: { b: "B" } }],
    ["full", "nestedExclusion", { id: 1, title: "t", a: { b: "B" } }],
    ["nestedExclusion", "full", { id: 1, title: "t", a: { b: "B" } }],
    ["full", "parentExclusion", { id: 1, title: "t" }],
  ])("user %s ∩ credential %s → only the common fields", async (userView, credView, row) => {
    const get = await bootAs(userView, credView);
    const list = await get("query");
    expect(list.status).toBe(200);
    expect(list.body).toEqual([row]);
    const one = await get("one/1");
    expect(one.status).toBe(200);
    expect(one.body).toEqual(row);
  });

  it.each([
    ["titleOnly", "disjoint"],
    ["parentExclusion", "disjoint"],
  ])(
    "user %s ∩ credential %s share no field → no rows (never the unrestricted {})",
    async (userView, credView) => {
      const get = await bootAs(userView, credView);
      const list = await get("query");
      expect(list.status).toBe(200);
      expect(list.body).toEqual([]);
      expect((await get("one/1")).status).toBe(404);
    },
  );
});

describe("writes by a scope-hidden unique key answer like a nonexistent key", () => {
  let user: FakeUserProvider;
  let http: MoostHttp;

  beforeEach(async () => {
    clearGlobalWooks();
    const arbac = new MoostArbac<object, ArbacDbScope>();
    for (const role of [keyedScopedRole, keyedProjectionRole, keyedAdminRole]) {
      arbac.registerRole(role);
    }
    user = new FakeUserProvider("u1", ["keyed-scoped"]);
    http = await bootArbacHttp({
      arbac,
      user,
      controllers: [KeyedController],
      authorize: true,
    });
  });

  async function send(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<{ status: number; body: string }> {
    const res = await http.request(path ? `/keyed/${path}` : "/keyed", {
      method,
      headers: body === undefined ? undefined : { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: res!.status, body: await res!.text() };
  }

  // [method, path, body for the hidden existing key K1, the same for the absent key NOPE]
  const WRITES: Array<
    [method: string, path: (code: string) => string, body?: (code: string) => unknown]
  > = [
    ["DELETE", (code) => code],
    ["PATCH", () => "", (code) => ({ code, title: "x" })],
    ["PUT", () => "", (code) => ({ code, title: "x", owner: "u1" })],
  ];

  it.each(WRITES)("%s: hidden existing key ≡ nonexistent key", async (method, path, body) => {
    const hidden = await send(method, path("K1"), body?.("K1"));
    const missing = await send(method, path("NOPE"), body?.("NOPE"));
    expect(hidden.status, method).toBe(404);
    expect(JSON.parse(hidden.body), method).toMatchObject({ message: "Not found" });
    expect(hidden.body.replaceAll("K1", "NOPE"), method).toBe(missing.body);
  });

  it.each(WRITES)("%s without a row filter: still identical", async (method, path, body) => {
    user.roles = ["keyed-projection"];
    const hidden = await send(method, path("K1"), body?.("K1"));
    const missing = await send(method, path("NOPE"), body?.("NOPE"));
    expect(hidden.status, method).toBe(missing.status);
    expect(hidden.body.replaceAll("K1", "NOPE"), method).toBe(missing.body);
  });

  it("the key is a real identification for a role that sees it", async () => {
    user.roles = ["keyed-admin"];
    const res = await send("PATCH", "", { code: "K1", title: "renamed" });
    expect(res.status).toBe(202);
    expect(JSON.parse(res.body)).toMatchObject({ matchedCount: 1 });
  });

  it("the scoped role still writes through the visible primary key", async () => {
    const res = await send("PATCH", "", { id: 1, title: "by-pk" });
    expect(res.status).toBe(202);
    expect(JSON.parse(res.body)).toMatchObject({ matchedCount: 1 });
  });
});
