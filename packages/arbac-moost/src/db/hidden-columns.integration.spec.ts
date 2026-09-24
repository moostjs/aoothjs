import { allowTableRead, defineRole } from "@aooth/arbac";
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
import { MoostArbac } from "../moost-arbac";
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
