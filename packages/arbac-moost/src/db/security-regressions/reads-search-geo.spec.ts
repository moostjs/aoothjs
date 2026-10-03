import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

import { bootPlain, bootWith, ids, setupSpace, teardownSpace } from "./reads-harness";

/**
 * Native search and `/geo` over scope-hidden fields (SQLite): an index that
 * reads a hidden field is never an oracle, `/geo` runs the same control
 * validation as `/query`, and SQL `/geo` honours `$select` and the
 * `@db.writeOnly` seal. (`/meta`'s search surface under an exclusion scope is
 * pinned in read-policy.integration.spec.ts.)
 *
 * `read_accounts.txt_idx` (the default text index) covers title + secretNote;
 * `home` carries the geo index "home".
 */

beforeAll(() => setupSpace());
afterAll(teardownSpace);

const NO_NOTE = { accounts: { projection: { secretNote: 0 } } } as const;
const sortedIds = (body: unknown) => ids(body).toSorted((a, b) => a - b);

// moost-db ≥ 0.1.147: `$search` naming no index is refused (400) when the
// DEFAULT index reads a hidden field — no fallback on a native-search table,
// so the answer never depends on the term.
const NO_INDEX = { statusCode: 400, message: "No search index available" };

describe("native full-text search over a hidden column", () => {
  it("the default index over a hidden field refuses $search (400)", async () => {
    // Control: natively, "zebra" only occurs in secretNote (rows 1 and 3).
    const all = await bootWith({ accounts: undefined });
    expect(sortedIds((await all("/read-accounts/query?$search=zebra&$select=id")).body)).toEqual([
      1, 3,
    ]);

    const get = await bootWith(NO_NOTE);
    for (const endpoint of ["query", "pages"]) {
      for (const term of ["zebra", "open"]) {
        const r = await get(`/read-accounts/${endpoint}?$search=${term}&$select=id`);
        expect(r.body, `${endpoint} ${term}`).toMatchObject(NO_INDEX);
      }
    }
  });

  it("a grouped $search counts only visible matches", async () => {
    const all = await bootWith({ accounts: undefined });
    const native = await all(
      "/read-accounts/query?$search=zebra&$select=status,count(*):n&$groupBy=status&$sort=status",
    );
    expect(native.body).toEqual([
      { status: "done", n: 1 },
      { status: "open", n: 1 },
    ]);

    const get = await bootWith(NO_NOTE);
    for (const term of ["zebra", "open"]) {
      const hidden = await get(
        `/read-accounts/query?$search=${term}&$select=status,count(*):n&$groupBy=status`,
      );
      expect(hidden.body, term).toMatchObject(NO_INDEX);
    }
  });

  it("$index naming an index over a hidden field answers like a nonexistent index", async () => {
    const all = await bootWith({ accounts: undefined });
    expect(
      (await all("/read-accounts/query?$search=launch&$index=txt_idx&$select=id")).body,
    ).toEqual([{ id: 1 }]);

    const get = await bootWith(NO_NOTE);
    for (const endpoint of ["query", "pages"]) {
      const hidden = await get(`/read-accounts/${endpoint}?$search=launch&$index=txt_idx`);
      const missing = await get(`/read-accounts/${endpoint}?$search=launch&$index=nope`);
      expect(hidden.status, endpoint).toBe(400);
      expect(hidden.body, endpoint).toMatchObject({ message: 'Search index "txt_idx" not found' });
      expect(hidden.text.replaceAll("txt_idx", "nope"), endpoint).toBe(missing.text);
    }
    const grouped = await get(
      "/read-accounts/query?$search=zebra&$index=txt_idx&$select=status,count(*):n&$groupBy=status",
    );
    expect(grouped.status).toBe(400);
  });

  it("without a visible default index the answer never depends on the term", async () => {
    const projections: Array<Record<string, 0 | 1>> = [
      { secretNote: 0, status: 0 },
      { id: 1, title: 1 },
    ];
    for (const projection of projections) {
      const get = await bootWith({ accounts: { projection } });
      const plain = await get("/read-accounts/query?$select=id&$sort=id");
      expect(plain.body).toEqual([{ id: 1 }, { id: 2 }, { id: 3 }]);
      for (const term of ["zebra", "launch", "no-such-term"]) {
        const r = await get(`/read-accounts/query?$search=${term}&$select=id&$sort=id`);
        expect(r.body, `${term} ${JSON.stringify(projection)}`).toMatchObject(NO_INDEX);
      }
      const meta = (await get("/read-accounts/meta")).body;
      expect(meta.searchable).toBe(false);
      expect(meta.searchIndexes).toEqual([]);
      expect(JSON.stringify(meta)).not.toContain("secretNote");
    }
  });

  it("a fallback-only table searches only its visible searchable columns", async () => {
    const get = await bootWith({ depts: { projection: { secretCode: 0 } } });
    expect((await get("/read-depts/query?$search=xylo&$select=id")).body).toEqual([]);
    expect((await get("/read-depts/query?$search=eng&$select=id")).body).toEqual([{ id: 1 }]);
  });
});

describe("/geo over scope-hidden fields", () => {
  it("allowTableRead grants /geo, under the row scope", async () => {
    const get = await bootWith({ accounts: { filter: { owner: "u1" } } });
    const r = await get("/read-accounts/geo?$center=0,0&$select=id");
    expect(r.status).toBe(200);
    expect(ids(r.body)).toEqual([2, 1]);
  });

  it("a hidden geo column answers like a table without a geo index", async () => {
    const all = await bootWith({ accounts: undefined });
    expect(
      ids((await all("/read-accounts/geo?$center=2.35,48.85&$index=home&$select=id")).body),
    ).toEqual([2, 3, 1]);

    const get = await bootWith({ accounts: { projection: { home: 0 } }, depts: undefined });
    const noIndex = await get("/read-depts/geo?$center=2.35,48.85");
    expect(noIndex.status).toBe(400);
    for (const query of ["$center=2.35,48.85", "$center=2.35,48.85&$maxDistance=1000&$select=id"]) {
      const hidden = await get(`/read-accounts/geo?${query}`);
      expect(hidden.status, query).toBe(400);
      expect(hidden.text.replaceAll("read_accounts", "read_depts"), query).toBe(noIndex.text);
    }
    const named = await get("/read-accounts/geo?$center=2.35,48.85&$index=home");
    const missing = await get("/read-accounts/geo?$center=2.35,48.85&$index=nope");
    expect(named.status).toBe(400);
    expect(named.body).toMatchObject({
      message: 'Geo index "home" not found on table "read_accounts"',
    });
    expect(named.text.replaceAll("home", "nope")).toBe(missing.text);
  });

  it("SQL /geo honours $select and the scope projection", async () => {
    const get = await bootWith({ accounts: { projection: { salary: 0, settings: 0 } } });
    const selected = await get("/read-accounts/geo?$center=2.35,48.85&$select=id");
    expect(selected.status).toBe(200);
    expect(ids(selected.body)).toEqual([2, 3, 1]);
    for (const row of selected.body)
      expect(Object.keys(row).toSorted()).toEqual(["$distance", "id"]);

    const paged = await get("/read-accounts/geo?$center=2.35,48.85&$select=id&$size=1");
    expect(paged.body).toMatchObject({ data: [{ id: 2, $distance: 0 }], count: 3 });

    const plain = await get("/read-accounts/geo?$center=2.35,48.85");
    expect(plain.body[0]).toMatchObject({ id: 2, title: "beta", home: [2.35, 48.85] });
    for (const row of plain.body) {
      for (const key of ["salary", "settings", "apiKeyCopy", "themeCopy", "pin"]) {
        expect(row).not.toHaveProperty(key);
      }
    }
    for (const query of ["$select=id,salary", "salary>1"]) {
      const r = await get(`/read-accounts/geo?$center=2.35,48.85&${query}`);
      expect(r.status, query).toBe(400);
      expect(r.body, query).toMatchObject({ message: 'Unknown field "salary"' });
    }
  });

  it("/geo never returns a @db.writeOnly column, even when $select names it", async () => {
    const get = await bootWith({ accounts: undefined });
    const plain = await get("/read-accounts/geo?$center=2.35,48.85");
    expect(plain.body).toHaveLength(3);
    for (const row of plain.body) expect(row).not.toHaveProperty("pin");
    const named = await get("/read-accounts/geo?$center=2.35,48.85&$select=id,pin");
    for (const row of named.body) expect(Object.keys(row).toSorted()).toEqual(["$distance", "id"]);
  });
});

describe("/geo runs the same control validation as /query", () => {
  it("a controls.$with=false gate rejects $with on /geo", async () => {
    const get = await bootWith({ accounts: { controls: { $with: false } } });
    const q = await get("/read-accounts/query?$with=dept");
    const g = await get("/read-accounts/geo?$center=0,0&$with=dept");
    expect(q.status).toBe(403);
    expect(g.status).toBe(403);
    expect(g.text).toBe(q.text);
  });

  it("a declared with.<rel> sub-scope (filter + projection) applies to /geo joins", async () => {
    const get = await bootWith({
      accounts: {
        with: { dept: { filter: { name: "eng" }, projection: { budget: 0, secretCode: 0 } } },
      },
    });
    const g = await get("/read-accounts/geo?$center=0,0&$with=dept&$select=id,deptId");
    expect(g.status).toBe(200);
    const eng = { id: 1, name: "eng", rowVersion: 0 };
    const byId = Object.fromEntries(
      (g.body as Array<{ id: number; dept: unknown }>).map((r) => [r.id, r.dept]),
    );
    expect(byId).toEqual({ 1: eng, 2: eng, 3: null });

    const hidden = await get("/read-accounts/geo?$center=0,0&$with=dept(budget>150)");
    const missing = await get("/read-accounts/geo?$center=0,0&$with=dept(nope>150)");
    expect(hidden.status).toBe(400);
    expect(hidden.text.replaceAll("budget", "nope")).toBe(missing.text);
  });

  it("a relation the projection hides is an unknown relation on /geo too", async () => {
    const get = await bootWith({ accounts: { projection: { id: 1, title: 1 } } });
    const q = await get("/read-accounts/query?$with=dept");
    const g = await get("/read-accounts/geo?$center=0,0&$with=dept");
    expect(g.status).toBe(400);
    expect(g.body).toMatchObject({ message: expect.stringContaining('Unknown relation "dept"') });
    expect(g.text).toBe(q.text);
  });
});

// Last: bootPlain() declares its controller lazily (it stamps the shared type).
describe("plain moost-db /geo (no ARBAC)", () => {
  it("honours $select (inclusion + exclusion) and never returns @db.writeOnly", async () => {
    const get = await bootPlain();
    const all = await get("/plain-accounts/geo?$center=2.35,48.85");
    expect(all.status).toBe(200);
    expect(all.body[0]).toMatchObject({ id: 2, salary: 900, home: [2.35, 48.85] });
    for (const row of all.body) expect(row).not.toHaveProperty("pin");

    const included = await get("/plain-accounts/geo?$center=2.35,48.85&$select=id,title");
    expect(included.body).toEqual([
      { id: 2, title: "beta", $distance: 0 },
      { id: 3, title: "gamma", $distance: expect.any(Number) },
      { id: 1, title: "alpha", $distance: expect.any(Number) },
    ]);

    const pin = await get("/plain-accounts/geo?$center=2.35,48.85&$select=id,pin");
    for (const row of pin.body) expect(Object.keys(row).toSorted()).toEqual(["$distance", "id"]);

    const excluded = await get(
      "/plain-accounts/geo?$center=2.35,48.85&$select=-settings,-secretNote&$size=1",
    );
    const row = excluded.body.data[0];
    expect(row).toMatchObject({ id: 2, title: "beta", salary: 900 });
    for (const key of ["settings", "secretNote", "pin"]) expect(row).not.toHaveProperty(key);
  });
});
