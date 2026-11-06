import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

import { bootWith, setupSpace, teardownSpace } from "./reads-harness";

/**
 * Two-level aggregates (`$from`, atscript-db ≥ 0.1.168) under the `controls`
 * gates: `$from: false` denies them (and `/meta` stops advertising them); a
 * `$groupBy` whitelist governs the inner level's keys, while the outer level
 * may group by the inner level's columns (its keys and aliases).
 */

beforeAll(() => setupSpace());
afterAll(teardownSpace);

// count of accounts per department, then departments per count
const BY_COUNT =
  "/read-accounts/query?$from=($groupBy=deptId&$select=count(*):n)&$groupBy=n&$select=n,count(*):depts&$sort=n";

describe("$from: the controls gate", () => {
  it("allowed by default (an unrestricted role)", async () => {
    const get = await bootWith({ accounts: {} });
    const r = await get(BY_COUNT);
    expect(r.status, r.text).toBe(200);
    expect(r.body).toEqual([
      { n: 1, depts: 1 },
      { n: 2, depts: 1 },
    ]);
    expect((await get("/read-accounts/meta")).body).toMatchObject({ nestedAggregates: true });
  });

  it("$from: false → 403 ARBAC_CONTROL_NOT_ALLOWED; /meta drops nestedAggregates and `from`", async () => {
    const get = await bootWith({ accounts: { controls: { $from: false } } });
    const r = await get(BY_COUNT);
    expect(r.status).toBe(403);
    expect(r.body).toMatchObject({
      code: "ARBAC_CONTROL_NOT_ALLOWED",
      params: { control: "$from" },
    });
    // a single-level aggregate is still fine
    const single = await get("/read-accounts/query?$groupBy=deptId&$select=deptId,count(*):n");
    expect(single.status, single.text).toBe(200);
    const meta = (await get("/read-accounts/meta")).body;
    expect(meta.nestedAggregates).toBeUndefined();
    expect(meta.crud.query).not.toContain("from");
    expect(meta.crud.query).toContain("groupBy");
  });
});

describe("$from under a $groupBy whitelist", () => {
  const WHITELIST = { accounts: { controls: { $groupBy: ["deptId", "status", "hiredAt"] } } };

  it("the outer level may group by an inner aggregate alias", async () => {
    const get = await bootWith(WHITELIST);
    const r = await get(BY_COUNT);
    expect(r.status, r.text).toBe(200);
    expect(r.body).toEqual([
      { n: 1, depts: 1 },
      { n: 2, depts: 1 },
    ]);
  });

  it("…and by an inner key and an inner bucket alias", async () => {
    const get = await bootWith(WHITELIST);
    const key = await get(
      "/read-accounts/query?$from=($groupBy=deptId,status&$select=count(*):n)&$groupBy=deptId&$select=deptId,sum(n):total&$sort=deptId",
    );
    expect(key.status, key.text).toBe(200);
    expect(key.body).toEqual([
      { deptId: 1, total: 2 },
      { deptId: 2, total: 1 },
    ]);
    const bucket = await get(
      "/read-accounts/query?$from=($groupBy=y&$select=bucket(hiredAt,year):y,count(*):n)&$groupBy=y&$select=y,sum(n):total&$sort=y",
    );
    expect(bucket.status, bucket.text).toBe(200);
    expect(bucket.body).toHaveLength(2);
  });

  it("an inner key off the whitelist is still refused", async () => {
    const get = await bootWith(WHITELIST);
    const r = await get(
      "/read-accounts/query?$from=($groupBy=owner&$select=count(*):n)&$groupBy=n&$select=n,count(*):owners",
    );
    expect(r.status).toBe(403);
    expect(r.body).toMatchObject({
      code: "ARBAC_CONTROL_VALUE_NOT_ALLOWED",
      params: { control: "$groupBy", value: "owner" },
    });
  });

  it("an outer name that is not an inner column is refused", async () => {
    // atscript-db ≥ 0.1.170 rejects it as an invalid query (the outer level
    // reads only the inner columns) before any whitelist question — never served.
    const get = await bootWith(WHITELIST);
    const r = await get(
      "/read-accounts/query?$from=($groupBy=deptId&$select=count(*):n)&$groupBy=owner&$select=owner,count(*):c",
    );
    expect(r.status).toBe(400);
    expect(r.body).toMatchObject({
      code: "INVALID_QUERY",
      errors: [{ path: "$groupBy", code: "AGG_NESTED_UNKNOWN_COLUMN" }, expect.anything()],
    });
  });
  it("an un-aliased inner aggregate (count(*) → count_star) groups the outer level like an alias", async () => {
    // The inner column's name is uniqu's default alias (the unit tests of
    // `extractUsedControlValues` cover controls that arrive without a `$as`).
    const get = await bootWith(WHITELIST);
    const r = await get(
      "/read-accounts/query?$from=($groupBy=deptId&$select=count(*))&$groupBy=count_star&$select=count_star,count(*):depts&$sort=count_star",
    );
    expect(r.status, r.text).toBe(200);
    expect(r.body).toEqual([
      { count_star: 1, depts: 1 },
      { count_star: 2, depts: 1 },
    ]);
  });

  it("a table field off the whitelist is still refused as a grouping key", async () => {
    const get = await bootWith(WHITELIST);
    const r = await get("/read-accounts/query?$groupBy=owner&$select=owner,count(*):n");
    expect(r.status).toBe(403);
    expect(r.body).toMatchObject({ params: { control: "$groupBy", value: "owner" } });
  });

  it("an inner alias named like an off-whitelist field groups on the inner value, never the field", async () => {
    // The outer level reads only inner columns: `owner` here is the inner
    // count, so the off-whitelist `owner` column is not grouped on (or shown).
    const get = await bootWith(WHITELIST);
    const r = await get(
      "/read-accounts/query?$from=($groupBy=deptId&$select=count(*):owner)&$groupBy=owner&$select=owner,count(*):depts&$sort=owner",
    );
    expect(r.status, r.text).toBe(200);
    expect(r.body).toEqual([
      { owner: 1, depts: 1 },
      { owner: 2, depts: 1 },
    ]);
  });
});
