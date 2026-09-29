import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

import { bootWith, setupSpace, teardownSpace } from "./reads-harness";

/**
 * View controllers as their own ARBAC resource (SQLite): a view column over a
 * base-table `@db.writeOnly` field inherits the seal, and a view scope hides
 * joined, JSON-leaf, join-alias and view-over-view columns everywhere.
 */

beforeAll(() => setupSpace());
afterAll(teardownSpace);

describe("views", () => {
  it("a view column over a @db.writeOnly base field is sealed like on the table", async () => {
    const get = await bootWith({ "account-view": undefined });
    const rows = await get("/read-account-view/query");
    expect(rows.status).toBe(200);
    expect(rows.body).toHaveLength(3);
    for (const row of rows.body) expect(row).not.toHaveProperty("pin");
    expect(rows.body[0]).toMatchObject({ id: 1, salary: 100, leafKey: "KEY-AAA" });

    const pages = await get("/read-account-view/pages?$select=-title");
    for (const row of pages.body.data) expect(row).not.toHaveProperty("pin");
    const named = await get("/read-account-view/query?$select=id,pin");
    expect(named.body).toEqual([{ id: 1 }, { id: 2 }, { id: 3 }]);

    const filter = await get("/read-account-view/query?pin='2222'&$select=id");
    expect(filter.status).toBe(400);
    expect(filter.body).toMatchObject({
      message: 'Filtering on field "pin" is not permitted — field is @db.writeOnly.',
    });
    const sort = await get("/read-account-view/query?$sort=pin");
    expect(sort.status).toBe(400);
    expect(sort.body).toMatchObject({
      message: 'Sorting on field "pin" is not permitted — field is @db.writeOnly.',
    });
    const meta = await get("/read-account-view/meta");
    expect(meta.body.fields.pin).toEqual({ sortable: false, filterable: false, writeOnly: true });
  });

  it("a scoped view hides joined and JSON-leaf columns everywhere", async () => {
    const get = await bootWith({ "account-view": { projection: { deptBudget: 0, leafKey: 0 } } });
    const rows = await get("/read-account-view/query");
    expect(rows.body[0]).toMatchObject({ id: 1, deptName: "eng" });
    expect(rows.body[0]).not.toHaveProperty("deptBudget");
    expect(rows.body[0]).not.toHaveProperty("leafKey");
    for (const query of [
      "deptBudget>150",
      "$sort=leafKey",
      "$select=deptName,sum(deptBudget):b&$groupBy=deptName",
    ]) {
      expect((await get(`/read-account-view/query?${query}`)).status, query).toBe(400);
    }
    const meta = (await get("/read-account-view/meta")).body;
    expect(meta.fields).not.toHaveProperty("deptBudget");
    expect(meta.type.type.props).not.toHaveProperty("leafKey");
  });

  it("join-alias (self-join) columns are hidden and gated", async () => {
    const get = await bootWith({ staff: { projection: { managerSalary: 0 } } });
    const rows = await get("/read-staff/query?$sort=id");
    expect(rows.body[1]).toEqual({ id: 2, title: "beta", managerTitle: "alpha" });
    expect((await get("/read-staff/query?managerSalary>50")).status).toBe(400);
    expect((await get("/read-staff/meta")).body.fields).not.toHaveProperty("managerSalary");
  });

  it("a view over a view hides and gates its scoped columns", async () => {
    const get = await bootWith({ vov: { projection: { deptBudget: 0 } } });
    const rows = await get("/read-vov/query?$sort=id");
    expect(rows.body[0]).toEqual({ id: 1, leafKey: "KEY-AAA" });
    expect((await get("/read-vov/query?deptBudget=111")).status).toBe(400);
    expect((await get("/read-vov/meta")).body.fields).not.toHaveProperty("deptBudget");
  });
});
