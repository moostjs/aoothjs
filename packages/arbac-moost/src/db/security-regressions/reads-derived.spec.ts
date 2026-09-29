import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

import { bootWith, setupSpace, teardownSpace } from "./reads-harness";

/**
 * Derived columns follow their source (SQLite): a `@db.column.derived` copy of
 * a scope-hidden `@db.json` source answers every read control exactly like a
 * nonexistent field. (Rows, filters and `/meta` for the whole-column case are
 * pinned in read-policy.integration.spec.ts.)
 */

beforeAll(() => setupSpace());
afterAll(teardownSpace);

const HIDE_JSON = { accounts: { projection: { settings: 0 } } } as const;
const HIDE_LEAF = { accounts: { projection: { "settings.apiKey": 0 } } } as const;

describe("a hidden JSON source seals its derived copies", () => {
  it.each([
    ["$sort=-apiKeyCopy&$select=id", "apiKeyCopy"],
    ["$select=apiKeyCopy", "apiKeyCopy"],
    ["$select=apiKeyCopy,count(*):n&$groupBy=apiKeyCopy", "apiKeyCopy"],
    ["themeCopy='dark'", "themeCopy"],
    ["$sort=themeCopy", "themeCopy"],
  ])("?%s answers byte-for-byte like a nonexistent field", async (query, field) => {
    const get = await bootWith(HIDE_JSON);
    const hidden = await get(`/read-accounts/query?${query}`);
    const missing = await get(`/read-accounts/query?${query.replaceAll(field, "nope")}`);
    expect(hidden.status).toBe(400);
    expect(hidden.body).toMatchObject({ message: `Unknown field "${field}"` });
    expect(hidden.text.replaceAll(field, "nope")).toBe(missing.text);
  });

  it("/one/:id carries neither the source nor any derived copy", async () => {
    const get = await bootWith(HIDE_JSON);
    const one = await get("/read-accounts/one/1");
    expect(one.status).toBe(200);
    expect(one.body).toMatchObject({ id: 1, title: "alpha" });
    for (const key of ["settings", "apiKeyCopy", "themeCopy"]) {
      expect(one.body).not.toHaveProperty(key);
    }
  });

  it("aggregates cannot group by or reduce over a sealed derived column", async () => {
    const get = await bootWith(HIDE_JSON);
    const grouped = await get(
      "/read-accounts/query?$select=themeCopy,max(apiKeyCopy):k&$groupBy=themeCopy",
    );
    expect(grouped.status).toBe(400);
    expect(grouped.body).toMatchObject({ message: 'Unknown field "themeCopy"' });
    const reduced = await get(
      "/read-accounts/query?$select=status,max(apiKeyCopy):k&$groupBy=status",
    );
    expect(reduced.status).toBe(400);
    expect(reduced.body).toMatchObject({ message: 'Unknown field "apiKeyCopy"' });

    // Control: with the source visible the same aggregate runs.
    const all = await bootWith({ accounts: undefined });
    const ok = await all(
      "/read-accounts/query?$select=themeCopy,max(apiKeyCopy):k&$groupBy=themeCopy&$sort=themeCopy",
    );
    expect(ok.status).toBe(200);
    expect(ok.body).toEqual([
      { themeCopy: "dark", k: "KEY-CCC" },
      { themeCopy: "light", k: "KEY-BBB" },
    ]);
  });

  it("SQL: a hidden leaf seals every derived copy of the (atomic) JSON column", async () => {
    const get = await bootWith(HIDE_LEAF);
    for (const [query, field] of [
      ["apiKeyCopy~=/^KEY-C/&$select=id", "apiKeyCopy"],
      ["themeCopy='dark'&$select=id", "themeCopy"],
      ["$select=id,themeCopy", "themeCopy"],
    ]) {
      const r = await get(`/read-accounts/query?${query}`);
      expect(r.status, query).toBe(400);
      expect(r.body, query).toMatchObject({ message: `Unknown field "${field}"` });
    }
  });
});
