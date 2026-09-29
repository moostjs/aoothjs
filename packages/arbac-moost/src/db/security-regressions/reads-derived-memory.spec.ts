import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

import { bootWith, setupSpace, teardownSpace } from "./reads-harness";

/**
 * Derived columns follow their source on a document-style adapter
 * (`@atscript/db-memory`), where `@db.json` sub-paths stay addressable: hiding
 * the whole column seals every derived copy; hiding one leaf seals only the
 * copy of that leaf. (The leaf case's rows + `/meta` are pinned in
 * read-policy-memory.integration.spec.ts.)
 */

beforeAll(() => setupSpace("memory"));
afterAll(teardownSpace);

describe("memory adapter: derived columns follow their source", () => {
  it("{ settings: 0 } seals the column and every derived copy of it", async () => {
    const get = await bootWith({ accounts: { projection: { settings: 0 } } });
    const rows = await get("/read-accounts/query");
    const one = await get("/read-accounts/one/1");
    expect(rows.status).toBe(200);
    expect(rows.body).toHaveLength(3);
    for (const row of [...rows.body, one.body]) {
      for (const key of ["settings", "apiKeyCopy", "themeCopy"]) {
        expect(row).not.toHaveProperty(key);
      }
    }
    for (const [query, field] of [
      ["apiKeyCopy='KEY-BBB'&$select=id", "apiKeyCopy"],
      ["themeCopy='dark'&$select=id", "themeCopy"],
      ["$sort=apiKeyCopy&$select=id", "apiKeyCopy"],
    ]) {
      const r = await get(`/read-accounts/query?${query}`);
      expect(r.status, query).toBe(400);
      expect(r.body, query).toMatchObject({ message: `Unknown field "${field}"` });
    }
  });

  it("a hidden leaf seals only the derived copy of that leaf", async () => {
    const get = await bootWith({ accounts: { projection: { "settings.apiKey": 0 } } });
    const filtered = await get("/read-accounts/query?themeCopy='dark'&$select=id,themeCopy");
    expect(filtered.body).toEqual([
      { id: 1, themeCopy: "dark" },
      { id: 3, themeCopy: "dark" },
    ]);
    const grouped = await get(
      "/read-accounts/query?$select=themeCopy,count(*):n&$groupBy=themeCopy&$sort=themeCopy",
    );
    expect(grouped.body).toEqual([
      { themeCopy: "dark", n: 2 },
      { themeCopy: "light", n: 1 },
    ]);
    const reduced = await get(
      "/read-accounts/query?$select=themeCopy,max(apiKeyCopy):k&$groupBy=themeCopy",
    );
    expect(reduced.status).toBe(400);
    expect(reduced.body).toMatchObject({ message: 'Unknown field "apiKeyCopy"' });
  });
});
