import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

import { bootWith, setupSpace, teardownSpace } from "./reads-harness";

/**
 * Aggregates, calendar buckets, `$having` and `$count` under a row + column
 * scope — the shapes hidden-columns.integration.spec.ts does not already pin
 * (plain `$groupBy` / `sum` / `max` over a hidden column live there).
 */

beforeAll(() => setupSpace());
afterAll(teardownSpace);

const SCOPE = {
  accounts: { filter: { owner: "u1" }, projection: { salary: 0, hiredAt: 0, secretNote: 0 } },
} as const;

describe("aggregates under { owner: u1 } with salary / hiredAt / secretNote hidden", () => {
  it.each([
    ["$select=status,count(secretNote):c&$groupBy=status", "secretNote"],
    ["$select=bucket(hiredAt,month):m,count(*):n&$groupBy=m", "hiredAt"],
    ["$select=status,count(*):n&$groupBy=status&$having=salary>1", "salary"],
    ["$select=status,count(*):n&$groupBy=status&salary>500", "salary"],
    ["$select=status,count(*):n&$groupBy=status&$sort=salary", "salary"],
    ["$count=true&salary>500", "salary"],
  ])("?%s → 400 Unknown field", async (query, field) => {
    const get = await bootWith(SCOPE);
    const r = await get(`/read-accounts/query?${query}`);
    expect(r.status).toBe(400);
    expect(r.text).toContain(`Unknown field \\"${field}\\"`);
  });

  it("count(*), $count and $having count only in-scope rows", async () => {
    const get = await bootWith(SCOPE);
    const grouped = await get("/read-accounts/query?$select=status,count(*):n&$groupBy=status");
    const count = await get("/read-accounts/query?$count=true");
    const having = await get(
      "/read-accounts/query?$select=status,count(*):n&$groupBy=status&$having=n>1",
    );
    expect(grouped.body).toEqual([{ status: "open", n: 2 }]);
    expect(count.body).toBe(2);
    expect(having.body).toEqual([{ status: "open", n: 2 }]);
  });
});
