// Shared harness for the round-12 regressions (atscript-db 0.1.148): the
// relations-harness space over the r12 fixtures (items, dictionaries, unique
// codes), reseeded per test, with a SELECT counter on the driver.
import { vi } from "vite-plus/test";

import { R12Code, R12Dict, R12Item } from "./fixtures/round12-fixtures.as";
import { all, createSpace } from "./relations-harness";

export interface R12Space {
  seed: () => Promise<void>;
  /** SELECT statements run through the driver since `resetQueries()`. */
  queries: () => number;
  resetQueries: () => void;
  /** Raw rows of a table, bypassing every controller. */
  rows: (type: unknown) => Promise<Array<Record<string, any>>>;
  close: () => void;
}

const ITEMS = [
  { id: 1, owner: "u1", status: "open", rank: 1, createdAt: 10, ownerId: 1, color: "red" },
  { id: 2, owner: "u1", status: "open", rank: 5, createdAt: 20, ownerId: 1, color: "blue" },
  { id: 3, owner: "u2", status: "done", rank: 9, createdAt: 30, ownerId: 2, color: "red" },
];

export async function createR12Space(): Promise<R12Space> {
  const h = await createSpace([R12Dict, R12Item, R12Code]);
  const { driver } = h;
  let selects = 0;
  const count = (sql: string) => {
    if (/^\s*select/i.test(sql)) selects++;
  };
  const rows = driver.all.bind(driver);
  const row = driver.get.bind(driver);
  vi.spyOn(driver, "all").mockImplementation((sql: string, params?: unknown[]) => {
    count(sql);
    return rows(sql, params);
  });
  vi.spyOn(driver, "get").mockImplementation((sql: string, params?: unknown[]) => {
    count(sql);
    return row(sql, params);
  });
  return {
    async seed() {
      for (const t of [R12Item, R12Code, R12Dict]) {
        driver.exec(`DELETE FROM "${(h.table(t) as { tableName: string }).tableName}"`);
      }
      await h.table(R12Dict).insertMany([
        { id: 1, code: "A", label: "Alpha", secretCode: "x", region: "eu" },
        { id: 2, code: "B", label: "Beta", secretCode: "y", region: "us" },
      ]);
      await h.table(R12Item).insertMany(structuredClone(ITEMS));
      await h.table(R12Code).insertMany([
        { id: 1, code: "T-NEW", tenant: "a", title: "ticket a" },
        { id: 2, code: "T-OTHER", tenant: "b", title: "ticket b" },
      ]);
    },
    queries: () => selects,
    resetQueries: () => {
      selects = 0;
    },
    rows: (t) => all(h, t),
    close() {
      vi.restoreAllMocks();
      h.close();
    },
  };
}
