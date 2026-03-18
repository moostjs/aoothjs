import { describe, expect, it } from "vite-plus/test";

import { mergeScopeFilters } from "./filter";

describe("mergeScopeFilters", () => {
  it("must return undefined for empty array", () => {
    expect(mergeScopeFilters([])).toBeUndefined();
  });

  it("must return undefined when any filter is empty", () => {
    expect(mergeScopeFilters([{ department: "sales" }, {}])).toBeUndefined();
  });

  it("must return single filter as-is", () => {
    expect(mergeScopeFilters([{ department: "sales" }])).toStrictEqual({
      department: "sales",
    });
  });

  it("must optimize same single-key primitive values to $in", () => {
    expect(mergeScopeFilters([{ department: "sales" }, { department: "marketing" }])).toStrictEqual(
      {
        department: { $in: ["sales", "marketing"] },
      },
    );
  });

  it("must optimize numeric values to $in", () => {
    expect(mergeScopeFilters([{ level: 1 }, { level: 2 }, { level: 3 }])).toStrictEqual({
      level: { $in: [1, 2, 3] },
    });
  });

  it("must use $or for different keys", () => {
    expect(mergeScopeFilters([{ department: "sales" }, { region: "west" }])).toStrictEqual({
      $or: [{ department: "sales" }, { region: "west" }],
    });
  });

  it("must use $or for multi-key filters", () => {
    expect(
      mergeScopeFilters([
        { department: "sales", active: true },
        { department: "marketing", active: true },
      ]),
    ).toStrictEqual({
      $or: [
        { department: "sales", active: true },
        { department: "marketing", active: true },
      ],
    });
  });

  it("must use $or when values are objects (operator expressions)", () => {
    expect(mergeScopeFilters([{ age: { $gt: 18 } }, { age: { $lt: 10 } }])).toStrictEqual({
      $or: [{ age: { $gt: 18 } }, { age: { $lt: 10 } }],
    });
  });

  it("must handle null values in $in optimization", () => {
    expect(mergeScopeFilters([{ status: null }, { status: "active" }])).toStrictEqual({
      status: { $in: [null, "active"] },
    });
  });
});
