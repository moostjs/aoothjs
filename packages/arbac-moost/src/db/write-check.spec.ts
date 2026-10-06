import { describe, expect, it } from "vite-plus/test";

import {
  checkFields,
  compileScopeCheck,
  insertRowsVerdict,
  patchPostImage,
  UnsupportedCheckError,
} from "./write-check";

describe("compileScopeCheck", () => {
  const row = { tenant: "a", n: 5, s: null, nested: { k: "v" }, at: new Date(1000) };

  it.each<[Record<string, unknown>, boolean]>([
    [{ tenant: "a" }, true],
    [{ tenant: "b" }, false],
    [{ tenant: { $ne: "b" } }, true],
    [{ tenant: { $in: ["x", "a"] } }, true],
    [{ tenant: { $nin: ["a"] } }, false],
    [{ n: { $gt: 4, $lte: 5 } }, true],
    [{ n: { $lt: 5 } }, false],
    [{ s: null }, true],
    [{ missing: null }, true],
    [{ s: { $exists: true } }, false],
    [{ tenant: { $exists: true } }, true],
    [{ "nested.k": "v" }, true],
    [{ at: { $gte: new Date(1000) } }, true],
    [{ $or: [{ tenant: "b" }, { n: 5 }] }, true],
    [{ $and: [{ tenant: "a" }, { n: 4 }] }, false],
    [{ $not: { tenant: "a" } }, false],
    [{}, true],
  ])("%j → %s", (filter, expected) => {
    expect(compileScopeCheck(filter)(row)).toBe(expected);
  });

  it("an unsupported operator throws (callers fail closed)", () => {
    expect(() => compileScopeCheck({ title: { $regex: "^x" } })).toThrow(UnsupportedCheckError);
  });

  it("a relational predicate throws — it needs the related rows", () => {
    for (const check of [
      { ticket: { $some: { status: "open" } } },
      { $or: [{ tenant: "a" }, { ticket: { $none: {} } }] },
    ]) {
      expect(() => compileScopeCheck(check)).toThrow(UnsupportedCheckError);
      expect(() => checkFields(check)).toThrow(UnsupportedCheckError);
    }
  });
});

describe("checkFields / patchPostImage", () => {
  it("collects every referenced path", () => {
    expect([...checkFields({ $or: [{ a: 1 }, { "b.c": { $in: [1] } }] })]).toEqual(["a", "b.c"]);
  });

  it("untouched fields keep the pre-image; plain SETs apply", () => {
    const fields = new Set(["tenant", "status"]);
    expect(
      patchPostImage({ tenant: "a", status: "open", x: 1 }, { status: "done", y: 2 }, fields),
    ).toMatchObject({ tenant: "a", status: "done" });
  });

  it("operators, nested objects and ancestor / descendant keys are undecidable", () => {
    const fields = new Set(["n", "profile.tenant"]);
    const cur = { n: 1, profile: { tenant: "a" } };
    expect(patchPostImage(cur, { n: { $inc: 1 } }, fields)).toBeUndefined();
    expect(patchPostImage(cur, { profile: { tenant: "b" } }, fields)).toBeUndefined();
    expect(patchPostImage(cur, { "profile.tenant.x": 1 }, fields)).toBeUndefined();
    expect(patchPostImage(cur, { tags: [1] }, fields)).toMatchObject({ n: 1 });
  });
});

describe("insertRowsVerdict", () => {
  const rows = [
    { tenant: "a", n: 1 },
    { tenant: "a", n: 2 },
  ];

  it("true when every row passes", () => {
    expect(insertRowsVerdict(rows, { tenant: "a" })).toBe(true);
    expect(insertRowsVerdict([], { tenant: "a" })).toBe(true);
  });

  it("false when a decidable row fails the check — even beside an undecidable one", () => {
    expect(insertRowsVerdict([...rows, { tenant: "b", n: 3 }], { tenant: "a" })).toBe(false);
    expect(insertRowsVerdict([{ n: 1 }, { tenant: "b", n: 2 }], { tenant: "a" })).toBe(false);
  });

  it("undefined when a row omits a field the check reads (a database default)", () => {
    expect(insertRowsVerdict([{ n: 1 }], { tenant: "a" })).toBeUndefined();
    expect(insertRowsVerdict([...rows, { n: 3 }], { tenant: "a" })).toBeUndefined();
  });

  it("undefined for a check the evaluator does not model ($regex, relational)", () => {
    expect(insertRowsVerdict(rows, { tenant: { $regex: "^a" } })).toBeUndefined();
    expect(insertRowsVerdict(rows, { ticket: { $some: { n: 1 } } })).toBeUndefined();
  });

  it("reads dotted paths and treats null as a present value", () => {
    expect(insertRowsVerdict([{ nested: { k: "v" } }], { "nested.k": "v" })).toBe(true);
    expect(insertRowsVerdict([{ s: null }], { s: null })).toBe(true);
  });
});
