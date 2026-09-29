import { describe, expect, it } from "vite-plus/test";

import {
  checkFields,
  compileScopeCheck,
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
