import { describe, expect, it } from "vite-plus/test";

import { applyAllowedFieldsAndSet, type ArbacDbScope } from "./as-arbac-db-controller";

describe("applyAllowedFieldsAndSet", () => {
  it("returns the data untouched when no scopes are provided", () => {
    const data = { a: 1, b: 2 };
    expect(applyAllowedFieldsAndSet(data, [])).toEqual({ a: 1, b: 2 });
  });

  it("does not strip fields when no scope declares allowedFields", () => {
    const data = { a: 1, b: 2, c: 3 };
    const scopes: ArbacDbScope[] = [{ filter: { tenantId: "t1" } }];
    expect(applyAllowedFieldsAndSet(data, scopes)).toEqual({ a: 1, b: 2, c: 3 });
  });

  it("keeps only union of allowedFields across scopes when at least one declares them", () => {
    const data = { a: 1, b: 2, c: 3, d: 4 };
    const scopes: ArbacDbScope[] = [{ allowedFields: ["a", "b"] }, { allowedFields: ["c"] }];
    expect(applyAllowedFieldsAndSet(data, scopes)).toEqual({ a: 1, b: 2, c: 3 });
  });

  it("applies scope.set on top of allowed fields (last writer wins)", () => {
    const data = { a: 1, b: 2 };
    const scopes: ArbacDbScope[] = [
      { allowedFields: ["a", "b"], set: { creator: "u1" } },
      { set: { creator: "u2" } },
    ];
    expect(applyAllowedFieldsAndSet(data, scopes)).toEqual({ a: 1, b: 2, creator: "u2" });
  });

  it("set overrides input fields even when allowedFields is absent", () => {
    const data = { tenantId: "wrong", title: "x" };
    const scopes: ArbacDbScope[] = [{ set: { tenantId: "t1" } }];
    expect(applyAllowedFieldsAndSet(data, scopes)).toEqual({ tenantId: "t1", title: "x" });
  });

  it("recurses into arrays (insertMany payload shape)", () => {
    const data = [
      { a: 1, b: 2, secret: "x" },
      { a: 3, b: 4, secret: "y" },
    ];
    const scopes: ArbacDbScope[] = [{ allowedFields: ["a", "b"], set: { tenantId: "t1" } }];
    expect(applyAllowedFieldsAndSet(data, scopes)).toEqual([
      { a: 1, b: 2, tenantId: "t1" },
      { a: 3, b: 4, tenantId: "t1" },
    ]);
  });
});
