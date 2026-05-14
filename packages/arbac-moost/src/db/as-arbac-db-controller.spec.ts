import { unionControlsPolicy } from "@aoothjs/arbac";
import { HttpError } from "@moostjs/event-http";
import { describe, expect, it } from "vite-plus/test";

import {
  applyAllowedFieldsAndSet,
  type ArbacDbScope,
  enforceControlsPolicy,
  extractUsedControlValues,
} from "./as-arbac-db-controller";

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

describe("extractUsedControlValues", () => {
  it("$with: extracts names from parsed entries (objects with .name)", () => {
    const value = [
      { name: "comments", filter: {}, controls: {} },
      { name: "owner", filter: {}, controls: {} },
    ];
    expect(extractUsedControlValues("$with", value)).toEqual(["comments", "owner"]);
  });

  it("$with: tolerates bare string entries (defensive)", () => {
    expect(extractUsedControlValues("$with", ["comments", "owner"])).toEqual([
      "comments",
      "owner",
    ]);
  });

  it("$with: skips entries with no .name", () => {
    expect(extractUsedControlValues("$with", [{ filter: {} }, { name: "ok" }])).toEqual([
      "ok",
    ]);
  });

  it("$groupBy: returns the array as-is (filtered to strings)", () => {
    expect(extractUsedControlValues("$groupBy", ["status", "owner"])).toEqual([
      "status",
      "owner",
    ]);
  });

  it("returns [] for unknown / undefined / null values", () => {
    expect(extractUsedControlValues("$with", undefined)).toEqual([]);
    expect(extractUsedControlValues("$with", null)).toEqual([]);
    expect(extractUsedControlValues("$having", { count: { $gt: 1 } })).toEqual([]);
  });
});

describe("enforceControlsPolicy", () => {
  it("no policy → no-op", () => {
    expect(() => enforceControlsPolicy({}, { $with: [{ name: "x" }] })).not.toThrow();
  });

  it("denies entire control when gate is false", () => {
    expect(() =>
      enforceControlsPolicy({ $with: false }, { $with: [{ name: "comments" }] }),
    ).toThrow(HttpError);
    try {
      enforceControlsPolicy({ $with: false }, { $with: [{ name: "comments" }] });
    } catch (e) {
      expect(e).toBeInstanceOf(HttpError);
      expect((e as HttpError).body.statusCode).toBe(403);
      expect((e as HttpError).body.message).toMatch(/\$with.*not allowed/);
    }
  });

  it("allows when control is absent from request even if gated false", () => {
    expect(() => enforceControlsPolicy({ $with: false }, {})).not.toThrow();
  });

  it("treats empty-array control value as not used", () => {
    expect(() => enforceControlsPolicy({ $with: false }, { $with: [] })).not.toThrow();
  });

  it("whitelist: passes when all used values are listed", () => {
    expect(() =>
      enforceControlsPolicy(
        { $with: ["comments", "owner"] },
        { $with: [{ name: "comments" }, { name: "owner" }] },
      ),
    ).not.toThrow();
  });

  it("whitelist: rejects when a used value is not listed", () => {
    expect(() =>
      enforceControlsPolicy(
        { $with: ["comments"] },
        { $with: [{ name: "comments" }, { name: "tasks" }] },
      ),
    ).toThrow(/\$with=tasks.*not allowed/);
  });

  it("$groupBy whitelist: passes / rejects on column names", () => {
    expect(() =>
      enforceControlsPolicy({ $groupBy: ["status"] }, { $groupBy: ["status"] }),
    ).not.toThrow();
    expect(() =>
      enforceControlsPolicy({ $groupBy: ["status"] }, { $groupBy: ["owner"] }),
    ).toThrow(/\$groupBy=owner/);
  });

  it("integrates with unionControlsPolicy: silence + deny → allow (no throw)", () => {
    const scopes: ArbacDbScope[] = [{ controls: {} }, { controls: { $with: false } }];
    expect(() =>
      enforceControlsPolicy(unionControlsPolicy(scopes), {
        $with: [{ name: "comments" }],
      }),
    ).not.toThrow();
  });

  it("integrates with unionControlsPolicy: deny + deny → throws", () => {
    const scopes: ArbacDbScope[] = [
      { controls: { $with: false } },
      { controls: { $with: false } },
    ];
    expect(() =>
      enforceControlsPolicy(unionControlsPolicy(scopes), {
        $with: [{ name: "comments" }],
      }),
    ).toThrow(HttpError);
  });

  it("integrates with unionControlsPolicy: whitelist union allows union of values", () => {
    const scopes: ArbacDbScope[] = [
      { controls: { $with: ["comments"] } },
      { controls: { $with: ["owner"] } },
    ];
    const policy = unionControlsPolicy(scopes);
    expect(() =>
      enforceControlsPolicy(policy, {
        $with: [{ name: "comments" }, { name: "owner" }],
      }),
    ).not.toThrow();
    expect(() =>
      enforceControlsPolicy(policy, { $with: [{ name: "tasks" }] }),
    ).toThrow(/tasks/);
  });
});
