import { describe, expect, it } from "vite-plus/test";

import { conjoinScopeFilters } from "./filter";
import { intersectControlsPolicy } from "./controls";

describe("conjoinScopeFilters — restrict-only $and combiner", () => {
  it("both unrestricted → undefined", () => {
    expect(conjoinScopeFilters(undefined, undefined)).toBeUndefined();
    expect(conjoinScopeFilters({}, {})).toBeUndefined();
    expect(conjoinScopeFilters(undefined, {})).toBeUndefined();
  });

  it("{} / undefined is the IDENTITY — the side with a filter passes through unchanged", () => {
    // This is the sentinel most likely to be implemented backwards: under the
    // additive `mergeScopeFilters` a `{}` ABSORBS to "unrestricted"; under
    // conjunction it must be the IDENTITY (drop it, keep the other side).
    expect(conjoinScopeFilters({ tenant: "a" }, undefined)).toStrictEqual({ tenant: "a" });
    expect(conjoinScopeFilters({ tenant: "a" }, {})).toStrictEqual({ tenant: "a" });
    expect(conjoinScopeFilters(undefined, { tenant: "a" })).toStrictEqual({ tenant: "a" });
    expect(conjoinScopeFilters({}, { tenant: "a" })).toStrictEqual({ tenant: "a" });
  });

  it("two real filters → $and (both must match), never an object spread", () => {
    expect(conjoinScopeFilters({ tenant: "a" }, { owner: "u" })).toStrictEqual({
      $and: [{ tenant: "a" }, { owner: "u" }],
    });
    // same key, different values → $and keeps BOTH (a spread would drop one and widen)
    expect(conjoinScopeFilters({ tenant: "a" }, { tenant: "b" })).toStrictEqual({
      $and: [{ tenant: "a" }, { tenant: "b" }],
    });
  });
});

describe("intersectControlsPolicy — deny-wins ∩ combiner", () => {
  it("empty ∩ empty → empty (everything allowed)", () => {
    expect(intersectControlsPolicy({}, {})).toStrictEqual({});
  });

  it("deny on EITHER side → deny (deny-wins, opposite of the additive union)", () => {
    expect(intersectControlsPolicy({ $with: false }, {})).toStrictEqual({ $with: false });
    expect(intersectControlsPolicy({}, { $with: false })).toStrictEqual({ $with: false });
    expect(intersectControlsPolicy({ $with: true }, { $with: false })).toStrictEqual({
      $with: false,
    });
  });

  it("allowed on one side → the OTHER side's gate (allow ∧ X = X)", () => {
    // user silent/allow on $with, cred whitelists → result is the whitelist.
    expect(intersectControlsPolicy({}, { $with: ["comments"] })).toStrictEqual({
      $with: ["comments"],
    });
    expect(intersectControlsPolicy({ $with: true }, { $with: ["comments"] })).toStrictEqual({
      $with: ["comments"],
    });
  });

  it("whitelist ∧ whitelist → intersection (only values admitted by BOTH)", () => {
    expect(
      intersectControlsPolicy({ $with: ["comments", "owner"] }, { $with: ["comments", "tags"] }),
    ).toStrictEqual({ $with: ["comments"] });
    // disjoint whitelists → empty whitelist = nothing permitted
    expect(intersectControlsPolicy({ $with: ["a"] }, { $with: ["b"] })).toStrictEqual({
      $with: [],
    });
  });
});
