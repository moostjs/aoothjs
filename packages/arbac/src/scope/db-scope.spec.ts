import { describe, expect, it } from "vite-plus/test";

import {
  applyScopeFieldFilters,
  conjoinRowPolicies,
  conjoinScopes,
  DB_SCOPE_KEYS,
  effectiveScope,
  intersectEnabled,
  needsInheritedConjunction,
  normalizeScopes,
  ScopeFieldConfigError,
  stableKey,
  unionOutcomes,
} from "./db-scope";
import type { TDbScope, TScopeFieldRules } from "./db-scope";

describe("effectiveScope", () => {
  it("unions every facet once, memoized per scopes array", () => {
    const scopes: TDbScope[] = [
      {
        filter: { tenant: "a" },
        projection: { a: 1 },
        allowedFields: ["a"],
        set: { tenant: "a", x: 1 },
        nestedWrites: ["comments"],
        checkRefs: ["projectId", "ownerId"],
        with: { comments: { filter: { hidden: false } } },
      },
      {
        filter: { tenant: "b" },
        check: { status: "open" },
        projection: { b: 1 },
        allowedFields: ["b"],
        set: { tenant: "b" },
        checkRefs: ["projectId"],
      },
    ];
    const eff = effectiveScope(scopes);
    expect(effectiveScope(scopes)).toBe(eff);
    expect(eff.filter).toStrictEqual({ tenant: { $in: ["a", "b"] } });
    expect(eff.hasExplicitCheck).toBe(true);
    expect(eff.check).toStrictEqual({ $or: [{ tenant: "a" }, { status: "open" }] });
    expect(eff.projection).toStrictEqual({ a: 1, b: 1 });
    expect(eff.allowedFields).toStrictEqual(new Set(["a", "b"]));
    expect(eff.set).toStrictEqual({ tenant: "b", x: 1 });
    expect(eff.nestedWrites).toStrictEqual(new Set(["comments"]));
    expect(eff.checkRefs).toStrictEqual(new Set(["projectId"]));
    expect(eff.withNames).toStrictEqual(new Set(["comments"]));
    expect(eff.withScopes("comments")).toStrictEqual([{ filter: { hidden: false } }]);
    expect(eff.withScopes("comments")).toBe(eff.withScopes("comments"));
    expect(eff.withScopes("other")).toStrictEqual([]);
  });

  it("check defaults to filter and `{}` opts out", () => {
    expect(effectiveScope([{ filter: { t: 1 } }]).check).toStrictEqual({ t: 1 });
    expect(effectiveScope([{ filter: { t: 1 }, check: {} }]).check).toBeUndefined();
  });

  it("is the identity of every union for an empty list", () => {
    const eff = effectiveScope([]);
    expect(eff.filter).toBeUndefined();
    expect(eff.projection).toStrictEqual({});
    expect(eff.controls).toStrictEqual({});
    expect(eff.allowedFields).toBeUndefined();
    expect(eff.set).toBeUndefined();
    expect(eff.checkRefs).toStrictEqual(new Set());
  });

  it("computes facets lazily — a bad controls gate throws only when read", () => {
    const eff = effectiveScope([{ filter: { t: 1 }, controls: { $having: ["x"] } }]);
    expect(eff.filter).toStrictEqual({ t: 1 });
    expect(() => eff.controls).toThrow(/only supports boolean gates/);
  });
});

describe("intersectEnabled", () => {
  it("enforces only what every input enables; `true` enables all", () => {
    expect(intersectEnabled([new Set(["a", "b"]), true, new Set(["b"])])).toStrictEqual(
      new Set(["b"]),
    );
    expect(intersectEnabled([true, true])).toBe(true);
    expect(intersectEnabled([new Set(["a"]), new Set<string>()])).toStrictEqual(new Set());
    expect(intersectEnabled([])).toStrictEqual(new Set());
  });
});

describe("normalizeScopes — the unified empty-scope rule", () => {
  it("denied → undefined", () => {
    expect(normalizeScopes({ allowed: false, scopes: [{}] })).toBeUndefined();
  });

  it("allowed without scopes (scope-agnostic evaluator) → unrestricted [{}]", () => {
    expect(normalizeScopes({ allowed: true })).toStrictEqual([{}]);
  });

  it("allowed with an EMPTY scope list → deny (fail closed)", () => {
    expect(normalizeScopes({ allowed: true, scopes: [] })).toBeUndefined();
  });

  it("drops scope predicates that returned nothing — all dropped → deny", () => {
    expect(normalizeScopes({ allowed: true, scopes: [undefined, { f: 1 }] })).toStrictEqual([
      { f: 1 },
    ]);
    expect(normalizeScopes({ allowed: true, scopes: [undefined, null] })).toBeUndefined();
  });

  it("keeps the input array when nothing is dropped", () => {
    const scopes = [{ f: 1 }];
    expect(normalizeScopes({ allowed: true, scopes })).toBe(scopes);
  });
});

describe("unionOutcomes", () => {
  it("concatenates the allowed outcomes' normalized scopes", () => {
    expect(
      unionOutcomes([
        { allowed: false },
        { allowed: true, scopes: [{ a: 1 }] },
        { allowed: true, scopes: [] },
        { allowed: true },
      ]),
    ).toStrictEqual([{ a: 1 }, {}]);
    expect(unionOutcomes([{ allowed: false }, { allowed: true, scopes: [] }])).toBeUndefined();
  });
});

describe("conjoinRowPolicies", () => {
  it("conjoins filters; no explicit check → none emitted (defaults to the filter)", () => {
    expect(conjoinRowPolicies({ filter: { a: 1 } }, { filter: { b: 1 } })).toStrictEqual({
      filter: { $and: [{ a: 1 }, { b: 1 }] },
    });
  });

  it("conjoins the effective checks (check ?? filter) of both sides", () => {
    expect(conjoinRowPolicies({ filter: { a: 1 } }, { check: { c: 1 } })).toStrictEqual({
      filter: { a: 1 },
      check: { $and: [{ a: 1 }, { c: 1 }] },
    });
  });

  it("emits a `{}` check only when it differs from the filter", () => {
    expect(conjoinRowPolicies({ check: {} }, {})).toStrictEqual({});
    expect(conjoinRowPolicies({ filter: { a: 1 }, check: {} }, {})).toStrictEqual({
      filter: { a: 1 },
      check: {},
    });
    expect(conjoinRowPolicies({ filter: { a: 1 } }, { check: {} })).toStrictEqual({
      filter: { a: 1 },
    });
  });
});

describe("conjoinScopes", () => {
  it("conjoins every facet of the two unions", () => {
    const s = conjoinScopes(
      [
        {
          filter: { t: "a" },
          projection: { a: 1, b: 1 },
          allowedFields: ["a", "b"],
          set: { t: "a" },
        },
      ],
      [{ filter: { o: "u" }, projection: { b: 1 }, allowedFields: ["b"], set: { t: "x", o: "u" } }],
    );
    expect(s).toStrictEqual({
      filter: { $and: [{ t: "a" }, { o: "u" }] },
      projection: { b: 1 },
      allowedFields: ["b"],
      set: { t: "a", o: "u" },
    });
  });

  it("an empty field intersection keeps the first side's projection and matches nothing", () => {
    const s = conjoinScopes<TDbScope>([{ projection: { a: 1 } }], [{ projection: { a: 0 } }]);
    expect(s.projection).toStrictEqual({ a: 1 });
    expect(s.filter).toStrictEqual({ $or: [] });
  });

  it("enforces checkRefs either side enforces (schema-less names)", () => {
    expect(
      conjoinScopes<TDbScope>([{ checkRefs: ["a"] }], [{ checkRefs: ["b"] }]).checkRefs,
    ).toStrictEqual(["a", "b"]);
    expect(conjoinScopes<TDbScope>([{}], [{ checkRefs: true }]).checkRefs).toBe(true);
    expect(conjoinScopes<TDbScope>([{}], [{}]).checkRefs).toBeUndefined();
  });
});

describe("conjoinScopes — one-sided `with` declarations", () => {
  it("marks a relation only one side declares (its inherited grant is still owed)", () => {
    const s = conjoinScopes<TDbScope>([{}], [{ with: { owner: { filter: { t: 1 } } } }]);
    const owner = (s.with as Record<string, TDbScope>).owner;
    expect(owner.filter).toStrictEqual({ t: 1 });
    expect(needsInheritedConjunction(owner)).toBe(true);
  });

  it("does not mark a relation both sides declare", () => {
    const s = conjoinScopes<TDbScope>(
      [{ with: { owner: { filter: { a: 1 } } } }],
      [{ with: { owner: { filter: { b: 1 } } } }],
    );
    expect(needsInheritedConjunction((s.with as Record<string, TDbScope>).owner)).toBe(false);
  });
});

// An app field: `regions` restricts to a region list; absent = unrestricted.
type S = TDbScope & { regions?: string[]; label?: string };
function unionRegions(side: readonly S[]): Set<string> | undefined {
  if (side.some((s) => s.regions === undefined)) return undefined;
  return new Set(side.flatMap((s) => s.regions ?? []));
}

describe("conjoinScopes — custom scope fields", () => {
  const fields: TScopeFieldRules<S> = {
    regions: {
      conjoin(a, b) {
        const ra = unionRegions(a);
        const rb = unionRegions(b);
        if (!ra) return rb && [...rb].toSorted();
        if (!rb) return [...ra].toSorted();
        return [...ra].filter((r) => rb.has(r)).toSorted();
      },
    },
  };

  it("carries the value the registered rule conjoins", () => {
    const out = conjoinScopes<S>(
      [{ regions: ["eu", "us"] }, { regions: ["apac"] }],
      [{ regions: ["eu", "apac", "latam"] }],
      { fields },
    );
    expect(out).toStrictEqual({ regions: ["apac", "eu"] });
  });

  it("one restricted side wins over an unrestricted one; undefined omits the key", () => {
    expect(conjoinScopes<S>([{}], [{ regions: ["eu"] }], { fields }).regions).toStrictEqual(["eu"]);
    const rule = { conjoin: () => undefined };
    expect(
      conjoinScopes<S>([{ regions: ["eu"] }], [{}], { fields: { regions: rule } }),
    ).toStrictEqual({});
  });

  it("the rule runs only when some scope carries the field", () => {
    let calls = 0;
    const counting = { regions: { conjoin: () => (calls++, ["x"]) } };
    expect(conjoinScopes<S>([{ filter: { a: 1 } }], [{}], { fields: counting })).toStrictEqual({
      filter: { a: 1 },
    });
    expect(calls).toBe(0);
    // A key holding `undefined` does not count as present.
    expect(conjoinScopes<S>([{ regions: undefined }], [{}])).toStrictEqual({});
  });

  it("a custom field without a rule throws (fail closed) — on either side", () => {
    for (const [a, b] of [
      [[{ label: "x" }], [{}]],
      [[{}], [{ label: "x" }]],
    ] as Array<[S[], S[]]>) {
      expect(() => conjoinScopes<S>(a, b, { fields })).toThrow(ScopeFieldConfigError);
      expect(() => conjoinScopes<S>(a, b, { fields })).toThrow(
        /Scope field "label" has no conjunction rule/,
      );
    }
    expect(() => conjoinScopes<S>([{ regions: ["eu"] }], [{}])).toThrow(/"regions"/);
  });

  it("applies to `with` sub-scopes too", () => {
    const out = conjoinScopes<S>(
      [{ with: { comments: { regions: ["eu", "us"] } } }],
      [{ with: { comments: { regions: ["us"] } } }],
      { fields },
    );
    expect((out.with as Record<string, S>).comments.regions).toStrictEqual(["us"]);
    expect(() =>
      conjoinScopes<S>([{ with: { comments: { label: "x" } } }], [{}], { fields }),
    ).toThrow(/Scope field "label"/);
  });

  it("built-in keys never need a rule", () => {
    expect(DB_SCOPE_KEYS).toContain("checkRefs");
    const all: TDbScope = {
      filter: { a: 1 },
      check: { a: 1 },
      projection: { a: 1 },
      controls: { $sort: false },
      allowedFields: ["a"],
      set: { a: 1 },
      nestedWrites: ["x"],
      checkRefs: ["a"],
      with: { x: {} },
    };
    expect(Object.keys(all).toSorted()).toStrictEqual([...DB_SCOPE_KEYS].toSorted());
    expect(() => conjoinScopes([all], [all])).not.toThrow();
  });
});

describe("applyScopeFieldFilters", () => {
  type T = TDbScope & { teams?: string[] };
  let calls = 0;
  const rules: TScopeFieldRules<T> = {
    teams: {
      conjoin: () => undefined,
      rowFilter: (value) => (calls++, { team: { $in: value } }),
    },
  };

  it("ANDs the row filter into each scope; the union across scopes stays OR", () => {
    const lead: T = {};
    const triage: T = { teams: ["A"], filter: { tenant: "t" } };
    const out = applyScopeFieldFilters([lead, triage], rules);
    expect(out[0]).toBe(lead);
    expect(out[1]).toStrictEqual({
      teams: ["A"],
      filter: { $and: [{ tenant: "t" }, { team: { $in: ["A"] } }] },
    });
    expect(triage).toStrictEqual({ teams: ["A"], filter: { tenant: "t" } }); // never mutated
    // lead is unrestricted → the union is unrestricted.
    expect(effectiveScope(out).filter).toBeUndefined();
    expect(effectiveScope(applyScopeFieldFilters([triage], rules)).filter).toStrictEqual(
      out[1].filter,
    );
  });

  it("leaves an explicit check as written; an absent check follows the folded filter", () => {
    const [explicit, implicit] = applyScopeFieldFilters<T>(
      [{ teams: ["A"], check: { status: "open" } }, { teams: ["B"] }],
      rules,
    );
    expect(explicit.check).toStrictEqual({ status: "open" });
    expect(explicit.filter).toStrictEqual({ team: { $in: ["A"] } });
    expect(effectiveScope([implicit]).check).toStrictEqual({ team: { $in: ["B"] } });
  });

  it("folds `with` sub-scopes; memoizes per scope object; no-op without row rules", () => {
    const scope: T = { with: { owner: { teams: ["A"] } as T } };
    calls = 0;
    const [a] = applyScopeFieldFilters([scope], rules);
    const [b] = applyScopeFieldFilters([scope], rules);
    expect(a).toBe(b);
    expect(calls).toBe(1);
    expect((a.with as Record<string, T>).owner.filter).toStrictEqual({ team: { $in: ["A"] } });
    const list: T[] = [{ teams: ["A"] }];
    expect(applyScopeFieldFilters<T>(list, { teams: { conjoin: () => undefined } })).toBe(list);
    expect(applyScopeFieldFilters(list, undefined)).toBe(list);
    // undefined / {} from rowFilter = no row restriction.
    const none: TScopeFieldRules<T> = {
      teams: { conjoin: () => undefined, rowFilter: () => ({}) },
    };
    expect(applyScopeFieldFilters(list, none)).toBe(list);
  });

  it("is idempotent and reports unregistered custom keys once per scope object", () => {
    const [folded] = applyScopeFieldFilters<T>([{ teams: ["A"] }], rules);
    expect(applyScopeFieldFilters([folded], rules)[0]).toBe(folded);
    const unknown: string[] = [];
    const scope = { teams: ["A"], region: "eu", filter: { a: 1 } } as T;
    const onUnknownField = (f: string) => unknown.push(f);
    applyScopeFieldFilters([scope, { with: { x: { label: "y" } } } as T], rules, {
      onUnknownField,
    });
    applyScopeFieldFilters([scope], rules, { onUnknownField });
    expect(unknown).toEqual(["region", "label"]);
  });
});

describe("stableKey", () => {
  it("serializes bigints", () => {
    expect(stableKey({ id: 10n })).toBe('{"id":"10n"}');
  });
});
