import { Get, HttpError, type MoostHttp } from "@moostjs/event-http";
import { clearGlobalWooks, Controller, Resolve } from "moost";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import { bootArbacHttp } from "../__testing__/arbac-http";
import { FakeUserProvider } from "../__testing__/user-provider";
import { ArbacAction, ArbacResource, MoostArbac } from "../index";
import type { ArbacDbScope } from "./as-arbac-db-controller";
import { fieldChildrenOf } from "./field-children";
import { arbacRowFilter, resolveRequestScopes } from "./request-scopes";
import { applyArbacProjection, applyArbacRelationScopes } from "./shared-read-helpers";

/**
 * Captures the result of `arbacRowFilter(filter)` for the current event
 * context. Defaults to `undefined` (no user filter) so the response is purely
 * the scope-merge outcome — the value under test for most of this file; pass a
 * filter to exercise the merge against a user-supplied one.
 */
const ProbeTransform = (filter?: Record<string, unknown>) =>
  Resolve(async () => {
    // The entry point resolves the event's scopes once (deny → 403); the
    // row filter then reads them synchronously.
    await resolveRequestScopes();
    return { result: arbacRowFilter(filter) };
  });

// Controller is declared at module scope, not inside async test functions —
// class declarations inside async `it()` bodies can lose method-level decorator
// metadata when pre-cached by Mate's read cache (same constraint documented on
// the module-scope controllers in arbac.composables.spec.ts).
// Pin resource/action so the test's role rules align with the values
// `useArbac()` will auto-resolve at handler time. Without this the resolver
// falls back to the class/method names, which is brittle and hides intent.
@Controller("probe")
@ArbacResource("thing")
class ProbeController {
  @Get("a")
  @ArbacAction("read")
  handler(@ProbeTransform() out?: { result: Record<string, unknown> }) {
    return { out };
  }

  // Same-key probe: the scope constrains `tenantId` too — see the test at the
  // bottom of the file.
  @Get("b")
  @ArbacAction("read")
  sameKey(@ProbeTransform({ tenantId: "b" }) out?: { result: Record<string, unknown> }) {
    return { out };
  }
}

function buildAndInit(
  arbac: MoostArbac<Record<string, never>, ArbacDbScope>,
  roles: string[],
): Promise<MoostHttp> {
  return bootArbacHttp({
    arbac,
    user: new FakeUserProvider("u1", roles),
    controllers: [ProbeController],
  });
}

async function readMergedFilter(
  http: MoostHttp,
  path = "/probe/a",
): Promise<Record<string, unknown>> {
  const res = await http.request(path);
  expect(res?.status).toBe(200);
  const body = (await res!.json()) as { out: { result: Record<string, unknown> } };
  return body.out.result;
}

describe("applyArbacRelationScopes", () => {
  // WHY: without a table (legacy callers) an undeclared relation is not
  // recognised as one — no projection/filter injection. With the readable,
  // it follows the inherit-target policy (see relation-policy.spec.ts).
  it("no scope declares `with`, no table → user controls pass through unchanged", () => {
    const controls = { $with: [{ name: "comments", controls: { $select: ["body"] } }] };
    const scopes: ArbacDbScope[] = [{ filter: { tenantId: "t1" } }];
    const before = JSON.parse(JSON.stringify(controls));
    applyArbacRelationScopes(controls, scopes);
    expect(controls).toEqual(before);
  });

  // WHY: the load-bearing feature — parent scope masks fields on joined rows
  // even though the user asked for the full relation row.
  it("scope.with.X.projection → injects $select onto entry.controls", () => {
    const controls: Record<string, unknown> = { $with: [{ name: "comments" }] };
    const scopes: ArbacDbScope[] = [
      { with: { comments: { projection: { body: 1, authorUsername: 1 } } } },
    ];
    applyArbacRelationScopes(controls, scopes);
    const entry = (controls.$with as Array<{ controls?: { $select?: unknown } }>)[0];
    expect(entry.controls?.$select).toEqual({ body: 1, authorUsername: 1 });
  });

  // WHY: moost-db (0.1.147) gates and overlays only the CLIENT's `$with`
  // predicate maps, recorded before `validateControls`; it answers 500 when
  // one is missing from the live tree. The scope must WRAP the client's
  // filter object (never copy it) so its predicates stay findable, while the
  // server-added predicate passes ungated.
  it("keeps the client's entry.filter object inside the $and (identity)", () => {
    const client = { team: { $some: { name: "x" } } };
    const controls: Record<string, unknown> = { $with: [{ name: "ticket", filter: client }] };
    const scopes: ArbacDbScope[] = [
      { with: { ticket: { filter: { owner: { $some: { active: true } } } } } },
    ];
    applyArbacRelationScopes(controls, scopes);
    const entry = (controls.$with as Array<{ filter: { $and: Array<typeof client> } }>)[0];
    expect(entry.filter.$and[1]).toBe(client);
  });

  // WHY: confirms the relation filter goes through the same `conjoinScopeFilters`
  // combiner as the parent filter, so a user-supplied filter is intersected with
  // the scope's rather than spread over it (which could replace a same-key
  // constraint and widen access).
  it("scope.with.X.filter → merged into entry.filter via $and", () => {
    const controls: Record<string, unknown> = {
      $with: [{ name: "comments", filter: { $or: [{ flagged: true }] } }],
    };
    const scopes: ArbacDbScope[] = [{ with: { comments: { filter: { tenantId: "t1" } } } }];
    applyArbacRelationScopes(controls, scopes);
    const entry = (controls.$with as Array<{ filter?: unknown }>)[0];
    expect(entry.filter).toEqual({
      $and: [{ tenantId: "t1" }, { $or: [{ flagged: true }] }],
    });
  });

  // WHY: nested $with gating recurses — a parent scope can forbid drilling
  // further from a relation even though the relation itself is allowed.
  it("scope.with.X.controls.$with:false + user nested $with → 403", () => {
    const controls: Record<string, unknown> = {
      $with: [
        {
          name: "comments",
          controls: { $with: [{ name: "task" }] },
        },
      ],
    };
    const scopes: ArbacDbScope[] = [{ with: { comments: { controls: { $with: false } } } }];
    expect(() => applyArbacRelationScopes(controls, scopes)).toThrow(HttpError);
  });

  // WHY: multi-role union semantics must compose at every depth — additive,
  // identical to the top-level scope rules; here both roles exclude a different
  // field, so universe wins (each role grants what the other denies).
  it("two scopes union exclude-mode projections → universe (no $select set)", () => {
    const controls: Record<string, unknown> = { $with: [{ name: "comments" }] };
    const scopes: ArbacDbScope[] = [
      { with: { comments: { projection: { tenantId: 0 } } } },
      { with: { comments: { projection: { internalNotes: 0 } } } },
    ];
    applyArbacRelationScopes(controls, scopes);
    const entry = (controls.$with as Array<{ controls?: { $select?: unknown } }>)[0];
    // unionProjections of {tenantId:0} ∪ {internalNotes:0} = {} (universe);
    // applyArbacProjection therefore leaves $select untouched.
    expect(entry.controls?.$select).toBeUndefined();
  });

  // WHY: silence on `with.<name>` means "I don't care", not "I forbid"; one
  // role declaring a restriction must apply, the silent role doesn't dilute it.
  it("one declaring scope + one silent → declaring scope's restriction applies", () => {
    const controls: Record<string, unknown> = { $with: [{ name: "comments" }] };
    const scopes: ArbacDbScope[] = [
      { with: { comments: { projection: { body: 1 } } } },
      { filter: { tenantId: "t1" } }, // silent on `with`
    ];
    applyArbacRelationScopes(controls, scopes);
    const entry = (controls.$with as Array<{ controls?: { $select?: unknown } }>)[0];
    expect(entry.controls?.$select).toEqual({ body: 1 });
  });

  // WHY: arbitrary depth must work without API change — recursion is the
  // design's payoff. Without recursion, the inner $with's $select would not
  // be restricted at all.
  it("nested with.X.with.Y → recurses, restricts the inner $select", () => {
    const controls: Record<string, unknown> = {
      $with: [
        {
          name: "comments",
          controls: { $with: [{ name: "task" }] },
        },
      ],
    };
    const scopes: ArbacDbScope[] = [
      {
        with: {
          comments: { with: { task: { projection: { title: 1 } } } },
        },
      },
    ];
    applyArbacRelationScopes(controls, scopes);
    const outer = (controls.$with as Array<{ controls: { $with: unknown } }>)[0];
    const inner = (outer.controls.$with as Array<{ controls?: { $select?: unknown } }>)[0];
    expect(inner.controls?.$select).toEqual({ title: 1 });
  });

  // WHY: ARBAC enforces "no broader than scope" but must NOT widen what the
  // user asked for — the result is the intersection, not the scope projection.
  it("user $select is intersected with scope projection, not overwritten", () => {
    const controls: Record<string, unknown> = {
      $with: [{ name: "comments", controls: { $select: ["body"] } }],
    };
    const scopes: ArbacDbScope[] = [
      { with: { comments: { projection: { body: 1, authorUsername: 1 } } } },
    ];
    applyArbacRelationScopes(controls, scopes);
    const entry = (controls.$with as Array<{ controls?: { $select?: unknown } }>)[0];
    expect(entry.controls?.$select).toEqual({ body: 1 });
  });

  // WHY: round-2 audit (finding C) — `applyArbacRelationScopes` recurses without
  // a depth cap, so the bound has to come from somewhere else. It comes from
  // the relation policy: recursion only continues into a relation that is
  // RESOLVED (declared `with.<name>`, or the caller's grant on the related
  // table resolved in `prepareRequest`). A nested relation neither declared
  // nor resolved is hidden → the walk stops there (moost-db then answers the
  // 400 `Unknown relation` through `hasField`) — adversarial user depth alone
  // CANNOT force unbounded recursion or reach a joined table unrestricted.
  it("deeply-nested user $with stops at the first unresolved relation", () => {
    // Build user $with nested 50 levels deep — `comments` → `comments` → ...
    let entry: Record<string, unknown> = { name: "comments" };
    for (let i = 0; i < 49; i++) {
      entry = { name: "comments", controls: { $with: [entry] } };
    }
    const controls: Record<string, unknown> = { $with: [entry] };
    // Scope declares `with.comments` ONE level deep.
    const scopes: ArbacDbScope[] = [{ with: { comments: { projection: { body: 1 } } } }];

    applyArbacRelationScopes(controls, scopes);

    // Depth 1 (outer): scope hits, $select injected.
    const lvl1 = (
      controls.$with as Array<{ controls?: { $select?: unknown; $with?: unknown[] } }>
    )[0];
    expect(lvl1.controls?.$select).toEqual({ body: 1 });
    // Depth 2: unresolved → not walked (left for moost-db's `Unknown relation`).
    const lvl2 = lvl1.controls!.$with![0] as { controls?: { $select?: unknown } };
    expect(lvl2.controls?.$select).toBeUndefined();
  });

  // WHY: guards against accidental injection when expansion isn't requested —
  // controls without $with must be a clean no-op.
  it("no $with in user controls → no-op", () => {
    const controls: Record<string, unknown> = { $select: { id: 1 } };
    const scopes: ArbacDbScope[] = [{ with: { comments: { projection: { body: 1 } } } }];
    const before = JSON.parse(JSON.stringify(controls));
    applyArbacRelationScopes(controls, scopes);
    expect(controls).toEqual(before);
  });
});

/**
 * WHY this block exists:
 *
 * `arbacRowFilter` does `scopes.map(s => s.filter ?? {})` (request-scopes.ts),
 * coercing a missing `filter` to `{}`. Both shapes
 * mean "this scope adds no filter constraint", but `mergeScopeFilters` has a
 * specific contract for `{}` (treats it as universe → returns `undefined`
 * meaning unrestricted access). A future refactor of `mergeScopeFilters` that
 * changes how `{}` is treated would silently widen — or narrow — every
 * cross-role union built on this path. These tests pin the current behaviour
 * so such a refactor breaks a test instead of silently changing tenant
 * visibility.
 *
 * We bootstrap a real Moost app rather than mock `useArbac` because the
 * composable's evaluation pipeline (controller context, DI of `MoostArbac` +
 * `ArbacUserProvider`, then `arbac.evaluate`) is what actually produces the
 * `scopes` array `arbacRowFilter` consumes. Mocking it would test a
 * fiction; this is one rung above unit and one rung below e2e, matching the
 * style already established in `arbac.composables.spec.ts`.
 */
describe("arbacRowFilter — empty vs undefined filter coercion", () => {
  beforeEach(() => {
    clearGlobalWooks();
  });

  // WHY: pins the `s.filter ?? {}` coercion — a single role whose
  // rule has no `scope()` (engine pushes `{}` into scopes) must produce the
  // same merged filter as a single role whose `scope()` returns `{ filter: {} }`.
  // Both are "this role grants unrestricted access"; if they ever diverge, the
  // `?? {}` coercion has been broken or `mergeScopeFilters`'s handling of `{}`
  // has shifted.
  it("single scope with undefined filter ≡ single scope with {} filter (both → allow-all, returns {})", async () => {
    // Variant A: rule with no scope() — engine pushes `{} as TScope` into
    // scopes (arbac-core/src/arbac.ts:147), so s.filter is undefined and the
    // `?? {}` coercion kicks in.
    const arbacA = new MoostArbac<Record<string, never>, ArbacDbScope>();
    arbacA.registerRole({
      id: "r",
      rules: [{ resource: "thing", action: "read" }],
    });
    const httpA = await buildAndInit(arbacA, ["r"]);
    const resA = await readMergedFilter(httpA);

    // Variant B: rule with scope() returning `{ filter: {} }` explicitly —
    // the same shape, but `s.filter` is the explicit `{}`, bypassing `?? {}`.
    const arbacB = new MoostArbac<Record<string, never>, ArbacDbScope>();
    arbacB.registerRole({
      id: "r",
      rules: [
        {
          resource: "thing",
          action: "read",
          scope: () => ({ filter: {} }),
        },
      ],
    });
    const httpB = await buildAndInit(arbacB, ["r"]);
    const resB = await readMergedFilter(httpB);

    // Pinned contract: both → mergeScopeFilters returns undefined (universe
    // via filter.ts:22), arbacRowFilter then returns `userFilter ?? {}`
    // = `{}`.
    expect(resA).toEqual({});
    expect(resB).toEqual({});
    expect(resA).toEqual(resB);
  });

  // WHY: load-bearing union case. Two roles: one tenant-restricted, one with
  // no filter (universe). Per `mergeScopeFilters` line 22 — "Any empty filter
  // means unrestricted" — the union widens to universe. This is correct under
  // $or semantics ({tenantId:'a'} ∪ universe = universe), but it means an
  // overly-permissive role silently DEFEATS a restrictive sibling role. Pin
  // this — if a future refactor flips to intersection semantics, every
  // existing multi-role grant would suddenly become narrower, breaking grants
  // in production silently.
  it("multi-scope union: tenant-scoped + undefined-filter scope → widens to universe (allow-all)", async () => {
    const arbac = new MoostArbac<Record<string, never>, ArbacDbScope>();
    arbac.registerRole({
      id: "tenant-a-reader",
      rules: [
        {
          resource: "thing",
          action: "read",
          scope: () => ({ filter: { tenantId: "a" } }),
        },
      ],
    });
    arbac.registerRole({
      // No scope() → engine pushes `{}` into scopes (s.filter === undefined).
      id: "global-reader",
      rules: [{ resource: "thing", action: "read" }],
    });
    const http = await buildAndInit(arbac, ["tenant-a-reader", "global-reader"]);
    const merged = await readMergedFilter(http);
    // mergeScopeFilters([{tenantId:'a'}, {}]) → undefined (universe) →
    // arbacRowFilter returns userFilter ?? {} = {}.
    expect(merged).toEqual({});
  });

  // WHY: pins the equivalence between `{}` and `undefined` for s.filter under
  // the `?? {}` coercion. If `mergeScopeFilters` ever started treating
  // explicit `{}` differently from undefined (e.g. "explicit empty = strict
  // empty match"), this test would catch it — the result must be IDENTICAL to
  // the previous test's universe-widen outcome.
  it("multi-scope union: tenant-scoped + explicit `{}` filter → identical to undefined case", async () => {
    const arbac = new MoostArbac<Record<string, never>, ArbacDbScope>();
    arbac.registerRole({
      id: "tenant-a-reader",
      rules: [
        {
          resource: "thing",
          action: "read",
          scope: () => ({ filter: { tenantId: "a" } }),
        },
      ],
    });
    arbac.registerRole({
      id: "global-reader-explicit",
      rules: [
        {
          resource: "thing",
          action: "read",
          scope: () => ({ filter: {} }),
        },
      ],
    });
    const http = await buildAndInit(arbac, ["tenant-a-reader", "global-reader-explicit"]);
    const merged = await readMergedFilter(http);
    expect(merged).toEqual({});
  });

  // WHY: the deny path is structurally separate from the scope-less-allowed
  // path, and their MEANING is opposite:
  //   - `allowed: false` → the resolver answers 403 before any row filter.
  //   - `allowed: true, [{}]` (a rule without `scope()`) → `{}` → matches ALL.
  // A refactor that collapses these two cases would convert every deny into
  // an allow-all, a critical tenant-leakage bug. This test pins that divergence.
  it("allowed=false → 403; allowed=true with a scope-less grant ([{}]) → {} (allow-all)", async () => {
    // Deny path: user holds no role granting `thing/read`.
    const arbacDeny = new MoostArbac<Record<string, never>, ArbacDbScope>();
    arbacDeny.registerRole({
      id: "unrelated",
      rules: [{ resource: "other", action: "write" }],
    });
    const denyHttp = await buildAndInit(arbacDeny, ["unrelated"]);
    expect((await denyHttp.request("/probe/a"))?.status).toBe(403);

    // Allow-all path: rule exists, no scope() → scopes is `[{}]` (one empty
    // scope). The filter union short-circuits on the empty entry ("any empty
    // filter means unrestricted") and arbacRowFilter folds it to `{}`.
    const arbacAllow = new MoostArbac<Record<string, never>, ArbacDbScope>();
    arbacAllow.registerRole({
      id: "open-reader",
      rules: [{ resource: "thing", action: "read" }],
    });
    const allowHttp = await buildAndInit(arbacAllow, ["open-reader"]);
    expect(await readMergedFilter(allowHttp)).toEqual({});
  });

  // WHY: pins the WIRING, not the algebra. `conjoinScopeFilters` owns the
  // `$and`-never-spread rule and its own unit spec (arbac/src/scope/
  // conjunction.spec.ts) already proves the same-key case; nothing there would
  // notice if this function stopped calling it. Swapping the body back to
  // `{ ...merged, ...filter }` fails this test and only this test — a tenant-a
  // reader asking for tenantId 'b' would otherwise be handed tenant b's rows.
  //
  // Historical note: recorded as BUG-2 against @uniqu/core's `walkFilter`
  // dropping sibling field keys next to a logical operator. That short-circuit
  // was fixed in @uniqu/core 0.1.8 (mixed field/logical nodes are an implicit
  // AND) — the same-key overwrite pinned here is independent of it and is why
  // the spread stays unsafe regardless.
  it("user filter on the same field as the scope → conjoined, not overwritten", async () => {
    const arbac = new MoostArbac<Record<string, never>, ArbacDbScope>();
    arbac.registerRole({
      id: "tenant-a-reader",
      rules: [
        {
          resource: "thing",
          action: "read",
          scope: () => ({ filter: { tenantId: "a" } }),
        },
      ],
    });
    const http = await buildAndInit(arbac, ["tenant-a-reader"]);
    // Probe passes `{ tenantId: 'b' }` — the scope says 'a'.
    const merged = await readMergedFilter(http, "/probe/b");

    // The scope's constraint survives verbatim; it is not replaced by 'b'.
    expect(merged).toEqual({ $and: [{ tenantId: "a" }, { tenantId: "b" }] });
  });
});

describe("applyArbacProjection — $select ∩ scope projection", () => {
  const table = {
    primaryKeys: ["id"],
    preferredId: ["id"],
    flatMap: new Map<string, unknown>(
      ["id", "title", "a", "a.b", "a.c", "owner", "owner.name"].map((k) => [k, {}]),
    ),
    navFields: new Set(["owner"]),
  };
  const children = fieldChildrenOf(table);
  const inc: ArbacDbScope[] = [{ projection: { id: 1, title: 1, "a.b": 1 } }];
  const exc: ArbacDbScope[] = [{ projection: { "a.c": 0 } }];

  it('reads an array $select as an inclusion (not an exclusion keyed "0")', () => {
    expect(applyArbacProjection(["title"], inc, table)).toEqual({ title: 1 });
    expect(applyArbacProjection(["a"], exc, table)).toEqual({ "a.b": 1 });
  });

  it("splits a requested parent into the visible leaves", () => {
    expect(applyArbacProjection(["a"], inc, table)).toEqual({ "a.b": 1 });
    // No schema: an inclusion scope's own descendants; an exclusion scope fails closed.
    expect(applyArbacProjection(["a"], inc)).toEqual({ "a.b": 1 });
    expect(applyArbacProjection(["a", "title"], exc)).toEqual({ title: 1 });
  });

  it("never returns the universe for a non-empty $select", () => {
    expect(applyArbacProjection(["a"], exc)).toEqual({ "a.c": 0 });
  });

  it("names excluded parents by their own leaves (never nav descendants)", () => {
    expect(applyArbacProjection(undefined, [{ projection: { a: 0 } }], table)).toEqual({
      "a.b": 0,
      "a.c": 0,
    });
    expect(applyArbacProjection({ title: 0 }, exc, table)).toEqual({ title: 0, "a.c": 0 });
    expect(children!("owner")).toEqual([]);
  });

  it("no scope projection: the $select passes through untouched", () => {
    expect(applyArbacProjection(["a"], [{}], table)).toEqual(["a"]);
  });
});
