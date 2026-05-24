import { Get, HttpError, MoostHttp } from "@moostjs/event-http";
import {
  clearGlobalWooks,
  Controller,
  createProvideRegistry,
  createReplaceRegistry,
  Moost,
  Resolve,
} from "moost";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import { FakeUserProvider } from "../__testing__/user-provider";
import { ArbacAction, ArbacResource, ArbacUserProviderToken, MoostArbac } from "../index";
import type { ArbacDbScope } from "./as-arbac-db-controller";
import { applyArbacRelationScopes, transformArbacFilter } from "./shared-read-helpers";

/**
 * Captures the result of `transformArbacFilter(undefined)` for the current
 * event context. Called with `undefined` (no user filter) so the response is
 * purely the scope-merge outcome — the value under test in this file.
 */
const ProbeTransform = () =>
  Resolve(async () => {
    const result = await transformArbacFilter(undefined);
    return { result };
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
}

async function buildAndInit(
  arbac: MoostArbac<Record<string, never>, ArbacDbScope>,
  roles: string[],
): Promise<MoostHttp> {
  const app = new Moost();
  const user = new FakeUserProvider("u1", roles);
  app.setReplaceRegistry(createReplaceRegistry([ArbacUserProviderToken, FakeUserProvider]));
  app.setProvideRegistry(
    createProvideRegistry([FakeUserProvider, () => user], [MoostArbac, () => arbac]),
  );
  const http = new MoostHttp();
  app.adapter(http);
  app.registerControllers(ProbeController);
  await app.init();
  return http;
}

async function readMergedFilter(http: MoostHttp): Promise<Record<string, unknown>> {
  const res = await http.request("/probe/a");
  expect(res?.status).toBe(200);
  const body = (await res!.json()) as { out: { result: Record<string, unknown> } };
  return body.out.result;
}

describe("applyArbacRelationScopes", () => {
  // WHY: silence-wins default — pre-existing roles that don't opt into `with`
  // must keep working, no projection/filter injection.
  it("no scope declares `with` → user controls pass through unchanged", () => {
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

  // WHY: confirms relation filter uses same $and overlay as parent filter
  // (BUG-2 pattern) so a user-supplied logical operator can't drop scope siblings.
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
  // the silence-wins guard at line 111: recursion only continues when at least
  // one scope declares `with.<name>` for the current entry. The user controls
  // a TREE (URL/JSON, no cycles possible at the wire level), so deeply-nested
  // user `$with` against a shallow scope tree terminates immediately when the
  // scope tree runs out — adversarial user depth alone CANNOT force unbounded
  // recursion. Roles are admin-declared, not attacker-controlled, so the depth
  // is bounded by the role catalogue, not the request. If this test ever fails
  // (stack overflow, hang, or the inner `$select` getting injected), the
  // silence-wins bound has been broken and an explicit depth cap is required.
  it("deeply-nested user $with bounded by shallow scope tree (silence-wins at every depth)", () => {
    // Build user $with nested 50 levels deep — `comments` → `comments` → ...
    let entry: Record<string, unknown> = { name: "comments" };
    for (let i = 0; i < 49; i++) {
      entry = { name: "comments", controls: { $with: [entry] } };
    }
    const controls: Record<string, unknown> = { $with: [entry] };
    // Scope declares `with.comments` ONE level deep, with a projection that
    // would otherwise inject `$select` at every recursion level.
    const scopes: ArbacDbScope[] = [{ with: { comments: { projection: { body: 1 } } } }];

    expect(() => applyArbacRelationScopes(controls, scopes)).not.toThrow();

    // Depth 1 (outer): scope hits, $select injected.
    const lvl1 = (
      controls.$with as Array<{ controls?: { $select?: unknown; $with?: unknown[] } }>
    )[0];
    expect(lvl1.controls?.$select).toEqual({ body: 1 });

    // Depth 2: scope.with.comments has no further `with` → subScopes empty →
    // silence-wins `continue` at line 111. The entry must pass through with
    // its name intact and NO $select injected at this or any deeper level.
    const lvl2 = (
      lvl1.controls?.$with as Array<{ name: string; controls?: { $select?: unknown } }> | undefined
    )?.[0];
    expect(lvl2?.name).toBe("comments");
    expect(lvl2?.controls?.$select).toBeUndefined();

    // Spot-check depth 25 — well past any plausible scope depth — still untouched.
    let cursor: { controls?: { $with?: unknown[] } } | undefined = lvl1;
    for (let i = 0; i < 24 && cursor; i++) {
      cursor = (
        cursor.controls?.$with as Array<{ controls?: { $with?: unknown[] } }> | undefined
      )?.[0];
    }
    expect(
      (cursor as { controls?: { $select?: unknown } } | undefined)?.controls?.$select,
    ).toBeUndefined();
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
 * `transformArbacFilter` does `scopes.map(s => s.filter ?? {})` (line 42 of
 * shared-read-helpers.ts), coercing a missing `filter` to `{}`. Both shapes
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
 * `scopes` array `transformArbacFilter` consumes. Mocking it would test a
 * fiction; this is one rung above unit and one rung below e2e, matching the
 * style already established in `arbac.composables.spec.ts`.
 */
describe("transformArbacFilter — empty vs undefined filter coercion", () => {
  beforeEach(() => {
    clearGlobalWooks();
  });

  // WHY: pins the coercion at line 42 (`s.filter ?? {}`) — a single role whose
  // rule has no `scope()` (engine pushes `{}` into scopes) must produce the
  // same merged filter as a single role whose `scope()` returns `{ filter: {} }`.
  // Both are "this role grants unrestricted access"; if they ever diverge, the
  // `?? {}` coercion has been broken or `mergeScopeFilters`'s handling of `{}`
  // has shifted.
  it("single scope with undefined filter ≡ single scope with {} filter (both → allow-all, returns {})", async () => {
    // Variant A: rule with no scope() — engine pushes `{} as TScope` into
    // scopes (arbac-core/src/arbac.ts:147), so s.filter is undefined and the
    // `?? {}` coercion at shared-read-helpers.ts:42 kicks in.
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
          scope: () => ({ filter: {} as Record<string, unknown> }),
        },
      ],
    });
    const httpB = await buildAndInit(arbacB, ["r"]);
    const resB = await readMergedFilter(httpB);

    // Pinned contract: both → mergeScopeFilters returns undefined (universe
    // via filter.ts:22), transformArbacFilter then returns `userFilter ?? {}`
    // = `{}` (shared-read-helpers.ts:44).
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
    // transformArbacFilter returns userFilter ?? {} = {}.
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
          scope: () => ({ filter: {} as Record<string, unknown> }),
        },
      ],
    });
    const http = await buildAndInit(arbac, ["tenant-a-reader", "global-reader-explicit"]);
    const merged = await readMergedFilter(http);
    expect(merged).toEqual({});
  });

  // WHY: the deny path is structurally separate from the empty-scopes-allowed
  // path. Both produce a "small" result, but their MEANING is opposite:
  //   - `allowed: false`     → DENY_FILTER `{ $or: [] }` → matches NOTHING.
  //   - `allowed: true, []`  → falls through to `userFilter ?? {}` → matches ALL.
  // A refactor that collapses these two cases (e.g. "if scopeList empty, just
  // return {}") would convert every deny into an allow-all, a critical
  // tenant-leakage bug. This test pins the divergence at line 38 vs line 44.
  it("allowed=false → DENY_FILTER ({$or:[]}); allowed=true with empty scopes → {} (allow-all)", async () => {
    // Deny path: user holds no role granting `thing/read`.
    const arbacDeny = new MoostArbac<Record<string, never>, ArbacDbScope>();
    arbacDeny.registerRole({
      id: "unrelated",
      rules: [{ resource: "other", action: "write" }],
    });
    const denyHttp = await buildAndInit(arbacDeny, ["unrelated"]);
    const denyResult = await readMergedFilter(denyHttp);
    expect(denyResult).toEqual({ $or: [] });

    // Allow-all path: rule exists, no scope() → scopes is `[{}]` (one empty
    // scope). mergeScopeFilters short-circuits on the empty entry (filter.ts:22
    // "any empty filter means unrestricted") and returns undefined, which
    // transformArbacFilter then folds to `{}` (shared-read-helpers.ts:44).
    // The result must be `{}` (allow-all), structurally distinct from the
    // deny path's `{ $or: [] }` (match-nothing).
    const arbacAllow = new MoostArbac<Record<string, never>, ArbacDbScope>();
    arbacAllow.registerRole({
      id: "open-reader",
      rules: [{ resource: "thing", action: "read" }],
    });
    const allowHttp = await buildAndInit(arbacAllow, ["open-reader"]);
    const allowResult = await readMergedFilter(allowHttp);
    expect(allowResult).toEqual({});

    // The two outcomes must be structurally distinct — one matches nothing,
    // one matches everything. Equality would mean the deny path is broken.
    expect(allowResult).not.toEqual(denyResult);
  });
});
