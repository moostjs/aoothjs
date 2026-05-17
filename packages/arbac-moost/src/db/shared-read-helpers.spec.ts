import { HttpError } from "@moostjs/event-http";
import { describe, expect, it } from "vite-plus/test";

import type { ArbacDbScope } from "./as-arbac-db-controller";
import { applyArbacRelationScopes } from "./shared-read-helpers";

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
