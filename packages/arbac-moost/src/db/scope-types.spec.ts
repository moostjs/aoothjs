import { describe, expect, it } from "vite-plus/test";

import type { ArbacDbScope } from "./as-arbac-db-controller";

/**
 * Compile-time tests for the generic `ArbacDbScope<T>` shape. The runtime
 * body of every `it(...)` is a trivial `expect(true).toBe(true)` — the test
 * IS the type-check itself. If TypeScript compiles this file, the assertion
 * holds; if a regression breaks the generic, the build fails before any
 * test runs.
 */

// --- Fake annotated models used only by these type-level assertions ----------
// Mirrors the `__ownProps` / `__navProps` shape that `OwnPropsOf` / `NavPropsOf`
// from @atscript/typescript read. Authoring a fake here keeps the test
// independent of the real atscript-generated `.as.d.ts` artefacts and avoids
// pulling demo models into the arbac-moost package boundary.

interface TestComment {
  __ownProps: { id: string; body: string; tenantId: string };
  __navProps: Record<string, never>;
}

interface TestTask {
  __ownProps: { id: string; title: string; internalNotes: string };
  __navProps: { comments: TestComment[]; reviewer: TestComment };
}

describe("ArbacDbScope generic typing", () => {
  // WHY: the load-bearing backward-compat guarantee. Every pre-Step-B role
  // and helper passes `ArbacDbScope` with no type arg. The default must
  // resolve to the legacy untyped shape (string-keyed projection, string-keyed
  // set, string[] allowedFields, Record<string, ControlGate> controls,
  // Record<string, ArbacDbScope> with) or those call sites silently break.
  it("untyped (T = unknown) compiles like the pre-Step-B shape", () => {
    const _s: ArbacDbScope = {
      filter: { tenantId: "abc" },
      projection: { foo: 0, "bar.baz": 0 },
      set: { auditedBy: "system" },
      allowedFields: ["id", "title"],
      controls: { $with: false, $groupBy: ["dept"] },
      with: { anything: { projection: { x: 1 } } },
    };
    expect(_s).toBeDefined();
  });

  // WHY: the primary feature — direct own-field names autocomplete and
  // typo-check. Without this Step B has no value; if `internalNotes` (typed)
  // and `'title.foo'` (dotted-path escape) ever stop coexisting, the design
  // has regressed.
  it("typed scope accepts known own fields AND dotted-path escape", () => {
    const _s: ArbacDbScope<TestTask> = {
      projection: { internalNotes: 0, "title.foo": 0 },
      allowedFields: ["id", "title"],
      set: { internalNotes: "redacted" },
    };
    expect(_s).toBeDefined();
  });

  // WHY: the `with` mapped type must recurse with the JOINED model, not the
  // array wrapper. `comments: TestComment[]` → inner scope is
  // `ArbacDbScope<TestComment>`, so `tenantId` autocompletes from
  // `TestComment.__ownProps`, not `TestTask`. If the unwrap (`NavTarget<U>`)
  // breaks, the inner key set silently widens to whatever the parent had.
  it("typed `with.<rel>` recurses against the joined model's own fields", () => {
    const _s: ArbacDbScope<TestTask> = {
      with: {
        comments: { projection: { tenantId: 0 } },
        reviewer: { projection: { body: 0 } },
      },
    };
    expect(_s).toBeDefined();
  });

  // WHY: `satisfies` here forces TS to prove the literal matches
  // `ArbacDbScope<TestTask>`. Combined with no `@ts-expect-error` above
  // the literal, this asserts the typed keys ARE in the accepted set —
  // i.e. autocomplete will surface them, not flag them.
  it("typed shape is satisfied by literal with known own-field keys", () => {
    const s = {
      projection: { internalNotes: 0 as const },
      allowedFields: ["internalNotes" as const],
    } satisfies ArbacDbScope<TestTask>;
    expect(s).toBeDefined();
  });

  // WHY: roles that already declare `ArbacDbScope` (no third type param to
  // `defineRole<...>`) keep their untyped scope shape — fields use the
  // legacy permissive types. Regression here means existing role files in
  // e2e-demo would fail to type-check.
  it("backward-compat: ArbacDbScope without generic == legacy untyped shape", () => {
    // Literal keys that no atscript model would declare — proves the untyped
    // form takes arbitrary strings without any casting.
    const _s: ArbacDbScope = {
      projection: { "any.nested.path": 0, anotherDeepField: 0 },
      controls: { $with: ["comments", "reviewer"], $groupBy: false },
      with: { unknownRel: { allowedFields: ["x", "y"] } },
    };
    expect(_s).toBeDefined();
  });
});
