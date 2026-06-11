# Scope merging

The engine returns `scopes: TScope[]` — a UNION the caller has to fold. Three orthogonal mergers cover the three sub-shapes you'll encounter: filter expressions, field projections, and Uniquery control gates. All three follow **additive RBAC**: more roles = broader access.

## Contents

- [The `ArbacDbScope` shape](#the-arbacdbscope-shape)
- [`mergeScopeFilters` — filter union](#mergescopefilters--filter-union)
- [`unionProjections` — projection union](#unionprojections--projection-union)
- [`restrictProjection` — query-time intersection](#restrictprojection--query-time-intersection)
- [`getProjectionMode` / `isFieldAllowed`](#getprojectionmode--isfieldallowed)
- [`unionControlsPolicy` — per-control gate merge](#unioncontrolspolicy--per-control-gate-merge)

## The `ArbacDbScope` shape

`ArbacDbScope` is the conventional scope shape consumed by `AsArbacDbController` (which lives in `@aooth/arbac-moost`, not here) — full field table in [db-controllers.md](db-controllers.md). The merge utilities in this package each operate on one of its fields: `filter` (row-level WHERE — UNION via `mergeScopeFilters`), `projection` (Mongo-style — UNION via `unionProjections`), `controls` (URL control gates, `ControlGate = boolean | readonly string[]` — UNION via `unionControlsPolicy`); `set` and `allowedFields` are caller-handled.

`@aooth/arbac` only exports the merge utilities; `ArbacDbScope` itself is owned by `@aooth/arbac-moost`. If you're writing roles that target the AsDb controller, type `TScope` as `ArbacDbScope`.

## `mergeScopeFilters` — filter union

```ts
mergeScopeFilters(scopes: TScopeFilter[]): TScopeFilter | undefined
```

OR-style merge of `@uniqu/core` filter expressions. Resolution order:

1. **Empty input** → `undefined` (no constraint at all).
2. **Any empty filter `{}` in the array** → `undefined` (a role granted unrestricted access; the union covers everything).
3. **Length 1** → return as-is.
4. **`$in` optimization** — when every filter has the SAME single primitive key, collapse to `{ key: { $in: [v1, v2, ...] } }`. `null` values are eligible for `$in`.
5. **Fallback** → `{ $or: scopes }`.

The `$in` optimization is skipped when:

- Filters have different keys.
- Any filter has more than one key.
- Any value is an operator object (`{ $gt: 18 }`).
- The single key is `$and` or `$or`.

Examples:

```ts
mergeScopeFilters([]);
// undefined

mergeScopeFilters([{ dept: "sales" }, {}, { dept: "marketing" }]);
// undefined   ← {} short-circuits to universal

mergeScopeFilters([{ dept: "sales" }]);
// { dept: "sales" }

mergeScopeFilters([{ dept: "sales" }, { dept: "marketing" }, { dept: null }]);
// { dept: { $in: ["sales", "marketing", null] } }

mergeScopeFilters([{ dept: "sales" }, { region: "EU" }]);
// { $or: [{ dept: "sales" }, { region: "EU" }] }

mergeScopeFilters([{ age: { $gt: 18 } }, { age: { $gt: 21 } }]);
// { $or: [{ age: { $gt: 18 } }, { age: { $gt: 21 } }] }   ← operator objects defeat $in
```

## `unionProjections` — projection union

```ts
unionProjections(...projections: TProjection[]): TProjection
type TProjection = Record<string, 0 | 1>;
```

Combines Mongo-style projections under "field is allowed if any input grants it". A single projection MUST be uniform — all 1s (include mode) or all 0s (exclude mode); mixing 1 and 0 in one input throws via `getProjectionMode`. ACROSS projections, the mix is legal.

Truth table:

| Input                    | Result                                                      |
| ------------------------ | ----------------------------------------------------------- |
| Empty input              | `{}` (universe — no projection applied)                     |
| Any `{}` input           | `{}` (universe wins)                                        |
| All include mode         | Include mode — union of all keys, sorted                    |
| All exclude mode         | Exclude mode — INTERSECTION of all exclude key-sets, sorted |
| Mix of include + exclude | See below                                                   |

Mix resolution (includes cancel matching excludes):

- Start from the intersection of all exclude key-sets.
- For each field present in any include projection, remove it from the exclude set.
- If the result is empty → `{}` (universe).
- Otherwise → exclude mode with the remaining keys.

Examples:

```ts
unionProjections();
// {}

unionProjections({});
// {}

unionProjections({ a: 1, b: 1 }, { c: 1 });
// { a: 1, b: 1, c: 1 }   ← include union

unionProjections({ secret: 0, audit: 0 }, { secret: 0 });
// { secret: 0 }   ← exclude intersection

unionProjections({ a: 1, b: 1 }, { c: 0 });
// { c: 0 }   ← include union doesn't cover `c`, so exclude mode wins

unionProjections({ a: 1, b: 1 }, { b: 0 });
// {}   ← include cancels the only exclusion → universe
```

## `restrictProjection` — query-time intersection

```ts
restrictProjection(desired: TProjection, accessControl: TProjection): TProjection
```

This is the OPPOSITE of `unionProjections`. Where union is multi-role "broader wins", `restrictProjection` is "what the user asked for ∩ what they're allowed to see". Use it when applying a single merged AC projection to a caller's `$select`.

Behavior:

- Both include mode → intersection of keys, sorted.
- Both exclude mode → union of keys, sorted.
- Mixed → walks `desired`, keeps each key only if `isFieldAllowed(field, accessControl)` returns true.

## `getProjectionMode` / `isFieldAllowed`

```ts
getProjectionMode(p: TProjection): "include" | "exclude" | "empty"
isFieldAllowed(field: string, p: TProjection): boolean
```

`getProjectionMode`:

- `{}` → `"empty"`.
- All values `1` → `"include"`.
- All values `0` → `"exclude"`.
- Mixed `1` and `0` → throws.

`isFieldAllowed` is dot-path aware: `isFieldAllowed("user.email", { user: 0 })` → `false`. It walks the dotted path against the projection and respects include vs exclude semantics.

```ts
isFieldAllowed("name", {}); // true  — empty projection grants everything
isFieldAllowed("secret", { name: 1 }); // false — include mode means "only listed"
isFieldAllowed("name", { name: 1 }); // true
isFieldAllowed("name", { secret: 0 }); // true  — exclude mode means "everything except"
isFieldAllowed("secret", { secret: 0 }); // false
```

## `unionControlsPolicy` — per-control gate merge

```ts
unionControlsPolicy(scopes: ReadonlyArray<Pick<ArbacDbScope, "controls">>): Record<string, ControlGate>
type ControlGate = boolean | readonly string[];
```

`controls` gates Uniquery URL controls (`$with`, `$groupBy`, `$having`, `$sort`, …) per role. The result tells `AsArbacDbController` which controls the caller may use after the multi-role union.

Resolution per control key:

1. **If ANY input scope omits the `controls` map entirely** → return `{}` (silent-on-everything = full grant across all controls). This is the "back door": a single role with no `controls` map opens every control.
2. For each key present in any scope's `controls`:
   - **Any scope contributes `undefined` or `true`** → key is dropped from the result (absent ≡ allowed).
   - **All scopes contribute `false`** → result is `false` (fully denied).
   - **Mix of `false` and `string[]`** → union of all whitelists, sorted and deduplicated.
3. **`string[]` is ONLY legal for `$with` and `$groupBy`.** Any other key with a `string[]` gate throws.

Examples (single array arg):

```ts
unionControlsPolicy([{ controls: { $with: ["tasks"] } }, { controls: { $with: ["comments"] } }]);
// { $with: ["comments", "tasks"] }   ← union, sorted

unionControlsPolicy([{ controls: { $with: false } }, { controls: { $with: ["tasks"] } }]);
// { $with: ["tasks"] }   ← whitelist beats false

unionControlsPolicy([{ controls: { $with: false } }, { controls: { $with: false } }]);
// { $with: false }

unionControlsPolicy([{ controls: { $with: true } }, { controls: { $with: false } }]);
// {}   ← `true` drops the key (absent ≡ allowed)

unionControlsPolicy([
  { controls: { $with: ["tasks"] } },
  {
    /* no controls */
  },
]);
// {}   ← any omission = full grant
```

The "back door" semantic in (1) is intentional: roles that don't care about controls shouldn't constrain other roles' grants. If you want a role to enforce a control gate, every role must opt into `controls`.

## Attenuation conjunction — the restrictive mirror

Everything above UNIONS (additive RBAC: more roles = more access). Credential attenuation (scoped tokens / PATs — see the [attenuation docs page](https://aoothjs.dev/arbac/attenuation)) needs the OPPOSITE: `assigned ∩ presented`. Dedicated combiners, exported from `@aooth/arbac` + `@aooth/arbac-moost`:

```ts
import { conjoinScopeFilters, intersectControlsPolicy } from "@aooth/arbac";
import { conjoinArbacDbScopes } from "@aooth/arbac-moost"; // facet-by-facet composite
import { extractAttenuation, validateAttenuationTargets } from "@aooth/arbac-moost/atscript";
```

| #   | Rule                                                                                                                                                                                                  |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | NEVER combine user + credential scopes with `mergeScopeFilters` / `unionControlsPolicy` — they widen (empty `{}` = "unrestricted" erases the narrowing). Use the conjoin/intersect pair.              |
| 2   | `conjoinScopeFilters(a, b)` → `{ $and: [a, b] }`; empty/`undefined` side is the IDENTITY (no constraint), the polar opposite of `mergeScopeFilters`' "empty wins as unrestricted".                    |
| 3   | `intersectControlsPolicy(a, b)`: `false` either side wins; `true` defers; whitelist ∧ whitelist = set INTERSECTION (may be empty = nothing).                                                          |
| 4   | `conjoinArbacDbScopes(userScopes, credScopes)` does the whole composite (filter `$and`, projection `restrictProjection`, controls intersect, `allowedFields` ∩, recursive `with`) → one-element list. |
| 5   | `Arbac.evaluate` with `user.attenuate` runs the policy TWICE and intersects OUTCOMES — attenuated scopes return as `credScopes`, separate from `scopes`.                                              |
| 6   | `extractAttenuation` treats `null` AND `undefined` as ABSENT (no narrowing) — a stateful store returns unset optional columns as SQL `null`; only present non-null values narrow.                     |
| 7   | Unusable role values extract to `[]` = deny-all (fail-closed), never fall back to full authority. Boot-validate attr targets with `validateAttenuationTargets`.                                       |
