# Scope Merging

This page answers: _the engine returned `scopes: TScope[]` for a user with multiple roles — now how do I turn that into one filter, one projection, and one set of Uniquery controls to apply at query time?_ It documents the scope-merge utilities in [`@aooth/arbac`](https://github.com/moostjs/aoothjs/tree/main/packages/arbac).

All three utilities operate under **additive RBAC**: when a user has multiple matching roles, the _broader_ access wins. An empty filter, an empty projection, or a missing controls map signals "no restriction" and short-circuits the union.

## The `ArbacDbScope` shape

The Moost integration uses a conventional scope shape. The utilities on this page are designed around it, though each one operates on its own piece in isolation:

```ts
interface ArbacDbScope {
  filter?: TScopeFilter; // row filter (Uniquery-compatible)
  check?: TScopeFilter; // WITH CHECK for written rows (default: filter; {} = off)
  projection?: TProjection; // field visibility map
  set?: Record<string, unknown>; // forced field values on write (dotted keys = nested paths)
  allowedFields?: readonly string[]; // writable field paths
  controls?: Record<string, ControlGate>; // per-control Uniquery gate
  with?: Record<string, ArbacDbScope>; // per-relation sub-scopes
  nestedWrites?: readonly string[]; // nav relations writable through the parent (default: none)
  checkRefs?: true | readonly string[]; // FKs whose target row must be readable by the caller
}
```

`check` merges across roles with `mergeScopeFilters`, exactly like `filter`. `checkRefs` is the one write facet that does **not** union additively: an FK is checked only when EVERY scope enables it — a role without the flag grants unconstrained writes of that FK, so adding it widens access like any other role. How the DB controllers enforce each key: [DB Controllers](/moost/db-controllers#write-pipeline).

`with.<rel>` sub-scopes merge per relation with the same utilities, over the roles that declare it — a role silent on `with.<rel>` contributes nothing. When no role declares it, the DB controllers apply the caller's own grant on the related table instead (0.1.72+; no grant → the relation is unknown). See [Per-relation `with`](/moost/db-controllers#per-relation-with-recursive).

Each merger below takes a homogeneous slice of `ArbacDbScope` (filters, projections, or controls) and produces a single merged value.

## `mergeScopeFilters`

OR-style merge of [`@uniqu/core`](https://github.com/prostojs/uniqu) filter expressions. Returns `undefined` when there is no constraint to apply.

```ts
function mergeScopeFilters(scopes: TScopeFilter[]): TScopeFilter | undefined;
```

### Algorithm

| Input                               | Result                             |
| ----------------------------------- | ---------------------------------- |
| `[]`                                | `undefined` (no constraint)        |
| Any `{}` in the input               | `undefined` (universe — see below) |
| `[f]` (single)                      | `f` as-is                          |
| All filters share one primitive key | `{ key: { $in: [v1, v2, ...] } }`  |
| Otherwise                           | `{ $or: scopes }`                  |

### Examples

```ts
import { mergeScopeFilters } from "@aooth/arbac";

mergeScopeFilters([]);
// → undefined

mergeScopeFilters([{ dept: "sales" }]);
// → { dept: 'sales' }

mergeScopeFilters([{ dept: "sales" }, { dept: "marketing" }]);
// → { dept: { $in: ['sales', 'marketing'] } }

mergeScopeFilters([{ dept: "sales" }, { region: "EMEA" }]);
// → { $or: [{ dept: 'sales' }, { region: 'EMEA' }] }

mergeScopeFilters([{ dept: "sales" }, {}]);
// → undefined  (admin override widened the union)
```

::: warning Empty filter means _universe_
Any `{}` in the input array short-circuits to `undefined`. That's the contract: a role granted unrestricted access cancels every bounded role's filter in the union. Returning `{}` instead of `undefined` would mean "match nothing" in some filter dialects — the explicit `undefined` is unambiguous.
:::

### `$in` optimization

The `$in` collapse only triggers when **every** filter has the same single primitive key. A few non-eligible cases:

```ts
mergeScopeFilters([{ dept: 'sales' }, { dept: { $gt: 10 } }])
// → { $or: [...] }       // operator object on the right disqualifies $in

mergeScopeFilters([{ dept: 'sales' }, { dept: 'eu', tier: 'a' }])
// → { $or: [...] }       // second filter has two keys

mergeScopeFilters([{ $and: [...] }, { dept: 'sales' }])
// → { $or: [...] }       // $and/$or branches never collapse
```

`null` values are eligible for `$in` — `mergeScopeFilters([{ parent: null }, { parent: 'x' }])` collapses to `{ parent: { $in: [null, 'x'] } }`.

## `unionProjections`

Combines Mongo-style field projections under "field is allowed if **any** input grants it". The shape:

```ts
function unionProjections(...projections: TProjection[]): TProjection;

type TProjection = Record<string, 0 | 1>;
```

A projection is "include-mode" if all its values are `1`, "exclude-mode" if all its values are `0`, and "empty" (universe) if it's `{}`. Mixing `1` and `0` in a single projection is forbidden — see [`getProjectionMode`](#getprojectionmode) below.

### Truth table

| Input mix                                              | Result                                                                                     |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| Empty input                                            | `{}` (universe)                                                                            |
| Any `{}` in input                                      | `{}` (universe)                                                                            |
| All include                                            | Include-mode result = union of included keys, sorted                                       |
| Mix of include + exclude (includes cover the deny set) | `{}`                                                                                       |
| Mix of include + exclude (otherwise)                   | Exclude-mode = intersection of all exclude key-sets, minus any field granted by an include |
| All exclude                                            | Exclude-mode = intersection of excluded keys                                               |

Intersections are by **path**: a field stays excluded when every exclude role hides it or one of its parents, so `unionProjections({ a: 0 }, { "a.c": 0 })` → `{ "a.c": 0 }`. An include of a nested child under a parent that every exclude role hides (`{ "a.b": 1 }` ∪ `{ a: 0 }`) keeps the whole parent hidden: carving out the child would need the schema. The result is narrower, never wider.

The intuition: **inclusions widen** (any role granting a field wins), **exclusions narrow** (a field must be excluded by _every_ role to stay excluded).

### Examples

```ts
import { unionProjections } from "@aooth/arbac";

unionProjections({ name: 1, email: 1 }, { email: 1, phone: 1 });
// → { email: 1, name: 1, phone: 1 }     // all-include union

unionProjections({ ssn: 0 }, { ssn: 0, dob: 0 });
// → { ssn: 0 }                          // intersection of excludes

unionProjections({ name: 1, email: 1 }, { ssn: 0 });
// → { ssn: 0 }                          // include doesn't cancel an unrelated exclude

unionProjections({ name: 1, ssn: 1 }, { ssn: 0 });
// → {}                                  // include cancels its own exclusion

unionProjections({}, { ssn: 0 });
// → {}                                  // any universe widens to universe
```

### `getProjectionMode`

```ts
function getProjectionMode(p: TProjection): "include" | "exclude" | "empty";
```

Classifies a single projection. **Throws if `1` and `0` are mixed in one input.**

```ts
getProjectionMode({}); // → 'empty'
getProjectionMode({ a: 1, b: 1 }); // → 'include'
getProjectionMode({ a: 0, b: 0 }); // → 'exclude'
getProjectionMode({ a: 1, b: 0 }); // → throws
```

::: warning Mixing `1` and `0` in a single projection throws
The constraint is per-projection. _Across_ projections, mixing is fine — that's what `unionProjections` is for. Inside one, choose include-mode or exclude-mode and stick with it.
:::

### `isFieldAllowed`

```ts
function isFieldAllowed(field: string, p: TProjection): boolean;
```

Dot-path aware: `isFieldAllowed('address.city', { 'address.city': 1 })` returns `true`. `isFieldAllowed('address.city', { address: 1 })` also returns `true` — including a parent includes its children.

### `restrictProjection` — query-time intersection

The mergers above answer _"what does this user's access policy allow?"_. At query time you also have a client-requested projection — "give me only `name` and `email`". `restrictProjection` is the intersection of _desired_ ∩ _access-control_.

```ts
function restrictProjection(
  desired: TProjection,
  accessControl: TProjection,
  childrenOf?: TProjectionChildren,
): TProjection;
function intersectProjections(
  a: TProjection,
  b: TProjection,
  childrenOf?: TProjectionChildren,
): TProjection | null;
```

Both work by path and are never wider than either side.

| Modes                            | Semantics                                                                                                                                                                                       |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `desired` is `{}` or `undefined` | Use `accessControl` as-is.                                                                                                                                                                      |
| `accessControl` is `{}`          | Use `desired` as-is.                                                                                                                                                                            |
| Both include                     | Keep a key the other side includes (itself or a parent). If the other side only includes its children, keep those instead: `{ a: 1 }` ∩ `{ "a.b": 1 }` → `{ "a.b": 1 }`.                        |
| Both exclude                     | Union the key sets.                                                                                                                                                                             |
| Include ∩ exclude                | Drop included keys the exclusion hides (itself or a parent). An included parent with a hidden child (`{ a: 1 }` ∩ `{ "a.c": 0 }`) is split with `childrenOf`; without it the parent is dropped. |

When no field survives (`{ a: 1 }` ∩ `{ a: 0 }`, or disjoint whitelists), `intersectProjections` returns `null` and `restrictProjection` returns `accessControl` itself. An empty `{}` would mean "every field".

`expandExcludeToLeaves(projection, childrenOf)` rewrites an exclusion so each excluded nested-object parent is named by its leaves (`{ a: 0 }` → `{ "a.b": 0, "a.c": 0 }`). Use it before handing an exclusion to a storage adapter that flattens nested objects into columns.

`childrenOf(path)` returns a nested-object path's direct child paths from your schema (`"a"` → `["a.b", "a.c"]`, `[]` for a leaf).

::: warning Conjoining two ceilings
`restrictProjection` falls back to `accessControl` because that side is the ceiling. To intersect two policies, for example a user's and a credential's, use `intersectProjections` and treat `null` as "no field": deny the rows. Never fall back to either side.
:::

Use this in your query handler **after** unioning per-role projections via `unionProjections`. The two-step recipe:

```ts
const acProjection = unionProjections(...evalResult.scopes.map((s) => s.projection ?? {}));
const queryProjection = restrictProjection(req.query.fields, acProjection);
```

## `unionControlsPolicy`

Specific to `ArbacDbScope.controls` — gates Uniquery URL controls (`$with`, `$groupBy`, `$having`, `$select`, etc.) per role.

```ts
function unionControlsPolicy(
  scopes: ReadonlyArray<Pick<ArbacDbScope, "controls">>,
): Record<string, ControlGate>;

type ControlGate = boolean | readonly string[];
```

### `ControlGate` semantics

| Value               | Meaning                                                  |
| ------------------- | -------------------------------------------------------- |
| `true` (or absent)  | Control is allowed. Equivalent to omitting the key.      |
| `false`             | Control is denied.                                       |
| `readonly string[]` | Only the listed values are allowed. Whitelist semantics. |

`string[]` is **only** legal for `$with` and `$groupBy`. Using a whitelist for any other control throws.

### Resolution per control key

| Scenario across all input scopes            | Result for that key                                 |
| ------------------------------------------- | --------------------------------------------------- |
| Any scope omits the `controls` map entirely | `{}` (silent = full grant — see below)              |
| Any scope says `true` (or omits the key)    | Key dropped from result (absent ≡ allowed)          |
| All say `false`                             | `false` (full deny)                                 |
| Some say `false`, some say `string[]`       | Union of the whitelist arrays, sorted, deduplicated |
| All say `string[]`                          | Union of whitelists, sorted, deduplicated           |

::: warning Silence wins, globally
If **any** input scope lacks a `controls` map entirely, `unionControlsPolicy` returns `{}` — i.e. _every_ control is allowed for _every_ key. The "silence" is interpreted as "this role doesn't care, so it doesn't restrict". To actually restrict controls, every contributing role must declare a `controls` map (even an empty one).
:::

### Examples

```ts
import { unionControlsPolicy } from "@aooth/arbac";

// One role with no controls map → all controls allowed.
unionControlsPolicy([
  { controls: { $with: ["author"] } },
  {}, // no controls key at all
]);
// → {}

// Both roles deny $groupBy explicitly; second role whitelists $with.
// First scope is silent on $with (the key isn't present in its controls map) —
// silence = allow, so the $with key drops out of the result.
unionControlsPolicy([
  { controls: { $groupBy: false } },
  { controls: { $groupBy: false, $with: ["author"] } },
]);
// → { $groupBy: false }

// Both roles whitelist $with — union the arrays.
unionControlsPolicy([
  { controls: { $with: ["author"] } },
  { controls: { $with: ["comments", "author"] } },
]);
// → { $with: ['author', 'comments'] }   // sorted, deduplicated

// Mix of deny + whitelist for $with.
unionControlsPolicy([{ controls: { $with: false } }, { controls: { $with: ["author"] } }]);
// → { $with: ['author'] }   // whitelist union; the deny dissolves
```

## Putting it together

`effectiveScope` applies every per-facet union above to a whole scope list at once (lazily, memoized per array), and `normalizeScopes` turns an evaluation outcome into that list with the empty-scope rule (denied or nothing left → `undefined`; allowed without a `scopes` list → unrestricted; a `scope` function returning nothing contributes nothing). Since 0.1.72:

```ts
import {
  Arbac,
  conjoinScopeFilters,
  effectiveScope,
  normalizeScopes,
  restrictProjection,
} from "@aooth/arbac";

const scopes = normalizeScopes(
  await arbac.evaluate({ resource: "articles", action: "query" }, user),
);
if (!scopes) throw new ForbiddenError();

const eff = effectiveScope(scopes);
const rows = await db.find({
  filter: conjoinScopeFilters(eff.filter, req.query.filter), // never spread
  fields: restrictProjection(req.query.fields, eff.projection),
  controls: eff.controls,
});
```

To combine two independent constraints restrict-only (a credential's narrowed view over the user's ceiling), use `conjoinScopes(userScopes, credScopes)` — never the unions. Signatures: [API reference](/api/arbac#functions-db-scope-algebra).

## Custom scope fields

Apps may add their own keys to the scope type by declaration merging and read them from `useArbac().getScopes()` / `evaluate()` with their own union rule — typically "a scope without the field is unrestricted". The framework never reads them unless you register a rule, and hands them over untouched.

Where two scope lists are **conjoined** into one composite scope — credential [attenuation](./attenuation), and the `$with` conjunctions it triggers — the algebra cannot guess a custom field's meaning. Register its rule once per field (since 0.1.72):

```ts
declare module "@aooth/arbac-moost" {
  interface ArbacDbScope {
    regions?: string[]; // absent = every region
  }
}

const regionsOf = (side: readonly ArbacDbScope[]) =>
  side.some((s) => s.regions === undefined) ? undefined : new Set(side.flatMap((s) => s.regions!));

arbac.registerScopeFields({
  regions: {
    // a = the user's full authority, b = the credential's view; return ONE value, never wider
    conjoin(a, b) {
      const ra = regionsOf(a);
      const rb = regionsOf(b);
      if (!ra) return rb && [...rb];
      if (!rb) return [...ra];
      return [...ra].filter((r) => rb.has(r));
    },
  },
});
```

The composite carries the returned value (`undefined` = unrestricted, the key is omitted), in `with` sub-scopes too. A custom field present in a conjunction **without** a rule is a server configuration error: the request fails with a generic `500` (no field names in the response; the details are logged server-side once) — never served with the field dropped, which would read as unrestricted. Outside Moost, pass the rules as `conjoinScopes(a, b, { fields })`; it throws `ScopeFieldConfigError`. Signatures: [`registerScopeFields`](/api/arbac-moost#moostarbac-tuserattrs-tscope), [`TScopeFieldRule`](/api/arbac#tscopefieldrule-s-tscopefieldrules-s).

### Fields that restrict rows — `rowFilter`

When a custom field narrows which ROWS a scope reaches (a triage role may only act on its teams' rows), give its rule a `rowFilter`. The framework then enforces it on every row path: reads, the `@DbAction` gate, `/meta`, write USING and the default WITH CHECK, `checkRefs` targets and `$with` inherited grants.

```ts
arbac.registerScopeFields({
  teams: {
    conjoin: (a, b) => intersectTeams(a, b), // as above
    rowFilter: (teams) => ({ teamId: { $in: teams as string[] } }), // undefined / {} = no restriction
  },
});

defineRole<Attrs, ArbacDbScope>()
  .id("triage")
  .use(allowTableWrite("tickets", { scope: (a) => ({ teams: a.teams }) }));
```

Right after evaluation (inside `MoostArbac.evaluate`, so direct engine calls get it too), each scope that carries the field gets `filter = filter ∧ rowFilter(value, scope)`, also inside its `with` sub-scopes. This happens per scope, before the union across roles and before any attenuation conjunction. A role without the field stays unrestricted, so `leadership` (no `teams`) + `triage` (`teams: ["A"]`) reads leadership's rows plus team A's rows. The raw value stays on the scope for your own code.

- An absent `check` follows the folded filter (the RLS default), so an update that moves a row out of the caller's teams is rejected with 403.
- An explicit `check` is left **as written**. If you set one, include the team condition yourself (`check: {}` disables the check entirely).
- `rowFilter` must depend **only** on `(value, scope)`, never on the request (current user, headers). Its result is cached process-wide per scope object. Put user-dependent data into the field's value from the role's scope function (`scope: (attrs) => ({ teams: attrs.teams })`).
- The result may be a [relational predicate](/moost/db-controllers#relational-filter-predicates-some-none) (atscript-db ≥ 0.1.147) — e.g. `(teams) => ({ ticket: { $some: { teamId: { $in: teams as string[] } } } })` bounds issues by their ticket's team. Unions (`$or`) and attenuation (`$and`) treat it like any filter. Since 0.1.74. On an adapter without real transactions the default WITH CHECK then fails closed (403) — see the linked section.
- `MoostArbac` warns once, at evaluation, about a custom scope key with no registered rule. Such a key would otherwise fail the first attenuated request with 500.

## Gotchas

- **Empty filter is universe.** Treating `{}` as "match nothing" would be wrong here — `mergeScopeFilters` returns `undefined` whenever the union widens to no-constraint.
- **Mixed `1`/`0` in a single projection throws.** Choose include or exclude per projection. Across projections, mix freely.
- **`unionControlsPolicy` returns `{}` if _any_ input is silent on `controls`.** To restrict, every role must declare a controls map.
- **`string[]` whitelists are only valid for `$with` and `$groupBy`.** Other control keys must be `true` / `false`.
- **Register a conjunction rule for every custom scope field** a role can return — an attenuated request that meets an unregistered one fails with 500. See [Custom scope fields](#custom-scope-fields).
- **A custom field restricts rows only with a `rowFilter`.** Without one, reads, actions and writes ignore it; only your own code sees it.
- **Map a missing filter to `{}`, don't drop it.** `mergeScopeFilters(scopes.map((s) => s.filter ?? {}))` — filtering out scopes without a filter would drop an unrestricted role and narrow the union (`effectiveScope` does this for you).

## Next

- [Codegen](./codegen) — generate TS unions for `Resource` and `Action` so you can type `resource: TArbacResource` instead of `string`.
- [Moost → ARBAC Authorize](/moost/arbac-authorize) — how `@aooth/arbac-moost` wires `ArbacDbScope` into request handlers.
