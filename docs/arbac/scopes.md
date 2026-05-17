# Scope Merging

This page answers: _the engine returned `scopes: TScope[]` for a user with multiple roles — now how do I turn that into one filter, one projection, and one set of Uniquery controls to apply at query time?_ It documents the scope-merge utilities in [`@aoothjs/arbac`](https://github.com/moostjs/aoothjs/tree/main/packages/arbac).

All three utilities operate under **additive RBAC**: when a user has multiple matching roles, the _broader_ access wins. An empty filter, an empty projection, or a missing controls map signals "no restriction" and short-circuits the union.

## The `ArbacDbScope` shape

The Moost integration uses a conventional scope shape with five keys. The utilities on this page are designed around it, though each one operates on its own piece in isolation:

```ts
interface ArbacDbScope {
  filter?: TScopeFilter; // row filter (Uniquery-compatible)
  projection?: TProjection; // field visibility map
  set?: Record<string, unknown>; // forced field values on write
  allowedFields?: readonly string[]; // additional whitelist
  controls?: Record<string, ControlGate>; // per-control Uniquery gate
}
```

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
import { mergeScopeFilters } from "@aoothjs/arbac";

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

The intuition: **inclusions widen** (any role granting a field wins), **exclusions narrow** (a field must be excluded by _every_ role to stay excluded).

### Examples

```ts
import { unionProjections } from "@aoothjs/arbac";

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
  desired: TProjection | undefined,
  accessControl: TProjection,
): TProjection;
```

| Modes                            | Semantics                                                       |
| -------------------------------- | --------------------------------------------------------------- |
| `desired` is `{}` or `undefined` | Use `accessControl` as-is.                                      |
| `accessControl` is `{}`          | Use `desired` as-is.                                            |
| Both include                     | Intersect the key sets.                                         |
| Both exclude                     | Union the key sets.                                             |
| Mixed                            | Filter through `isFieldAllowed` to drop fields the AC excludes. |

Use this in your query handler **after** unioning per-role projections via `unionProjections`. The two-step recipe:

```ts
const acProjection = unionProjections(...evalResult.scopes.map((s) => s.projection ?? {}));
const queryProjection = restrictProjection(req.query.fields, acProjection);
```

## `unionControlsPolicy`

Specific to `ArbacDbScope.controls` — gates Uniquery URL controls (`$with`, `$groupBy`, `$having`, `$select`, etc.) per role.

```ts
function unionControlsPolicy(
  ...scopes: Pick<ArbacDbScope, "controls">[]
): Record<string, ControlGate>;

type ControlGate = true | false | readonly string[];
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
import { unionControlsPolicy } from "@aoothjs/arbac";

// One role with no controls map → all controls allowed.
unionControlsPolicy(
  { controls: { $with: ["author"] } },
  {}, // no controls key at all
);
// → {}

// Both roles deny $groupBy explicitly.
unionControlsPolicy(
  { controls: { $groupBy: false } },
  { controls: { $groupBy: false, $with: ["author"] } },
);
// → { $groupBy: false }   // $with absent because second scope's array is implicit-allow when first is silent? See note.

// Both roles whitelist $with — union the arrays.
unionControlsPolicy(
  { controls: { $with: ["author"] } },
  { controls: { $with: ["comments", "author"] } },
);
// → { $with: ['author', 'comments'] }   // sorted, deduplicated

// Mix of deny + whitelist for $with.
unionControlsPolicy({ controls: { $with: false } }, { controls: { $with: ["author"] } });
// → { $with: ['author'] }   // whitelist union; the deny dissolves
```

## Putting it together

Typical query-time pipeline:

```ts
import {
  Arbac,
  mergeScopeFilters,
  unionProjections,
  restrictProjection,
  unionControlsPolicy,
} from "@aoothjs/arbac";

const r = await arbac.evaluate({ resource: "articles", action: "query" }, user);
if (!r.allowed) throw new ForbiddenError();

const filter = mergeScopeFilters(r.scopes.map((s) => s.filter).filter(Boolean));
const acProjection = unionProjections(...r.scopes.map((s) => s.projection ?? {}));
const projection = restrictProjection(req.query.fields, acProjection);
const controls = unionControlsPolicy(...r.scopes);

const rows = await db.find({
  filter: { ...req.query.filter, ...filter },
  fields: projection,
  controls,
});
```

The three utilities run in parallel — they don't depend on each other. The order in the snippet is just readability.

## Gotchas

- **Empty filter is universe.** Treating `{}` as "match nothing" would be wrong here — `mergeScopeFilters` returns `undefined` whenever the union widens to no-constraint.
- **Mixed `1`/`0` in a single projection throws.** Choose include or exclude per projection. Across projections, mix freely.
- **`unionControlsPolicy` returns `{}` if _any_ input is silent on `controls`.** To restrict, every role must declare a controls map.
- **`string[]` whitelists are only valid for `$with` and `$groupBy`.** Other control keys must be `true` / `false`.
- **`mergeScopeFilters` ignores `undefined` only for empty arrays.** Filter out the undefineds yourself (`.filter(Boolean)`) before passing — the function expects `TScopeFilter[]` shapes.

## Next

- [Codegen](./codegen) — generate TS unions for `Resource` and `Action` so you can type `resource: TArbacResource` instead of `string`.
- [Moost → ARBAC Authorize](/moost/arbac-authorize) — how `@aoothjs/arbac-moost` wires `ArbacDbScope` into request handlers.
