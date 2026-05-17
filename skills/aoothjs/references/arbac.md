# @aoothjs/arbac & @aoothjs/arbac-core

## Quick start

```ts
import {
  Arbac,
  defineRole,
  allowTableRead,
  mergeScopeFilters,
  unionProjections,
} from "@aoothjs/arbac";

type Attrs = { dept: string };
type Scope = { dept: string };

const manager = defineRole<Attrs, Scope>()
  .id("manager")
  .name("Department Manager")
  .use(allowTableRead("articles", { scope: (a) => ({ dept: a.dept }) }))
  .allow("comments", "moderate")
  .deny("articles", "publish")
  .build();

const arbac = new Arbac<Attrs, Scope>();
arbac.registerRole(manager);

const user = { id: "u1", roles: ["manager"], attrs: { dept: "sales" } };

const r = await arbac.evaluate({ resource: "articles", action: "query" }, user);
// r = { allowed: true, scopes: [{ dept: "sales" }] }

const denied = await arbac.evaluate({ resource: "articles", action: "publish" }, user);
// denied = { allowed: false }   // no `scopes` key

// Caller merges the scopes UNION-style:
mergeScopeFilters([{ dept: "sales" }, { dept: "marketing" }]);
// → { dept: { $in: ["sales", "marketing"] } }

unionProjections({ name: 1, email: 1 }, { secret: 0 });
// → { secret: 0 }   // includes cover the universe minus `secret`
```

## Invariants

| #   | Rule                                                                                                                                                                                                                                                                                                                                                                                                          |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Deny wins, period.** The engine runs the deny pass before the allow pass and short-circuits on the first match. No specificity weighting — a wildcard `deny` voids an exact-match `allow`. Caller-side ordering of `.allow()` / `.deny()` in a role does not change this.                                                                                                                                   |
| 2   | **Empty resolved roles → `{ allowed: false }` with NO `scopes` key.** `allowed: false` never carries `scopes` (not even `[]`). Conversely, `allowed: true` always carries `scopes` (possibly `[{}]`). Branch on `if (r.allowed)` and trust the discriminator.                                                                                                                                                 |
| 3   | **Universe sentinel `{}`.** An allow rule with NO `scope` fn pushes `{}` into the `scopes` array. Callers MUST interpret a `{}` element as "no restriction" — i.e. it widens the UNION to cover everything.                                                                                                                                                                                                   |
| 4   | **Scopes are UNION at the caller layer.** The engine concatenates every matching allow rule's scope into `scopes: TScope[]`. More roles = broader access (additive RBAC). Use `mergeScopeFilters` / `unionProjections` / `unionControlsPolicy` to fold the array into a single filter / projection / gate.                                                                                                    |
| 5   | **`userId` is stringified before scope fns.** The engine calls `rule.scope(userAttrs, String(user.id))`. Numeric IDs become strings inside scope callbacks; type them as `string` in your factories.                                                                                                                                                                                                          |
| 6   | **Rule order in `.build()` is preserved.** The builder pushes rules in call order; `.use(p1, p2)` splices each privilege's rules in-line. Order doesn't affect deny-wins, but it is observable when inspecting the emitted `TArbacRole`.                                                                                                                                                                      |
| 7   | **`.id()` is required.** Calling `.build()` without `.id()` throws `"Role id is required. Call .id() before .build()."`. The last `.id(x)` call wins.                                                                                                                                                                                                                                                         |
| 8   | **`definePrivilege` is a double-call factory.** First `()` binds `<TUserAttrs, TScope>`; second `(factory)` accepts `(...args) => TArbacRule[]`. Forgetting the first `()` defeats generic pinning and types collapse to `unknown`.                                                                                                                                                                           |
| 9   | **No `scope` key is emitted when scope is omitted.** `.allow(r, a)` produces `{ resource, action }` — `scope` is absent, not `undefined`. Code that checks `'scope' in rule` is meaningful.                                                                                                                                                                                                                   |
| 10  | **`getProjectionMode` throws on mixed 1/0 in ONE projection.** A single projection `{a: 1, b: 0}` is rejected. ACROSS projections (`unionProjections({a:1}, {b:0})`) the mix is legal and well-defined.                                                                                                                                                                                                       |
| 11  | **Empty filter / empty projection = universal grant.** In any merge, `{}` short-circuits: `mergeScopeFilters([..., {}, ...]) === undefined`, `unionProjections(..., {}, ...) === {}`. Treat `{}` as "no constraint", not "match nothing".                                                                                                                                                                     |
| 12  | **`unionControlsPolicy` returns `{}` if ANY input scope omits `controls` entirely.** Silent-on-everything = full grant. Only when every scope opts into a `controls` map does per-key merging kick in.                                                                                                                                                                                                        |
| 13  | **CLI codegen needs runnable JS, not TS, for `--roles`.** `aoothjs-arbac-codegen --roles dist/roles.mjs ...` — build your roles file first, then run codegen as a `pretsc` step or against `dist/`.                                                                                                                                                                                                           |
| 14  | **`allowTableAction(r, 'x')` ≡ `allowTableAction(r, ['x'])`.** Single name and `[name]` are interchangeable; both emit one rule per name with the same shared scope.                                                                                                                                                                                                                                          |
| 15  | **Action `*` matches anything WITHOUT a dot.** Single `*` is single-segment (`[^.]*`); use `**` for dotted actions like `db.read`. Same rule applies to resource patterns. The `.` separator is hard-coded in `arbacPatternToRegex`.                                                                                                                                                                          |
| 16  | **`.use()` accepts a mix of typed-scope privileges in one call — per-privilege scopes can be mixed.** A single `.use(...)` call accepts `ArbacDbScope<Task>`, `ArbacDbScope<Comment>`, etc., each carrying its own scope shape. The role-level `TScope` pin (`defineRole<Attrs, ArbacDbScope>()`) is upper-bound documentation of evaluate-time shape, not a structural assignability gate on each privilege. |

## Key imports

```ts
// Engine (zero-dep — re-exported by @aoothjs/arbac)
import { Arbac, arbacPatternToRegex } from "@aoothjs/arbac";
import type {
  TArbacRole,
  TArbacRule,
  TArbacEvalResult,
  TArbacCompiledRule,
  TArbacRoleForResource,
} from "@aoothjs/arbac";

// Builder
import { defineRole } from "@aoothjs/arbac";
import type { RoleBuilder } from "@aoothjs/arbac";

// Privilege factories
import { definePrivilege, allowTableRead, allowTableWrite, allowTableAction } from "@aoothjs/arbac";
import type { TPrivilegeFunction } from "@aoothjs/arbac";

// Scope merging
import {
  mergeScopeFilters,
  unionProjections,
  restrictProjection,
  getProjectionMode,
  isFieldAllowed,
  unionControlsPolicy,
} from "@aoothjs/arbac";
import type { ControlGate, TProjection, TProjectionMode, TScopeFilter } from "@aoothjs/arbac";

// NOTE: `ArbacDbScope` (the shape consumed by `AsArbacDbController`) is exported from
// `@aoothjs/arbac-moost`, not from this package. The merge utilities above operate on
// its `filter` / `projection` / `controls` fields.

// Codegen — library API
import { extractResourceActions, generateResourceTypes } from "@aoothjs/arbac";
import type { TCodegenOptions, TResourceActionMap } from "@aoothjs/arbac";

// Codegen — CLI is installed via `bin`: `aoothjs-arbac-codegen`
```

## References — load only what's needed

| Domain           | File                                     | When                                                                                                                                                         |
| ---------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| First contact    | [getting-started.md](getting-started.md) | Install, smallest end-to-end example, vocabulary table (role/rule/resource/scope/universe sentinel), `*` vs `**` wildcard matching with examples             |
| Engine + builder | [builder.md](./builder.md)               | `Arbac` class lifecycle, `defineRole().id/.name/.describe/.allow/.deny/.use/.build`, `definePrivilege` double-call pattern, `allowTable*` action vocabulary  |
| Scope merging    | [scopes.md](./scopes.md)                 | `mergeScopeFilters` (`$in` optimization + `$or` fallback), `unionProjections` truth table, `restrictProjection`, `unionControlsPolicy`, `ArbacDbScope` shape |
| Codegen          | [codegen.md](./codegen.md)               | `extractResourceActions`, `generateResourceTypes`, the `aoothjs-arbac-codegen` CLI, build-step (`pretsc`) wiring, wildcard handling, sample output           |

## See also

Reference docs: https://aoothjs.dev/arbac/. Source: https://github.com/moostjs/aoothjs.
