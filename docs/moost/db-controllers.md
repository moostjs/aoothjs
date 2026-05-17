# DB Controllers

This page documents `AsArbacDbController<T>` and `AsArbacDbReadableController<T>` — the `@atscript/moost-db`-derived controllers that auto-apply ARBAC scopes to CRUD endpoints. **The package does not own role/privilege storage** — there are no tables or migrations here. The controllers are pure hook overlays on top of `@atscript/moost-db`'s base classes.

## When to use them

Use `AsArbacDbController<T>` when:

- You expose a `.as`-annotated DB table over HTTP via `@atscript/moost-db`.
- You want ARBAC's `scope.filter` / `scope.projection` / `scope.set` / `scope.allowedFields` / `scope.controls` to be enforced automatically on every read / write / delete — without per-handler `getScopes()` plumbing.

Use `AsArbacDbReadableController<T>` when:

- The same, but read-only (view controllers, joined-table projections).

## `AsArbacDbController<T>` extends `AsDbController<T>`

The class wires four protected hooks of `@atscript/moost-db`'s base controller:

| Hook                              | What it does                                                                                                                                                                                                                                                         |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `transformFilter(filter)`         | Calls `arbac.evaluate<ArbacDbScope>()` once per event, caches scopes via `arbac.setScopes`, merges user filter with the **UNION of scope filters** using `$and: [merged, userFilter]` (never object spread). On deny returns a match-nothing filter (`{ $or: [] }`). |
| `transformProjection(projection)` | Unions per-scope `projection` whitelists and `restrictProjection`s the user projection to that union.                                                                                                                                                                |
| `validateControls(controls, ...)` | Runs the parent validator; then invokes `enforceControlsPolicy(unionControlsPolicy(scopes), controls)`. Violations throw `HttpError(403)`.                                                                                                                           |
| `applyMetaOverlay(meta)`          | For `/meta`, evaluates ARBAC in parallel for every declared action and CRUD op, filters `meta.actions` and `meta.crud` so the UI only sees ops the caller can invoke. Memoized per-class action-meta map.                                                            |
| `onWrite(action, data)`           | For non-insert writes: `assertInScope(data, scopes)` first; then `applyAllowedFieldsAndSet(data, scopes, identifierFields)` strips fields outside the union of `allowedFields` (**auto-preserving PK + unique-index columns**) and overlays `set` defaults.          |
| `onRemove(id)`                    | `assertInScope(id, scopes)`.                                                                                                                                                                                                                                         |
| `assertInScope(idOrIds, scopes)`  | Issues `table.count` with `{ $and: [resolveIdFilter(id), mergedScopeFilter] }` and throws `HttpError(404, "Not found")` if not every id is in scope.                                                                                                                 |

::: warning `$and: [scope, user]`, never object spread
`@uniqu/core`'s `walkFilter` short-circuits on logical operators. Merging via `{ ...scope, ...userFilter }` would silently drop scope conditions when the user filter has the same top-level keys. Always wrap as `$and: [scope, user]`.
:::

::: warning `assertInScope` MUST run before `onWrite` strips data
Without the pre-check, a caller knowing a row's primary key could mutate it past their scope filter (BUG-1). `AsArbacDbController.onWrite` calls `assertInScope(data, scopes)` first, then `applyAllowedFieldsAndSet(...)`. Custom subclasses MUST preserve this order.
:::

## `ArbacDbScope<T>` contract

```ts
interface ArbacDbScope<T = unknown> {
  filter?: TScopeFilter; // a Mongo-style filter merged into the read/delete/update WHERE
  projection?: ProjectionOf<T>; // a field-whitelist applied to read responses
  set?: Partial<Record<OwnFieldKey<T>, unknown>>; // default values overlaid onto inserts/updates
  allowedFields?: Array<OwnFieldKey<T>>; // whitelist of writable field paths
  controls?: ControlsOf<T>; // gate `$with` / `$groupBy` / etc.
  with?: WithOf<T>; // per-relation sub-scopes for `?$with=<name>` expansion
}
```

Pass an `.as` model as `T` (e.g. `ArbacDbScope<Task>`) to get autocomplete on `projection` / `with` / `controls` / `set` / `allowedFields` against the model's own and navigation fields. `T = unknown` (the default) keeps the legacy untyped `Record<string, ...>` shape for back-compat. Dotted-path projections on nested own-objects (e.g. `'mfa.value'`) still type-check via a `keyof | (string & {})` escape hatch.

### Per-relation `with` (recursive)

`with[name]` is a sub-scope applied when the request expands the `name` relation via `?$with=<name>`. Recursive — each sub-scope has the same shape and can declare its own `with` for nested expansions (`tasks → comments → task`).

**Parent-authority model**: the parent scope owns the policy for joined rows. arbac-moost does NOT re-evaluate ARBAC against the joined resource's own scopes — whatever the parent declares here is what surfaces from the expansion. Across roles, `with[name]` sub-scopes union additively at every nested level using the same primitives (`unionProjections` / `mergeScopeFilters` / `unionControlsPolicy`). **Silence wins**: if no role declares `with.<name>`, expansion is unrestricted (the `controls.$with` whitelist still applies if declared).

::: warning Known gap — joined-resource projection in exclude mode
arbac-moost does not apply the joined-resource projection mask to `$with` expansions when the request uses **exclude-mode** `$select` for the relation loader. Include-mode `$select` works end-to-end. Pin tight whitelists on the parent via `controls.$with` if exclude-mode masking is required.
:::

Apps can **declaration-merge** custom fields into `ArbacDbScope` — for example, to add a `restrictRows: number` cap or an `auditTag: string` you read in a custom subclass.

```ts
declare module "@aoothjs/arbac-moost" {
  interface ArbacDbScope {
    auditTag?: string;
    restrictRows?: number;
  }
}
```

## Control gates

`ControlGate` is `true | false | readonly string[]`. Semantics:

| Value               | Effect                                                                                          |
| ------------------- | ----------------------------------------------------------------------------------------------- |
| `true`              | Allowed. Any value is acceptable.                                                               |
| `false`             | Denied. Throws `HttpError(403, 'Control "${name}" is not allowed for your role')`.              |
| `readonly string[]` | Whitelist. Values outside the list are rejected with 403. Supported for `$with` and `$groupBy`. |

**Cross-role union**: when multiple roles match, the union is computed:

| Combination                                   | Result                                                     |
| --------------------------------------------- | ---------------------------------------------------------- |
| Any role has `true`                           | `true` (silence wins — more permissive role lifts denial). |
| All roles have `false`                        | `false`.                                                   |
| Some role has `string[]`, others have `false` | Union of all string lists (whitelists union additively).   |
| Multiple `string[]`                           | Union of all string lists.                                 |

### Control-gate enforcement table

| Caller sends             | Scope `$with`            | Outcome                    |
| ------------------------ | ------------------------ | -------------------------- |
| `?$with=author`          | `true`                   | Allowed.                   |
| `?$with=author`          | `false`                  | 403.                       |
| `?$with=author`          | `['comments']`           | 403 (not in whitelist).    |
| `?$with=author,comments` | `['comments', 'author']` | Allowed.                   |
| `?$with=` (omitted)      | `false`                  | Allowed (no control sent). |

## `AsArbacDbReadableController<T>`

Read-only mirror of `AsArbacDbController<T>`. Wires only the read hooks (`transformFilter`, `transformProjection`, `validateControls`, `applyMetaOverlay`). Use it for view controllers and joined-table projections that should never accept writes.

## Subclassing

The most common subclass overrides nothing and just plugs in a table — the table is bound by the `@TableController(table)` decorator from `@atscript/moost-db`, **not** by passing it through `super(...)`:

```ts
import { AsArbacDbController, ArbacResource } from "@aoothjs/arbac-moost";
import { TableController } from "@atscript/moost-db";
import type { AtscriptDbTable } from "@atscript/db";
import { Article } from "./article.as";

export function makeArticlesController(table: AtscriptDbTable<typeof Article>) {
  @TableController(table)
  @ArbacResource("articles")
  class ArticlesController extends AsArbacDbController<typeof Article> {}
  return ArticlesController;
}
```

For a custom secondary check (e.g. enforce a tenant filter even when no scope is configured), override one of the hooks and call `super` first:

```ts
@TableController(table)
@ArbacResource("articles")
class ArticlesController extends AsArbacDbController<typeof Article> {
  protected override async transformFilter(filter) {
    const merged = await super.transformFilter(filter);
    const tenantId = useAuth().getAuthContext()?.claims?.tenantId;
    if (!tenantId) throw new HttpError(403, "Missing tenant");
    return { $and: [merged, { tenantId }] };
  }
}
```

## Cross-controller scope reads

Inside a custom handler that's not a hook, read scopes via `useArbac().getScopes<ArbacDbScope>()`:

```ts
@Controller("articles")
class ArticlesController extends AsArbacDbController<Article> {
  @Get("custom-summary")
  @ArbacAction("read")
  async customSummary() {
    const scopes = useArbac().getScopes<ArbacDbScope>();
    // hand-write a query using `scopes` directly
  }
}
```

`useArbac().getScopes()` returns whatever the GUARD-priority interceptor previously set — including when this controller's own `transformFilter` ran a few microseconds earlier on the same event and cached scopes via `arbac.setScopes`.

## Tuning ARBAC roles for DB controllers

A typical role tuned for `AsArbacDbController`:

```ts
import { allowTableRead, allowTableWrite, defineRole } from "@aoothjs/arbac";
import type { ArbacDbScope } from "@aoothjs/arbac-moost";
import { Article } from "./article.as";

type UserAttrs = { tenantId: string; id: string };

const editor = defineRole<UserAttrs>()
  .id("editor")
  .use(
    allowTableRead<UserAttrs, ArbacDbScope<typeof Article>>("articles", {
      scope: (attrs) => ({ filter: { tenantId: attrs.tenantId } }),
    }),
    allowTableWrite<UserAttrs, ArbacDbScope<typeof Article>>("articles", {
      // ... see @aoothjs/arbac for the full allowTable* surface
    }),
  )
  .deny("articles", "delete")
  .build();
```

Note: typed scopes are passed **per-privilege** (the `ArbacDbScope<Article>` generic on `allowTable*`). Don't pin a single `ArbacDbScope<X>` at the `defineRole<UserAttrs, ArbacDbScope<X>>()` level — `ArbacDbScope<T>` is not assignable to `ArbacDbScope<unknown>` across `allowTable*` calls. The role-level generic stays as the untyped upper bound.

| Scope field                            | What it does at runtime                                                                 |
| -------------------------------------- | --------------------------------------------------------------------------------------- |
| `filter: { tenantId: attrs.tenantId }` | Every read/update/delete is wrapped in `$and: [filter, userFilter]`.                    |
| `set: { tenantId, ownerId }`           | Every insert/update has these defaults overlaid (caller can't fake `tenantId`).         |
| `allowedFields: ["title", "body"]`     | Every update strips fields outside this list. PK + unique-index columns auto-preserved. |
| `controls: { $with: false }`           | Caller can't expand joined relations on this resource.                                  |
| `projection: ['id', 'title']`          | Read responses are whitelisted to these fields only.                                    |

## Identifier auto-preservation

`applyAllowedFieldsAndSet` always preserves keys from `table.identifications` — your primary key, every column in a `@db.table.uniqueIndex` group, etc. This means a scope like `allowedFields: ["title"]` doesn't accidentally strip the `id` from an update payload, which would silently break the update.

## Deny verdict (match-nothing)

On a deny verdict, `transformFilter` returns a match-nothing filter (`{ $or: [] }`). The controller does this whenever:

- `arbac.evaluate()` returns `{ allowed: false }`.
- The action resolution chain produces a name with no role grant.

Match-nothing produces an empty result set on read (200 with an empty array) and zero affected rows on write — fail-closed without surfacing a 403 to the caller for queries that legitimately return no rows. The constant itself is internal to the package — don't import it; the observable behavior is what's contracted.

## See also

- [ARBAC Authorize](./arbac-authorize) — the upstream interceptor that produces the scopes.
- [Atscript Models](./atscript) — the `.as`-annotated user model that drives `getRoles` / `getAttrs`.
- [Config Reference](./config) — workflow-level options. Role tuning is framework-agnostic, see [/arbac](../arbac/) for the engine.
