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

| Hook                              | What it does                                                                                                                                                                                                                                                                                                                                                          |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `transformFilter(filter)`         | Calls `arbac.evaluate<ArbacDbScope>()` once per event, caches scopes via `arbac.setScopes`, merges user filter with the **UNION of scope filters** using `$and: [merged, userFilter]` (never object spread). On deny returns a match-nothing filter (`{ $or: [] }`).                                                                                                  |
| `transformProjection(projection)` | Unions per-scope `projection` whitelists and `restrictProjection`s the user projection to that union.                                                                                                                                                                                                                                                                 |
| `validateControls(controls, ...)` | Runs the parent validator; then invokes `enforceControlsPolicy(unionControlsPolicy(scopes), controls)`. Violations throw `HttpError(403)`.                                                                                                                                                                                                                            |
| `applyMetaOverlay(meta)`          | For `/meta`, evaluates ARBAC in parallel for every declared action and CRUD op, filters `meta.actions` and `meta.crud` so the UI only sees ops the caller can invoke — then **prunes the field surface** (`fields`, the serialized `type`, `relations`, `versionColumn`) to the union of the allowed read ops' scope projections. Memoized per-class action-meta map. |
| `hasField(path)`                  | Scope-aware field visibility — moost-db's visibility hook, consulted at every gated query position: paths outside the read-scope projection union answer `false`, so any reference to a hidden field gets the **identical** `Unknown field "x"` 400 a nonexistent field gets. See [Column-scope security floor](#column-scope-security-floor).                        |
| `onWrite(action, data)`           | For non-insert writes: `assertInScope(data, scopes)` first; then `applyAllowedFieldsAndSet(data, scopes, identifierFields)` strips fields outside the union of `allowedFields` (**auto-preserving PK + unique-index columns**) and overlays `set` defaults.                                                                                                           |
| `onRemove(id)`                    | `assertInScope(id, scopes)`.                                                                                                                                                                                                                                                                                                                                          |
| `assertInScope(idOrIds, scopes)`  | Issues `table.count` with `{ $and: [resolveIdFilter(id), mergedScopeFilter] }` and throws `HttpError(404, "Not found")` if not every id is in scope.                                                                                                                                                                                                                  |

::: tip A scope projection removes fields from EXISTENCE, not just from rows
With a constrained read projection, `/meta` no longer advertises the hidden fields (a table UI cannot even offer them as columns — previously they rendered as permanently-empty columns, and secret-bearing column NAMES leaked), and referencing one anywhere in a query (`$select`, a filter, a sort, a group, an aggregate) is indistinguishable from referencing a field that was never declared — see [Column-scope security floor](#column-scope-security-floor). PK + `preferredId` always stay visible — reads always return them (projection widening / id addressing). Unscoped read grants keep the full envelope; relations stay visible when projected **or** explicitly `with`-granted (their content is governed by the `with` sub-scope, not the projection).
:::

::: warning `$and: [scope, user]`, never object spread
A user filter may constrain the same field as the scope. Merging via `{ ...scope, ...userFilter }` lets the user's value **replace** the scope's — a reader scoped to `tenantId: 'a'` who asks for `tenantId: 'b'` would be served tenant b's rows. `$and` intersects instead, so the contradiction matches nothing.

Prefer `conjoinScopeFilters(scope, userFilter)` from `@aooth/arbac` over hand-rolling the wrap: it owns this invariant and treats an empty side as the identity.

Historically this was recorded as BUG-2 against `@uniqu/core`'s `walkFilter` dropping sibling field keys next to a logical operator. That short-circuit was fixed in `@uniqu/core` 0.1.8 (mixed field/logical nodes are an implicit AND) — **the rule still stands**, for the same-key reason above, which is independent of it.
:::

::: warning `assertInScope` MUST run before `onWrite` strips data
Without the pre-check, a caller knowing a row's primary key could mutate it past their scope filter (BUG-1). `AsArbacDbController.onWrite` calls `assertInScope(data, scopes)` first, then `applyAllowedFieldsAndSet(...)`. Custom subclasses MUST preserve this order.
:::

### Column-scope security floor

::: warning Column scopes need `@atscript/moost-db` ≥ 0.1.133 and the authorize interceptor
moost-db consults `hasField` at every gated query position: filter keys at any depth (`$exists` included), `$sort`, `$select`, `$groupBy`, `$having`, aggregate and calendar-bucket `$field`s, navigation paths, `$with` relation names and the `$search` fallback fields. 0.1.128–0.1.132 skipped it for stored columns, so a projection-scoped caller could filter, sort, group and aggregate on hidden columns — a value oracle, even though `$select` values stayed stripped. `@aooth/arbac-moost` releases after 0.1.66 peer on `^0.1.133`. If you override `hasField`, keep the `super` call.

`hasField` and `transformProjection`'s value stripping read the scopes [`arbacAuthorizeInterceptor`](./arbac-authorize) caches before the handler runs. Without it (globally or via `@ArbacAuthorize()`) column scopes fail open — hidden columns are queryable and returned. Guard every ARBAC DB controller with it.

Native full-text search and vector search (`$vector` names an index) run inside the database over their indexes, outside `hasField`'s reach — keep hidden columns out of those indexes. The `$search` fallback used when a table has no search index only matches fields the caller can see.
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
declare module "@aooth/arbac-moost" {
  interface ArbacDbScope {
    auditTag?: string;
    restrictRows?: number;
  }
}
```

## Control gates

`ControlGate` is `true | false | readonly string[]`. Semantics:

| Value               | Effect                                                                                                                                                                                                                                                                                                                |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `true`              | Allowed. Any value is acceptable.                                                                                                                                                                                                                                                                                     |
| `false`             | Denied. Throws `HttpError(403, 'Control "${name}" is not allowed for your role')`.                                                                                                                                                                                                                                    |
| `readonly string[]` | Whitelist. Values outside the list are rejected with 403. Supported for `$with` and `$groupBy`. A `$groupBy` whitelist lists **source fields**: a calendar-bucket alias (`$select=bucket(openedAt,week):week&$groupBy=week`) is checked as the field it buckets (`openedAt`), so whitelist `openedAt`, not the alias. |

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

Read-only mirror of `AsArbacDbController<T>`. Wires only the read hooks (`transformFilter`, `transformProjection`, `validateControls`, `applyMetaOverlay`, `hasField` — including the same `/meta` field pruning + `Unknown field` parity). Use it for view controllers and joined-table projections that should never accept writes.

::: tip Binding a `@db.view`
Bind view models with `@ReadableController(ViewModel)` from `@atscript/moost-db`. Both ARBAC controller classes are view-safe on every read path — the enforcement seams go through the bound readable surface, never the writable `.table` getter (which throws for view-bound controllers by moost-db design). Prefer `AsArbacDbReadableController` for pure dict/value-help views; a view bound through `AsArbacDbController` still serves all reads, and its write routes fail loudly at moost-db's `.table` guard.
:::

## Subclassing

The most common subclass overrides nothing and just plugs in a table — the table is bound by the `@TableController(table)` decorator from `@atscript/moost-db`, **not** by passing it through `super(...)`:

```ts
import { AsArbacDbController, ArbacResource } from "@aooth/arbac-moost";
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
    const tenantId = useAuth().getAuthContext<{ tenantId?: string }>()?.tenantId;
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
import { allowTableRead, allowTableWrite, defineRole } from "@aooth/arbac";
import type { ArbacDbScope } from "@aooth/arbac-moost";
import { Article } from "./article.as";

type UserAttrs = { tenantId: string; id: string };

const editor = defineRole<UserAttrs>()
  .id("editor")
  .use(
    allowTableRead<UserAttrs, ArbacDbScope<typeof Article>>("articles", {
      scope: (attrs) => ({ filter: { tenantId: attrs.tenantId } }),
    }),
    allowTableWrite<UserAttrs, ArbacDbScope<typeof Article>>("articles", {
      // ... see @aooth/arbac for the full allowTable* surface
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
