# db-controllers

`AsArbacDbController` and `AsArbacDbReadableController` — Moost-DB controllers that enforce per-row scope on reads, writes, removes, and `/meta`. **No tables or migrations live here** — the package does not own role/privilege storage.

## Contents

- [`AsArbacDbController<T>` / `AsArbacDbReadableController<T>`](#asarbacdbcontrollert--asarbacdbreadablecontrollert)
- [Protected hook table](#protected-hook-table)
- [`ArbacDbScope` contract](#arbacdbscope-contract)
- [Control-gate semantics](#control-gate-semantics)
- [Multi-role union](#multi-role-union)
- [Deny verdict (match-nothing)](#deny-verdict-match-nothing)
- [Identifier auto-preservation](#identifier-auto-preservation)
- [Wiring example](#wiring-example)

## `AsArbacDbController<T>` / `AsArbacDbReadableController<T>`

`AsArbacDbController<T>` extends `AsDbController<T>` from `@atscript/moost-db`. Adds ARBAC enforcement via the six protected seams on `AsDbController`. Use for tables with both read and write access. `AsArbacDbReadableController<T>` extends `AsDbReadableController<T>` — view-only counterpart, only read-side seams.

Both classes work over `@db.view` models too (bind with `@ReadableController(ViewModel)`): every read-side seam goes through the bound READABLE surface, never the writable `.table` getter (which throws for view-bound controllers by moost-db design). Prefer `AsArbacDbReadableController` for pure dict/value-help views; the writable class over a view is also safe for reads — its write routes fail loudly at moost-db's `.table` guard, which is the intended contract.

Both controllers call `useArbac().evaluate<ArbacDbScope>()` exactly once per event, cache scopes via `useArbac().setScopes()`, then apply per-operation enforcement using the cached array.

## Protected hook table

| Hook                              | When                             | Behavior                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| --------------------------------- | -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `transformFilter(filter)`         | Every read query                 | Merges user filter with union of scope filters as `$and: [merged, userFilter]` — **never object spread** (walkFilter short-circuits on logical operators). On deny returns a match-nothing filter (`{ $or: [] }`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `transformProjection(projection)` | Every read query                 | Unions per-scope `projection` whitelists and `restrictProjection`s the user projection to that union. Empty union → unrestricted.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `validateControls(controls, ...)` | Every read with `controls.*`     | Runs the parent validator first; then invokes `enforceControlsPolicy(unionControlsPolicy(scopes), controls)`. Violations throw `HttpError(403, 'Control "$with" is not allowed for your role')`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `applyMetaOverlay(meta)`          | `/meta` requests                 | Evaluates ARBAC in parallel for every declared action and CRUD op; filters `meta.actions` and `meta.crud`, then PRUNES the field surface (`fields`, serialized `type`, `relations`, `versionColumn`) by the union of the allowed read ops' scope projections (BUG-3) — a scoped UI cannot even offer hidden columns. PK + `preferredId` always survive; unscoped read grant → full envelope; NO read op allowed → field surface untouched (write-only forms need `type`). Relations survive when projected OR `with`-granted. Since 0.1.57, fields in the caller's WRITE scopes' `allowedFields` union (or any field under an unrestricted/whitelist-free write grant) that fall OUTSIDE the read projection are STAMPED instead of pruned: they stay in `fields` as `{ writeOnly: true, filterable: false, sortable: false }` and in the serialized `type` with `db.writeOnly` metadata (subtree kept whole) — generic forms can SET sealed fields the caller can never read. Shared impl: `applyArbacMetaOverlay(meta, alwaysVisible)`. |
| `hasField(path)`                  | `validateInsights` (field refs)  | Scope-aware existence (BUG-3 twin): paths outside the read-projection union answer `false` → `$select`/filter/sort on a hidden field throws the IDENTICAL `Unknown field "x"` 400 a nonexistent field gets (no existence/value oracle). Identifiers always pass; `with`-granted relation subpaths pass through to sub-scope enforcement.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `onWrite(action, data)`           | `insertOne` / `updateOne` / etc. | For **non-insert** writes calls `assertInScope(data, scopes)`; then calls `applyAllowedFieldsAndSet(data, scopes, identifierFields)` to strip fields outside the union of `allowedFields` (auto-preserving PK + unique-index columns) and overlay `set` defaults. **`assertInScope` MUST run before `applyAllowedFieldsAndSet`** — otherwise a caller knowing the PK could mutate past their filter (BUG-1).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `onRemove(id)`                    | `deleteOne`                      | `assertInScope(id, scopes)`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `assertInScope(idOrIds, scopes)`  | Reused by `onWrite` + `onRemove` | Issues a `readable.count` with `{ $and: [resolveIdFilter(id), mergedScopeFilter] }` and throws `HttpError(404, 'Not found')` if not every id is in scope. **Returns 404, not 403, to hide existence.**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |

The read-only controller exposes only `transformFilter`, `transformProjection`, `validateControls`, `applyMetaOverlay`, `hasField` (same meta pruning + Unknown-field parity).

## `ArbacDbScope<T>` contract

`ArbacDbScope<T = unknown>` — every field optional:

| Field            | Type                                       | Default | Meaning                                      |
| ---------------- | ------------------------------------------ | ------- | -------------------------------------------- |
| `filter?`        | `TScopeFilter`                             | —       | Row-level predicate (semantics table below). |
| `projection?`    | `ProjectionOf<T>`                          | —       | Read-side field whitelist.                   |
| `set?`           | `Partial<Record<OwnFieldKey<T>, unknown>>` | —       | Write-side field defaults.                   |
| `allowedFields?` | `Array<OwnFieldKey<T>>`                    | —       | Write-side field whitelist.                  |
| `controls?`      | `ControlsOf<T>`                            | —       | Per-control gate map.                        |
| `with?`          | `WithOf<T>`                                | —       | Per-relation sub-scope, recursive.           |

Exact shape: [docs api](https://aoothjs.dev/api/arbac-moost#arbacdbscope-t).

Pass an `.as` model as `T` (e.g. `ArbacDbScope<Task>`) to get autocomplete on `projection` / `with` / `controls` / `set` / `allowedFields` against the model's own and navigation fields. `T = unknown` (the default) keeps the legacy untyped `Record<string, ...>` shape for back-compat.

**`with[name]`** is a recursive sub-scope applied when the request expands the `name` relation via `?$with=<name>`. The PARENT scope owns the policy for joined rows — arbac-moost does NOT re-evaluate ARBAC against the joined resource. Across roles, `with[name]` sub-scopes union additively at every nested level.

::: warning Known gap — joined-resource projection in exclude mode
arbac-moost does not apply the joined-resource projection mask to `$with` expansions when the relation loader uses **exclude-mode** `$select`. Include-mode `$select` works end-to-end. Pin tight whitelists on the parent via `controls.$with` if exclude-mode masking matters.
:::

| Field           | Used by                                    | Semantics                                                                                                                                                       |
| --------------- | ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `filter`        | `transformFilter`, `assertInScope`         | Row-level predicate. Merged with user filter as `$and: [scope, user]`. Union across roles = `$or` of per-role filters (existing `mergeScopeFilters` semantics). |
| `projection`    | `transformProjection`                      | Field whitelist on reads. Union across roles. Empty union → unrestricted.                                                                                       |
| `set`           | `onWrite` (via `applyAllowedFieldsAndSet`) | Field defaults overlaid on every write. Useful for tenant tagging (`{ tenantId: callerTenantId }`).                                                             |
| `allowedFields` | `onWrite` (via `applyAllowedFieldsAndSet`) | Write-side field whitelist. Union across roles. Identifier columns ALWAYS preserved (see [Identifier auto-preservation](#identifier-auto-preservation)).        |
| `controls`      | `validateControls`                         | Per-control gate map (`$with`, `$groupBy`, ...). See [Control-gate semantics](#control-gate-semantics).                                                         |

Apps can declaration-merge custom fields into `ArbacDbScope` — your scope predicate factories may produce extra keys that downstream controllers consume.

## Control-gate semantics

`ControlGate` is `true | false | readonly string[]`. Used for query controls like `$with` and `$groupBy`.

| Gate       | Effect                                                                                     |
| ---------- | ------------------------------------------------------------------------------------------ |
| `true`     | Allowed without restriction.                                                               |
| `false`    | Denied. Throws `HttpError(403, 'Control "$with" is not allowed for your role')`.           |
| `string[]` | Whitelist. Rejects values not in the list. Currently supported for `$with` and `$groupBy`. |

**Cross-role union semantics**: silence wins (a more permissive role lifts denial); whitelists union additively. So if Role A says `controls.$with = false` and Role B says `controls.$with = ['comments']`, the union is `['comments']` — allowing `comments` but not other joins.

## Multi-role union

Inside the controller, `arbac.evaluate(...)` returns the array of scopes contributed by every matching role. The controller unions across roles:

- **Filters**: `$or` of per-role filters (`mergeScopeFilters`). Empty `{}` from a single role means "no constraint" — the union short-circuits to unrestricted.
- **Projections**: additive whitelist union (`unionProjections`). One unrestricted role grants unrestricted read.
- **AllowedFields**: additive whitelist union.
- **Set**: shallow merge — last-write-wins on key collision. Avoid conflicting `set` defaults across roles.
- **Controls**: per-key union with the [semantics](#control-gate-semantics) above.

## Deny verdict (match-nothing)

When `arbac.evaluate(...)` denies, `transformFilter` returns a match-nothing filter (`{ $or: [] }`). `$or` of empty array is universally match-nothing across SQL and Mongo adapters. Counts, finds, and aggregates all return empty. Writes / removes are gated separately by `assertInScope`. The constant itself is internal to the package — don't import it; the observable behavior is what's contracted.

## Identifier auto-preservation

`applyAllowedFieldsAndSet(data, scopes, identifierFields)` **always preserves**:

- The PK field(s) (`@meta.id`).
- Every column in any `@db.index.unique` group.

This is BUG-8's fix: without auto-preservation, an `allowedFields = ['name']` scope would silently strip the PK from an `updateOne({ id, name })` patch, causing the write to fail or — worse — produce a multi-row update.

`identifierFields` is computed from the table's `identifications` metadata at controller construction.

## Wiring example

```ts
import { ArbacResource, AsArbacDbController } from "@aooth/arbac-moost";
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

The table is bound through `@TableController(table)` from `@atscript/moost-db`. The subclass has a default (no-arg) constructor — **never** `super({ table, model })` or `super(table, Article)`.

With a role like:

```ts
import { allowTableRead, defineRole } from "@aooth/arbac";
import type { ArbacDbScope } from "@aooth/arbac-moost";
import { Article } from "./article.as";

type UserAttrs = { tenantId: string; id: string };

defineRole<UserAttrs>()
  .id("editor")
  .use(
    allowTableRead<UserAttrs, ArbacDbScope<typeof Article>>("articles", {
      scope: (attrs) => ({
        filter: { tenantId: attrs.tenantId },
        projection: { title: 1, body: 1, tenantId: 1, id: 1 },
        set: { tenantId: attrs.tenantId },
        allowedFields: ["title", "body"],
        controls: { $with: ["comments"], $groupBy: false },
      }),
    }),
  )
  .build();
```

Note: pass typed scopes **per-privilege** via the `ArbacDbScope<Article>` generic on `allowTable*` — don't pin a single `ArbacDbScope<X>` at the `defineRole<UserAttrs, ArbacDbScope<X>>()` level, because `ArbacDbScope<T>` is not assignable to `ArbacDbScope<unknown>` across `allowTable*` calls for different models.

A `GET /articles?$with=comments` request from an `editor`:

1. `transformFilter`: user filter merged with `{ tenantId: user.attrs.tenantId }` as `$and`.
2. `transformProjection`: response restricted to `{ title, body, tenantId, id }`.
3. `validateControls`: `$with: ['comments']` allowed; `$with: ['author']` → 403.

A `PUT /articles/42` with `{ id: 42, title: 'x', body: 'y', tenantId: 'other-tenant' }`:

1. `onWrite`:
   - `assertInScope({ id: 42 })` → `count` filter `{ $and: [{ id: 42 }, { tenantId: user.attrs.tenantId }] }`. Returns 0 → throws 404.
   - If in scope, `applyAllowedFieldsAndSet` strips fields outside `allowedFields = ['title', 'body']`, preserves `id`, overlays `set = { tenantId: user.attrs.tenantId }`. So a malicious `tenantId: 'other-tenant'` is overwritten with the caller's tenant.
