# db-controllers

`AsArbacDbController` and `AsArbacDbReadableController` — Moost-DB controllers that enforce per-row scope on reads, writes, removes, and `/meta`. **No tables or migrations live here** — the package does not own role/privilege storage.

## Contents

- [`AsArbacDbController<T>` / `AsArbacDbReadableController<T>`](#asarbacdbcontrollert--asarbacdbreadablecontrollert)
- [Protected hook table](#protected-hook-table)
- [`ArbacDbScope` contract](#arbacdbscope-contract)
- [Control-gate semantics](#control-gate-semantics)
- [Multi-role union](#multi-role-union)
- [`DENY_FILTER`](#deny_filter)
- [Identifier auto-preservation](#identifier-auto-preservation)
- [Wiring example](#wiring-example)

## `AsArbacDbController<T>` / `AsArbacDbReadableController<T>`

`AsArbacDbController<T>` extends `AsDbController<T>` from `@atscript/moost-db`. Adds ARBAC enforcement via the six protected seams on `AsDbController`. Use for tables with both read and write access. `AsArbacDbReadableController<T>` extends `AsDbReadableController<T>` — view-only counterpart, only read-side seams.

Both controllers call `useArbac().evaluate<ArbacDbScope>()` exactly once per event, cache scopes via `useArbac().setScopes()`, then apply per-operation enforcement using the cached array.

## Protected hook table

| Hook                              | When                             | Behavior                                                                                                                                                                                                                                                                                                                                                                                                     |
| --------------------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `transformFilter(filter)`         | Every read query                 | Merges user filter with union of scope filters as `$and: [merged, userFilter]` — **never object spread** (walkFilter short-circuits on logical operators). On deny returns `DENY_FILTER`.                                                                                                                                                                                                                    |
| `transformProjection(projection)` | Every read query                 | Unions per-scope `projection` whitelists and `restrictProjection`s the user projection to that union. Empty union → unrestricted.                                                                                                                                                                                                                                                                            |
| `validateControls(controls, ...)` | Every read with `controls.*`     | Runs the parent validator first; then invokes `enforceControlsPolicy(unionControlsPolicy(scopes), controls)`. Violations throw `HttpError(403, 'Control "$with" is not allowed for your role')`.                                                                                                                                                                                                             |
| `applyMetaOverlay(meta)`          | `/meta` requests                 | Evaluates ARBAC in parallel for every declared action and CRUD op; filters `meta.actions` and `meta.crud` so the UI only sees ops the caller can invoke. Memoized per-class action-meta map.                                                                                                                                                                                                                 |
| `onWrite(action, data)`           | `insertOne` / `updateOne` / etc. | For **non-insert** writes calls `assertInScope(data, scopes)`; then calls `applyAllowedFieldsAndSet(data, scopes, identifierFields)` to strip fields outside the union of `allowedFields` (auto-preserving PK + unique-index columns) and overlay `set` defaults. **`assertInScope` MUST run before `applyAllowedFieldsAndSet`** — otherwise a caller knowing the PK could mutate past their filter (BUG-1). |
| `onRemove(id)`                    | `deleteOne`                      | `assertInScope(id, scopes)`.                                                                                                                                                                                                                                                                                                                                                                                 |
| `assertInScope(idOrIds, scopes)`  | Reused by `onWrite` + `onRemove` | Issues a `table.count` with `{ $and: [resolveIdFilter(id), mergedScopeFilter] }` and throws `HttpError(404, 'Not found')` if not every id is in scope. **Returns 404, not 403, to hide existence.**                                                                                                                                                                                                          |

The read-only controller exposes only `transformFilter`, `transformProjection`, `validateControls`, `applyMetaOverlay`.

## `ArbacDbScope` contract

```ts
interface ArbacDbScope {
  filter?: TScopeFilter;
  projection?: TProjection;
  set?: Record<string, unknown>;
  allowedFields?: string[];
  controls?: Record<string, ControlGate>;
}
```

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

## `DENY_FILTER`

```ts
export const DENY_FILTER = { $or: [] } as const;
```

Returned by `transformFilter` when `arbac.evaluate(...)` denies. `$or` of empty array is universally match-nothing across SQL and Mongo adapters. Counts, finds, and aggregates all return empty. Writes / removes are gated separately by `assertInScope`.

## Identifier auto-preservation

`applyAllowedFieldsAndSet(data, scopes, identifierFields)` **always preserves**:

- The PK field(s) (`@meta.id`).
- Every column in any `@db.index.unique` group.

This is BUG-8's fix: without auto-preservation, an `allowedFields = ['name']` scope would silently strip the PK from an `updateOne({ id, name })` patch, causing the write to fail or — worse — produce a multi-row update.

`identifierFields` is computed from the table's `identifications` metadata at controller construction.

## Wiring example

```ts
import { AsArbacDbController } from "@aoothjs/arbac-moost";
import { Controller } from "moost";
import { Article } from "./article.as";

@Controller("articles")
class ArticlesController extends AsArbacDbController<typeof Article> {
  constructor() {
    super(articlesTable, Article);
  }
}
```

With a role like:

```ts
defineRole()
  .id("editor")
  .use({
    resource: "articles",
    action: ["read", "update"],
    scope: (user) => ({
      filter: { tenantId: user.attrs.tenantId },
      projection: { title: 1, body: 1, tenantId: 1, id: 1 },
      set: { tenantId: user.attrs.tenantId },
      allowedFields: ["title", "body"],
      controls: { $with: ["comments"], $groupBy: false },
    }),
  })
  .build();
```

A `GET /articles?$with=comments` request from an `editor`:

1. `transformFilter`: user filter merged with `{ tenantId: user.attrs.tenantId }` as `$and`.
2. `transformProjection`: response restricted to `{ title, body, tenantId, id }`.
3. `validateControls`: `$with: ['comments']` allowed; `$with: ['author']` → 403.

A `PUT /articles/42` with `{ id: 42, title: 'x', body: 'y', tenantId: 'other-tenant' }`:

1. `onWrite`:
   - `assertInScope({ id: 42 })` → `count` filter `{ $and: [{ id: 42 }, { tenantId: user.attrs.tenantId }] }`. Returns 0 → throws 404.
   - If in scope, `applyAllowedFieldsAndSet` strips fields outside `allowedFields = ['title', 'body']`, preserves `id`, overlays `set = { tenantId: user.attrs.tenantId }`. So a malicious `tenantId: 'other-tenant'` is overwritten with the caller's tenant.
