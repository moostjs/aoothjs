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

| Hook                              | What it does                                                                                                                                                                                                                                                              |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `transformFilter(filter)`         | Calls `arbac.evaluate<ArbacDbScope>()` once per event, caches scopes via `arbac.setScopes`, merges user filter with the **UNION of scope filters** using `$and: [merged, userFilter]` (never object spread). On deny returns `DENY_FILTER = { $or: [] }` (match-nothing). |
| `transformProjection(projection)` | Unions per-scope `projection` whitelists and `restrictProjection`s the user projection to that union.                                                                                                                                                                     |
| `validateControls(controls, ...)` | Runs the parent validator; then invokes `enforceControlsPolicy(unionControlsPolicy(scopes), controls)`. Violations throw `HttpError(403)`.                                                                                                                                |
| `applyMetaOverlay(meta)`          | For `/meta`, evaluates ARBAC in parallel for every declared action and CRUD op, filters `meta.actions` and `meta.crud` so the UI only sees ops the caller can invoke. Memoized per-class action-meta map.                                                                 |
| `onWrite(action, data)`           | For non-insert writes: `assertInScope(data, scopes)` first; then `applyAllowedFieldsAndSet(data, scopes, identifierFields)` strips fields outside the union of `allowedFields` (**auto-preserving PK + unique-index columns**) and overlays `set` defaults.               |
| `onRemove(id)`                    | `assertInScope(id, scopes)`.                                                                                                                                                                                                                                              |
| `assertInScope(idOrIds, scopes)`  | Issues `table.count` with `{ $and: [resolveIdFilter(id), mergedScopeFilter] }` and throws `HttpError(404, "Not found")` if not every id is in scope.                                                                                                                      |

::: warning `$and: [scope, user]`, never object spread
`@uniqu/core`'s `walkFilter` short-circuits on logical operators. Merging via `{ ...scope, ...userFilter }` would silently drop scope conditions when the user filter has the same top-level keys. Always wrap as `$and: [scope, user]`.
:::

::: warning `assertInScope` MUST run before `onWrite` strips data
Without the pre-check, a caller knowing a row's primary key could mutate it past their scope filter (BUG-1). `AsArbacDbController.onWrite` calls `assertInScope(data, scopes)` first, then `applyAllowedFieldsAndSet(...)`. Custom subclasses MUST preserve this order.
:::

## `ArbacDbScope` contract

```ts
interface ArbacDbScope {
  filter?: TScopeFilter; // a Mongo-style filter merged into the read/delete/update WHERE
  projection?: TProjection; // a field-whitelist applied to read responses
  set?: Record<string, unknown>; // default values overlaid onto inserts/updates
  allowedFields?: string[]; // whitelist of writable field paths
  controls?: Record<string, ControlGate>; // gate `$with` / `$groupBy` / etc.
}
```

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

The most common subclass overrides nothing and just plugs in a table:

```ts
import { AsArbacDbController } from "@aoothjs/arbac-moost";
import { Controller } from "moost";
import { Get } from "@moostjs/event-http";

@Controller("articles")
class ArticlesController extends AsArbacDbController<Article> {
  constructor() {
    super({ table: appDb.tables.articles, model: Article });
  }
}
```

For a custom secondary check (e.g. enforce a tenant filter even when no scope is configured), override one of the hooks and call `super` first:

```ts
@Controller("articles")
class ArticlesController extends AsArbacDbController<Article> {
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
import { defineRole } from "@aoothjs/arbac";
import type { ArbacDbScope } from "@aoothjs/arbac-moost";

const editor = defineRole<{ tenantId: string }, ArbacDbScope>()
  .id("editor")
  .allow("articles", "read", (attrs) => ({ filter: { tenantId: attrs.tenantId } }))
  .allow("articles", "create", (attrs) => ({
    filter: { tenantId: attrs.tenantId },
    set: { tenantId: attrs.tenantId, ownerId: attrs.id },
    allowedFields: ["title", "body", "draft"],
  }))
  .allow("articles", "update", (attrs) => ({
    filter: { tenantId: attrs.tenantId, draft: true },
    allowedFields: ["title", "body"],
  }))
  .deny("articles", "delete")
  .build();
```

| Scope field                            | What it does at runtime                                                                 |
| -------------------------------------- | --------------------------------------------------------------------------------------- |
| `filter: { tenantId: attrs.tenantId }` | Every read/update/delete is wrapped in `$and: [filter, userFilter]`.                    |
| `set: { tenantId, ownerId }`           | Every insert/update has these defaults overlaid (caller can't fake `tenantId`).         |
| `allowedFields: ["title", "body"]`     | Every update strips fields outside this list. PK + unique-index columns auto-preserved. |
| `controls: { $with: false }`           | Caller can't expand joined relations on this resource.                                  |
| `projection: ['id', 'title']`          | Read responses are whitelisted to these fields only.                                    |

## Identifier auto-preservation

`applyAllowedFieldsAndSet` always preserves keys from `table.identifications` — your primary key, every column in a `@db.table.uniqueIndex` group, etc. This means a scope like `allowedFields: ["title"]` doesn't accidentally strip the `id` from an update payload, which would silently break the update.

## `DENY_FILTER`

`DENY_FILTER` is the constant `{ $or: [] }` — match-nothing. The controller returns this from `transformFilter` whenever:

- `arbac.evaluate()` returns `{ allowed: false }`.
- The action resolution chain produces a name with no role grant.

Match-nothing produces an empty result set on read (200 with an empty array) and zero affected rows on write — fail-closed without surfacing a 403 to the caller for queries that legitimately return no rows.

## See also

- [ARBAC Authorize](./arbac-authorize) — the upstream interceptor that produces the scopes.
- [Atscript Models](./atscript) — the `.as`-annotated user model that drives `getRoles` / `getAttrs`.
- [Config Reference](./config) — workflow-level options. Role tuning is framework-agnostic, see [/arbac](../arbac/) for the engine.
