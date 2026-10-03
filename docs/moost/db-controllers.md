# DB Controllers

This page documents `AsArbacDbController<T>` and `AsArbacDbReadableController<T>` — the `@atscript/moost-db`-derived controllers that auto-apply ARBAC scopes to CRUD endpoints. **The package does not own role/privilege storage** — there are no tables or migrations here. The controllers are pure hook overlays on top of `@atscript/moost-db`'s base classes.

## When to use them

Use `AsArbacDbController<T>` when:

- You expose a `.as`-annotated DB table over HTTP via `@atscript/moost-db`.
- You want ARBAC's `scope.filter` / `scope.projection` / `scope.set` / `scope.allowedFields` / `scope.controls` to be enforced automatically on every read / write / delete — without per-handler `getScopes()` plumbing.

Use `AsArbacDbReadableController<T>` when:

- The same, but read-only (view controllers, joined-table projections).

## `AsArbacDbController<T>` extends `AsDbController<T>`

The class wires these protected hooks of `@atscript/moost-db`'s base controller (needs `@atscript/moost-db` ≥ 0.1.143):

| Hook                                    | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `prepareRequest(ctx)`                   | Runs first on every endpoint. Reuses the scopes the authorize interceptor cached, else evaluates the handler's resource/action itself. A deny is a **403**. On reads it also resolves the `$with` relation policy — for the `$with` entries and (since 0.1.74) the relations the client filter's [relational predicates](#relational-filter-predicates-some-none) name. See [Fail-closed](#fail-closed-every-endpoint).                          |
| `transformFilter(filter)`               | Merges the user filter with the **UNION of scope filters** as `$and: [merged, userFilter]` (never object spread). Also the row overlay of `/one`, `DELETE` and `@DbAction` ids. On a route that skipped `prepareRequest`, evaluates lazily; a deny returns a match-nothing filter (`{ $or: [] }`).                                                                                                                                               |
| `transformProjection(projection)`       | Unions per-scope `projection` whitelists and narrows the user `$select` (array inclusion or object exclusion) to its intersection with that union: `$select=a` under a scope that shows only `a.b` (or hides `a.c`) returns just `a.b`. An excluded nested object is stripped leaf by leaf.                                                                                                                                                      |
| `transformRelationFilter(path, filter)` | The operand of a client [relational predicate](#relational-filter-predicates-some-none) (`ticket=$some(…)`) ∧ the row filter of the related rows the caller may see there — the same policy `$with` of that relation applies. Since 0.1.74 (moost-db ≥ 0.1.147).                                                                                                                                                                                 |
| `validateControls(controls, ...)`       | Runs the parent validator; then invokes `enforceControlsPolicy(unionControlsPolicy(scopes), controls)`. Violations throw `HttpError(403)`.                                                                                                                                                                                                                                                                                                       |
| `applyMetaOverlay(meta)`                | For `/meta`, evaluates ARBAC in parallel for every declared action and CRUD op, filters `meta.actions` and `meta.crud` so the UI only sees ops the caller can invoke — then **prunes the field surface** (`fields`, the serialized `type`, `relations`, `versionColumn`) to the union of the allowed read ops' scope projections. Memoized per-class action-meta map.                                                                            |
| `authorizeForm(name, actions)`          | `GET /meta/form/:name` serves a form only if the caller may run at least one action that takes it as input. Otherwise the response is the unknown-form 404.                                                                                                                                                                                                                                                                                      |
| `actionRowScope(name, ctx)`             | The rows the `@DbAction` `name` may run on: the filter of the caller's grant on that action. Enforced by the action gate, reflected in `$actions` and `GET /meta/actions/:id`. `ctx` (the candidate rows, since 0.1.74 with moost-db ≥ 0.1.147) is passed through but not consulted — see [Bounding an action by its candidate rows](#bounding-an-action-by-its-candidate-rows). Since 0.1.72 (moost-db ≥ 0.1.145).                              |
| `allowedActions(names)`                 | The row-level actions `$actions` and `GET /meta/actions/:id` list: the ones the caller holds a grant on, by the `/meta` overlay's rule, without building the overlay. Since 0.1.72 (moost-db ≥ 0.1.145).                                                                                                                                                                                                                                         |
| `hasField(path)`                        | Scope-aware field visibility — moost-db's visibility hook, consulted at every gated query position: paths outside the read-scope projection union — or, inside a `$with` sub-query, outside the [relation's policy](#per-relation-with-recursive) — answer `false`, so any reference to a hidden field gets the **identical** `Unknown field "x"` 400 a nonexistent field gets. See [Column-scope security floor](#column-scope-security-floor). |
| `onWrite(action, data)`                 | Rejects [nested writes](#nested-writes) the scopes don't opt in, then applies `allowedFields` / `set` (see [`allowedFields` and `set`](#allowedfields-and-set)).                                                                                                                                                                                                                                                                                 |
| `guardWrite(ctx)`                       | Inside the write's transaction: **USING** — every update / replace target's pre-image must match the scope `filter`. Without a real transaction it also runs **WITH CHECK** before the write.                                                                                                                                                                                                                                                    |
| `guardRemove(ctx)`                      | Inside the delete's transaction: USING for the row being deleted.                                                                                                                                                                                                                                                                                                                                                                                |
| `checkWrite(ctx)`                       | After the write, inside its transaction: **WITH CHECK** — every written row must match the scope `check`. A failure rolls the write back.                                                                                                                                                                                                                                                                                                        |

::: tip A scope projection removes fields from EXISTENCE, not just from rows
With a constrained read projection, `/meta` no longer advertises the hidden fields (a table UI cannot even offer them as columns — previously they rendered as permanently-empty columns, and secret-bearing column NAMES leaked), and referencing one anywhere in a query (`$select`, a filter, a sort, a group, an aggregate) is indistinguishable from referencing a field that was never declared — see [Column-scope security floor](#column-scope-security-floor). PK + `preferredId` always stay visible — reads always return them (projection widening / id addressing). Unscoped read grants keep the full field envelope. Relations and their nav types follow the `$with` policy (see [Per-relation `with`](#per-relation-with-recursive)): a declared `with.<rel>` sub-scope, else the caller's own grant on the related table — none → the relation is dropped. A `ref` to a hidden field or an unreadable table is stripped.

The search surface is pruned by moost-db itself (≥ 0.1.147, under the overridden `hasField`): a `searchIndexes` entry that reads a hidden field is dropped and `searchable` / `vectorSearchable` / `geoSearchable` turn off when the default index reads one. Since 0.1.74 the ARBAC overlay no longer prunes it a second time, and no longer strips `search` / `index` / `vector` from `crud.query` / `crud.pages` or drops `crud.geo` — read the flags. Each `crud` op is evaluated as the handler(s) serving it: `one` via `getOne` / `getOneComposite`, `remove` via `remove` / `removeComposite` (allowed when any is), the rest by name. An action is evaluated with the same id `useArbac` uses for its handler (`@ArbacAction`, else the `@DbAction` name, never the method `@Id`). If several methods declare it, it is allowed when any of them is. A class-level `@DbActions` / `@DbRowActions` entry has no handler method, so it is evaluated as the controller's resource plus the entry name. The same rule applies in `$actions`, `GET /meta/actions/:id` and `/meta/form/:name`.
:::

::: warning `$and: [scope, user]`, never object spread
A user filter may constrain the same field as the scope. Merging via `{ ...scope, ...userFilter }` lets the user's value **replace** the scope's — a reader scoped to `tenantId: 'a'` who asks for `tenantId: 'b'` would be served tenant b's rows. `$and` intersects instead, so the contradiction matches nothing.

Prefer `conjoinScopeFilters(scope, userFilter)` from `@aooth/arbac` over hand-rolling the wrap: it owns this invariant and treats an empty side as the identity.

Historically this was recorded as BUG-2 against `@uniqu/core`'s `walkFilter` dropping sibling field keys next to a logical operator. That short-circuit was fixed in `@uniqu/core` 0.1.8 (mixed field/logical nodes are an implicit AND) — **the rule still stands**, for the same-key reason above, which is independent of it.
:::

### Write pipeline

From `@aooth/arbac-moost` 0.1.72 a write runs these checks, in order:

| Step                         | Rule                                                                                                      | Failure                                         |
| ---------------------------- | --------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| `prepareRequest`             | The caller holds a grant for the write action.                                                            | 403                                             |
| `onWrite` — nested writes    | No nav-prop key unless a scope lists it in `nestedWrites`.                                                | 403 `Nested writes through "x" are not allowed` |
| `onWrite` — fields           | `allowedFields` whitelist + `set` overlay.                                                                | Fields dropped silently                         |
| `guardWrite` / `guardRemove` | **USING**: the stored row (by exact primary key, read inside the transaction) matches the scope `filter`. | 404, same as a missing row                      |
| `guardWrite` — `checkRefs`   | Opt-in: every FK the write sets references a row the caller can read on the target table.                 | 403 `Referenced row "x" is outside your scope`  |
| `checkWrite`                 | **WITH CHECK**: every written row matches `check` (default: `filter`; `{}` = off).                        | 403 `Row outside your write scope`, rolled back |

- **Every targeted row must pass.** A bulk PATCH / PUT with one out-of-scope row is a 404, and nothing is written. Duplicate ids count once.
- **USING and WITH CHECK are different questions.** USING asks "may you touch this row?"; WITH CHECK asks "is the result still yours?". A tenant-scoped writer can edit their rows but cannot insert into, or move a row to, another tenant.
- **`check` overrides the default.** `{ filter: { tenant }, check: { status: { $ne: "archived" } } }` lets the writer move rows between tenants but never archive one. `check: {}` turns WITH CHECK off. Across roles, a row passing any role's check passes.
- **Deletes** are scoped twice: moost-db pins the id among the rows the remove scope's `filter` admits, and `guardRemove` re-checks the stored row.

::: warning Adapters without transactions (in-memory, standalone MongoDB)
A post-write check cannot roll back there, so the controller checks **before** the write. It evaluates `check` in memory:

- An insert / replace row is checked as sent.
- An update patch is checked against the stored row plus the patch. Every field `check` references must be untouched or set to a plain value.

Everything else is a **403** (fail closed): an operator (`$inc`, array ops) or a nested object over a checked field, or an operator outside `$eq` / `$ne` / `$in` / `$nin` / `$gt(e)` / `$lt(e)` / `$exists` / `$and` / `$or` / `$not` (e.g. `$regex`) in `check`.
:::

### Nested writes

A write payload that carries a nav prop (`TO` / `FROM` / `VIA`) is a **403** unless a write scope lists that relation in `nestedWrites`. This covers `{ owner: {...} }`, `{ comments: [...] }` and patch operators like `{ tags: { $insert: [...] } }`. Bulk payloads are checked row by row.

```ts
allowTableWrite("projects", {
  scope: () => ({ filter: { tenant: "a" }, nestedWrites: ["notes"] }),
});
```

- **Opt-in only.** An unrestricted scope (`{}`) does not allow nested writes. Across roles the listed relations union; a [credential](/arbac/attenuation) can only narrow them.
- **Parent authority.** The related rows are written under the PARENT scope. The related table's own ARBAC policy, `filter`, `set` and `check` are not applied to them. Opt a relation in only when the parent's policy is enough for its rows.
- **`/meta` follows the same rule.** A relation is never offered as writable unless a write scope lists it: one the caller cannot read but may write through keeps its nav type in `/meta`, stamped `db.writeOnly`; any other hidden relation is dropped.

### FK target checks (`checkRefs`)

The row `filter` / `check` constrain the row being written, not the rows its foreign keys point at. A tenant-scoped writer can still set `projectId` to another tenant's project. `checkRefs` closes that: each listed FK must reference a row the caller can **read** on the target table.

```ts
allowTableWrite<UserAttrs, ArbacDbScope<Task>>("tasks", {
  scope: (attrs) => ({
    filter: { tenantId: attrs.tenantId },
    set: { tenantId: attrs.tenantId },
    checkRefs: ["projectId"], // or the TO relation name ("project"), or `true` for every FK
  }),
});
```

- **What is checked.** Insert and replace rows; update patches only when they touch the FK. A null or absent FK is skipped. A bulk write costs one `count` per FK, inside the write's transaction.
- **"Can read" = the caller's own `query` grant on the target's ARBAC resource**, found through the target table's registered ARBAC DB controller (the same rule as [`$with`](#per-relation-with-recursive)). No registered controller, or no read grant there → 403. So is a missing target row.
- **Union across roles: every scope must enable it.** Write scopes are additive, so a role without the flag grants unconstrained writes of that FK.

  | Roles (each a write scope on `tasks`)     | `projectId` checked? |
  | ----------------------------------------- | -------------------- |
  | `member: { checkRefs: ["projectId"] }`    | yes                  |
  | `member` + `auditor: { checkRefs: true }` | yes                  |
  | `member` + `importer: {}` (no flag)       | **no**               |

  A [credential](/arbac/attenuation) enforces what either side (user or credential) enforces.

- **Handler-side writes** (a `@DbAction` that calls `this.table.insertOne`) skip `guardWrite`. Pass [`useArbacDbScope()`](#custom-routes-usearbacdbscope)`.writeOptions(this.table)` to the write — it runs the same check (with that action's scopes) inside the write's transaction. `scope.assertRefsInScope(this.table, [row])` is the standalone check.
- **FK values that are class instances** (a Mongo `ObjectId`, a `Date`) are referenced values; a plain object or an array in an FK field (an operator shape) is a 403.
- **A name that is neither an FK field nor a TO relation** throws on the first write (configuration error, 500).

### `allowedFields` and `set`

`allowedFields` entries are paths:

| Entry          | Payload `{ profile: { name, tenant } }` keeps    |
| -------------- | ------------------------------------------------ |
| `profile`      | The whole `profile` object                       |
| `profile.name` | `{ profile: { name } }` — other nested keys drop |

- **PATCH replaces a nested object as a whole** unless the field is `@db.patch.strategy 'merge'`. So on PATCH, a dotted entry only works under a merge block. Under a replace block the partial object is dropped: writing it would clear the non-whitelisted leaves.
- **Always kept:** the primary key, unique-index columns, the `@db.column.version` column and `$cas`. Optimistic concurrency works under any whitelist.
- **A dotted `set` key** (`set: { "profile.tenant": "a" }`) sets the nested path and merges into the payload's object. On PATCH it never adds a replace block the payload doesn't carry, so the stored block is not cleared.

### Column-scope security floor

::: warning Column scopes need `@atscript/moost-db` ≥ 0.1.134
moost-db consults `hasField` at every gated query position: filter keys at any depth (`$exists` included), `$sort`, `$select`, `$groupBy`, `$having`, aggregate and calendar-bucket `$field`s, navigation paths, `$with` relation names and the `$search` fallback fields. 0.1.128–0.1.132 skipped it for stored columns, so a projection-scoped caller could filter, sort, group and aggregate on hidden columns — a value oracle, even though `$select` values stayed stripped. `@aooth/arbac-moost` 0.1.68 peers on `^0.1.134` (0.1.67 on `^0.1.133`). 0.1.134 adds two fixes. A unique index over a hidden column no longer identifies a row (see [Hidden unique keys](#hidden-unique-keys)). Excluding a nested object (`$select=-a`, or a scope's `{ a: 0 }`) now removes its whole subtree; before, the object's leaves came back. If you override `hasField`, keep the `super` call.

`hasField` and `transformProjection`'s value stripping read the scopes `prepareRequest` resolves before anything else runs (reusing [`arbacAuthorizeInterceptor`](./arbac-authorize)'s cache). Before `@aooth/arbac-moost` 0.1.72 they read only that cache, so a controller without the interceptor served hidden columns. Now, if scopes are somehow unresolved, `hasField` hides every field and the other hooks answer 403.

Native full-text, vector and geo search run inside the database over their indexes. From `@atscript/moost-db` 0.1.143 an index that reads a hidden field answers like a nonexistent one. Since moost-db 0.1.147, `$search` without `$index` whose DEFAULT text index reads a hidden field answers `400 No search index available` (before, it fell back to the visible `@db.column.searchable` fields); tables without native search keep that fallback, which only ever matches fields the caller can see.
:::

#### Derived columns and JSON columns

From `@aooth/arbac-moost` 0.1.72:

- **Derived columns follow their source.** A `@db.column.derived` field is visible only while its source path is. `{ settings: 0 }` also hides a `apiKeyCopy: Model.settings.apiKey` column: it is stripped from rows, unknown to filters and dropped from `/meta`.
- **`@db.json` columns are atomic on SQL adapters** (SQLite, PostgreSQL, MySQL), which cannot address a JSON sub-path. A hidden leaf (`{ "settings.apiKey": 0 }`) hides the whole `settings` column. A whitelisted leaf alone (`{ id: 1, "settings.theme": 1 }`) does not reveal it. MongoDB and the memory adapter keep sub-path precision: only `settings.apiKey` is hidden.

#### Hidden related fields

The floor extends to joined rows. A path under a relation is checked against the policy of its joined rows (see [Per-relation `with`](#per-relation-with-recursive)), not the parent projection. With a declared `with.<rel>` sub-scope:

```ts
scope: () => ({
  projection: { secret: 0 },
  with: { author: { projection: { salary: 0 }, with: { org: { projection: { budget: 0 } } } } },
});
```

| Request                                                    | Result                                                |
| ---------------------------------------------------------- | ----------------------------------------------------- |
| `?$with=author(salary>100)` / `$with=author($sort=salary)` | 400 `Unknown field "author.salary"`                   |
| `?$with=author($select=salary)`                            | 400, identical to `$with=author($select=nope)`        |
| `?$with=author($with=org(budget>1))`                       | 400 `Unknown field "author.org.budget"`               |
| `?$with=author(name='b')`, `$with=author($select=id)`      | 200 (visible field; the related PK is always visible) |
| `/one/2?$with=author(salary>100)`                          | 400, same rule on `/one`                              |

- The sub-scopes **union across roles** like top-level projections: a field any role's `with.<rel>` shows is visible.
- The related table's own PK / `preferredId` stay visible even when the sub-scope whitelist omits them. The parent's top-level rule works the same way.
- **No sub-scope declared** (0.1.72+): joined rows and their paths follow the caller's own read grant on the related table. No grant there → `400 Unknown relation`, identical to a nonexistent relation.
- `/meta` agrees: `relations` and the nav types under `type` list only what the same rule shows, recursively. A `ref` to a hidden field or to a table the caller cannot read is stripped.
- Row stripping (`transformProjection` / the `$with` sub-select) stays in place as the second layer.

Before `@aooth/arbac-moost` 0.1.68, paths under a `with`-granted relation skipped the sub-scope check. A filter on a hidden related field then decided whether the relation populated (a value oracle), and `$select` / `$sort` on it were accepted (an existence oracle).

#### `$select` narrowing and nested objects

A client `$select` is narrowed to its intersection with the scope projection, by path. It can ask for less than the scope shows, never more. Both wire forms are handled: an inclusion (`$select=a,b`) and an exclusion (`$select=-a`). For a row `{ id: 1, title: "t", a: { b: "B", c: "C" } }`:

| Scope projection                | Request          | Row returned               |
| ------------------------------- | ---------------- | -------------------------- |
| `{ id: 1, title: 1, "a.b": 1 }` | `$select=a`      | `{ id: 1, a: { b: "B" } }` |
| `{ id: 1, title: 1, "a.b": 1 }` | `$select=-title` | `{ id: 1, a: { b: "B" } }` |
| `{ "a.c": 0 }`                  | `$select=a`      | `{ id: 1, a: { b: "B" } }` |
| `{ a: 0 }`                      | (none)           | `{ id: 1, title: "t" }`    |
| `{ a: 0 }`                      | `$select=-title` | `{ id: 1 }`                |

`/query`, `/pages` and `/one` return the same rows, and `$with` sub-selects follow the same rule against the [relation's policy](#per-relation-with-recursive). A scope that excludes a parent (`{ a: 0 }`) hides the whole object. Across roles, projections [union by path](/arbac/scopes): `{ a: 0 }` from one role and `{ "a.c": 0 }` from another leave only `a.c` hidden. A [credential](/arbac/attenuation) narrows the same way and never widens the user's projection.

#### Hidden unique keys

A unique index over a column the read scope hides is not an identification. Addressing a row through it answers exactly like a value that matches no row, so the key cannot confirm that a value exists:

| Request (scope hides the unique `code`)     | Hidden existing value vs. nonexistent value |
| ------------------------------------------- | ------------------------------------------- |
| `DELETE /<code>`                            | Identical response; nothing is deleted      |
| `PATCH /` or `PUT /` keyed by `code`, no PK | Identical response; nothing is written      |
| `GET /one/<code>`                           | Identical `404`                             |

DELETE and PATCH answer both with the same 404. A PUT is a full row, so without its primary key both get the same 400. The primary key and `preferredId` stay addressable. Before `@aooth/arbac-moost` 0.1.68, a DELETE / PATCH / PUT by a hidden unique value that existed got a different 404 body than a value that did not.

## `ArbacDbScope<T>` contract

```ts
interface ArbacDbScope<T = unknown> {
  filter?: TScopeFilter; // a Mongo-style filter merged into the read/delete/update WHERE
  check?: TScopeFilter; // WITH CHECK: a written row must match it (default: `filter`; `{}` = off)
  projection?: ProjectionOf<T>; // a field-whitelist applied to read responses
  set?: Partial<Record<OwnFieldKey<T>, unknown>>; // default values overlaid onto inserts/updates
  allowedFields?: Array<OwnFieldKey<T>>; // whitelist of writable field paths
  controls?: ControlsOf<T>; // gate `$with` / `$groupBy` / etc.
  with?: WithOf<T>; // per-relation sub-scopes for `?$with=<name>` expansion
  nestedWrites?: Array<NavRelationKey<T>>; // nav relations writable through the parent payload
  checkRefs?: true | Array<OwnFieldKey<T> | NavRelationKey<T>>; // FK targets must be readable
}
```

::: info `check`, `nestedWrites` and `checkRefs` are enforced from `@aooth/arbac-moost` 0.1.72

- **`check`** — Postgres-RLS-style WITH CHECK. Every row an insert / replace / update writes must match it, or the write is rejected. Omitted → the scope's `filter` is the check, so a tenant-scoped writer cannot move a row out of their tenant. `check: {}` turns it off. Multiple roles: a row passing any role's check passes.
- **`nestedWrites`** — nested writes through nav props (`{ title, comments: [...] }`) are **denied by default** (403). List a relation to allow it; the related rows are written under the PARENT scope, the related table's own ARBAC policy is not consulted.
- **`checkRefs`** — FKs whose target row must be readable by the caller (403 otherwise). Enforced only when every write scope enables it. See [FK target checks](#fk-target-checks-checkrefs).

:::

Pass an `.as` model as `T` (e.g. `ArbacDbScope<Task>`) to get autocomplete on `projection` / `with` / `controls` / `set` / `allowedFields` against the model's own and navigation fields. `T = unknown` (the default) keeps the legacy untyped `Record<string, ...>` shape for back-compat. Dotted-path projections on nested own-objects (e.g. `'mfa.value'`) still type-check via a `keyof | (string & {})` escape hatch.

### Per-relation `with` (recursive)

`with[name]` is a sub-scope applied when the request expands the `name` relation via `?$with=<name>`. Recursive — each sub-scope has the same shape and can declare its own `with` for nested expansions (`tasks → comments → task`).

Which policy the joined rows of `?$with=<name>` obey, at every nesting level:

- **Declared** — some role's scope declares `with.<name>`: the union of the declared sub-scopes (parent authority). Across roles they union additively (`unionProjections` / `mergeScopeFilters` / `unionControlsPolicy`). Roles silent on `with.<name>` contribute nothing.
- **Not declared** — the caller's OWN `query` grant on the related table's ARBAC resource: its `filter`, `projection`, `controls` and `with` apply. The resource comes from the ARBAC DB controller serving that table (`@ArbacResource`, else the controller id or class name). No such controller, or no grant → the relation is hidden: `400 Unknown relation`, absent from `/meta`. The 400's `Available relations: …` lists only the relations the caller may expand at that level (never a hidden one), so a hidden and a nonexistent name answer alike. An include-mode parent projection must also name the relation.

The `controls.$with` whitelist applies either way. A field the policy hides is unknown in `$with` sub-queries and pruned from the `/meta` nav type — see [Hidden related fields](#hidden-related-fields).

::: warning Breaking in `@aooth/arbac-moost` 0.1.72
Before 0.1.72 an undeclared relation was expanded **unrestricted** ("silence wins"), bypassing the related table's own grant. Grant `query` on the related resources (e.g. `allowTableRead("users")`), or declare `with.<name>`, to keep existing `$with` requests working.
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

Credential attenuation conjoins scopes into one composite scope, so each custom field needs a conjunction rule registered with `MoostArbac.registerScopeFields` — see [Custom scope fields](/arbac/scopes#custom-scope-fields).

## Relational filter predicates (`$some` / `$none`)

moost-db ≥ 0.1.147 filters rows by their related rows: `ticket=$some(status=open)` (has a matching related row), `ticket=$none()` (has none). Under the ARBAC controllers (since 0.1.74) both sides of the feature are covered.

**In your scopes** — a scope `filter` (or a custom field's [`rowFilter`](/arbac/scopes#fields-that-restrict-rows-rowfilter)) may use a predicate on any relation, opted in or not. It is the rule itself, so it applies on every row path: reads, `$with` inherited grants, the action gate, `$actions`, `GET /meta/actions/:id`, query targets and write USING. Several grants union (`$or`), attenuation intersects:

```ts
allowTableAction<UserAttrs, ArbacDbScope<Issue>>("issues", ["resolve"], {
  scope: (attrs) => ({
    filter: { ticket: { $some: { teamId: { $in: attrs.teams }, status: "open" } } },
  }),
});
```

**From the client** — a predicate on a relation (it must also carry `@db.rel.filterable`) is allowed exactly when `$with` of that relation is for the caller: the same [relation policy](#per-relation-with-recursive) (a declared `with.<rel>` sub-scope, else the caller's own read grant on the related table; none → `Unknown field` 400) and the same `controls.$with` gate (`false` or a whitelist without the relation → 403). There is no separate per-role switch. Its operand is conjoined with the related rows the caller may see (`transformRelationFilter`), so `$some` only matches, and `$none` only excludes, on rows `$with` would show: a hidden related row never changes the answer. The same holds for predicates inside `$with` sub-filters (`$with=ticket(issues=$some(…))`).

::: warning A relational `check` needs a transactional adapter
WITH CHECK runs in the database inside the write's transaction, so a predicate works there. On an adapter without real transactions the check runs in memory before the write and cannot read related rows: a `check` (or a `filter` used as the default check) containing a predicate fails closed with 403 on every insert / update / replace. Use a transactional adapter, or give the scope an explicit non-relational `check`.
:::

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

Read-only mirror of `AsArbacDbController<T>`. Wires only the read hooks (`prepareRequest`, `transformFilter`, `transformProjection`, `validateControls`, `applyMetaOverlay`, `authorizeForm`, `hasField` — including the same fail-closed `prepareRequest`, `/meta` field pruning + `Unknown field` parity). Use it for view controllers and joined-table projections that should never accept writes.

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

For a custom secondary check (e.g. enforce a tenant filter even when no scope is configured), override one of the hooks and call `super` first. For a controller on another moost-db base class, compose the same hook bodies from the [building blocks](/api/arbac-moost#custom-arbac-controller-building-blocks) (`prepareArbacRequest`, `arbacRowFilter`, `registerArbacDbTarget`, …):

```ts
@TableController(table)
@ArbacResource("articles")
class ArticlesController extends AsArbacDbController<typeof Article> {
  protected override async transformFilter(filter: FilterExpr): Promise<FilterExpr> {
    const merged = await super.transformFilter(filter);
    const tenantId = useAuth().getAuthContext<{ tenantId?: string }>()?.tenantId;
    if (!tenantId) throw new HttpError(403, "Missing tenant");
    return { $and: [merged, { tenantId }] };
  }
}
```

`transformFilter` and `transformProjection` keep moost-db's async-capable signatures (`FilterExpr | Promise<FilterExpr>`, `$select | undefined | Promise<…>`) on every ARBAC controller — read-only and value-help included — so an override may be `async` (await a lookup, then `super`); moost-db awaits the result, on built-in reads, grouped reads and `/one` alike. A custom route that calls the hook itself must `await` it too. The ARBAC bodies still compute synchronously. Before 0.1.74 they were typed synchronous, and an `async` override failed TypeScript inheritance (TS2416).

## Custom routes: `useArbacDbScope()`

A `@DbAction` handler or custom route that queries `this.table` directly bypasses the controller's hooks — it must apply the scope itself. `useArbacDbScope()` returns the current event's merged scope as ready-to-use helpers ([signature](/api/arbac-moost#usearbacdbscope)):

```ts
import { ArbacResource, AsArbacDbController, useArbacDbScope } from "@aooth/arbac-moost";
import { DbAction, DbActionID, TableController } from "@atscript/moost-db";
import { HttpError, Post } from "@moostjs/event-http";
import { Task } from "./task.as";

@TableController(Task)
@ArbacResource("tasks")
export class TasksController extends AsArbacDbController<typeof Task> {
  @Post("actions/markDone")
  @DbAction<typeof Task>("markDone", { label: "Mark done" })
  async markDone(@DbActionID() id: { id: string }) {
    const scope = await useArbacDbScope<typeof Task>();
    const r = await this.table.updateMany(scope.filter({ id: id.id }), {
      status: "done",
      ...scope.set(),
    });
    if (r.matchedCount === 0) throw new HttpError(404, "Not found");
    return { ok: true };
  }
}
```

| Helper                           | Returns                                                                                                                                                                                                                                                                                       |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `filter(extra?)`                 | The union of the scopes' row filters, `$and` `extra`. `{}` when unrestricted.                                                                                                                                                                                                                 |
| `set()`                          | The merged `set` overrides (later scopes win) — spread them LAST over your data.                                                                                                                                                                                                              |
| `check()`                        | The effective WITH CHECK filter (`check`, else `filter`; unioned across roles). `{}` when unrestricted.                                                                                                                                                                                       |
| `assertRowsInScope(table, ids)`  | Resolves every id to exactly one row (primary key first, else a unique key the scope shows), one `count`; 404 `Not found` if any is missing or out of scope. Duplicate ids count once.                                                                                                        |
| `assertRefsInScope(table, rows)` | The [`checkRefs`](#fk-target-checks-checkrefs) FK target check for rows you insert: 403 `Referenced row "x" is outside your scope`. From 0.1.72.                                                                                                                                              |
| `writeOptions(table)`            | Write options for `table.insertOne/Many`, `replaceOne` / `bulkReplace`, `updateOne` / `bulkUpdate`: the CRUD endpoints' in-transaction enforcement — nested writes (403), USING (404), `checkRefs` (403), WITH CHECK (403, rolled back). Does not apply `allowedFields` / `set`. From 0.1.72. |
| `removeOptions(table)`           | Options for `table.deleteOne`: the id is pinned among in-scope rows and an out-of-scope row is a 404, like `DELETE`. From 0.1.72.                                                                                                                                                             |
| `scopes`                         | The raw evaluated `ArbacDbScope[]`.                                                                                                                                                                                                                                                           |

- **Fails closed.** Scopes come from the authorize interceptor's cache; when none are cached (a `@Public()` route, no interceptor) it evaluates ARBAC for the route's resource/action — a deny is a 403. The [empty-scope rule](#empty-scope-rule) applies: an allow left with no scope is a 403 too.
- **Prefer `writeOptions` over hand-rolled checks** for inserts / updates through `this.table`: the checks run inside the write's transaction against the exact rows written.
- **Never spread the scope filter.** `{ ...scopeFilter, id }` lets a key of your filter replace the scope's; pass your filter as `filter(extra)` (or combine with `conjoinScopeFilters`).
- Use `assertRowsInScope` before a write that addresses rows by id but doesn't filter by the scope itself (a handler that takes ids and calls another service).
- `useArbac().getScopes<ArbacDbScope>()` still returns the raw cached list (or `undefined`) when you need it without evaluation.

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

| Scope field                            | What it does at runtime                                                              |
| -------------------------------------- | ------------------------------------------------------------------------------------ |
| `filter: { tenantId: attrs.tenantId }` | Every read/update/delete is wrapped in `$and: [filter, userFilter]`.                 |
| `set: { tenantId, ownerId }`           | Every insert/update has these defaults overlaid (caller can't fake `tenantId`).      |
| `allowedFields: ["title", "body"]`     | Every write strips fields outside these paths. Identifiers + version auto-preserved. |
| `controls: { $with: false }`           | Caller can't expand joined relations on this resource.                               |
| `projection: ['id', 'title']`          | Read responses are whitelisted to these fields only.                                 |
| `check: { status: "draft" }`           | Written rows must match (default: `filter`; `{}` = off). From 0.1.72.                |
| `nestedWrites: ["comments"]`           | Allows nested writes through the `comments` nav prop (default: 403). From 0.1.72.    |
| `checkRefs: ["projectId"]`             | A set `projectId` must reference a project the caller can read (403). From 0.1.72.   |

To give reads, writes and actions of one table different scopes over a shared row filter, use [`defineTableAccess`](/arbac/privileges#definetableaccess-one-policy-per-table) instead of separate `allowTable*` calls.

## Identifier auto-preservation

`applyAllowedFieldsAndSet` always preserves keys from `table.identifications` — your primary key, every column in a `@db.table.uniqueIndex` group, etc. — plus the `@db.column.version` column and `$cas`. This means a scope like `allowedFields: ["title"]` doesn't accidentally strip the `id` from an update payload (which would silently break the update) or the `version` (which would silently turn off optimistic concurrency — before 0.1.72 a stale PATCH then succeeded instead of answering 409).

## Row actions run only where their grant reaches

A caller may read many rows but act on only some of them. Each row-level `@DbAction` is scoped by the caller's grant **on that action**, not by the read grant (since 0.1.72, moost-db ≥ 0.1.145):

```ts
defineRole<UserAttrs, ArbacDbScope<Ticket>>()
  .id("triage")
  .use(
    allowTableRead("tickets"), // reads the whole table
    allowTableAction("tickets", ["resolve"], { scope: (a) => ({ filter: { teamId: a.teamId } }) }),
  );
```

- **Action gate.** `POST /tickets/actions/resolve` on another team's ticket answers the missing-row 404.
- **`$actions`.** `?$actions=true` lists `resolve` only on the team's rows.
- **`GET /tickets/meta/actions/:id`** (and `meta/actions?k=v`). This answers which row-level actions the caller may run on one row, as `{ actions, disabledReasons? }`, with no row data. It needs no read grant. The caller must hold a grant on at least one row-level action of the controller, otherwise 403. An out-of-scope row and a missing one both answer `{ actions: [] }`. Field visibility on this route is the union of the granted actions' projections, so a `disabled` rule never sees a column that every granted action hides.

The action's filter includes custom-field [`rowFilter`s](/arbac/scopes#fields-that-restrict-rows-rowfilter) and credential [attenuation](/arbac/attenuation). Actions with equal grants are checked with one query. How the route is authorized: it has no grant of its own. moost-db tags its handlers as delegating authorization to `prepareRequest` (`getDbEndpoint`, moost-db ≥ 0.1.145). The ARBAC authorize interceptor therefore skips its own evaluation for them on the ARBAC DB controllers, and `prepareRequest` authorizes them. Subclasses need nothing extra and the route is not public (`useArbac().isPublic` stays `false`). On a plain moost-db controller the interceptor still evaluates the handler, so the route answers 403.

`$actions` and the route list only the actions the caller holds a grant on. The controllers' `allowedActions(names)` override answers this per action, with the same rule `/meta` uses, without building the `/meta` overlay on every read.

### Bounding an action by its candidate rows

Since moost-db 0.1.147 `actionRowScope(name, ctx)` receives the candidate rows (`ctx.purpose`, `ctx.ids`, `ctx.loadRows(fields)`), so an app can bound an action by data the grant cannot express — e.g. "resolve only issues whose **ticket** belongs to my team" (a related table). The ARBAC grant filter stays candidate-free (it is evaluated once per action per request): several grants on the action **union**, credential attenuation **intersects**. Add your bound on top with `conjoinScopeFilters` (re-exported from `@aooth/arbac-moost` since 0.1.74) — always AND it onto `super`'s filter, never return it instead:

```ts
import { AsArbacDbController, conjoinScopeFilters } from "@aooth/arbac-moost";
import type { TDbActionScopeContext } from "@atscript/moost-db";

class IssuesController extends AsArbacDbController<typeof Issue> {
  protected async actionRowScope(name: string, ctx?: TDbActionScopeContext) {
    const grant = await super.actionRowScope(name, ctx); // union of grants ∧ attenuation
    if (name !== "resolve" || !ctx) return grant;
    const issues = await ctx.loadRows(["ticketKey"]);
    const own = await tickets.findMany({
      filter: { key: { $in: issues.map((i) => i.ticketKey) }, teamId: currentTeamId() },
      controls: { $select: ["key"] },
    });
    return conjoinScopeFilters(grant, { ticketKey: { $in: own.map((t) => t.key) } });
  }
}
```

The bound applies on every surface — `$actions`, `GET /meta/actions/:id` and the action gate (an id outside it answers the missing-row 404, a `'rows'` request fails like a disabled row). An action-only caller (an action grant, no read grant) keeps working: the action event's overlay is the action grant. Call `super.actionRowScope(name, ctx)` with `ctx` possibly `undefined` (a direct call from your own code passes none).

### Actions listed on a view (`@DbActionsFrom`)

A view controller decorated with moost-db's `@DbActionsFrom(() => SourceController)` (moost-db ≥ 0.1.147) lists the source's row actions on its rows. Under ARBAC (since 0.1.74):

- Every delegated verdict — `/meta.actions`, `$actions` on the view's rows, `GET /meta/actions…` — is the SOURCE's, evaluated under the caller's grants on the source's resource (its row grants, `actionRowScope`, `disabled`). A grant on the view's own resource never adds a delegated action, even under the same action name.
- The view's rows (and so the source ids) come only from what the caller may read on the view.
- `GET {view}/meta/actions…` is served without any grant on the view when the view has no own row-level grant: its own part lists nothing; each delegated action is answered by the source (no source grant → `{ actions: [] }`).
- Executing always goes through the source's own route (`info.value`), authorized there.

### Query targets: read and action

An action declaring moost-db's `queryTarget` accepts `{ query: { q, exclude?, expectCount?, dryRun? } }` instead of `{ ids }` — "every row matching this query". On the ARBAC controllers (since 0.1.74) the target reaches only rows the caller can **both act on** (the action's grant, as the row overlay) **and list**: moost-db re-checks the query as a READ of the controller (its `query` route), where `prepareRequest` resolves the caller's read grant (attenuation included) and its filter becomes the read overlay. Nothing to override:

- A caller with an action grant but no read grant gets **403** (dry run included). It targets rows by id.
- A region reader with an unrestricted action grant targets only its region; a whole-table reader with a team-scoped action grant targets only the team's rows; an attenuated credential narrows `matched`.
- The query's filter is checked exactly like a `/query` filter, under the read grant's field visibility: a field the caller cannot read is `Unknown field` (400); a field only the action grant hides may filter the target (the caller can read it anyway).
- A query that matches nothing never runs the handler (an empty summary).
- A [relational predicate](#relational-filter-predicates-some-none) in the target's `q` works as on `/query`: it is allowed when the read-side `$with` policy allows the relation (else `Unknown field` 400), and the related table's row scope is conjoined into it.

On a view, `POST {view}/delegated-actions/:name` is a READ of the view: it needs the caller's read grant on the view (else 403) and grants nothing on the action. The source must also list the action for the caller (any grant on it there) — else 403, dry runs included. The matching rows are run through the source's own route in batches, and that route re-authorizes every batch (guards, the action grant, `actionRowScope`, `disabled`): rows outside the caller's source grant are reported as `skipped` and never run.

## Fail-closed: every endpoint

Every built-in route (`/query`, `/pages`, `/geo`, `/one`, `/meta`, `/meta/form`, and every write) resolves the caller's scopes in `prepareRequest` before anything else runs — `@DbAction` handlers too (moost-db ≥ 0.1.143 calls `prepareRequest` with `endpoint: "action"` before any action id is validated or row loaded, table-level actions included). It uses the ones [`arbacAuthorizeInterceptor`](./arbac-authorize) cached, otherwise the controller evaluates the handler's resource/action itself. So:

- A principal with no grant gets **403** on every route.
- A missing authorize interceptor does **not** open the table.
- `@Public()` (`arbacPublic`) does **not** bypass an ARBAC DB controller. It only skips the interceptor. Grant the actions to a public role instead.
- `GET /meta/actions/:id` is authorized by row-level action grants, not a read grant. See [Row actions](#row-actions-run-only-where-their-grant-reaches).
- `POST /delegated-actions/:name` (a view's delegated query target) is authorized by the read grant on the view; the source route authorizes each batch. See [Query targets](#query-targets-read-and-action).

Before 0.1.72, a controller without the interceptor ran writes unscoped, and reads returned rows with hidden columns.

The scopes are resolved **once** per request at that entry point; every other hook (`transformFilter`, `hasField`, `validateControls`, the write guards) reads them and answers **403** when they are unresolved — never "unrestricted". A custom (non-action) route that wants the scope calls [`useArbacDbScope()`](#custom-routes-usearbacdbscope), which resolves them. A granted action is still bound to its own scope: an id outside it answers like a missing row (404).

### Empty-scope rule

How an evaluation outcome turns into scopes (0.1.72+, `normalizeScopes` in `@aooth/arbac`):

| Outcome                                                | Result                                      |
| ------------------------------------------------------ | ------------------------------------------- |
| denied                                                 | 403                                         |
| allowed, rule without `scope`                          | unrestricted (`{}`)                         |
| allowed, no `scopes` list (a scope-agnostic evaluator) | unrestricted (`[{}]`)                       |
| a `scope` function returns `undefined` / `null`        | that rule contributes nothing (fail closed) |
| allowed, but no scope left (`scopes: []`)              | 403                                         |

Every deny answers `Insufficient privileges for action "<action>" on resource "<resource>"`, the same message as the authorize interceptor. Before 0.1.72 an allow with an empty scope list matched nothing (200, no rows) in `useArbacDbScope`, and a `scope` returning `undefined` was treated as unrestricted.

If you override `prepareRequest`, call `super.prepareRequest(ctx)` first.

## Value-help controllers

`AsArbacJsonValueHelpController<T>` and `AsArbacValueHelpController<T>` (since 0.1.72) are the ARBAC mirrors of `@atscript/moost-db`'s value-help controllers — the `/query`, `/pages`, `/one`, `/meta` surface behind FK pickers and dictionaries. Use the JSON variant for a static row set, the abstract one to plug your own source (implement `query` + `getOne`). Needs `@atscript/moost-db` ≥ 0.1.143.

```ts
import { allowTableRead, defineRole } from "@aooth/arbac";
import { ArbacResource, AsArbacJsonValueHelpController } from "@aooth/arbac-moost";
import { Controller, Moost } from "moost";

@Controller("dicts/status")
@ArbacResource("dict-status")
export class StatusDictController extends AsArbacJsonValueHelpController<typeof StatusDict> {
  constructor(app: Moost) {
    super(StatusDict, STATUS_ROWS, app);
  }
}

// Grant it like a table:
export const staffRole = defineRole()
  .id("staff")
  .use(allowTableRead("dict-status", { scope: () => ({ filter: { active: true } }) }))
  .build();
```

### Resource and action names

The resource is the controller's `@ArbacResource(...)` (else the usual fallback: controller id, then class name). The data routes are re-tagged with the standard table **read** action ids, so `allowTableRead` / `allowTableOps(resource, ["read"])` / `defineTableAccess({ read })` grant a value-help source exactly like a table:

| Route             | Handler              | ARBAC action      |
| ----------------- | -------------------- | ----------------- |
| `GET /query`      | `runQuery`           | `query`           |
| `GET /pages`      | `runPages`           | `pages`           |
| `GET /one/:id`    | `runGetOne`          | `getOne`          |
| `GET /one?<pk>=…` | `runGetOneComposite` | `getOneComposite` |
| `GET /meta`       | `meta`               | `meta`            |

The plain moost-db value-help controllers keep the method names (`runQuery`, …) as action ids — `allowTableRead` grants only their `/meta`, and no scope is applied to their data routes. Put ARBAC-governed value-help sources on the ARBAC classes.

### What the scope does

The same [`ArbacDbScope`](#arbacdbscope-t-contract) contract as the DB controllers, through the value-help hooks:

| Scope field     | Effect on value-help                                                                                                                    |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `filter`        | `$and`-ed with the request filter on `/query` / `/pages`; a row outside it answers **404** on `/one`.                                   |
| `projection`    | Hidden columns are stripped from every row; the PK is always returned (unless an explicit `$select` leaves it out).                     |
| (hidden fields) | A hidden field in a filter, `$sort` or `$select` is `400 Unknown field "x"`, and never matches `$search`.                               |
| `controls`      | Gates such as `{ $search: false }` answer 403.                                                                                          |
| — (`/meta`)     | `crud` filtered per action; `fields` / `type` pruned to the visible fields; `searchable: false` when no searchable field stays visible. |

`with`, `set`, `allowedFields`, `check`, `nestedWrites` and `checkRefs` do not apply — value-help is read-only and has no relations.

### Fail-closed

Every route resolves the caller's scopes before anything else runs: the ones [`arbacAuthorizeInterceptor`](./arbac-authorize) cached, otherwise the controller evaluates the handler's resource/action itself. So:

- A principal with no grant gets **403** on every route (`/meta` included).
- A missing authorize interceptor does **not** open the data — the controller evaluates on its own.
- `@Public()` (`arbacPublic`) does **not** bypass it — it only skips the interceptor.

### DOs and DON'Ts

- **Do** keep the `super` call when overriding `hasField`, `transformFilter`, `transformProjection`, `validateControls`, `applyMetaOverlay` or `prepareRequest`.
- **Do**, in a custom `AsArbacValueHelpController.query`, skip fields `this.hasField(f)` rejects when you implement `$search` — the ARBAC layer can't see inside your search. `filter` and `$select` arrive already scoped.
- **Don't** override `runQuery` / `runPages` / `runGetOne` / `runGetOneComposite` without re-applying `@ArbacAction(...)` — without it the action id reverts to the method name and `allowTableRead` stops granting the route.
- **Don't** mark an ARBAC value-help controller `@Public()` expecting open access — grant the read actions to the public role instead.

## See also

- [ARBAC Authorize](./arbac-authorize) — the upstream interceptor that produces the scopes.
- [Atscript Models](./atscript) — the `.as`-annotated user model that drives `getRoles` / `getAttrs`.
- [Config Reference](./config) — workflow-level options. Role tuning is framework-agnostic, see [/arbac](../arbac/) for the engine.
