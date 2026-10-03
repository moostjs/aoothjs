# `@aooth/arbac-moost` API Reference

Complete export reference for `@aooth/arbac-moost`. See the [Moost Integration Guide](/moost/) and [ARBAC Authorize](/moost/arbac-authorize) for narrative documentation. Subpaths: `./atscript`, `./plugin`.

## Classes

### `MoostArbac<TUserAttrs, TScope>`

```ts
@Injectable()
class MoostArbac<TUserAttrs extends object, TScope extends object> extends Arbac<
  TUserAttrs,
  TScope
> {
  registerScopeFields(rules: TScopeFieldRules<TScope>): this; // since 0.1.72
  override evaluate(/* as Arbac.evaluate */): Promise<TArbacEvalResult<TScope>>; // folds rowFilter (since 0.1.72)
  getScopeFields(): TScopeFieldRules<TScope>; // since 0.1.72
}
```

DI-injectable `Arbac` subclass. Register a singleton in the provide registry so `registerRole(...)` is reachable at boot. See [ARBAC Authorize](/moost/arbac-authorize).

`registerScopeFields` registers the conjunction rule ([`TScopeFieldRule`](/api/arbac#tscopefieldrule-s-tscopefieldrules-s)) of each custom (declaration-merged) `ArbacDbScope` field, once per field — used by credential attenuation and the `$with` conjunctions it triggers. A rule's optional `rowFilter` folds the field into each evaluated scope's `filter`, so every row path enforces it. Validates every rule before registering any (atomic). Throws on a built-in key, a missing `conjoin`, a non-function `rowFilter`, or re-registering a name with a different rule. `evaluate` returns the engine's result with the `rowFilter`s folded into both passes' scopes, and warns once about a custom scope key with no rule. An attenuated evaluation that meets a custom field with no rule fails with a generic `HttpError(500)` instead of dropping it; the details are logged server-side once. See [Custom scope fields](/arbac/scopes#custom-scope-fields).

### `ArbacUserProvider<TUserAttrs>` (abstract)

```ts
abstract class ArbacUserProvider<TUserAttrs extends object = object> {
  abstract getUserId(): string | Promise<string>;
  abstract getRoles(id: string): string[] | Promise<string[]>;
  abstract getAttrs(id: string): TUserAttrs | Promise<TUserAttrs>;
}
```

Abstract base. Every concrete subclass MUST re-apply `@Injectable()` — moost@0.6.x does not inherit injectable metadata across `extends`. Bind your concrete class via `setReplaceRegistry([ArbacUserProviderToken, MyProvider])`. See [ARBAC Authorize](/moost/arbac-authorize).

### `ArbacUserProviderToken`

```ts
const ArbacUserProviderToken: TClassConstructor<ArbacUserProvider>;
```

DI key used to look up the user provider. The abstract class itself does not satisfy moost's `TClassConstructor` shape, so this cast is the registration handle. See [ARBAC Authorize](/moost/arbac-authorize).

### `AsArbacDbController<T>`

```ts
class AsArbacDbController<T> extends AsDbController<T> {}
```

`@atscript/moost-db` controller subclass that wires ARBAC into every CRUD seam: `prepareRequest` (fail-closed scope resolution), `transformFilter`, `transformProjection`, `validateControls`, `applyMetaOverlay`, `authorizeForm`, `hasField`, `actionRowScope` (each row action scoped by its own grant; since 0.1.72 — takes moost-db's candidate `ctx` since 0.1.74, see [Bounding an action by its candidate rows](/moost/db-controllers#bounding-an-action-by-its-candidate-rows)), `transformRelationFilter` (a client relational predicate's operand ∧ the related rows the caller may see; since 0.1.74, moost-db ≥ 0.1.147), `allowedActions` (the granted row-level actions for `$actions` / `meta/actions`, without building the `/meta` overlay; since 0.1.72), `onWrite` (nested writes + `allowedFields` / `set`), `guardWrite` / `guardRemove` (USING), `checkWrite` (WITH CHECK). `GET meta/actions/:id` / `meta/actions?…` are served iff the caller holds a grant on at least one row-level action; moost-db tags them as delegating authorization to `prepareRequest` (`getDbEndpoint`), so the authorize interceptor skips its own evaluation for them on this controller (it carries [`ARBAC_DELEGATED_AUTH`](#arbac-delegated-auth)). They need no read grant and are not public (since 0.1.72, moost-db ≥ 0.1.145; see [Row actions](/moost/db-controllers#row-actions-run-only-where-their-grant-reaches)). On a `@DbActionsFrom` view they are served even without an own row-level grant (delegated actions answer per source), and the view's `POST delegated-actions/:name` is authorized by the read grant on the view (since 0.1.74; see [Actions listed on a view](/moost/db-controllers#actions-listed-on-a-view-dbactionsfrom)). Scopes auto-applied — no explicit `getScopes()` call needed in handlers. See [DB Controllers](/moost/).

Two seams enforce that a scope `projection` removes fields from existence, not just from row payloads:

- **`applyMetaOverlay`** prunes the `/meta` envelope — `fields`, the serialized `type`, `relations`, `versionColumn` — down to the union of the allowed read ops' scope projections (PK + `preferredId` always survive; reads always return them). A scoped UI can no longer offer columns that would never populate, and secret-bearing column names stop leaking. Unscoped read grants keep the full envelope; write-only principals keep `type` for their insert/update forms.
- **`hasField`** answers `false` for paths outside that union, so any query reference to a hidden field gets the **identical** `Unknown field "x"` 400 a nonexistent field gets — no existence or value oracle. A path under a relation (`$with=rel(x>1)`, `$with=rel($sort=x)`, `$with=rel($select=x)`) is checked as `x` against the relation's policy — the union of declared `with.rel` sub-scopes, else (0.1.72+) the caller's own grant on the related table; no grant → the relation is unknown. Recursive; the related table's PK / `preferredId` stay visible, and `/meta` prunes the relation's nav type the same way. Derived columns follow their source; SQL `@db.json` columns are atomic. Requirements (moost-db version, authorize interceptor, search indexes): [Column-scope security floor](/moost/db-controllers#column-scope-security-floor).

### `AsArbacDbReadableController<T>`

```ts
class AsArbacDbReadableController<T> extends AsDbReadableController<T> {}
```

Read-only mirror of `AsArbacDbController` for view controllers — including the same `/meta` pruning + `hasField` parity. Both classes are view-safe on every read path (all read-side enforcement goes through the bound readable, never the view-guarded `.table` getter); bind `@db.view` models with `@ReadableController(ViewModel)`. See [DB Controllers](/moost/).

### `AsArbacValueHelpController<T>` / `AsArbacJsonValueHelpController<T>`

```ts
abstract class AsArbacValueHelpController<
  T,
  DataType = TAtscriptDataType<T>,
> extends AsValueHelpController<T, DataType> {}
class AsArbacJsonValueHelpController<
  T,
  DataType = TAtscriptDataType<T>,
> extends AsJsonValueHelpController<T, DataType> {}
```

Since 0.1.72 (needs `@atscript/moost-db` ≥ 0.1.143). ARBAC mirrors of moost-db's value-help controllers (`/query`, `/pages`, `/one`, `/meta`): `prepareRequest` resolves the scopes on every route (evaluates when the interceptor didn't; deny → 403; `arbacPublic` does not bypass), `transformFilter` conjoins the scope filter (`/one` outside it → 404), `transformProjection` strips hidden columns (PK kept), `hasField` makes hidden fields unknown (filter / `$sort` / `$select`, never matched by `$search`), `validateControls` enforces `controls` gates, `applyMetaOverlay` prunes `/meta`. The data handlers carry the table read action ids (`query`, `pages`, `getOne`, `getOneComposite`), so `allowTableRead` grants them. See [Value-help controllers](/moost/db-controllers#value-help-controllers).

## Functions

### `arbacAuthorizeInterceptor`

```ts
const arbacAuthorizeInterceptor: TInterceptorFn & {
  __authTransports: TAuthTransportDeclaration;
};
```

`defineBeforeInterceptor` at `TInterceptorPriority.GUARD`. No-ops on public/no-metadata events. On deny throws `HttpError(403)`; non-`HttpError` from the evaluator is rethrown as `HttpError(401)`. The `__authTransports: {}` marker makes `@moostjs/swagger` treat it as an auth-guard with no transport requirement. See [ARBAC Authorize](/moost/arbac-authorize).

### `useArbac`

```ts
function useArbac(ctx?: EventContext): ArbacBindings;

interface ArbacBindings {
  readonly resource: string;
  readonly action: string;
  readonly isPublic: boolean;
  getScopes<TScope>(): TScope[] | undefined;
  setScopes<TScope>(scopes: TScope[]): void;
  evaluate<TScope>(
    over?: ArbacEvaluateOptions,
  ): Promise<{ allowed: boolean; scopes?: TScope[]; userId: string }>;
  evaluateOrThrow<TScope>(
    over?: ArbacEvaluateOptions,
  ): Promise<{ allowed: true; scopes?: TScope[]; userId: string }>;
}

interface ArbacEvaluateOptions {
  resource?: string;
  action?: string;
  /** Readable whose schema an attenuation conjunction uses (0.1.72+); default: the controller's. */
  table?: VisibilityTableSource;
}
```

Pass `table` when you evaluate a grant on a different table than the current controller's, so a credential-attenuated projection subtracts nested exclusions against that table's schema.

### `getArbacScopes`

```ts
function getArbacScopes<TScope extends object>(ctx?: EventContext): TScope[] | undefined;
```

Reads the scopes cached for the current event, the same slot `useArbac().getScopes()` reads, without resolving controller metadata. Use it in per-field hot paths such as a custom `hasField`. `undefined` before the authorize interceptor or `setScopes` ran.

**`useArbac` is intentionally not a `defineWook`** — wook cache would replay parent HTTP resolution into WF child events. Resource/action resolution chain: `mMeta.arbacResourceId → cMeta.arbacResourceId → cMeta.id → constructor.name` and `mMeta.arbacActionId → mMeta.atscript_db_action.name → cMeta.arbacActionId → mMeta.id → cc.getMethod()`. See [ARBAC Authorize](/moost/arbac-authorize).

### `useArbacDbScope`

```ts
function useArbacDbScope<T = unknown>(): Promise<ArbacDbScopeHelpers<T>>;

interface ArbacDbScopeHelpers<T = unknown> {
  scopes: ArbacDbScope<T>[];
  filter(extra?: TScopeFilter): TScopeFilter;
  set(): Record<string, unknown>;
  check(): TScopeFilter;
  assertRowsInScope(table: ArbacScopedTable, ids: readonly unknown[]): Promise<void>;
  assertRefsInScope(
    table: RefTableSource,
    rows: ReadonlyArray<Record<string, unknown>>,
  ): Promise<void>;
  writeOptions<Row extends object = Record<string, unknown>>(
    table: ArbacGuardedTable,
  ): TWriteOptions<Row>;
  removeOptions<Row extends object = Record<string, unknown>>(
    table: ArbacGuardedTable,
  ): TDeleteOptions<Row>;
}

interface ArbacScopedTable extends VisibilityTableSource {
  resolveRowFilter(id: unknown, opts?: TRowResolveOptions): Promise<object | null | undefined>;
  count(query: { filter: TScopeFilter; controls?: Record<string, never> }): Promise<number>;
}

interface ArbacGuardedTable extends ArbacScopedTable, ArbacWriteTable, RefTableSource {}
```

The current event's merged DB scope for custom routes and `@DbAction` handlers: scope filter `$and` an extra filter, merged `set`, effective WITH CHECK filter, one-count id verification (each id pinned to exactly one row, primary key first; 404 `Not found`), `assertRefsInScope` — the [`checkRefs`](/moost/db-controllers#fk-target-checks-checkrefs) FK target check (403) — and `writeOptions` / `removeOptions`: atscript-db write / delete options carrying the CRUD endpoints' in-transaction enforcement (nested writes, USING, `checkRefs`, WITH CHECK; `allowedFields` / `set` are not applied). Resolves the event's scopes once (the interceptor's cache, else an evaluation); a deny — including the [empty-scope rule](/moost/db-controllers#empty-scope-rule)'s "allowed but no scope left" — is a 403. `AtscriptDbTable` satisfies `ArbacGuardedTable`. Since 0.1.72. See [DB Controllers](/moost/db-controllers#custom-routes-usearbacdbscope).

### Custom ARBAC controller building blocks

```ts
// Scope resolution — once per event at the entry point; the rest read it
function resolveRequestScopes(): Promise<ArbacDbScope[]>; // 403 on deny
function requireRequestScopes(): ArbacDbScope[]; // 403 when not resolved yet
function cachedRequestScopes(): ArbacDbScope[] | undefined;

// Controller hook bodies
function prepareArbacRequest(
  ctx: TDbRequestContext,
  readable?: VisibilityTableSource,
): Promise<void>;
function arbacRowFilter(filter?: Record<string, unknown>): Record<string, unknown>;
function requestFieldVisible(
  path: string,
  source: VisibilityTableSource | ReadonlySet<string>,
): boolean;
function authorizeArbacForm(actionNames: readonly string[]): Promise<boolean>;
function arbacActionRowScope(name: string): Promise<Record<string, unknown> | undefined>; // since 0.1.72
function arbacRelationFilter(
  path: string,
  filter: FilterExpr,
  readable: VisibilityTableSource,
): FilterExpr; // since 0.1.74
function arbacAllowedActions(names: readonly string[]): Promise<string[]>; // since 0.1.72
function applyArbacProjection(
  projection: unknown,
  scopes: ArbacDbScope[],
  readable?: VisibilityTableSource,
): TProjection | undefined;
function applyArbacControls(controls: Record<string, unknown>, scopes: ArbacDbScope[]): void;
function applyArbacRelationScopes(
  controls: Record<string, unknown>,
  scopes: ArbacDbScope[],
  readable?: VisibilityTableSource,
): void;

// Write guards (`guardWrite` / `checkWrite` / `guardRemove` bodies)
function guardArbacWrite(
  ctx: TDbWriteGuardContext,
  scopes: readonly ArbacDbScope[],
  table: ArbacWriteTable,
  refs: RefTableSource,
): Promise<void>;
function checkArbacWrite(ctx: TDbWriteCheckContext, scopes: readonly ArbacDbScope[]): Promise<void>;
function guardArbacRemove(
  ctx: TDbRemoveGuardContext,
  scopes: readonly ArbacDbScope[],
  table: Pick<ArbacWriteTable, "count">,
): Promise<void>;

// `$with` inherit-target policy
function registerArbacDbTarget(controller: object): true;
function resolveHandlerArbacIds(
  instance: object,
  methodName: string,
): { resource: string; action: string };
```

Since 0.1.72. The pieces `AsArbacDbController` / `AsArbacDbReadableController` are built from, for a controller on another moost-db base (or an overridden hook that must keep the ARBAC contract):

- **Scopes** — resolved once per event by `resolveRequestScopes` (the `prepareRequest` / action-guard entry point, [empty-scope rule](/moost/db-controllers#empty-scope-rule) applied); every other hook reads them with `requireRequestScopes` (403 when unresolved) or `cachedRequestScopes`. Unresolved scopes are never "unrestricted".
- **`@DbAction` handlers** — covered by `prepareRequest` (`endpoint: "action"`, moost-db ≥ 0.1.143): `prepareArbacRequest` resolves the scopes before any action id / row is read (403 on deny, `arbacPublic` does not bypass). Don't read action ids or rows inside `prepareRequest`.
- **Hooks** — `prepareArbacRequest` is the `prepareRequest` body (resolve scopes, 403 on deny, resolve the `$with` policy on read endpoints); `arbacRowFilter` the `transformFilter` body; `requestFieldVisible` the `hasField` body; `authorizeArbacForm` the `authorizeForm` body; `arbacActionRowScope` the `actionRowScope` body (the action's grant filter; no grant → match-nothing; one object per equal filter per request); `arbacRelationFilter` the `transformRelationFilter` body (the operand ∧ the row filter of the relation's policy at `path`; an unresolved relation → 400; since 0.1.74); `prepareArbacRequest` also resolves the relations the client filter's relational predicates name (`ctx.filter`) and applies the `controls.$with` gates to them (since 0.1.74), and authorizes `endpoint: "delegatedAction"` (a view's `POST /delegated-actions/:name`: the read grant, else 403; since 0.1.74); `prepareArbacRequest` also authorizes `endpoint: "availableActions"` (any row-level action grant, else 403; request scopes = the granted actions' scopes without `filter` / `check` — unrestricted row overlay, field visibility of the granted actions — to let the interceptor delegate the route, the controller must carry `ARBAC_DELEGATED_AUTH`; without it the route stays 403); `arbacAllowedActions` the `allowedActions` body; `applyArbacProjection` / `applyArbacControls` / `applyArbacRelationScopes` the `transformProjection` / `validateControls` bodies (pass `requireRequestScopes()` — the request's scopes carry its `$with` resolution).
- **Write guards** — `guardArbacWrite` (USING, `checkRefs`, WITH CHECK on non-transactional adapters), `checkArbacWrite` (post-write WITH CHECK) and `guardArbacRemove` (USING for deletes) are the bodies of `guardWrite` / `checkWrite` / `guardRemove` — the same functions `useArbacDbScope().writeOptions()` uses.
- **`$with` targets** — `registerArbacDbTarget(this)` (a field initializer) makes a controller the policy source for its table, so a `$with` from another controller applies the caller's grant on it; without a registered controller an undeclared relation is `Unknown relation`.
- **`resolveHandlerArbacIds`** — the resource / action a handler is authorized as, with `useArbac()` precedence (method `@ArbacResource` → class → controller id → class name; method `@ArbacAction` → `@DbAction` name → class `@ArbacAction` → `@Id` → method name).

Removed before release (0.1.72 pre-release names): `ensureRequestScopes` (use `resolveRequestScopes`, which now throws), `resolveRelationScopes`, `enforcedRefs` / `assertRefsInScope` (use the write guards or `useArbacDbScope().assertRefsInScope`), `arbacDbActionGuard` / `WithArbacDbActionGuard` (`prepareRequest` covers actions).

A `$with` relation the scopes hide is left to moost-db: it answers `Unknown relation` through `hasField` at every level, like a nonexistent one. `VisibilityTableSource.jsonParents` / `RefTableSource.foreignKeyOf` are atscript-db's `readable.jsonParents` / `readable.foreignKeyOf`.

### `ARBAC_DELEGATED_AUTH` {#arbac-delegated-auth}

```ts
const ARBAC_DELEGATED_AUTH: unique symbol;
interface ArbacDelegatedAuth {
  [ARBAC_DELEGATED_AUTH](method: string): boolean;
}
```

Marks a controller whose `prepareRequest` authorizes moost-db's delegated handlers (`GET meta/actions/:id`) with ARBAC. The method answers whether `method` is such a handler. `AsArbacDbController` / `AsArbacDbReadableController` implement it as `getDbEndpoint(this, method) !== undefined`. For such a handler, `arbacAuthorizeInterceptor` skips its own evaluation. A custom controller built on another moost-db base, using `prepareArbacRequest`, adds the same method; without it the route stays 403. Since 0.1.72.

### `getArbacMate`

```ts
function getArbacMate(): Mate<TArbacMeta>;
interface TArbacMeta {
  arbacResourceId?: string;
  arbacActionId?: string;
  arbacPublic?: boolean;
}
```

Shared moost `Mate` typed with `TArbacMeta`. `TArbacMeta` is **declaration-merged into `moost`'s `TMoostMetadata`** so framework consumers see fields on their handler metadata. See [Decorators](/moost/decorators).

::: warning Internal — exposed for custom subclassers
The three helpers below (`enforceControlsPolicy`, `extractUsedControlValues`, `applyAllowedFieldsAndSet`) are wired into `AsArbacDbController`'s hooks for you. They're exported so subclassers writing custom hook overrides can compose them; app code that stays on the documented `AsArbacDbController` subclassing patterns never calls them directly. See [DB Controllers](/moost/).
:::

### `enforceControlsPolicy`

```ts
function enforceControlsPolicy(
  policy: Record<string, ControlGate>,
  controls: Record<string, unknown>,
): void;
```

Throws `HttpError(403, 'Control "$with" is not allowed for your role')` on violations. Applied by `AsArbacDbController.validateControls` against the union of scope `controls` maps.

### `extractUsedControlValues`

```ts
function extractUsedControlValues(key: string, value: unknown): string[];
```

Normalizes a control value into the list of names it references — used to feed `enforceControlsPolicy` for `$with` / `$groupBy` whitelist checks. Pass the query's `controls` as the third argument to map `$groupBy` calendar-bucket aliases to their source fields (`groupByFields` from `@uniqu/core`); `enforceControlsPolicy` does this.

### `applyAllowedFieldsAndSet`

```ts
function applyAllowedFieldsAndSet(
  data: unknown,
  scopes: ArbacDbScope[],
  identifierFields?: readonly string[],
): unknown;
```

Strips fields outside the union of `allowedFields` and overlays `set` defaults. Auto-preserves keys in `identifierFields` (PK + unique-index columns). Used by `AsArbacDbController.onWrite`.

### `applyArbacMetaOverlay` / `pruneMetaByVisibility` / `unionScopeProjection` / `collectWithGrantNames` / `isMetaFieldVisible` / `buildScopeVisibility`

```ts
function applyArbacMetaOverlay(
  meta: TMetaResponse,
  source: VisibilityTableSource | ReadonlySet<string>,
  _indexes?: readonly TDbIndexFieldPaths[], // ignored since 0.1.74 — moost-db ≥ 0.1.147 prunes the search surface
): Promise<TMetaResponse>;
function pruneMetaByVisibility(
  meta: TMetaResponse,
  vis: MetaVisibility,
  refTargets?: ReadonlyMap<object, MetaVisibility | null>, // foreign `ref` targets
): TMetaResponse;
function unionScopeProjection(scopes: ArbacDbScope[]): TProjection | undefined;
function collectWithGrantNames(scopes: ArbacDbScope[]): ReadonlySet<string>;
function isMetaFieldVisible(path: string, vis: MetaVisibility): boolean;
function isScopedFieldVisible(
  scopes: ArbacDbScope[],
  path: string,
  source: VisibilityTableSource | ReadonlySet<string>,
): boolean;
function buildScopeVisibility(
  scopes: ArbacDbScope[],
  table: VisibilityTableSource | undefined,
  opts?: ScopeVisibilityOptions | ReadonlySet<string>, // a Set = the 0.1.71 `alwaysVisible`
): MetaVisibility;

interface ScopeVisibilityOptions {
  alwaysVisible?: ReadonlySet<string>; // default: the table's PK + preferredId
  relations?: ArbacRelationResolution; // undeclared relations resolved (name → visibility | null)
}
function metaAlwaysVisibleFields(
  controller: object,
  source: { primaryKeys: readonly string[]; preferredId: readonly string[] },
): ReadonlySet<string>;
```

The `/meta` field-visibility machinery behind both ARBAC controllers (see [`AsArbacDbController`](#asarbacdbcontroller-t)). `applyArbacMetaOverlay` is the full per-request overlay (actions/crud filtering + field pruning; needs the moost event context); the rest are pure and composable from custom `applyMetaOverlay` / `hasField` overrides. Pass the controller's `this.readable` as `source` (a `VisibilityTableSource`): identifiers (PK + `preferredId`) are derived from it, and its `relatedTable(navField)` reaches each joined table so that table's identifiers stay visible too.

- `isScopedFieldVisible` checks a path against any scopes (memoized per scopes array and readable); for the current request's scopes it uses the request's `$with` resolution. The controllers' `hasField` body is `requestFieldVisible` (see the building blocks).
- `buildScopeVisibility` is the single builder behind `hasField`, `/meta` pruning, `$select` value stripping and the `$with` overlay.
- `metaAlwaysVisibleFields` returns the PK + `preferredId` set; it is kept for compatibility.

`MetaVisibility` is `{ allowed: TProjection; alwaysVisible: ReadonlySet<string>; withGrants: ReadonlySet<string>; relation?: (name) => MetaVisibility | undefined; relationNames?: ReadonlySet<string>; isAllowed?: (path) => boolean; scopes?; table?; writable?: … }`:

- `allowed` is `{}` when own fields are unrestricted. It is normalized for the table: an atomic (SQL) `@db.json` column is excluded whole, a derived field with a hidden source is excluded.
- `isAllowed` is `isFieldAllowed(path, allowed)` precompiled, plus the derived-source rule.
- `relation(name)` is the visibility a `name.x` path is checked against: the declared `with.<name>` sub-scopes, else the resolved grant on the related table (`undefined` = hidden).
- `relationNames` are the table's relations; an undeclared one is visible only when resolved and its name passes the projection.

`VisibilityTableSource` gained optional `type`, `fieldDescriptors`, `jsonParents` and `isSearchable()` in 0.1.72 — a moost-db `this.readable` (atscript-db ≥ 0.1.143) has them.

A hand-built `MetaVisibility` without `relation` lets granted paths through unchecked, so build it with `buildScopeVisibility`. Passing a bare identifier set as `source` (the 0.1.67 signatures) still enforces sub-scopes, but does not exempt related identifiers. `pruneMetaByVisibility` never mutates its input (the base controller caches the static envelope).

### `conjoinScopeFilters` (re-export)

```ts
import { conjoinScopeFilters } from "@aooth/arbac-moost";
```

Re-export of [`@aooth/arbac`'s `conjoinScopeFilters`](/api/arbac#conjoinscopefilters) (since 0.1.74) — AND your own filter onto an ARBAC hook's result, e.g. a candidate-bounded `actionRowScope` ([recipe](/moost/db-controllers#bounding-an-action-by-its-candidate-rows)).

### `conjoinArbacDbScopes`

```ts
function conjoinArbacDbScopes(
  userScopes: ArbacDbScope[],
  credScopes: ArbacDbScope[],
  opts?: TProjectionChildren | ConjoinArbacDbScopesOptions, // a bare function = childrenOf (legacy form)
): ArbacDbScope[];

interface ConjoinArbacDbScopesOptions {
  childrenOf?: TProjectionChildren; // the evaluated table's schema lookup
  refTable?: RefTableSource; // resolves checkRefs names to its foreign keys
  fields?: TScopeFieldRules<ArbacDbScope>; // custom scope field rules
}
```

Credential-attenuation combiner: UNIONs each side with the additive helpers, then CONJOINS the two results facet-by-facet (`conjoinScopeFilters` `$and`, `intersectProjections` path-wise field ∩ — a parent narrows to the other side's nested whitelist; the optional `childrenOf` schema lookup (supplied by `useArbac().evaluate` for DB controllers) splits an included parent with a hidden child exactly, otherwise it is dropped; no common field → the user's projection plus a match-nothing filter, never `{}` — `intersectControlsPolicy` deny-wins, `allowedFields` intersection, recursive `with` — a relation only ONE side declares is marked `INHERITED_CONJUNCTION` and conjoined, when the request resolves it, with the caller's own grant on the related table (no grant → hidden), so a credential's declared sub-scope never stands alone as parent authority —, `checkRefs` enforced when EITHER side enforces it — `refTable`, the evaluated table, resolves the names to its foreign keys; a custom field via its `fields` rule, no rule → throws) — never the additive union helpers, which would silently widen. Returns a single-element list so downstream scope-application sites (which union the scope list per facet) see the conjunction unchanged. Consumes `credScopes` from an attenuated [`Arbac.evaluate`](/api/arbac-core#arbac-tuserattrs-tscope). See [Scope Merging](/arbac/scopes).

## Decorators

### `@ArbacResource`

```ts
function ArbacResource(name: string): ClassDecorator & MethodDecorator;
```

Writes `arbacResourceId` onto class or method mate. Method-level wins over class-level. See [Decorators](/moost/decorators).

### `@ArbacAction`

```ts
function ArbacAction(name: string): ClassDecorator & MethodDecorator;
```

Writes `arbacActionId`. Typically applied per-method. See [Decorators](/moost/decorators).

### `@ArbacAuthorize`

```ts
function ArbacAuthorize(): ClassDecorator & MethodDecorator;
```

Sugar for `Authenticate(arbacAuthorizeInterceptor)`. Use when you don't apply the interceptor globally and want to authorize a single route. See [Decorators](/moost/decorators).

::: info Not exported
`@ArbacPublic` and `@ArbacScopes` are intentionally NOT exported. Use [`@Public()`](./auth-moost#public) from `@aooth/auth-moost` (writes both `authPublic` and `arbacPublic`), and read scopes via `useArbac().getScopes<TScope>()`.
:::

## Types

### `ArbacDbScope<T>`

```ts
interface ArbacDbScope<T = unknown> {
  filter?: TScopeFilter;
  /** WITH CHECK filter a written row must match; defaults to `filter`, `{}` disables. */
  check?: TScopeFilter;
  projection?: ProjectionOf<T>;
  set?: Partial<Record<OwnFieldKey<T>, unknown>>;
  allowedFields?: Array<OwnFieldKey<T>>;
  controls?: ControlsOf<T>;
  /** Nav relations writable through the parent payload (default deny). */
  nestedWrites?: Array<NavRelationKey<T>>;
  /** FK target checks: `true` = every FK; else FK fields / the TO relations they back. */
  checkRefs?: true | Array<OwnFieldKey<T> | NavRelationKey<T>>;
  /** Per-relation sub-scopes applied when the request expands a relation via
   *  `?$with=<name>`. Recursive — each sub-scope has the same shape and can
   *  declare its own `with` for nested expansions: keys are the model's nav
   *  relations, values are `ArbacDbScope<NavTarget>` (untyped `T` falls back to
   *  `Record<string, ArbacDbScope>`; the mapped type is internal, not an
   *  exported symbol). Declared in any role → those sub-scopes govern the
   *  joined rows; otherwise (0.1.72+) the caller's own grant on the related
   *  table does — no grant → `Unknown relation`. */
  with?: Record<string, ArbacDbScope>;
}
```

The scope shape `AsArbacDbController` understands. `check`, `nestedWrites` and `checkRefs` are enforced from 0.1.72. Pass an `.as` model as `T` (e.g. `ArbacDbScope<Task>`) to get autocomplete on `projection` / `with` / `controls` / `set` / `allowedFields` against the model's own and navigation fields. `T = unknown` (the default) keeps the legacy untyped shape for back-compat. **Open to declaration merging** — augment with custom fields if you extend the controller. See [DB Controllers](/moost/).

### `RefTableSource` / `RefForeignKey`

```ts
interface RefForeignKey {
  readonly fields: readonly string[];
  readonly targetFields: readonly string[];
  readonly targetTable?: string;
  readonly alias?: string;
  readonly targetTypeRef?: () => unknown;
}

interface RefTableSource {
  readonly foreignKeys?: ReadonlyMap<string, RefForeignKey>;
  readonly relations?: ReadonlyMap<string, unknown>;
}
```

The table surface `checkRefs` resolves names against — `AtscriptDbTable` / a controller's `readable` satisfy it. Since 0.1.72.

### `AoothArbacClaims`

```ts
interface AoothArbacClaims {
  roles?: string[];
  attrs?: Record<string, unknown>;
  allowUnheldRoles?: boolean; // since 0.1.72
}
```

Restrict-only attenuation claims carried by a credential (extracted via `extractAttenuation`). `roles` = assume a SUBSET of the user's roles — `[]` means no roles (deny-all, fail-closed), an omitted key keeps all the user's roles; a role the user lacks is dropped by the intersection. `allowUnheldRoles: true` evaluates `roles` as given instead ("view as" a role the user does not hold) — still conjoined with the user's full authority, so never wider than the user; `extractAttenuation` never sets it, the app's `getAttenuation()` does. `attrs` are merged into the credential pass only and clipped by the scope conjunction, so they can never widen beyond the user's own authority. Feeds `Arbac.evaluate`'s `attenuate` option. See [View as](/arbac/attenuation#view-as-previewing-a-role-the-user-does-not-hold).

## Subpath: `@aooth/arbac-moost/atscript`

```ts
import {
  AtscriptArbacUserProvider,
  ArbacUserTable,
  AoothArbacUserCredentials,
  extractAttenuation,
  getArbacAttenuationSpec,
  validateAttenuationTargets,
  getAoothUserHandleSpec,
  getAoothCredentialMetadataSpec,
} from "@aooth/arbac-moost/atscript";
```

### `AtscriptArbacUserProvider<T>`

```ts
abstract class AtscriptArbacUserProvider<T extends object> extends ArbacUserProvider<T> {
  constructor(userType: TAtscriptAnnotatedType, table: ArbacUserTable<T>);
  abstract getUserId(): string | Promise<string>;
}
```

Drop-in subclass driven by a `.as` user model. Only `getUserId()` remains abstract — typically reads from `useAuth()`. Caches `(EventContext, this, userId)` so `getRoles + getAttrs` collapse to one round-trip per request. Missing record → `getRoles: []`, `getAttrs: {}` (fail-closed). See [Atscript Models](/moost/).

### `ArbacUserTable<T>`

```ts
interface ArbacUserTable<T extends object> {
  findOne(opts: {
    filter: Record<string, unknown>;
    controls?: { $select?: TProjection; $with?: Array<{ name: string }> };
  }): Promise<T | null>;
}
```

Structural interface — the subset of `AtscriptDbTable` `AtscriptArbacUserProvider` calls. Structurally compatible at runtime with `AtscriptDbTable<T>.findOne` but the public typings differ (atscript-db's signature has wider engine-specific `controls.*` keys), so you cast at the call site:

```ts
super(MyUser, db.getTable(MyUser) as unknown as ArbacUserTable<MyUser>);
```

See [Atscript Models](/moost/).

### `extractAttenuation`

```ts
function extractAttenuation(
  credType: TAtscriptAnnotatedType,
  record: object | null | undefined,
): AoothArbacClaims | undefined;
```

Reads a validated credential record's `@arbac.attenuate.role` / `@arbac.attenuate.attr` fields into the `AoothArbacClaims` shape consumed by `Arbac.evaluate`'s `attenuate` option. Returns `undefined` when the model declares no attenuation fields or the record is absent (→ plain non-attenuated evaluation). See [Atscript Models](/moost/).

### `getArbacAttenuationSpec` / `validateAttenuationTargets`

```ts
function getArbacAttenuationSpec(credType: TAtscriptAnnotatedType): ArbacAttenuationSpec;
function validateAttenuationTargets(
  credType: TAtscriptAnnotatedType,
  validUserAttrs: Iterable<string>,
): void;
```

`getArbacAttenuationSpec` walks (and caches per type) the credential model's `@arbac.attenuate.*` annotations into `ArbacAttenuationSpec` (`{ roleField, attrFields: [{ field, userAttr }] }`). `validateAttenuationTargets` throws at boot when an `@arbac.attenuate.attr` target names a user attribute that doesn't exist in the user model's `@arbac.attribute` keyspace — call it once at startup, fail fast.

### `getAoothUserHandleSpec`

```ts
function getAoothUserHandleSpec(userType: TAtscriptAnnotatedType): AoothUserHandleSpec;
```

Resolves (and caches per type) the user model's `@aooth.user.email` / `@aooth.user.phone` identity-handle fields into `AoothUserHandleSpec` (`{ emailField, phoneField, handleFields, warnings }`). A handle field missing `@db.index.unique` is dropped with a warning (warn-and-disable contract) — surface `warnings` in your boot log. See [Recovery & Handles](/moost/recovery-and-handles).

### `getAoothCredentialMetadataSpec`

```ts
function getAoothCredentialMetadataSpec(
  credentialType: TAtscriptAnnotatedType,
): AoothCredentialMetadataSpec;
```

Resolves (and caches per type) the credential model's `@aooth.auth.metadata` column into `AoothCredentialMetadataSpec` (`{ metadataField, warnings }`). Thread `metadataField` into `CredentialStoreAtscriptDb` (`@aooth/auth/atscript-db`) so the store maps the envelope's `metadata` through your fully-typed `@db.json` column (shape it as `AoothCredentialMetadataBase & { ...your keys }` — the type exported from `@aooth/auth/atscript-db/model` single-sources the framework envelope keys). At most one annotated field per type (throws on ambiguity); a field without `@db.json` is dropped with a warning (warn-and-disable contract) — surface `warnings` in your boot log. No annotated field → `metadataField: undefined`, and the atscript-db credential store persists no metadata.

### `AoothArbacUserCredentials`

Re-exported from `@aooth/arbac-moost/atscript/models[.as]`. Extends `AoothUserCredentials` with `@arbac.role roles: string[]`. See [Atscript Models](/moost/).

## Subpath: `@aooth/arbac-moost/plugin`

```ts
import arbacPlugin from "@aooth/arbac-moost/plugin";
```

### `arbacPlugin()` (default export)

```ts
export default function arbacPlugin(): TAtscriptPlugin;
```

Atscript compile-time plugin registering eight prop-level `AnnotationSpec`s across two namespaces: `@arbac.role`, `@arbac.attribute`, `@arbac.userId`, `@arbac.attenuate.role`, `@arbac.attenuate.attr "userAttrName"` (credential-attenuation field markers — see `extractAttenuation`), the identity-handle pair `@aooth.user.email` / `@aooth.user.phone` (login/recovery handle discovery — each requires `@db.index.unique`, warn-and-disable otherwise; at most one field per type), plus `@aooth.auth.metadata` (the consumer's fully-typed credential-metadata column — requires `@db.json`, warn-and-disable otherwise; at most one field per type; resolved by `getAoothCredentialMetadataSpec`). Pull into `atscript.config.ts`. **No runtime DI surface**. See [Atscript Models](/moost/) and [Recovery & Handles](/moost/recovery-and-handles).
