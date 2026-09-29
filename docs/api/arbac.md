# `@aooth/arbac` API Reference

Complete export reference for `@aooth/arbac`. See the [ARBAC Conceptual Guide](/arbac/) for narrative documentation.

`@aooth/arbac` re-exports the entire engine from [`@aooth/arbac-core`](./arbac-core) (`export * from '@aooth/arbac-core'`) and adds a fluent builder, privilege factories, scope-merge utilities, and codegen.

## Re-exports

Everything from [`@aooth/arbac-core`](./arbac-core) — `Arbac`, `arbacPatternToRegex`, `TArbacEvalResult`, `TArbacRole`, `TArbacRule`, `TArbacCompiledRule`, `TArbacRoleForResource`.

## Functions — Builder

### `defineRole`

```ts
function defineRole<
  TUserAttrs extends object = object,
  TScope extends object = object,
>(): RoleBuilder<TUserAttrs, TScope>;
```

Builder entry point. Generics pin once; subsequent chain calls carry them through. `.build()` throws if `.id(...)` was never called. See [Builder API](/arbac/builder).

## Functions — Privileges

### `definePrivilege`

```ts
function definePrivilege<TUserAttrs extends object, TScope extends object>(): <
  TArgs extends unknown[],
>(
  factory: (...args: TArgs) => TArbacRule<TUserAttrs, TScope>[],
) => (...args: TArgs) => TPrivilegeFunction<TUserAttrs, TScope>;
```

Double-call factory: the first `()` pins generics, the second wraps a rule-emitting factory. Forgetting the first call defeats generic pinning. See [Privilege Factories](/arbac/privileges).

### `allowTableRead`

```ts
function allowTableRead<TUserAttrs extends object, TScope extends object>(
  resource: string,
  opts?: { scope?: (attrs: TUserAttrs, userId: string) => TScope },
): TPrivilegeFunction<TUserAttrs, TScope>;
```

Emits 7 rules covering `AsDbController` read actions: `query`, `pages`, `getOne`, `getOneComposite`, `geo`, `meta`, `metaForm` (`geo` since 0.1.72). See [Privilege Factories](/arbac/privileges).

### `allowTableWrite`

```ts
function allowTableWrite<TUserAttrs extends object, TScope extends object>(
  resource: string,
  opts?: { scope?: (attrs: TUserAttrs, userId: string) => TScope },
): TPrivilegeFunction<TUserAttrs, TScope>;
```

Emits 12 rules covering reads + `insert`, `update`, `replace`, `remove`, `removeComposite`. See [Privilege Factories](/arbac/privileges).

### `allowTableAction`

```ts
function allowTableAction<TUserAttrs extends object, TScope extends object>(
  resource: string,
  action: string | string[],
  opts?: { scope?: (attrs: TUserAttrs, userId: string) => TScope },
): TPrivilegeFunction<TUserAttrs, TScope>;
```

Emits one rule per action name. `allowTableAction(r, 'x')` is equivalent to `allowTableAction(r, ['x'])`. See [Privilege Factories](/arbac/privileges).

### `allowTableOps`

```ts
function allowTableOps<TUserAttrs extends object, TScope extends object>(
  resource: string,
  ops: readonly TTableOp[],
  opts?: { scope?: (attrs: TUserAttrs, userId: string) => TScope },
): TPrivilegeFunction<TUserAttrs, TScope>;
```

Emits one rule per handler action of the listed ops (see [`TABLE_OP_ACTIONS`](#table-action-constants)), deduplicated. Throws on an unknown op. Since 0.1.72. See [Privilege Factories](/arbac/privileges#allowtableops).

### `defineTableAccess`

```ts
function defineTableAccess<
  TUserAttrs extends object = object,
  TScope extends TTableAccessScope = TTableAccessScope,
>(
  resource: string,
  def: TTableAccessDef<TUserAttrs, TScope>,
): TPrivilegeFunction<TUserAttrs, TScope>;
```

One table policy → read / write / action rules with a shared scope; a part scope merges over it (`filter` and the effective `check` conjoined via `conjoinRowPolicies`, other keys from the part). Scope callbacks are not inference sites — pin the generics or call it inside `defineRole<A, S>().use(...)`. Since 0.1.72. See [Privilege Factories](/arbac/privileges#definetableaccess-one-policy-per-table).

### Table action constants

```ts
const TABLE_READ_ACTIONS: readonly [
  "query",
  "pages",
  "getOne",
  "getOneComposite",
  "geo",
  "meta",
  "metaForm",
];
const TABLE_WRITE_ACTIONS: readonly ["insert", "update", "replace", "remove", "removeComposite"];
const TABLE_META_ACTIONS: readonly ["meta", "metaForm"];
const TABLE_OP_ACTIONS: Readonly<Record<TTableOp, readonly string[]>>;
```

The `AsDbController` handler-action vocabulary the `allowTable*` factories emit — for custom privileges and `deny(...)` loops. Since 0.1.72.

## Functions — Scope merging

### `mergeScopeFilters`

```ts
function mergeScopeFilters(scopes: TScopeFilter[]): TScopeFilter | undefined;
```

OR-style merge under additive RBAC. Empty input or any empty `{}` → `undefined` (no constraint). Single-key collapses to `$in`. Fallback → `{ $or: scopes }`. See [Scope Merging](/arbac/scopes).

### `DENY_FILTER`

```ts
const DENY_FILTER: Readonly<TScopeFilter>; // { $or: [] }
```

The match-nothing filter: what a denied read filters by, and what `conjoinArbacDbScopes` adds when a credential and its user share no visible field. Shared; never mutate it.

### `conjoinScopeFilters`

```ts
function conjoinScopeFilters(
  a: TScopeFilter | undefined,
  b: TScopeFilter | undefined,
): TScopeFilter | undefined;
```

AND-merge of two ALREADY-UNIONED filters (each a `mergeScopeFilters` output for one authority pass) — the credential-attenuation combiner: a row survives only if BOTH sides admit it. Polarity is the **opposite** of `mergeScopeFilters`: empty/`undefined` is the identity (contributes no constraint), never the absorbing "unrestricted wins". Never object-spread the two filters instead — credential keys could overwrite user keys and silently widen. See [Scope Merging](/arbac/scopes).

### `unionProjections`

```ts
function unionProjections(...projections: TProjection[]): TProjection;
```

Field-level union under "field is allowed if any input grants it". Mixed include/exclude inputs reconcile to exclude-mode (path-wise intersection of exclude sets minus any include-granted field). See [Scope Merging](/arbac/scopes).

### `restrictProjection`

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
type TProjectionChildren = (path: string) => readonly string[];
```

Path-wise projection intersection, never wider than either side. `{a:1}` ∩ `{"a.b":1}` → `{"a.b":1}`. An included parent with an excluded child is split via the optional `childrenOf` schema lookup, or dropped without one. `intersectProjections` returns `null` when no field survives. `restrictProjection` (desired vs. the access-control ceiling) then returns `accessControl`, never `{}`. See [Scope Merging](/arbac/scopes).

### `expandExcludeToLeaves`

```ts
function expandExcludeToLeaves(
  projection: TProjection,
  childrenOf: TProjectionChildren | undefined,
): TProjection;
```

Rewrites an exclusion projection so each excluded nested-object parent is named by its leaf paths (`{ a: 0 }` → `{ "a.b": 0, "a.c": 0 }`), using the schema lookup. Flattening storage adapters strip excluded leaf columns only, so a parent key alone would strip nothing. Inclusion and empty projections, and calls without `childrenOf`, come back unchanged. See [Scope Merging](/arbac/scopes).

### `getProjectionMode`

```ts
function getProjectionMode(projection: TProjection): TProjectionMode;
```

Classifies a single projection. **Throws** if `1` and `0` are mixed in one input (`getProjectionMode` is strict; `unionProjections` is not). See [Scope Merging](/arbac/scopes).

### `isFieldAllowed`

```ts
function isFieldAllowed(field: string, projection: TProjection): boolean;
```

Dot-path aware membership check. Walks the projection respecting include/exclude semantics. See [Scope Merging](/arbac/scopes).

### `unionControlsPolicy`

```ts
function unionControlsPolicy(
  scopes: ReadonlyArray<{ controls?: Record<string, ControlGate> }>,
): Record<string, ControlGate>;
```

Specific to `ArbacDbScope.controls` — gates Uniquery URL controls per role. If any input omits `controls` entirely, returns `{}` (silent = full grant). `string[]` whitelists union additively. See [Scope Merging](/arbac/scopes).

### `intersectControlsPolicy`

```ts
function intersectControlsPolicy(
  a: Record<string, ControlGate>,
  b: Record<string, ControlGate>,
): Record<string, ControlGate>;
```

AND-merge of two controls policies (each a `unionControlsPolicy` output) — the restrictive counterpart used by credential attenuation. Per key (absent ≡ allowed): `false` on either side wins; `true` defers to the other side; whitelist ∧ whitelist → set **intersection** (possibly empty = nothing permitted). See [Scope Merging](/arbac/scopes).

## Functions — DB scope algebra

The union / conjunction rules of a DB scope (`ArbacDbScope` in `@aooth/arbac-moost`), each facet defined once. Since 0.1.72. See [Scope Merging](/arbac/scopes).

### `effectiveScope`

```ts
function effectiveScope<S extends TDbScope>(scopes: readonly S[]): TEffectiveDbScope<S>;
```

The additive union of a scope list (one scope per allowing rule), memoized per scopes array; facets compute lazily. `filter` / `check` (`check ?? filter`, `{}` = none) union via `mergeScopeFilters`, `projection` via `unionProjections`, `controls` via `unionControlsPolicy`, `allowedFields` / `nestedWrites` as set unions, `set` as an overlay (later wins), `checkRefs` as the entries EVERY scope enables, `withScopes(name)` as the declared `with.<name>` list. An empty list is the identity of every union — decide denial first with `normalizeScopes`.

### `conjoinScopes`

```ts
function conjoinScopes<S extends TDbScope>(
  a: readonly S[],
  b: readonly S[],
  opts?: TConjoinScopesOptions<S>, // { childrenOf?, checkRefs?(a, b), fields? }
): S;
```

Restrict-only conjunction of two scope lists into one composite scope (credential attenuation): each side unioned, then conjoined facet by facet — `$and` filters / checks, path-wise projection ∩ (no common field → the first side's projection plus a match-nothing filter), deny-wins controls, intersected `allowedFields` / `nestedWrites`, `set` with the first side winning, `checkRefs` either side enforces, recursive `with`. A custom (non-built-in) key is combined by its `opts.fields` rule at every level; a custom key present with no rule throws `ScopeFieldConfigError` — it is never dropped (since 0.1.72). See [Custom scope fields](/arbac/scopes#custom-scope-fields).

### `applyScopeFieldFilters`

```ts
function applyScopeFieldFilters<S extends TDbScope>(
  scopes: readonly S[],
  fields: TScopeFieldRules<S> | undefined,
  opts?: TApplyScopeFieldFiltersOptions, // { onUnknownField?(field) }
): readonly S[];
```

Folds each custom field's `rowFilter` into its scope's `filter` (`filter ∧ rowFilter(value, scope)`), recursively into `with` sub-scopes. Apply it to each evaluated scope list before any union or conjunction. An explicit `check` is left as written. Scopes are never mutated: a changed one is a copy, memoized process-wide per scope object, so `rowFilter` must be pure in `(value, scope)`. The fold is idempotent. The input list is returned when nothing changes. `onUnknownField` reports a non-built-in key that has no rule. `MoostArbac.evaluate` applies it to every evaluation. Since 0.1.72. See [Fields that restrict rows](/arbac/scopes#fields-that-restrict-rows-rowfilter).

### `ScopeFieldConfigError`

```ts
class ScopeFieldConfigError extends Error {
  readonly field: string;
}
```

Thrown by `conjoinScopes` for a custom field without a rule. It is a server configuration error; `@aooth/arbac-moost` maps it to a generic 500. Since 0.1.72.

### `DB_SCOPE_KEYS`

```ts
const DB_SCOPE_KEYS: readonly string[]; // filter, check, projection, controls, allowedFields, set, nestedWrites, checkRefs, with
```

The built-in scope keys the algebra combines itself; any other key is a custom field. Since 0.1.72.

### `INHERITED_CONJUNCTION` / `needsInheritedConjunction`

```ts
const INHERITED_CONJUNCTION: unique symbol;
function needsInheritedConjunction(scope: object): boolean;
```

`conjoinScopes` marks a `with.<rel>` sub-scope only ONE side declared: the silent side's policy for those joined rows is its inherited grant on the related table, so a resolver must conjoin the marked sub-scope with the caller's own grant there (unresolved → hidden) — never apply it alone as parent authority. `@aooth/arbac-moost`'s `$with` resolution does this.

### `conjoinRowPolicies`

```ts
function conjoinRowPolicies(a: TRowPolicy, b: TRowPolicy): TRowPolicy; // { filter?, check? }
```

`filter = a.filter ∧ b.filter`, WITH CHECK `(a.check ?? a.filter) ∧ (b.check ?? b.filter)`; `check` is emitted only when it differs from the conjoined filter.

### `normalizeScopes` / `unionOutcomes`

```ts
function normalizeScopes<S extends object>(outcome: {
  allowed: boolean;
  scopes?: ReadonlyArray<S | null | undefined>;
}): S[] | undefined;
function unionOutcomes<S extends object>(
  outcomes: ReadonlyArray<{ allowed: boolean; scopes?: ReadonlyArray<S | null | undefined> }>,
): S[] | undefined;
```

The empty-scope rule: denied → `undefined`; allowed without a `scopes` list → `[{}]` (unrestricted); a `null` / `undefined` scope (a scope function that returned nothing) is dropped; nothing left → `undefined` (deny). `unionOutcomes` concatenates several normalized outcomes (one surface served by several handlers).

### `intersectEnabled` / `stableKey`

```ts
function intersectEnabled<K>(inputs: Iterable<true | ReadonlySet<K>>): true | Set<K>;
function stableKey(value: unknown): string;
```

`intersectEnabled` — entries every input enables (`true` = all; no input → none). `stableKey` — a bigint-safe JSON key for de-duplicating filters / tuples.

## Functions — Codegen

### `extractResourceActions`

```ts
function extractResourceActions(
  roles: TArbacRole<unknown, unknown>[],
  options?: { includeWildcards?: boolean },
): TResourceActionMap;
```

Walks every role's rules and collects unique `(resource, action)` pairs. By default skips entries containing `*`. See [Codegen](/arbac/codegen).

### `generateResourceTypes`

```ts
function generateResourceTypes(map: TResourceActionMap, options?: TCodegenOptions): string;
```

Emits TS source — `Resource`, `Action`, and `ResourceActionMap` types. See [Codegen](/arbac/codegen).

## Types

### `RoleBuilder<TUserAttrs, TScope>`

```ts
interface RoleBuilder<TUserAttrs, TScope> {
  id(id: string): this;
  name(name: string): this;
  describe(description: string): this;
  allow(
    resource: string,
    action: string,
    scope?: (attrs: TUserAttrs, userId: string) => TScope,
  ): this;
  deny(resource: string, action: string): this;
  use<TScopes extends readonly unknown[]>(
    ...privileges: { [K in keyof TScopes]: TPrivilegeFunction<TUserAttrs, TScopes[K]> }
  ): this;
  build(): TArbacRole<TUserAttrs, TScope>;
}
```

Fluent chain returned by `defineRole`. `.build()` returns a plain `TArbacRole` with a _copy_ of the rules array. Rule order is preserved. See [Builder API](/arbac/builder).

### `TPrivilegeFunction<TUserAttrs, TScope>`

```ts
type TPrivilegeFunction<TUserAttrs, TScope> = () => TArbacRule<TUserAttrs, TScope>[];
```

Returned by `definePrivilege` / `allowTable*`. Invoked by `RoleBuilder.use()` to splice rules in place. See [Privilege Factories](/arbac/privileges).

### `TTableOp` / `TTableWriteOp`

```ts
type TTableOp = "read" | "meta" | "insert" | "update" | "replace" | "remove";
type TTableWriteOp = Exclude<TTableOp, "read">;
```

Operation names for `allowTableOps` and `defineTableAccess`'s `write` part. See [Privilege Factories](/arbac/privileges#allowtableops).

### `TTableAccessDef<TUserAttrs, TScope>` / `TTableAccessScope`

```ts
interface TTableAccessScope {
  filter?: TScopeFilter;
  check?: TScopeFilter;
}

interface TTableAccessDef<TUserAttrs, TScope> {
  scope?: (attrs: TUserAttrs, userId: string) => TScope;
  read?: boolean | { scope?: (attrs: TUserAttrs, userId: string) => TScope };
  write?:
    | boolean
    | readonly TTableWriteOp[]
    | { ops?: readonly TTableWriteOp[]; scope?: (attrs: TUserAttrs, userId: string) => TScope };
  actions?:
    | readonly string[]
    | { names: readonly string[]; scope?: (attrs: TUserAttrs, userId: string) => TScope };
}
```

Input of `defineTableAccess`. `TTableAccessScope` is the minimum scope shape — the keys it conjoins. See [Privilege Factories](/arbac/privileges#definetableaccess-one-policy-per-table).

### `TDbScope` / `TEffectiveDbScope<S>` / `TRowPolicy`

```ts
interface TDbScope {
  filter?: TScopeFilter;
  check?: TScopeFilter;
  projection?: object;
  controls?: object;
  allowedFields?: readonly string[];
  set?: object;
  nestedWrites?: readonly string[];
  checkRefs?: true | readonly string[];
  with?: object;
}
```

The structural DB scope shape the [scope algebra](#functions-db-scope-algebra) reads (`ArbacDbScope` satisfies it); `TEffectiveDbScope` is what `effectiveScope` returns; `TRowPolicy` is `{ filter?, check? }`. Since 0.1.72.

### `TScopeFieldRule<S>` / `TScopeFieldRules<S>`

```ts
interface TScopeFieldRule<S extends object = TDbScope> {
  conjoin(a: readonly S[], b: readonly S[]): unknown; // undefined = unrestricted (key omitted)
  rowFilter?(value: unknown, scope: S): TScopeFilter | undefined; // undefined / {} = no row restriction
}
type TScopeFieldRules<S extends object = TDbScope> = Readonly<Record<string, TScopeFieldRule<S>>>;
```

The conjunction rule of one custom scope field, passed as `conjoinScopes`' `fields` option (in Moost: [`MoostArbac.registerScopeFields`](/api/arbac-moost#moostarbac-tuserattrs-tscope)). `conjoin` is called only when some scope on either side carries the field; each side is a scope list the app unions with its own rule. `rowFilter` makes the field a row restriction — see `applyScopeFieldFilters`. Since 0.1.72.

### `ControlGate`

```ts
type ControlGate = boolean | readonly string[];
```

Per-control gate. `true` (or `undefined`) = allowed, `false` = denied (throws 403), `string[]` = whitelist (only legal for `$with` and `$groupBy`). See [Scope Merging](/arbac/scopes).

### `TProjection`

```ts
type TProjection = Record<string, 0 | 1>;
```

Mongo-style include (`1`) / exclude (`0`) projection. Mixing within one projection is forbidden; `getProjectionMode` throws. Cross-projection mixing is fine in `unionProjections`. See [Scope Merging](/arbac/scopes).

### `TProjectionMode`

```ts
type TProjectionMode = "include" | "exclude" | "empty";
```

Output of `getProjectionMode`. `'empty'` means `{}` — universal grant. See [Scope Merging](/arbac/scopes).

### `TScopeFilter`

```ts
type TScopeFilter = Record<string, unknown>; // @uniqu/core filter shape
```

Per-rule data filter — any `@uniqu/core`-compatible filter expression. Empty `{}` is the universe sentinel; `mergeScopeFilters` short-circuits to `undefined`. See [Scope Merging](/arbac/scopes).

### `TResourceActionMap`

```ts
interface TResourceActionMap {
  resources: Map<string, Set<string>>; // resource → set of actions
  allResources: Set<string>;
  allActions: Set<string>;
}
```

Codegen IR — output of `extractResourceActions`, input of `generateResourceTypes`. See [Codegen](/arbac/codegen).

### `TCodegenOptions`

```ts
interface TCodegenOptions {
  resourceTypeName?: string; // default 'Resource'
  actionTypeName?: string; // default 'Action'
  resourceActionMap?: boolean; // default true
  header?: string; // prepended verbatim
}
```

Codegen knobs. The CLI `aoothjs-arbac-codegen` exposes `--resource-type` / `--action-type`. See [Codegen](/arbac/codegen).
