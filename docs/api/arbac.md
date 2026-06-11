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

Emits 6 rules covering `AsDbController` read actions: `query`, `pages`, `getOne`, `getOneComposite`, `meta`, `metaForm`. See [Privilege Factories](/arbac/privileges).

### `allowTableWrite`

```ts
function allowTableWrite<TUserAttrs extends object, TScope extends object>(
  resource: string,
  opts?: { scope?: (attrs: TUserAttrs, userId: string) => TScope },
): TPrivilegeFunction<TUserAttrs, TScope>;
```

Emits 11 rules covering reads + `insert`, `update`, `replace`, `remove`, `removeComposite`. See [Privilege Factories](/arbac/privileges).

### `allowTableAction`

```ts
function allowTableAction<TUserAttrs extends object, TScope extends object>(
  resource: string,
  action: string | string[],
  opts?: { scope?: (attrs: TUserAttrs, userId: string) => TScope },
): TPrivilegeFunction<TUserAttrs, TScope>;
```

Emits one rule per action name. `allowTableAction(r, 'x')` is equivalent to `allowTableAction(r, ['x'])`. See [Privilege Factories](/arbac/privileges).

## Functions — Scope merging

### `mergeScopeFilters`

```ts
function mergeScopeFilters(scopes: TScopeFilter[]): TScopeFilter | undefined;
```

OR-style merge under additive RBAC. Empty input or any empty `{}` → `undefined` (no constraint). Single-key collapses to `$in`. Fallback → `{ $or: scopes }`. See [Scope Merging](/arbac/scopes).

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

Field-level union under "field is allowed if any input grants it". Mixed include/exclude inputs reconcile to exclude-mode (intersection of exclude sets minus any include-granted field). See [Scope Merging](/arbac/scopes).

### `restrictProjection`

```ts
function restrictProjection(desired: TProjection, accessControl: TProjection): TProjection;
```

Query-time intersection of a caller's desired projection with the AC-allowed projection. Both-include intersects; both-exclude unions; mixed modes filter through `isFieldAllowed`. See [Scope Merging](/arbac/scopes).

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
