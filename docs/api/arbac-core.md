# `@aoothjs/arbac-core` API Reference

Complete export reference for `@aoothjs/arbac-core` — the zero-dep ARBAC engine. See the [ARBAC Conceptual Guide](/arbac/) for narrative documentation. All exports come from `packages/arbac-core/src/index.ts` (re-exports `arbac`, `types`, `utils`).

## Classes

### `Arbac<TUserAttrs extends object, TScope extends object>`

```ts
class Arbac<TUserAttrs extends object, TScope extends object> {
  registerRole(role: TArbacRole<TUserAttrs, TScope>): this;
  registerResource(resource: string): this;
  evaluate(
    res: { resource: string; action: string },
    user: {
      id: string | number;
      roles: string[];
      attrs: TUserAttrs | ((id: string | number) => TUserAttrs | Promise<TUserAttrs>);
    },
  ): Promise<TArbacEvalResult<TScope>>;
}
```

Per-resource pre-compiled ARBAC evaluator. Deny rules win absolutely; allow scopes are unioned into `scopes: TScope[]`. The empty-object `{}` element is the "universe sentinel" — interpret as "no restriction". `evaluate` auto-registers the resource. See [Core Engine](/arbac/core) and [Mental Model](/arbac/concepts).

## Functions

### `arbacPatternToRegex`

```ts
function arbacPatternToRegex(input: string): RegExp;
```

Glob-to-regex compiler. `**` → `.*` (cross-dot), `*` → `[^.]*` (within-segment), anchored. Hard-codes `.` as the segment separator. See [Core Engine](/arbac/core).

## Types

### `TArbacEvalResult<TScope>`

```ts
interface TArbacEvalResult<TScope> {
  allowed: boolean;
  scopes?: TScope[]; // present only when allowed === true
}
```

Result of `Arbac.evaluate`. `scopes` is a UNION — callers OR-merge the array. `allowed: false` never carries `scopes`. See [Core Engine](/arbac/core).

### `TArbacRole<TUserAttrs, TScope>`

```ts
interface TArbacRole<TUserAttrs extends object, TScope extends object> {
  id: string;
  name?: string;
  description?: string;
  rules: Array<TArbacRule<TUserAttrs, TScope>>;
}
```

Named container of rules. Identified by `id` (registration idempotent — same id overwrites). See [Mental Model](/arbac/concepts).

### `TArbacRule<TUserAttrs, TScope>`

```ts
type TArbacRule<TUserAttrs extends object, TScope extends object> =
  | {
      resource: string;
      action: string;
      scope?: (userAttrs: TUserAttrs, userId: string) => TScope;
      effect?: never;
    } // allow (implicit)
  | { resource: string; action: string; effect: "deny"; scope?: never }; // deny — cannot carry scope
```

Discriminated union by presence of `effect`. Allow rules implicitly default to allow; their `scope` fn returns a `TScope` the caller treats as a data filter. `deny` rules cannot carry a scope. See [Core Engine](/arbac/core).

### `TArbacCompiledRule<TUserAttrs, TScope>`

```ts
type TArbacCompiledRule<TUserAttrs, TScope> = TArbacRule<TUserAttrs, TScope> & {
  _resourceRegex: RegExp;
  _actionRegex: RegExp;
};
```

Internal cache shape. `evalRoleForResource` mutates rule objects in place to attach pre-compiled regexes — **don't freeze rule literals before registration**. See [Core Engine](/arbac/core).

### `TArbacRoleForResource<TUserAttrs, TScope>`

```ts
interface TArbacRoleForResource<TUserAttrs, TScope> {
  allow: Array<TArbacCompiledRule<TUserAttrs, TScope>>;
  deny: Array<TArbacCompiledRule<TUserAttrs, TScope>>;
}
```

Pre-filtered allow/deny lists for a `(resource, role)` pair, cached in `resources[resourceId][roleId]`. See [Core Engine](/arbac/core).
