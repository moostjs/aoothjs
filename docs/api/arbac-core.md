# `@aooth/arbac-core` API Reference

Complete export reference for `@aooth/arbac-core` — the zero-dep ARBAC engine. See the [ARBAC Conceptual Guide](/arbac/) for narrative documentation. All exports come from `packages/arbac-core/src/index.ts` (re-exports `arbac`, `types`, `utils`).

## Classes

### `Arbac<TUserAttrs extends object, TScope extends object>`

```ts
class Arbac<TUserAttrs extends object, TScope extends object> {
  registerRole(role: TArbacRole<TUserAttrs, TScope>): this;
  registerResource(resource: string): this;
  evaluate<T extends string | undefined>(
    res: { resource: string; action: string },
    user: {
      id: T;
      roles: string[];
      attrs: TUserAttrs | ((id: T) => TUserAttrs | Promise<TUserAttrs>);
      attenuate?: { roles?: string[]; attrs?: Partial<TUserAttrs> };
    },
  ): Promise<TArbacEvalResult<TScope>>;
}
```

Per-resource pre-compiled ARBAC evaluator. Deny rules win absolutely; allow scopes are unioned into `scopes: TScope[]`. The empty-object `{}` element is the "universe sentinel" — interpret as "no restriction". `evaluate` auto-registers the resource. When `user.attenuate` is supplied (the credential-claims bridge), the policy is evaluated **twice** — once with the user's full authority, once with the attenuated roles/attrs — and the OUTCOMES are intersected: `allowed` only if both passes allow, with the attenuated pass's scopes returned as `credScopes` for restrictive conjunction downstream. Omitting `attenuate` is a single evaluation, byte-for-byte the non-attenuated behavior. See [Core Engine](/arbac/core), [Mental Model](/arbac/concepts), and [Scopes](/arbac/scopes) for the conjunction helpers.

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
  credScopes?: TScope[]; // attenuated evaluations only — the credential-side scope union
}
```

Result of `Arbac.evaluate`. `scopes` is a UNION — callers OR-merge the array. `allowed: false` never carries `scopes`. `credScopes` appears only when `evaluate` ran with `user.attenuate`: it is the attenuated pass's own scope union, to be **conjoined** (ANDed) with `scopes` — never additively merged. See [Core Engine](/arbac/core).

### `TArbacRole<TUserAttrs, TScope>`

```ts
interface TArbacRole<TUserAttrs, TScope> {
  id: string;
  name?: string;
  description?: string;
  rules: Array<TArbacRule<TUserAttrs, TScope>>;
}
```

Named container of rules. Identified by `id` (registration idempotent — same id overwrites). See [Mental Model](/arbac/concepts).

### `TArbacRule<TUserAttrs, TScope>`

```ts
type TArbacRule<TUserAttrs, TScope> =
  | {
      resource: string;
      action: string;
      scope?: (userAttrs: TUserAttrs, userId: string) => TScope;
      effect?: never;
    } // allow (implicit)
  | { resource: string; action: string; effect: "deny"; scope?: never }; // deny — cannot carry scope
```

Discriminated union by presence of `effect`. Allow rules implicitly default to allow; their `scope` fn returns a `TScope` the caller treats as a data filter. `deny` rules cannot carry a scope. See [Core Engine](/arbac/core).

::: warning Advanced — internal cache shapes
The two types below (`TArbacCompiledRule` and `TArbacRoleForResource`) are only useful when introspecting `Arbac` internals or building a custom evaluator. App code does not construct these.
:::

### `TArbacCompiledRule<TUserAttrs, TScope>`

```ts
type TArbacCompiledRule<TUserAttrs, TScope> = Omit<
  TArbacRule<TUserAttrs, TScope>,
  "resource" | "effect" | "_resourceRegex"
> & {
  _actionRegex: RegExp;
};
```

Internal cache shape — what `evalRoleForResource` pushes into a role's per-resource `allow` / `deny` arrays. `resource` and `effect` are dropped (already implied by the bucket), and only `_actionRegex` survives onto compiled rules (`_resourceRegex` is attached to the source rule object during pre-compilation, but is not part of the compiled shape). **Don't freeze rule literals before registration** — the engine mutates them to attach `_resourceRegex` / `_actionRegex`. See [Core Engine](/arbac/core).

### `TArbacRoleForResource<TUserAttrs, TScope>`

```ts
interface TArbacRoleForResource<TUserAttrs, TScope> {
  id: string;
  allow: Array<TArbacCompiledRule<TUserAttrs, TScope>>;
  deny: Array<TArbacCompiledRule<TUserAttrs, TScope>>;
}
```

Pre-filtered allow/deny lists for a `(resource, role)` pair, cached in `resources[resourceId][roleId]`. See [Core Engine](/arbac/core).
