# Privilege Factories

This page answers: _how do I bundle related rules into a named, parameterizable unit I can reuse across roles?_ It documents `definePrivilege()` and the curated `allowTable*` family from [`@aooth/arbac`](https://github.com/moostjs/aoothjs/tree/main/packages/arbac).

A _privilege_ is a function that returns an array of `TArbacRule[]` — exactly the shape `defineRole().use(...)` expects. You can hand-write one, or use `definePrivilege()` to keep generics flowing cleanly.

## `definePrivilege()` — the double-call pattern

```ts
function definePrivilege<TUserAttrs extends object, TScope extends object>(): <
  TArgs extends unknown[],
>(
  factory: (...args: TArgs) => TArbacRule<TUserAttrs, TScope>[],
) => (...args: TArgs) => TPrivilegeFunction<TUserAttrs, TScope>;

type TPrivilegeFunction<TUserAttrs, TScope> = () => TArbacRule<TUserAttrs, TScope>[];
```

Two layers of currying:

1. The **first** call, `definePrivilege<Attrs, Scope>()`, _binds the generics_. It returns a factory-builder.
2. The **second** call, `.(factory)`, accepts your rule-emitting function `(...args) => TArbacRule[]` and returns a curried wrapper `(...args) => TPrivilegeFunction`.

The whole point of the double call is to pin `TUserAttrs` and `TScope` once so every rule the factory emits is type-checked against them.

::: warning Don't forget the first `()`
Writing `definePrivilege(factory)` instead of `definePrivilege<A, S>()(factory)` defeats generic pinning — you'll get `unknown` inside the scope callback. The first call is empty by design.
:::

### Minimal example

```ts
import { definePrivilege, defineRole } from "@aooth/arbac";

type Attrs = { dept: string };
type Scope = { dept: string };

const canManageUsers = definePrivilege<Attrs, Scope>()((scope: (a: Attrs, id: string) => Scope) => [
  { resource: "users", action: "read", scope },
  { resource: "users", action: "update", scope },
]);

const manager = defineRole<Attrs, Scope>()
  .id("manager")
  .use(canManageUsers((a) => ({ dept: a.dept })))
  .build();
```

What just happened:

- `canManageUsers` is `(scope) => TPrivilegeFunction`. Call it once per role with the scope callback you want attached to all the rules it emits.
- `.use(canManageUsers((a) => ({ dept: a.dept })))` invokes the privilege function immediately and splices its two rules into the role.

### Parameter shapes are arbitrary

Privileges can take whatever arguments make sense. Pass a resource name, a list of actions, a scope, a tenant ID — anything:

```ts
const canActOnDocs = definePrivilege<Attrs, Scope>()((tenantId: string, actions: string[]) =>
  actions.map((action) => ({
    resource: `docs.${tenantId}`,
    action,
    scope: (a: Attrs) => ({ dept: a.dept }),
  })),
);

defineRole<Attrs, Scope>()
  .id("docs-editor")
  .use(canActOnDocs("acme", ["read", "update"]))
  .build();
```

The double-call wrapper preserves the parameter tuple as `TArgs`, so the caller-facing API is fully typed.

## The `allowTable*` family

[`@aooth/arbac`](https://github.com/moostjs/aoothjs/blob/main/packages/arbac/src/db-privileges.ts) ships three curated factories that bake in the action vocabulary `AsDbController` exposes for `@atscript/db` models. They save you from memorizing — or misspelling — those action names.

The vocabulary:

```ts
const TABLE_READ_ACTIONS = [
  "query",
  "pages",
  "getOne",
  "getOneComposite",
  "meta",
  "metaForm",
] as const;
const TABLE_WRITE_ACTIONS = ["insert", "update", "replace", "remove", "removeComposite"] as const;
```

All three helpers return `TPrivilegeFunction<TUserAttrs, TScope>` — i.e. they slot directly into `.use(...)`.

| Helper                                                | Emits                          | Use when                                          |
| ----------------------------------------------------- | ------------------------------ | ------------------------------------------------- |
| `allowTableRead(resource, opts?)`                     | 6 rules — one per read action  | Granting read-only access to a table.             |
| `allowTableWrite(resource, opts?)`                    | 11 rules — both read and write | Granting full CRUD to a table.                    |
| `allowTableAction(resource, name \| string[], opts?)` | One rule per action name       | Granting a single action, or an arbitrary subset. |

### Signatures

```ts
function allowTableRead<TUserAttrs extends object, TScope extends object>(
  resource: string,
  opts?: { scope?: (attrs: TUserAttrs, userId: string) => TScope },
): TPrivilegeFunction<TUserAttrs, TScope>;

function allowTableWrite<TUserAttrs extends object, TScope extends object>(
  resource: string,
  opts?: { scope?: (attrs: TUserAttrs, userId: string) => TScope },
): TPrivilegeFunction<TUserAttrs, TScope>;

function allowTableAction<TUserAttrs extends object, TScope extends object>(
  resource: string,
  action: string | readonly string[],
  opts?: { scope?: (attrs: TUserAttrs, userId: string) => TScope },
): TPrivilegeFunction<TUserAttrs, TScope>;
```

`opts.scope`, when provided, is attached to **every** generated rule. Omit it for unrestricted access.

### Examples

```ts
import { defineRole, allowTableRead, allowTableWrite, allowTableAction } from "@aooth/arbac";

type Attrs = { dept: string };
type Scope = { dept: string };

// Read-only over a table, bounded to the caller's department.
defineRole<Attrs, Scope>()
  .id("reader")
  .use(allowTableRead("articles", { scope: (a) => ({ dept: a.dept }) }))
  .build();

// Full CRUD, bounded.
defineRole<Attrs, Scope>()
  .id("editor")
  .use(allowTableWrite("articles", { scope: (a) => ({ dept: a.dept }) }))
  .build();

// Just one action.
defineRole<Attrs, Scope>().id("publisher").use(allowTableAction("articles", "publish")).build();

// A subset of actions.
defineRole<Attrs, Scope>()
  .id("moderator")
  .use(allowTableAction("comments", ["hide", "remove"]))
  .build();
```

::: tip `allowTableAction(r, 'x')` ≡ `allowTableAction(r, ['x'])`
The helper accepts either a single string or an array of strings. A single name is treated as a one-element array; there is no special behavior for the scalar form.
:::

## Composing privileges in a role

`.use()` accepts any number of privilege functions, so you can chain them:

```ts
const finance = defineRole<Attrs, Scope>()
  .id("finance")
  .use(allowTableWrite("invoices", { scope: (a) => ({ dept: a.dept }) }))
  .use(allowTableRead("reports", { scope: (a) => ({ dept: a.dept }) }))
  .use(allowTableAction("reports", "export"))
  .deny("invoices", "delete")
  .build();
```

All the rules end up flat in `finance.rules` in declaration order. The engine applies its own deny-wins precedence at evaluation time.

## When to write a custom privilege

Reach for `definePrivilege()` whenever you find yourself repeating the same `(resource, action, scope)` triple across two or more roles. Typical candidates:

- A "moderator" privilege that grants `flag`, `hide`, `remove` on a comments-like resource.
- A "tenant-bounded" privilege that wraps any other privilege with a tenant filter scope.
- A privilege parameterised by a resource ID prefix.

Custom privileges nest fine — a privilege can itself call `allowTableRead(...)` and return that array spread into its own output. The outer privilege still emits `TArbacRule[]`, so there is nothing special to do.

## Gotchas

- **The first `()` is mandatory.** `definePrivilege<A, S>()(factory)`. Forgetting it silently loses generics.
- **`opts.scope` is attached to every rule.** If you need a mix (some rules bounded, some unrestricted), write a custom privilege or compose multiple `allowTableAction(...)` calls.
- **`opts.scope` is the only option.** There is no per-action override slot. Mixed bounding requires splitting into multiple privilege calls.
- **Privileges are not first-class objects in the engine.** They are pure factories that emit `TArbacRule[]`. The engine never sees the privilege as a unit — only its rules. Don't expect to introspect "which privilege contributed this rule" at runtime.

## Next

- [Scope Merging](./scopes) — how to UNION the scopes that come back from multi-role evaluations and turn them into a single filter expression.
- [Codegen](./codegen) — emit `Resource` / `Action` TS unions from a roles array so `resource: string` becomes a typed literal.
