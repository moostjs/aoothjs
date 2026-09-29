# Privilege Factories

This page answers: _how do I bundle related rules into a named, parameterizable unit I can reuse across roles?_ It documents `definePrivilege()`, the curated `allowTable*` family and `defineTableAccess()` from [`@aooth/arbac`](https://github.com/moostjs/aoothjs/tree/main/packages/arbac).

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

[`@aooth/arbac`](https://github.com/moostjs/aoothjs/blob/main/packages/arbac/src/db-privileges.ts) ships curated factories that bake in the action vocabulary `AsDbController` exposes for `@atscript/db` models. They save you from memorizing — or misspelling — those action names.

The vocabulary is exported as constants — `TABLE_READ_ACTIONS`, `TABLE_WRITE_ACTIONS`, `TABLE_META_ACTIONS` and the op → actions map `TABLE_OP_ACTIONS` — for custom privileges and `deny(...)` loops:

```ts
import { TABLE_READ_ACTIONS, TABLE_WRITE_ACTIONS } from "@aooth/arbac";

TABLE_READ_ACTIONS; // query, pages, getOne, getOneComposite, geo, meta, metaForm
TABLE_WRITE_ACTIONS; // insert, update, replace, remove, removeComposite
```

All helpers return `TPrivilegeFunction<TUserAttrs, TScope>` — i.e. they slot directly into `.use(...)`.

| Helper                                                | Emits                                   | Use when                                            |
| ----------------------------------------------------- | --------------------------------------- | --------------------------------------------------- |
| `allowTableRead(resource, opts?)`                     | 7 rules — one per read action           | Granting read-only access to a table.               |
| `allowTableWrite(resource, opts?)`                    | 12 rules — both read and write          | Granting full CRUD to a table.                      |
| `allowTableOps(resource, ops, opts?)`                 | The actions of the listed operations    | Granting a CRUD subset (insert-only, no remove, …). |
| `allowTableAction(resource, name \| string[], opts?)` | One rule per action name                | Granting a single action, or an arbitrary subset.   |
| `defineTableAccess(resource, def)`                    | Read / write / action rules, one policy | Different scopes per side of the same table.        |

::: warning `allowTableRead` grants `/geo` since 0.1.72
`geo` joined the read set in 0.1.72, so every role built on `allowTableRead` / `allowTableWrite` / `allowTableOps(…, ["read"])` now reaches the table's `/geo` endpoint under the same scope. A role that must not run geo searches needs `.deny(resource, "geo")`.
:::

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

### `allowTableOps`

Grant a subset of table operations under one scope ([signature](/api/arbac#allowtableops)):

```ts
import { allowTableOps, defineRole } from "@aooth/arbac";

// A lead-capture form: create rows and render the form, nothing else.
defineRole<Attrs, Scope>()
  .id("lead-intake")
  .use(allowTableOps("leads", ["insert", "meta"]))
  .build();

// Read + edit, but never remove.
defineRole<Attrs, Scope>()
  .id("curator")
  .use(allowTableOps("articles", ["read", "update"], { scope: (a) => ({ dept: a.dept }) }))
  .build();
```

| Op        | Handler actions                                                          |
| --------- | ------------------------------------------------------------------------ |
| `read`    | `query`, `pages`, `getOne`, `getOneComposite`, `geo`, `meta`, `metaForm` |
| `meta`    | `meta`, `metaForm`                                                       |
| `insert`  | `insert`                                                                 |
| `update`  | `update`                                                                 |
| `replace` | `replace`                                                                |
| `remove`  | `remove`, `removeComposite`                                              |

`meta` exists for **write-only principals**: a form UI loads `/meta` (and `/meta/form/:name`) to render, so an insert-only role without `read` needs `meta` to show the form. Overlapping ops don't duplicate rules; an unknown op throws at definition time.

## `defineTableAccess` — one policy per table

Real apps rarely give a table one scope for everything: reads get a projection, writes get an `allowedFields` whitelist, and both share a row filter. Hand-building that from `allowTableRead` + `allowTableOps` + `allowTableAction` repeats the filter three times and lets the copies drift. `defineTableAccess` takes the shared part once ([signature](/api/arbac#definetableaccess)):

```ts
import { defineRole, defineTableAccess } from "@aooth/arbac";
import type { ArbacDbScope } from "@aooth/arbac-moost";
import { Task } from "./task.as";

type Attrs = { tenantId: string };

const editor = defineRole<Attrs>()
  .id("editor")
  .use(
    defineTableAccess<Attrs, ArbacDbScope<typeof Task>>("tasks", {
      // Shared by every part: row filter + read projection.
      scope: (a) => ({ filter: { tenantId: a.tenantId }, projection: { internalNotes: 0 } }),
      read: true,
      write: {
        ops: ["insert", "update"],
        scope: (a) => ({ allowedFields: ["title", "status"], set: { tenantId: a.tenantId } }),
      },
      actions: { names: ["archive"], scope: () => ({ filter: { status: "done" } }) },
    }),
  )
  .build();
```

| Part      | Accepts                              | Grants                                                                        |
| --------- | ------------------------------------ | ----------------------------------------------------------------------------- |
| `scope`   | `(attrs, userId) => scope`           | Nothing by itself — the base every part's scope builds on.                    |
| `read`    | `true` \| `{ scope }`                | The read actions (`geo` included).                                            |
| `write`   | `true` \| ops[] \| `{ ops?, scope }` | `true` / no `ops` = insert, update, replace, remove. The list may add `meta`. |
| `actions` | names[] \| `{ names, scope }`        | The named `@DbAction`s.                                                       |

How a part's scope merges over the shared one:

| Key                                                                                           | Merge                                                                                                                                                                                                                                                  |
| --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `filter`, `check`                                                                             | **Conjoined** (`$and`) — a part can only narrow the shared rows, never replace them. The WITH CHECK is `(shared.check ?? shared.filter) ∧ (part.check ?? part.filter)`, so a part's `check` (even `check: {}`) never widens the shared filter's check. |
| Everything else (`projection`, `allowedFields`, `set`, `controls`, `with`, `nestedWrites`, …) | The part's value when it sets the key, else the shared one. Arrays are not merged.                                                                                                                                                                     |

Before 0.1.72, a shared `{ filter }` with a part `{ check }` produced the part's `check` alone — written rows only had to match it, not the shared filter.

An action listed by an earlier part (`read` → `write` → `actions`) is not repeated by a later one — e.g. `write: ["update", "meta"]` next to `read: true` keeps `meta` under the read scope.

::: tip Pin the generics
`defineTableAccess`'s scope callbacks don't infer `TScope` — one part returning only `{ allowedFields }` would otherwise narrow the scope type for all of them. Pass `<Attrs, Scope>` explicitly, or call it inside a `defineRole<Attrs, Scope>().use(...)`, which supplies both.
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
- **`opts.scope` is attached to every rule.** For different scopes per side of a table use `defineTableAccess`; for anything else compose several `allowTableOps(...)` / `allowTableAction(...)` calls.
- **Never spread two filters together.** Combine a shared and a narrower filter with `conjoinScopeFilters` (what `defineTableAccess` does) — `{ ...a, ...b }` lets `b` replace a key of `a` and widens access.
- **Privileges are not first-class objects in the engine.** They are pure factories that emit `TArbacRule[]`. The engine never sees the privilege as a unit — only its rules. Don't expect to introspect "which privilege contributed this rule" at runtime.

## Next

- [Scope Merging](./scopes) — how to UNION the scopes that come back from multi-role evaluations and turn them into a single filter expression.
- [Codegen](./codegen) — emit `Resource` / `Action` TS unions from a roles array so `resource: string` becomes a typed literal.
