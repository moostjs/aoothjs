# Builder API

This page answers: _how do I write roles without hand-rolling `TArbacRole` object literals, and how do I keep the generics flowing from the role through to my scope functions?_ It documents `defineRole()` from [`@aoothjs/arbac`](https://github.com/moostjs/aoothjs/tree/main/packages/arbac).

The builder is the recommended way to declare roles. It pins generics once, preserves rule order, and lets you splice in reusable [privilege factories](./privileges) with `.use(...)`.

## Signature

```ts
function defineRole<
  TUserAttrs extends object = object,
  TScope extends object = object,
>(): RoleBuilder<TUserAttrs, TScope>;
```

Two generic parameters, both defaulting to `object`. They flow into every chain method so your scope callbacks are typed without manual annotations.

## The chain

| Method                             | Effect                                                                                                                                                                                                   | Required                                |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| `.id(value)`                       | Sets the role ID. Last call wins.                                                                                                                                                                        | **Yes** — `.build()` throws without it. |
| `.name(value)`                     | Optional display name. Last call wins.                                                                                                                                                                   | No                                      |
| `.describe(value)`                 | Optional description. Last call wins.                                                                                                                                                                    | No                                      |
| `.allow(resource, action, scope?)` | Pushes `{ resource, action, scope? }`. The `scope` key is omitted from the emitted rule when not provided.                                                                                               | —                                       |
| `.deny(resource, action)`          | Pushes `{ resource, action, effect: 'deny' }`. No `scope` argument — deny rules cannot carry a scope.                                                                                                    | —                                       |
| `.use(...privileges)`              | Invokes each `TPrivilegeFunction` and splices its rules into the current list in place. Variadic-tuple typed — each privilege keeps its own scope shape (see [Generic pinning](#generic-pinning) below). | —                                       |
| `.build()`                         | Returns a plain `TArbacRole<TUserAttrs, TScope>` with a _copy_ of the rules array.                                                                                                                       | —                                       |

::: warning `.id()` is required
Calling `.build()` without an ID throws `"Role id is required. Call .id() before .build()."`. There is no default ID.
:::

## Quick example

```ts
import { defineRole } from "@aoothjs/arbac";

type Attrs = { dept: string };
type Scope = { dept: string };

const editor = defineRole<Attrs, Scope>()
  .id("editor")
  .name("Editor")
  .describe("Can read articles globally, update only their department, never publish.")
  .allow("articles", "read")
  .allow("articles", "update", (a) => ({ dept: a.dept }))
  .deny("articles", "publish")
  .build();
```

The emitted `editor` is a plain object — pass it to `arbac.registerRole(editor)`.

## Generic pinning

Pin the generics on `defineRole<Attrs, Scope>()` once. Every subsequent `.allow()` / `.deny()` / `.use()` infers from them.

```ts
type Attrs = { dept: string };
type Scope = { dept: string };

const role = defineRole<Attrs, Scope>()
  .id("editor")
  .allow("articles", "update", (a) => ({
    // ^ TS infers a: Attrs
    dept: a.dept, // returning Scope ✓
  }))
  .build();
```

If you skip the generics, both default to `object` and you'll get `unknown` inside the scope callback. Pin them every time.

### Role-level `TScope` is upper-bound documentation, not enforcement

`.use()` accepts a mix of typed-scope privileges in a single call — each privilege keeps its own scope shape. This matters for typed-table privileges like `allowTableRead<Attrs, ArbacDbScope<Task>>(...)` and `allowTableRead<Attrs, ArbacDbScope<Comment>>(...)`: the two scope shapes are not structurally assignable to each other, but you can drop both into one `.use(...)` call. The role-level `TScope` pin (`defineRole<Attrs, ArbacDbScope>()`) stays as **upper-bound documentation** of what scope objects look like at evaluate time. See [`@aoothjs/arbac` API reference](/api/arbac) for the full `.use()` signature.

## Rule order preservation

The builder pushes rules in **call order**. Both `.deny()` and `.allow()` for the same `(resource, action)` end up in the emitted role — and the engine applies its own deny-wins semantics regardless of order.

```ts
defineRole().id("x").allow("articles", "read").deny("articles", "read").build();
// rules: [
//   { resource: 'articles', action: 'read' },
//   { resource: 'articles', action: 'read', effect: 'deny' },
// ]
// → engine evaluates as denied (deny wins)
```

Order matters for one thing only: **debugging**. Rule arrays end up in audit logs and codegen output in declared order, so write the most important rules first.

## Splicing in privilege factories with `.use()`

`.use(...privileges)` accepts any number of privileges, each typed as `TPrivilegeFunction<TUserAttrs, TScopes[K]>` (variadic tuple). Each is called _immediately_ and its returned rules are spliced into the current rule list.

```ts
import { defineRole, definePrivilege, allowTableWrite } from "@aoothjs/arbac";

type Attrs = { dept: string };
type Scope = { dept: string };

// A small factory.
const canModerate = definePrivilege<Attrs, Scope>()(() => [
  { resource: "comments", action: "flag" },
  { resource: "comments", action: "hide" },
]);

const manager = defineRole<Attrs, Scope>()
  .id("manager")
  .use(allowTableWrite("articles", { scope: (a) => ({ dept: a.dept }) }))
  .use(canModerate())
  .deny("articles", "publish")
  .build();
```

`.use()` is a splice, not a delegate — by the time `.build()` runs the role is a flat `TArbacRole` with all rules inlined. Privilege factories cannot reach into the builder to set metadata; they only contribute rules.

See [Privilege Factories](./privileges) for what to put in a privilege function, including `definePrivilege` and the `allowTable*` family.

## When to omit the `scope` argument

Two equivalent ways to grant unrestricted read on `articles`:

```ts
defineRole().id("admin").allow("articles", "read").build();
defineRole()
  .id("admin")
  .allow("articles", "read", () => ({}))
  .build();
```

Both result in the engine pushing `{}` (the universe sentinel) into the `scopes` array when the rule matches. The first form is preferred — it leaves the `scope` key absent on the emitted rule, which is what tooling (audit logs, codegen, etc.) usually expects.

::: tip Don't write `scope: () => ({})` "for symmetry"
The omitted form is slightly more efficient (no scope-fn call at eval time) and more honest about intent.
:::

## `.deny()` has no scope argument

`.deny()` accepts only `(resource, action)` — there is no third parameter. The type system reflects this: `TArbacRule` forbids `scope` alongside `effect: 'deny'`. If you find yourself wanting a "conditional deny", express it as a wildcard allow plus a tighter exception, or compute the condition inside a scope fn that returns _no matching rows_.

## End-to-end

```ts
import { Arbac, defineRole, allowTableWrite } from "@aoothjs/arbac";

type Attrs = { dept: string; assignment: string[] };
type Scope = { dept: string };

const manager = defineRole<Attrs, Scope>()
  .id("manager")
  .name("Manager")
  .describe("Departmental manager.")
  .use(allowTableWrite("articles", { scope: (a) => ({ dept: a.dept }) }))
  .deny("articles", "publish")
  .allow("comments", "moderate")
  .build();

const arbac = new Arbac<Attrs, Scope>();
arbac.registerRole(manager);

await arbac.evaluate(
  { resource: "articles", action: "update" },
  { id: "u1", roles: ["manager"], attrs: { dept: "sales", assignment: [] } },
);
// → { allowed: true, scopes: [{ dept: 'sales' }] }

await arbac.evaluate(
  { resource: "articles", action: "publish" },
  { id: "u1", roles: ["manager"], attrs: { dept: "sales", assignment: [] } },
);
// → { allowed: false }
```

## Gotchas

- **`.build()` throws without `.id()`.** Always set the ID first, or last — but set it.
- **`.use()` rules are inlined.** Don't expect to introspect "which privilege did this rule come from" at runtime. If you need that, name your rules with a resource-prefix convention.
- **No `effect: 'allow'` literal.** `.allow()` omits `effect` entirely; the engine treats absence as allow. The type system forbids the explicit literal.
- **No deduplication.** Calling the same `.allow()` twice emits two rules. Cheap at eval time, noisy in audits — write each rule once.

## Next

- [Privilege Factories](./privileges) — how to write reusable rule bundles that plug into `.use()`.
- [Codegen](./codegen) — generate `Resource` / `Action` TypeScript types from a roles array.
