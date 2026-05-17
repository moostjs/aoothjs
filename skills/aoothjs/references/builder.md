# Engine + builder

`Arbac<TUserAttrs, TScope>` is the engine. `defineRole()` is the fluent role authoring API. `definePrivilege()` and the `allowTable*` helpers package related rules into reusable, parameterizable units.

## Contents

- [The `Arbac` class](#the-arbac-class)
- [`defineRole()` chain](#definerole-chain)
- [`definePrivilege()` — double-call pattern](#defineprivilege--double-call-pattern)
- [The `allowTable*` family](#the-allowtable-family)
- [Hand-written `TArbacRole` literals](#hand-written-tarbacrole-literals)

## The `Arbac` class

```ts
class Arbac<TUserAttrs extends object = object, TScope extends object = object> {
  registerRole(role: TArbacRole<TUserAttrs, TScope>): this;
  registerResource(resource: string): this;
  evaluate(
    res: { resource: string; action: string },
    user: {
      id: string | number;
      roles: string[];
      attrs: TUserAttrs | ((id: string) => TUserAttrs | Promise<TUserAttrs>);
    },
  ): Promise<TArbacEvalResult<TScope>>;
}
```

**`registerRole(role)`** — stores under `roles[id]` (idempotent overwrite by `id`), then re-evaluates the role against every already-registered resource. Pre-compiles allow/deny lists per `(resource, role)` pair into the internal cache `resources[resourceId][roleId]`.

**`registerResource(resource)`** — idempotent no-op if already registered. Auto-called by `evaluate()`, so explicit pre-registration is rare. Use it to bound the cache in long-lived processes with high resource cardinality.

**`evaluate(res, user)`** — async because `user.attrs` may be a lazy `(userId) => Promise<TUserAttrs>`. Algorithm:

1. Auto-register `res.resource` if unseen.
2. Look up the user's roles in `resources[res.resource][roleId]`. Unknown role IDs log `console.warn` ONCE per ID.
3. **Empty resolved roles** → return `{ allowed: false }` immediately.
4. **Deny pass** — iterate every resolved role's deny list. First `_actionRegex` match → return `{ allowed: false }`.
5. **Allow pass** — iterate every resolved role's allow list. For each match:
   - Rule has `scope` fn → lazily resolve `userAttrs` (once, then memoized), then `scopes.push(rule.scope(userAttrs, String(user.id)))`.
   - No `scope` fn → push `{}` (universe sentinel).
6. Return `scopes.length ? { allowed: true, scopes } : { allowed: false }`.

Side effect to know about: `evalRoleForResource` writes `_resourceRegex` / `_actionRegex` onto the original rule objects when compiling. Don't `Object.freeze()` rules before registering.

## `defineRole()` chain

```ts
import { defineRole, allowTableRead } from "@aoothjs/arbac";

type Attrs = { dept: string };
type Scope = { dept: string };

const role = defineRole<Attrs, Scope>()
  .id("manager") // required, last call wins
  .name("Department Manager") // optional metadata
  .describe("Read articles in own dept; moderate comments") // optional metadata
  .allow("articles", "read", (a) => ({ dept: a.dept })) // allow with scope
  .allow("comments", "moderate") // allow without scope (universe)
  .deny("articles", "publish") // deny — no scope allowed
  .use(allowTableRead("reports", { scope: (a) => ({ dept: a.dept }) })) // splice privilege
  .build();
// role: TArbacRole<Attrs, Scope>
```

### Methods

| Method                 | Effect                                                                                                                           |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `.id(string)`          | Required. Last call wins. Building without it throws `"Role id is required. Call .id() before .build()."`.                       |
| `.name(string)`        | Optional human label. Stored on the emitted role as `name`.                                                                      |
| `.describe(string)`    | Optional description. Stored as `description`.                                                                                   |
| `.allow(r, a, scope?)` | Pushes `{ resource: r, action: a, scope? }`. When `scope` is omitted, the property is NOT present on the rule (not `undefined`). |
| `.deny(r, a)`          | Pushes `{ resource: r, action: a, effect: "deny" }`. Deny rules cannot carry a scope.                                            |
| `.use(...privs)`       | Invokes each `TPrivilegeFunction` and splices its rules in-line in call order.                                                   |
| `.build()`             | Returns a plain `TArbacRole<TUserAttrs, TScope>` with a COPY of the internal rules array. The builder may be discarded after.    |

Rules are emitted in call order. `.deny()` and a subsequent `.allow()` for the same `(resource, action)` are both emitted — the engine's deny-wins logic decides precedence at evaluation time, not the builder.

### Generics

```ts
defineRole<TUserAttrs extends object = object, TScope extends object = object>()
  : RoleBuilder<TUserAttrs, TScope>
```

The generics are pinned at builder construction. Every subsequent `.allow(...)` / `.use(...)` / privilege carries them through. Set the generics once at `defineRole<Attrs, Scope>()` and the rest type-checks for free.

## `definePrivilege()` — double-call pattern

A privilege is a reusable bundle of rules. The factory is curried into TWO calls:

```ts
const def = definePrivilege<TUserAttrs, TScope>(); // 1st call — binds generics
const factory = def((arg1, arg2) => [
  /* TArbacRule[] */
]); // 2nd call — provides rule factory
// `factory` is now `(arg1, arg2) => TPrivilegeFunction<TUserAttrs, TScope>`
// `TPrivilegeFunction` is `() => TArbacRule[]`, suitable for `.use(...)`.
```

Worked example:

```ts
import { definePrivilege, defineRole } from "@aoothjs/arbac";

type Attrs = { dept: string };
type Scope = { dept: string };

const canManageUsers = definePrivilege<Attrs, Scope>()((scope: (a: Attrs, id: string) => Scope) => [
  { resource: "users", action: "read", scope },
  { resource: "users", action: "update", scope },
]);

const role = defineRole<Attrs, Scope>()
  .id("manager")
  .use(canManageUsers((a) => ({ dept: a.dept })))
  .build();
```

Why two calls? Generics. TypeScript inference only flows one direction through a single call. The first call pins `<TUserAttrs, TScope>` so the factory's `scope` parameter types and `TArbacRule` return type resolve. Forgetting the first `()`:

```ts
// WRONG — generics collapse to `unknown`, rules become weakly typed
const broken = definePrivilege((scope) => [...]);
```

## The `allowTable*` family

These privileges bake in the action vocabulary exposed by `AsDbController` (from `@atscript/moost-db`) so app developers don't have to memorize action names.

```ts
const TABLE_READ_ACTIONS = ["query", "pages", "getOne", "getOneComposite", "meta", "metaForm"];
const TABLE_WRITE_ACTIONS = ["insert", "update", "replace", "remove", "removeComposite"];
```

| Helper                                                | Emits                                      | Notes                                                                |
| ----------------------------------------------------- | ------------------------------------------ | -------------------------------------------------------------------- |
| `allowTableRead(resource, opts?)`                     | 6 allow rules — every `TABLE_READ_ACTIONS` | Read-side only.                                                      |
| `allowTableWrite(resource, opts?)`                    | 11 allow rules — read + write actions      | Includes everything `allowTableRead` emits PLUS the 5 write actions. |
| `allowTableAction(resource, name \| string[], opts?)` | One allow rule per name                    | `allowTableAction(r, "x")` ≡ `allowTableAction(r, ["x"])`.           |

All three return `TPrivilegeFunction<TUserAttrs, TScope>` for `.use(...)`.

`opts.scope` is `(attrs: TUserAttrs, userId: string) => TScope`. When present, it attaches to EVERY generated rule. Omit `opts.scope` to grant unrestricted access (each rule will push `{}` into the scopes array).

```ts
import { defineRole, allowTableWrite, allowTableAction } from "@aoothjs/arbac";

type Attrs = { dept: string };
type Scope = { dept: string };

const editor = defineRole<Attrs, Scope>()
  .id("editor")
  .use(allowTableWrite("articles", { scope: (a) => ({ dept: a.dept }) }))
  .use(allowTableAction("articles", ["publish", "unpublish"]))
  .build();
```

The "db" in `db-privileges.ts` refers strictly to the `AsDbController` REST contract — no runtime DB I/O happens here. The helpers exist purely as a vocabulary shortcut.

## Hand-written `TArbacRole` literals

When you don't need the builder's ergonomics (e.g. roles loaded from a config file or DB), emit plain literals:

```ts
import type { TArbacRole } from "@aoothjs/arbac";

const role: TArbacRole<{ dept: string }, { dept: string }> = {
  id: "reader",
  name: "Reader",
  rules: [
    { resource: "articles", action: "read", scope: (a) => ({ dept: a.dept }) },
    { resource: "articles", action: "publish", effect: "deny" },
  ],
};
```

The engine doesn't care whether a role came from the builder or a literal — both end up in the same internal cache.
