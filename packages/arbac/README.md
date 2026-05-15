# @aoothjs/arbac

Batteries-included RBAC for the moost / atscript ecosystem. Re-exports
`@aoothjs/arbac-core` and adds a fluent role builder, reusable privilege
factories, scope-merge utilities (projection unions, filter `$or` merges),
and a codegen CLI that emits typed unions of every resource/action your
roles touch.

## Install

```bash
pnpm add @aoothjs/arbac
```

## Define a role

```ts
import { Arbac, defineRole, allowTableRead, allowTableWrite } from "@aoothjs/arbac";

type MyAttrs = { department: string };
type MyScope = { dept: string };

const editor = defineRole<MyAttrs, MyScope>()
  .id("editor")
  .name("Editor")
  .use(allowTableWrite("articles", { scope: (attrs) => ({ dept: attrs.department }) }))
  .deny("articles", "publish")
  .allow("comments", "moderate")
  .build();

const arbac = new Arbac<MyAttrs, MyScope>();
arbac.registerRole(editor);
```

`allowTableWrite` grants all read + write actions that `AsDbController` exposes:
`query`, `pages`, `getOne`, `getOneComposite`, `meta`, `metaForm`,
`insert`, `update`, `replace`, `remove`, `removeComposite`.

Use `allowTableRead` for read-only access, and `allowTableAction` for individual
or grouped custom actions:

```ts
import { allowTableAction } from "@aoothjs/arbac";

// single action
allowTableAction("tasks", "markDone", { scope: (attrs) => ({ dept: attrs.department }) });

// multiple actions sharing a scope
allowTableAction("tasks", ["markDone", "archive", "assign"], { scope: ... });
```

## Reusable privileges

```ts
import { definePrivilege } from "@aoothjs/arbac";

const canManageProjects = definePrivilege<MyAttrs, MyScope>()(
  (scope: (attrs: MyAttrs) => MyScope) => [
    { resource: "projects", action: "read", scope },
    { resource: "projects", action: "update", scope },
  ],
);

defineRole<MyAttrs, MyScope>()
  .id("manager")
  .use(canManageProjects((a) => ({ dept: a.department })))
  .build();
```

## Scope merging

When several roles grant access with different scope filters, merge them
with the most-permissive semantics for the user:

```ts
import { mergeScopeFilters, unionProjections } from "@aoothjs/arbac";

mergeScopeFilters([{ department: "sales" }, { department: "marketing" }]);
// → { department: { $in: ["sales", "marketing"] } }

unionProjections({ name: 1, email: 1 }, { name: 1, age: 1 });
// → { name: 1, email: 1, age: 1 }
```

`unionProjections` follows **additive RBAC** semantics — more roles = broader
access. Each projection represents a set of allowed fields: include-mode
`{a:1}` allows `{a}`; exclude-mode `{a:0}` allows `universe \ {a}`; empty
`{}` allows the universe. The union allows a field if any input grants it.

```ts
// Editor allows {name, email}; auditor allows everything except `secret`.
// Union: editor's grants are already covered, so the union is "universe \ {secret}".
unionProjections({ name: 1, email: 1 }, { secret: 0 });
// → { secret: 0 }

// Editor explicitly grants `secret`; auditor excludes it. Union = universe.
unionProjections({ secret: 1 }, { secret: 0 });
// → {}
```

Within a single projection, mixing `1` and `0` keys is still an error — call
sites should normalize first. Mixing modes **across** projections is
supported and resolves via the additive rule above.

## Codegen CLI

Generate a TS union of every resource and action your roles use:

```bash
# 1. Build your roles module to JS first (your own toolchain).
# 2. Run the CLI, pointing --roles at the built JS.
npx aoothjs-arbac-codegen \
  --roles ./dist/roles.js \
  --output ./src/types/arbac.gen.ts \
  --resource-type TArbacResource \
  --action-type TArbacAction
```

The roles module must export the role array as default or as `roles`. The
output is a plain `.ts` file you can commit and import.
