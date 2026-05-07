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
import { Arbac, defineRole, canCrud } from "@aoothjs/arbac";

type MyAttrs = { department: string };
type MyScope = { dept: string };

const editor = defineRole<MyAttrs, MyScope>()
  .id("editor")
  .name("Editor")
  .use(canCrud("articles", (attrs) => ({ dept: attrs.department })))
  .deny("articles", "publish")
  .allow("comments", "moderate")
  .build();

const arbac = new Arbac<MyAttrs, MyScope>();
arbac.registerRole(editor);
```

`canCrud` emits five rules — `create`, `read`, `update`, `delete`, `list` —
because list-of-many is commonly scoped differently than read-of-one.

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

`unionProjections` throws when given a mix of include and exclude
projections — silently widening to unrestricted is a security footgun.

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
