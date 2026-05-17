# ARBAC

This section answers: _what does Aooth's authorization layer actually do, and which package gives me which piece of it?_ It covers `@aoothjs/arbac-core` (the zero-dependency engine) and `@aoothjs/arbac` (the batteries-included layer of builders, privilege factories, scope mergers, and codegen).

## What ARBAC is

ARBAC stands for **Advanced** (or **Attribute-aware**) Role-Based Access Control. It keeps the familiar RBAC shape — _a role grants permission to perform an action on a resource_ — and adds three things that classic RBAC libraries leave to userland:

1. **Wildcard matching.** A single rule can target many resources or actions via `*` (single dotted segment) and `**` (cross-segment) patterns.
2. **Dynamic scopes.** An _allow_ rule may attach a `scope(userAttrs, userId)` callback whose return value is treated as a _data-level filter_ by the calling code. The engine never inspects the scope object — it just collects scopes from every matching allow rule into a UNION so the caller can OR them into a SQL/Mongo filter.
3. **Deny-wins precedence.** A matching `deny` rule on any of the user's roles vetoes every `allow` rule — regardless of specificity. There is no precedence weighting.

Together those three turn classic RBAC ("can Alice read articles?") into ARBAC ("can Alice read articles, _and which articles_?"). The engine answers both questions in one `evaluate()` call.

## The package split

Two packages, one engine. The split is deliberate — the engine is tiny and has no dependencies, so you can embed it anywhere; the second package is where the ergonomics live.

| Package                                                                                   | Role                                                                                                                                                                                                                         |
| ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`@aoothjs/arbac-core`](https://github.com/moostjs/aoothjs/tree/main/packages/arbac-core) | The evaluation engine. `class Arbac`, `arbacPatternToRegex`, and the rule/role/eval-result types. Zero dependencies.                                                                                                         |
| [`@aoothjs/arbac`](https://github.com/moostjs/aoothjs/tree/main/packages/arbac)           | Re-exports everything from `arbac-core`, then layers on `defineRole()`, `definePrivilege()`, the `allowTable*` family, scope-merge utilities, and the `aoothjs-arbac-codegen` CLI. Single dependency: `@aoothjs/arbac-core`. |

::: tip In practice
Almost every consumer installs `@aoothjs/arbac` only — it re-exports the core API, so you never need to import from `arbac-core` directly. The split exists so the engine stays embeddable.
:::

## Where to start

| If you want to…                                                | Read                                |
| -------------------------------------------------------------- | ----------------------------------- |
| Understand the vocabulary and the allow/deny algorithm         | [Mental Model](./concepts)          |
| Use the engine directly with hand-rolled `TArbacRole` literals | [Core Engine](./core)               |
| Build roles with a chainable, generic-aware API                | [Builder API](./builder)            |
| Bundle related rules into reusable named units                 | [Privilege Factories](./privileges) |
| UNION scopes from multiple roles at query time                 | [Scope Merging](./scopes)           |
| Generate TypeScript types from a roles array                   | [Codegen](./codegen)                |

## Where the framework glue lives

`@aoothjs/arbac` is framework-agnostic. The Moost-specific layer — `@ArbacAuthorize`, the `useArbac()` composable, role-aware `AsDbController`, and the `ArbacDbScope` shape that ties projections + filters + Uniquery controls together — lives in `@aoothjs/arbac-moost`. See [Moost Integration → ARBAC Authorize](/moost/arbac-authorize).

This section stays in the framework-agnostic layer. Everything you read here works the same whether you embed the engine in an Express app, a CLI, or a Moost project.

## The 30-second example

```ts
// minimal
import { Arbac, defineRole } from "@aoothjs/arbac";

const editor = defineRole<{ dept: string }, { dept: string }>()
  .id("editor")
  .allow("articles", "read")
  .allow("articles", "update", (attrs) => ({ dept: attrs.dept }))
  .deny("articles", "publish")
  .build();

const arbac = new Arbac();
arbac.registerRole(editor);

const result = await arbac.evaluate(
  { resource: "articles", action: "update" },
  { id: "u1", roles: ["editor"], attrs: { dept: "sales" } },
);
// → { allowed: true, scopes: [{ dept: 'sales' }] }
```

Three things to notice already, before moving on to the [Mental Model](./concepts):

- The role declares **what** the user may do (read, update) and **on which data** (the scope filter).
- The engine returns _one boolean and an array of scopes_. The caller decides how to apply them to a query.
- A subsequent `.deny('articles', 'publish')` would not be cancelled by any number of `.allow()` calls on the same resource/action.
