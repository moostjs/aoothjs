# @aoothjs/arbac-moost

Moost integration for `@aoothjs/arbac-core`. DI-injectable `MoostArbac`, an
authorize interceptor at `GUARD` priority, decorators for declaring resources
and actions, a `useArbac()` composable, and (under `/atscript`) auto-wired
provider plumbing driven by `.as` user models annotated with `@arbac.*`.

## Install

```bash
pnpm add @aoothjs/arbac-moost @aoothjs/arbac-core
```

Peer dependencies: `moost`, `@wooksjs/event-core`, `@wooksjs/event-http`. The
`/atscript` sub-export additionally depends on `@atscript/typescript` and
`@atscript/db` (both `optional` peers).

## Manual setup

```ts
import { Moost, createReplaceRegistry } from "moost";
import {
  MoostArbac,
  ArbacUserProvider,
  ArbacAuthorize,
  ArbacResource,
  ArbacAction,
  ArbacPublic,
} from "@aoothjs/arbac-moost";

class MyArbacUserProvider extends ArbacUserProvider<{ tenantId: string }> {
  getUserId() {
    return useAuth().getCurrentUserId();
  }
  async getRoles(id: string) {
    return (await db.users.find(id)).roles;
  }
  async getAttrs(id: string) {
    return { tenantId: (await db.users.find(id)).tenantId };
  }
}

const moost = new Moost();
moost.setReplaceRegistry(createReplaceRegistry([ArbacUserProvider, MyArbacUserProvider]));

// Register roles
const arbac = await moost.getInfact().get(MoostArbac);
arbac.registerRole(adminRole);
arbac.registerRole(editorRole);
```

## Decorators

| Decorator           | Target               | Effect                                                              |
| ------------------- | -------------------- | ------------------------------------------------------------------- |
| `@ArbacAuthorize()` | Method / class       | Applies the authorize interceptor                                   |
| `@ArbacResource(s)` | Method / class       | Sets the resource id for evaluation                                 |
| `@ArbacAction(a)`   | Method / class       | Sets the action id for evaluation                                   |
| `@ArbacPublic()`    | Method / class       | Bypasses authorization                                              |
| `@ArbacScopes()`    | Parameter / property | Injects evaluated `scopes` returned by the role's `scope(attrs)` fn |

```ts
@Controller("articles")
@ArbacAuthorize()
@ArbacResource("articles")
class ArticlesController {
  @Get(":id")
  @ArbacAction("read")
  async read(@Param("id") id: string, @ArbacScopes() scopes?: MyScope[]) {
    return db.articles.find(id, { restrict: mergeScopes(scopes) });
  }
}
```

The interceptor runs at `GUARD` priority, throws `HttpError(403)` on deny,
`HttpError(401)` on unexpected errors, and stores `scopes` in the event
context on allow.

## `useArbac()`

```ts
const { evaluate, getScopes, setScopes, resource, action, isPublic } = useArbac();
const { allowed, scopes, userId } = await evaluate({ resource: "articles", action: "read" });
```

Read-only inside handlers; the authorize interceptor calls `evaluate()` and
`setScopes()` for you when `@ArbacAuthorize()` is applied.

## `/atscript` — auto-wired provider

Sub-export at `@aoothjs/arbac-moost/atscript`. Pairs an `.as` user model
annotated with `@arbac.*` to an auto-built `ArbacUserProvider`.

### Annotation namespace

| Annotation         | Targets | Purpose                                                                     |
| ------------------ | ------- | --------------------------------------------------------------------------- |
| `@arbac.role`      | prop    | Source of role identifiers. `string` or `string[]`. Multiple roles unioned. |
| `@arbac.attribute` | prop    | Field becomes a user attribute keyed by its prop name                       |
| `@arbac.userId`    | prop    | Overrides the userId source (defaults to `@meta.id`)                        |

Register the plugin in your `atscript.config.ts`:

```ts
import arbacPlugin from "@aoothjs/arbac-moost/plugin";

export default {
  plugins: [arbacPlugin()],
};
```

### `AoothArbacUserCredentials` base model

Pre-applies `@arbac.role` to a `roles: string[]` field:

```
import { AoothArbacUserCredentials } from '@aoothjs/arbac-moost/atscript/models'

@db.table 'users'
export interface MyUser extends AoothArbacUserCredentials {
    @meta.id
    @db.default.uuid
    id: string

    @arbac.attribute
    tenantId: string

    @arbac.attribute
    department: string
}
```

### `AtscriptArbacUserProvider`

Abstract `ArbacUserProvider` driven by a `.as` user type and a wrapped
atscript-db readable. The consumer extends the class, implements
`getUserId()`, injects their table, and registers the subclass via
`setReplaceRegistry`:

```ts
import { AtscriptArbacUserProvider } from "@aoothjs/arbac-moost/atscript";
import { ArbacUserProvider } from "@aoothjs/arbac-moost";
import { useAuth } from "@aoothjs/auth-moost";
import { createReplaceRegistry, Injectable } from "moost";
import { MyUser } from "./models/user.as";

// `@Injectable()` MUST be re-applied on every consumer subclass —
// moost@0.6.x does not inherit injectable metadata across `extends`.
@Injectable()
class MyArbacUserProvider extends AtscriptArbacUserProvider<MyUser> {
  constructor() {
    // `usersTable` is your `@atscript/db` table (or any value implementing
    // `{ findOne({ filter, controls }): Promise<MyUser | null> }`).
    super(MyUser, usersTable);
  }
  override getUserId(): string {
    return useAuth().getCurrentUserId();
  }
}
moost.setReplaceRegistry(createReplaceRegistry([ArbacUserProvider, MyArbacUserProvider]));
```

The base constructor:

1. Reads atscript runtime metadata for `userType` and resolves the userId
   field (`@arbac.userId` ?? `@meta.id`); throws if neither is present.
2. Computes a minimum SELECT projection covering id + roles + attrs.

`getRoles(id)` and `getAttrs(id)` then call `table.findOne({ filter:
{ [userIdField]: id }, controls: { $select: projection } })` and feed the
record through the `protected extractRoles` / `extractAttrs` seams —
override either to reshape the output without re-implementing the fetch.

#### Per-event memoization

The base class caches the fetched record on the wooks event context,
keyed by `(this, userId)`. Two calls — `getRoles(id) + getAttrs(id)` —
share one DB read. Different subjects probed by the same event are
cached independently (safe for admin handlers).

Cross-request caching is **not** included. Auth changes (role revocation,
attribute updates) reflect immediately on the next request.

## API surface

```ts
// Main export
export { Arbac, arbacPatternToRegex }; // re-exports @aoothjs/arbac-core
export { MoostArbac };
export { ArbacUserProvider };
export { ArbacAuthorize, ArbacResource, ArbacAction, ArbacPublic, ArbacScopes };
export { arbacAuthorizeInterceptor };
export { useArbac };
export type { TArbacCompiledRule, TArbacEvalResult, TArbacRole, TArbacRoleForResource, TArbacRule };

// /atscript sub-export
export { AtscriptArbacUserProvider, type ArbacUserTable, AoothArbacUserCredentials };

// /plugin sub-export (atscript compile-time plugin)
export default function arbacPlugin(): TAtscriptPlugin;
```
