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

### `setupArbacFromAtscript()`

One call replaces `ArbacUserProvider` in the DI container with an
auto-wired implementation:

```ts
import { setupArbacFromAtscript } from "@aoothjs/arbac-moost/atscript";
import { useAuth } from "@aoothjs/auth-moost";
import { MyUser } from "./models/user.as";

setupArbacFromAtscript(moost, {
  userType: MyUser,
  table: usersTable, // @atscript/db Table<MyUser>
  // OR: store: usersStore,                // @aoothjs/user UserStore<MyUser>
  getUserId: () => useAuth().getCurrentUserId(),
});
```

| Option      | Required                   | Notes                                                              |
| ----------- | -------------------------- | ------------------------------------------------------------------ |
| `userType`  | yes                        | Atscript runtime type token for the user model                     |
| `table`     | one-of (`table` ⊕ `store`) | `@atscript/db` table; SELECT projection optimised for arbac fields |
| `store`     | one-of (`table` ⊕ `store`) | Any `{ read(id): Promise<T \| null> }` (matches `UserStore`)       |
| `getUserId` | yes                        | Resolves the current event's subject id                            |
| `warn`      | no                         | Warning sink (default `console.warn`)                              |

Internally it:

1. Reads atscript runtime metadata for `userType`.
2. Validates ≥ 1 `@arbac.role` field present (warns if none); requires a
   `userId` field (`@arbac.userId` ?? `@meta.id`).
3. Computes a minimum projection covering id + roles + attrs.
4. Installs a per-event memoized user-record fetcher via `defineWook`
   (see `useUserRecord`).
5. Replaces `ArbacUserProvider` in DI with `AutoArbacUserProvider`
   bound to `userType` and `getUserId`.

### Per-event memoization

`useUserRecord()` returns a per-event accessor keyed by `userId`. The first
call for an id fires the configured fetcher; subsequent calls within the
same event reuse the cached promise. Calls for **different** ids in the
same event are cached independently — safe for admin handlers that
evaluate policy against multiple subjects.

Cross-request caching is **not** included. Auth changes (role revocation,
attribute updates) must reflect immediately on the next request.

## API surface

```ts
// Main export
export { Arbac, arbacPatternToRegex }; // re-exports @aoothjs/arbac-core
export { MoostArbac };
export { ArbacUserProvider };
export { ArbacAuthorize, ArbacResource, ArbacAction, ArbacPublic, ArbacScopes, CurrentArbacScopes };
export { arbacAuthorizeInterceptor };
export { useArbac };
export type { TArbacCompiledRule, TArbacEvalResult, TArbacRole, TArbacRoleForResource, TArbacRule };

// /atscript sub-export
export {
  AutoArbacUserProvider,
  extractArbacAttrs,
  extractArbacRoles,
  extractArbacUserId,
  getArbacProjection,
  setupArbacFromAtscript,
  setUserRecordFetcher,
  useUserRecord,
  AoothArbacUserCredentials,
};

// /plugin sub-export (atscript compile-time plugin)
export default function arbacPlugin(): TAtscriptPlugin;
```
