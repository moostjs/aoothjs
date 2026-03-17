---
name: external code references
description: Locations of source code to migrate or reference for aoothjs packages
type: reference
---

- **@prostojs/arbac** (RBAC engine to migrate): `/Users/mavrik/code/prostojs/arbac/src/`
  - Core: `arbac.ts`, `types.ts`, `utils.ts`, `arbac.test.ts`
  - Zero deps, 6 tests, Arbac<TUserAttrs, TScope> class

- **@moostjs/arbac** (moost RBAC integration to migrate): `/Users/mavrik/code/moostjs/packages/arbac/src/`
  - MoostArbac, ArbacUserProvider, useArbac(), decorators, interceptor
  - 7 source files, peer deps on moost + @wooksjs/event-\*

- **rvmode/app-portal** (patterns to generalize, NOT copy directly): `/Users/mavrik/code/rvmode/packages/app-portal/src/auth/`
  - Role builder: `access-control/roles/.define-role.ts` (uses Proxy — generalize)
  - Privilege factory: `access-control/privileges/.define-privilege.ts`
  - Scope merging: `arbac-ext/arbac.composables.ts` (unionProjections, restrictProjection, mergeScopesFilters)
  - Codegen: `../../scripts/gen-resources.ts`
  - DB integration: `../../src/data-model/db-arbac.ts` (CollectionArbacController)

- **External docs:**
  - atscript: https://atscript.dev/llms.txt
  - atscript-db: https://db.atscript.dev/llms.txt
  - moost: https://moost.org/llms.txt
