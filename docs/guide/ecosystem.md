# Ecosystem & Packages

`aoothjs` is six packages. This page lists what each owns, what it depends on, and where to read more.

## Package map

| Package                                            | Role                                                                                                                                                        |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`@aoothjs/user`](../user/)                        | User credential record + password hashing + MFA primitives + lockout + pluggable `UserStore`.                                                               |
| [`@aoothjs/auth`](../auth/)                        | Issue / validate / refresh / revoke bearer credentials (sessions or JWT). Magic-link tokens. Email/SMS transport contracts.                                 |
| [`@aoothjs/arbac-core`](../arbac/core)             | Zero-dep RBAC engine — `Arbac`, `TArbacRole`, `TArbacRule`, deny-wins evaluator, wildcard matcher.                                                          |
| [`@aoothjs/arbac`](../arbac/)                      | Fluent `defineRole()` builder + `definePrivilege()` factories + scope-merge helpers + type codegen. Re-exports `arbac-core`.                                |
| [`@aoothjs/auth-moost`](../moost/)                 | moost glue: `AuthController`, `authGuardInterceptor`, `LoginWorkflow` / `RecoveryWorkflow` / `InviteWorkflow`, `@Public`, `@UserId`, `useAuth`.             |
| [`@aoothjs/arbac-moost`](../moost/arbac-authorize) | moost glue: `arbacAuthorizeInterceptor`, `@ArbacResource` / `@ArbacAction`, `useArbac`, `AsArbacDbController`, atscript-driven `AtscriptArbacUserProvider`. |

## Dependency graph

```
                           ┌────────────────────────────┐
                           │      @aoothjs/user         │
                           │  (credentials, hashing,    │
                           │   MFA, lockout, stores)    │
                           └────────────┬───────────────┘
                                        │
                ┌───────────────────────┴────────────────────┐
                │                                            │
                ▼                                            ▼
   ┌────────────────────────┐                  ┌─────────────────────────┐
   │   @aoothjs/auth        │                  │  @aoothjs/auth-moost    │
   │ (sessions / tokens,    │ ◄────────────────┤ (moost integration:     │
   │  refresh, magic-link,  │                  │  guard, workflows,      │
   │  email / SMS contracts)│                  │  AuthController)        │
   └────────────────────────┘                  └─────────────────────────┘

   ┌────────────────────────┐                  ┌─────────────────────────┐
   │   @aoothjs/arbac-core  │                  │  @aoothjs/arbac-moost   │
   │ (zero-dep RBAC engine) │ ◄────────────────┤ (moost integration:     │
   └────────────┬───────────┘                  │  arbacAuthorize, useArbac│
                │                              │  AsArbacDbController,   │
                ▼                              │  /atscript provider)    │
   ┌────────────────────────┐                  └─────────────────────────┘
   │     @aoothjs/arbac     │
   │ (builder + privileges  │
   │  + scope-merge + cgen) │
   └────────────────────────┘
```

- `@aoothjs/auth` depends on `@aoothjs/user` for the credential record shape and password verification.
- `@aoothjs/auth-moost` depends on both `@aoothjs/user` and `@aoothjs/auth` — workflows orchestrate `UserService` calls and store tokens via `AuthCredential`.
- `@aoothjs/arbac-moost` depends only on `@aoothjs/arbac-core`. It does NOT depend on `@aoothjs/arbac` — apps that want the builder/codegen layer install it separately.
- `@aoothjs/arbac-moost` and `@aoothjs/auth-moost` have **no dependency on each other**. They are bound only at the app's `Moost.applyGlobalInterceptors(...)` boundary. You can use either independently.

## What each package owns vs. delegates

| Package                | Owns                                                                                                                                                                       | Delegates                                                                                                                                   |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `@aoothjs/user`        | password hashing + verification, lockout, TOTP/backup-code generation, password policy evaluation, `UserStore` contract                                                    | persistence (you bring the store); MFA delivery (email/SMS); MFA challenge state machine                                                    |
| `@aoothjs/auth`        | bearer-credential lifecycle, refresh rotation with reuse detection, magic-link token generation, denylist abstraction                                                      | how tokens are persisted (store-pluggable); how email/SMS are delivered (interfaces only); the higher-level recovery / invite flow          |
| `@aoothjs/arbac-core`  | `Arbac.evaluate()`, deny-wins precedence, wildcard `*` matching, scope collection                                                                                          | role storage; how scopes are applied to queries                                                                                             |
| `@aoothjs/arbac`       | `defineRole` builder, `definePrivilege`, `allowTable*` factories, `mergeScopeFilters`, `unionProjections`, `unionControlsPolicy`, type codegen CLI                         | engine (re-exported from `arbac-core`)                                                                                                      |
| `@aoothjs/auth-moost`  | HTTP guard, `useAuth` composable, `AuthController` (4 endpoints), 3 workflow classes, cookie management, `WfTrigger(Provider)`                                             | the actual `AuthCredential` and `UserService` instances (DI-provided); senders (overridden via `protected deliver()`); workflow state store |
| `@aoothjs/arbac-moost` | authorize interceptor, `@ArbacResource` / `@ArbacAction` metadata, `useArbac` composable, DB CRUD scope enforcement (`AsArbacDbController`), atscript-driven user provider | role storage; user-identity resolution (`getUserId()`); the actual `Arbac` engine                                                           |

## Codegen requirements

`aoothjs` ships three `.as` models. Apps that extend them need the atscript compiler to run before TypeScript builds.

| Model                       | Ships in                                  | Used by                                                             |
| --------------------------- | ----------------------------------------- | ------------------------------------------------------------------- |
| `AoothUserCredentials`      | `@aoothjs/user/atscript-db/model.as`      | base — extends for any app using `UsersStoreAtscriptDb`             |
| `AoothArbacUserCredentials` | `@aoothjs/arbac-moost/atscript/models.as` | apps using `AtscriptArbacUserProvider` (auto-derives roles + attrs) |
| `AoothAuthCredential`       | `@aoothjs/auth/atscript-db/model.as`      | apps using `CredentialStoreAtscriptDb`                              |

::: tip Codegen is the bridge
The `*.as` files are the single source of truth. Build artefacts (`*.as.d.ts`, `*.as.js`) are produced by `asc -f dts` (or `unplugin-atscript` in a bundler). Without that step, `import { AoothArbacUserCredentials } from '...'` will fail with a missing-type error.
:::

For configuration, every app using a `.as` model registers `arbacPlugin()` from `@aoothjs/arbac-moost/plugin` in `atscript.config.ts`. See [Installation](./installation#atscript-codegen).

## Subpath exports

Subpaths group optional integrations away from the main entry, so a consumer not using (e.g.) Redis does not pay for an `ioredis` import.

| Subpath                                     | What it adds                                                                                                  |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `@aoothjs/user/atscript-db`                 | `UsersStoreAtscriptDb`, `AuthUserTable` types                                                                 |
| `@aoothjs/user/atscript-db/model.as`        | the raw `.as` file for the bundled `AoothUserCredentials`                                                     |
| `@aoothjs/auth/atscript-db`                 | `CredentialStoreAtscriptDb`, `AuthCredentialRow`, `AuthCredentialTable`                                       |
| `@aoothjs/auth/atscript-db/model.as`        | the raw `.as` file for `AoothAuthCredential`                                                                  |
| `@aoothjs/auth/redis`                       | `CredentialStoreRedis`, `DenylistStoreRedis`                                                                  |
| `@aoothjs/arbac-moost/atscript`             | `AtscriptArbacUserProvider`, `ArbacUserTable`, re-export of `AoothArbacUserCredentials`                       |
| `@aoothjs/arbac-moost/atscript/models[.as]` | the raw `.as` file for `AoothArbacUserCredentials`                                                            |
| `@aoothjs/arbac-moost/plugin`               | atscript-config plugin registering `@arbac.role`, `@arbac.attribute`, `@arbac.userId` — **compile-time only** |

## Picking the right surface

::: info You don't need every package
A worker that hashes passwords and validates credentials needs **only** `@aoothjs/user`. A microservice that needs ARBAC checks against pre-set roles needs **only** `@aoothjs/arbac-core` (or `@aoothjs/arbac` for the builder). The moost-glue packages are for apps that already use the moost HTTP / WF adapters.
:::

## Next steps

- [Quick Start](./quick-start) — runnable end-to-end example.
- [Installation](./installation) — peer-dep matrix per package.
- [Using atscript-db Models](./atscript-db) — concrete `.as` extension patterns.
