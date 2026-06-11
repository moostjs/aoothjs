# Ecosystem & Packages

`aoothjs` is eight packages. This page lists what each owns, what it depends on, and where to read more.

## Package map

| Package                                          | Role                                                                                                                                                                                                  |
| ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`@aooth/user`](../user/)                        | User credential record + password hashing + MFA primitives + lockout + pluggable `UserStore`.                                                                                                         |
| [`@aooth/auth`](../auth/)                        | Issue / validate / refresh / revoke bearer credentials (sessions or JWT). Magic-link tokens. Email/SMS transport contracts.                                                                           |
| [`@aooth/idp`](../idp/)                          | Federated-login core: OAuth2/OIDC provider clients (discovery + JWKS + ID-token verification), PKCE/state, `OAuthProviderRegistry`, `FederatedLoginService`.                                          |
| [`@aooth/arbac-core`](../arbac/core)             | Zero-dep RBAC engine — `Arbac`, `TArbacRole`, `TArbacRule`, deny-wins evaluator, wildcard matcher.                                                                                                    |
| [`@aooth/arbac`](../arbac/)                      | Fluent `defineRole()` builder + `definePrivilege()` factories + scope-merge helpers + type codegen. Re-exports `arbac-core`.                                                                          |
| [`@aooth/auth-moost`](../moost/)                 | moost glue: `AuthController`, `authGuardInterceptor`, the unified `AuthWorkflow` (login / invite / recovery), `ConsentStore`, `@Public`, `@UserId`, `useAuth`.                                        |
| [`@aooth/arbac-moost`](../moost/arbac-authorize) | moost glue: `arbacAuthorizeInterceptor`, `@ArbacResource` / `@ArbacAction`, `useArbac`, `AsArbacDbController`, atscript-driven `AtscriptArbacUserProvider`.                                           |
| [`@aooth/login-client`](/api/login-client)       | Zero-dependency CLI/loopback login helper — one `authorize()` call drives the browser + PKCE round-trip against an aoothjs [authorization server](../moost/authorization-server) and returns a token. |

## Dependency graph

```
                           ┌────────────────────────────┐
                           │      @aooth/user         │
                           │  (credentials, hashing,    │
                           │   MFA, lockout, stores)    │
                           └────────────┬───────────────┘
                                        │
                ┌───────────────────────┴────────────────────┐
                │                                            │
                ▼                                            ▼
   ┌────────────────────────┐                  ┌─────────────────────────┐
   │   @aooth/auth        │                  │  @aooth/auth-moost    │
   │ (sessions / tokens,    │ ◄────────────────┤ (moost integration:     │
   │  refresh, magic-link,  │                  │  guard, workflows,      │
   │  email / SMS contracts)│                  │  AuthController)        │
   └────────────────────────┘                  └─────────────────────────┘

   ┌────────────────────────┐                  ┌─────────────────────────┐
   │   @aooth/arbac-core  │                  │  @aooth/arbac-moost   │
   │ (zero-dep RBAC engine) │ ◄────────────────┤ (moost integration:     │
   └────────────┬───────────┘                  │  arbacAuthorize, useArbac│
                │                              │  AsArbacDbController,   │
                ▼                              │  /atscript provider)    │
   ┌────────────────────────┐                  └─────────────────────────┘
   │     @aooth/arbac     │
   │ (builder + privileges  │
   │  + scope-merge + cgen) │
   └────────────────────────┘
```

- `@aooth/auth` depends on `@aooth/user` for the credential record shape and password verification.
- `@aooth/idp` depends on `@aooth/user` (concrete `UserService` + the `FederatedIdentityStore` that ships there) and reuses `@aooth/auth`'s `Clock`. It's the framework-agnostic federated-login core; the HTTP/workflow wiring (`OAuthController` + the federated leg of `auth/login/flow`) lives in `@aooth/auth-moost`.
- `@aooth/auth-moost` depends on both `@aooth/user` and `@aooth/auth` — workflows orchestrate `UserService` calls and store tokens via `AuthCredential`.
- `@aooth/arbac-moost` depends on `@aooth/arbac-core`, `@aooth/arbac` (re-exports `ControlGate`, scope-merge helpers used by the DB controllers), and `@aooth/user` (for `UserCredentials` typing on the atscript provider) — all as runtime workspace deps.
- `@aooth/arbac-moost` and `@aooth/auth-moost` have **no dependency on each other**. They are bound only at the app's `Moost.applyGlobalInterceptors(...)` boundary. You can use either independently.
- `@aooth/login-client` depends on **nothing** — not even other `@aooth/*` packages (Node built-ins + global `fetch`). It is the client half of the [authorization server](../moost/authorization-server); the server half lives in `@aooth/auth-moost`.

## What each package owns vs. delegates

| Package              | Owns                                                                                                                                                                       | Delegates                                                                                                                                                                        |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `@aooth/user`        | password hashing + verification, lockout, TOTP generation + verify, password policy evaluation, `UserStore` contract                                                       | persistence (you bring the store); MFA delivery (email/SMS); MFA challenge state machine; backup/recovery codes                                                                  |
| `@aooth/auth`        | bearer-credential lifecycle, refresh rotation with reuse detection, magic-link token generation, denylist abstraction                                                      | how tokens are persisted (store-pluggable); how email/SMS are delivered (interfaces only); the higher-level recovery / invite flow                                               |
| `@aooth/arbac-core`  | `Arbac.evaluate()`, deny-wins precedence, wildcard `*` matching, scope collection                                                                                          | role storage; how scopes are applied to queries                                                                                                                                  |
| `@aooth/arbac`       | `defineRole` builder, `definePrivilege`, `allowTable*` factories, `mergeScopeFilters`, `unionProjections`, `unionControlsPolicy`, type codegen CLI                         | engine (re-exported from `arbac-core`)                                                                                                                                           |
| `@aooth/auth-moost`  | HTTP guard, `useAuth` composable, `AuthController` (7 endpoints), the unified `AuthWorkflow` (6 schemas), `ConsentStore`, cookie management, `WfTrigger(Provider)`         | the actual `AuthCredential` and `UserService` instances (DI-provided); senders (overridden via `protected deliver()`); durable workflow state store (override `storeStrategy()`) |
| `@aooth/arbac-moost` | authorize interceptor, `@ArbacResource` / `@ArbacAction` metadata, `useArbac` composable, DB CRUD scope enforcement (`AsArbacDbController`), atscript-driven user provider | role storage; user-identity resolution (`getUserId()`); the actual `Arbac` engine                                                                                                |

## Codegen requirements

`aoothjs` ships three `.as` models. Apps that extend them need the atscript compiler to run before TypeScript builds.

| Model                       | Ships in                                | Used by                                                             |
| --------------------------- | --------------------------------------- | ------------------------------------------------------------------- |
| `AoothUserCredentials`      | `@aooth/user/atscript-db/model.as`      | base — extends for any app using `UsersStoreAtscriptDb`             |
| `AoothArbacUserCredentials` | `@aooth/arbac-moost/atscript/models.as` | apps using `AtscriptArbacUserProvider` (auto-derives roles + attrs) |
| `AoothAuthCredential`       | `@aooth/auth/atscript-db/model.as`      | apps using `CredentialStoreAtscriptDb`                              |

::: tip Codegen is the bridge
The `*.as` files are the single source of truth. Build artefacts (`*.as.d.ts`, `*.as.js`) are produced by `asc -f dts` (or `unplugin-atscript` in a bundler). Without that step, `import { AoothArbacUserCredentials } from '...'` will fail with a missing-type error.
:::

For configuration, every app using a `.as` model registers `arbacPlugin()` from `@aooth/arbac-moost/plugin` in `atscript.config.ts`. See [Installation](./installation#atscript-codegen).

## Subpath exports

Subpaths group optional integrations away from the main entry, so a consumer not using (e.g.) Redis does not pay for an `ioredis` import.

| Subpath                                   | What it adds                                                                                                  |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `@aooth/user/atscript-db`                 | `UsersStoreAtscriptDb`, `AuthUserTable` types                                                                 |
| `@aooth/user/atscript-db/model.as`        | the raw `.as` file for the bundled `AoothUserCredentials`                                                     |
| `@aooth/auth/atscript-db`                 | `CredentialStoreAtscriptDb`, `AuthCredentialRow`, `AuthCredentialTable`                                       |
| `@aooth/auth/atscript-db/model.as`        | the raw `.as` file for `AoothAuthCredential`                                                                  |
| `@aooth/auth/redis`                       | `CredentialStoreRedis`, `DenylistStoreRedis`                                                                  |
| `@aooth/arbac-moost/atscript`             | `AtscriptArbacUserProvider`, `ArbacUserTable`, re-export of `AoothArbacUserCredentials`                       |
| `@aooth/arbac-moost/atscript/models[.as]` | the raw `.as` file for `AoothArbacUserCredentials`                                                            |
| `@aooth/arbac-moost/plugin`               | atscript-config plugin registering `@arbac.role`, `@arbac.attribute`, `@arbac.userId` — **compile-time only** |

## Picking the right surface

::: info You don't need every package
A worker that hashes passwords and validates credentials needs **only** `@aooth/user`. A microservice that needs ARBAC checks against pre-set roles needs **only** `@aooth/arbac-core` (or `@aooth/arbac` for the builder). The moost-glue packages are for apps that already use the moost HTTP / WF adapters.
:::

## Next steps

- [Quick Start](./quick-start) — runnable end-to-end example.
- [Installation](./installation) — peer-dep matrix per package.
- [Using atscript-db Models](./atscript-db) — concrete `.as` extension patterns.
