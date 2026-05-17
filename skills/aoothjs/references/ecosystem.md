# ecosystem

Where each piece of the aoothjs stack lives, which problem it solves, and which sibling
skill owns the deeper material. The umbrella SKILL gives the install matrix and the
canonical wiring; this page is the map for "I need X — which package and which skill?".

## Contents

- [Package responsibility matrix](#package-responsibility-matrix)
- [Dependency graph](#dependency-graph)
- [Which sub-skill to load](#which-sub-skill-to-load)
- [Peer dependencies](#peer-dependencies)
- [Build-step requirements](#build-step-requirements)
- [Subpath exports](#subpath-exports)

## Package responsibility matrix

| Package              | Owns                                                                                                                                                                                                                                                | Does NOT own                                                                                                              |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `@aooth/user`        | `UserService` orchestrator, scrypt `PasswordHasher`, `PasswordPolicy` engine + 6 transferable factories, TOTP/HOTP, backup-code generation/hashing, trusted-device HMAC, lockout, `UserStore` abstract + `UserStoreMemory` + `UsersStoreAtscriptDb` | Email/SMS delivery, JWT/session issuance, role storage, MFA challenge state machine                                       |
| `@aooth/arbac-core`  | Zero-dep `Arbac` evaluator with deny-wins, wildcard patterns (`*` / `**`), per-resource role pre-compile, lazy user-attrs resolve, `arbacPatternToRegex` utility                                                                                    | Role storage, builder API, scope-merge helpers, framework integration                                                     |
| `@aooth/arbac`       | Builder API (`defineRole`), privilege factories (`definePrivilege`, `allowTableRead/Write/Action`), scope mergers (`mergeScopeFilters`, `unionProjections`, `restrictProjection`, `unionControlsPolicy`), codegen lib + CLI                         | The evaluator (re-exports from `arbac-core`), persistence                                                                 |
| `@aooth/auth`        | `AuthCredential` issue/validate/refresh/revoke, 5 store impls (`Memory`/`Jwt`/`Encapsulated`/`Redis`/`AtscriptDb`), `DenylistStore` + impls, `generateMagicLinkToken`, transport contracts (`EmailSender`, `SmsSender`), `AuthError`                | Password hashing (delegates to `@aooth/user`), MFA verify, workflow orchestration                                         |
| `@aooth/auth-moost`  | `AuthController` (`/auth/{logout,refresh,status,trigger}`), `authGuardInterceptor`, `@Public` (dual auth+arbac), `@UserId`, `useAuth`, three workflows (`LoginWorkflow`, `RecoveryWorkflow`, `InviteWorkflow`), `WfTriggerProvider`                 | Email/SMS delivery (consumer ships `EmailSender`/`SmsSender`), authorization (handled by `arbac-moost`)                   |
| `@aooth/arbac-moost` | `arbacAuthorizeInterceptor` (GUARD), `useArbac`, `@ArbacResource`/`@ArbacAction`/`@ArbacAuthorize`, `MoostArbac` (DI-injectable), `ArbacUserProvider` abstract, `AsArbacDbController` + `AsArbacDbReadableController`, atscript provider            | Authentication (pair with `authGuardInterceptor`), role/privilege storage, `.as` syntax (only the `@arbac.*` plugin spec) |

## Dependency graph

```
                @aooth/arbac-core
                       ▲
                       │ re-export *
                       │
                @aooth/arbac ──────────────────┐
                       ▲                          │
                       │                          │
@aooth/user          │       @aooth/auth      │
   │                   │           │              │
   │ (workspace dep)   │           │              │
   ├───────────────────┼───────────┘              │
   │                   │                          │
   ▼                   ▼                          ▼
@aooth/auth ◄─── @aooth/auth-moost ◄─── @aooth/arbac-moost
                              │                   │
                              ▼                   ▼
                            moost            moost (+ /atscript subpath
                            @moostjs/event-http   needs @atscript/typescript)
                            @moostjs/event-wf
                            @atscript/moost-wf
```

Notable edges:

- `@aooth/arbac` has exactly **one** runtime dep: `@aooth/arbac-core`. No moost, no atscript.
- `@aooth/arbac-core` has **zero** runtime deps. Drop-in for non-moost stacks.
- `@aooth/user` and `@aooth/auth` only **optionally** peer-depend on `@atscript/db ≥ 0.1.79` — the subpath `./atscript-db` is gated.
- `@aooth/auth-moost` and `@aooth/arbac-moost` both depend on `moost`, but neither depends on the other directly. They cooperate through the dual-purpose `@Public()` (which writes both `authPublic` and `arbacPublic` mate flags).

## Which sub-skill to load

| User question / task                                                               | Load skill                                                                   |
| ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| "Create a user, change password, generate TOTP secret, mask MFA value"             | see [user.md](./user.md)                                                     |
| "Write a `PasswordPolicy`, transferable rules, scrypt parameters, history"         | see [user.md](./user.md)                                                     |
| "Lockout, trusted devices, backup codes, `consumeBackupCode`"                      | see [user.md](./user.md)                                                     |
| "Define a role, scope union, deny-wins, codegen TS resource types"                 | see [arbac.md](./arbac.md)                                                   |
| "`mergeScopeFilters` / `unionProjections` / `unionControlsPolicy` semantics"       | see [arbac.md](./arbac.md)                                                   |
| "Issue / refresh JWT, magic link, denylist, refresh rotation modes"                | see [auth.md](./auth.md)                                                     |
| "Redis / atscript-db credential store, `revokeAllForUser`, epoch"                  | see [auth.md](./auth.md)                                                     |
| "Wire `AuthController`, `@Public()`, `@UserId()`, `useAuth()`, cookie config"      | see [moost.md](./moost.md)                                                   |
| "Override `LoginWorkflow.deliver`, MFA pincode, `WfTriggerProvider`, outlets"      | see [moost.md](./moost.md)                                                   |
| "`arbacAuthorizeInterceptor`, `useArbac`, `@ArbacResource`, `AsArbacDbController`" | see [moost.md](./moost.md)                                                   |
| "`.as` user model, `@arbac.role` / `.attribute` / `.userId`, atscript plugin"      | this skill + see [moost.md](./moost.md) + [annotations.md](./annotations.md) |
| Multi-package architecture / install / which-package-owns-what                     | this skill                                                                   |

## Peer dependencies

| Package              | peerDep                | Range             | Optional?                                                          |
| -------------------- | ---------------------- | ----------------- | ------------------------------------------------------------------ |
| `@aooth/user`        | `@atscript/db`         | `≥ 0.1.79`        | yes (only for `./atscript-db` subpath)                             |
| `@aooth/auth`        | `@atscript/db`         | `≥ 0.1.79`        | yes (only for `./atscript-db` subpath)                             |
| `@aooth/auth`        | `jose` (regular dep)   | `^6.2.3`          | n/a — bundled as a regular dependency, not a peer (auto-installed) |
| `@aooth/auth-moost`  | `moost`                | matches workspace | no                                                                 |
| `@aooth/auth-moost`  | `@moostjs/event-http`  | matches workspace | no                                                                 |
| `@aooth/auth-moost`  | `@moostjs/event-wf`    | matches workspace | no                                                                 |
| `@aooth/auth-moost`  | `@atscript/moost-wf`   | matches workspace | no (`formInputInterceptor`, `AsWfStore`)                           |
| `@aooth/arbac-moost` | `moost`                | matches workspace | no                                                                 |
| `@aooth/arbac-moost` | `@atscript/moost-db`   | matches workspace | yes (only for `AsArbacDbController` subclass)                      |
| `@aooth/arbac-moost` | `@atscript/typescript` | matches workspace | yes (only for `./atscript` subpath)                                |

## Build-step requirements

`.as` files require a build step before runtime can `import` from them:

1. **`unplugin-atscript`** in `vite.config.ts` / `rollup.config.js` / `tsdown.config.ts` — typical dev path. Transforms `.as` → `.as.ts` on demand.
2. **`asc -f dts`** as a pre-build script — emits `.as.d.ts` + `.as.js` and an aggregate `atscript.d.ts`. Required when:
   - The build pipeline cannot run the unplugin (e.g. pure tsc, esbuild without plugins).
   - `@aooth/arbac-moost/atscript` is in use — the atscript provider reads runtime metadata that `asc` emits.
3. **Codegen** — `aoothjs-arbac-codegen --roles dist/roles.mjs --output src/generated/arbac-types.ts` consumes built JS (NOT TS). Build roles first, then run codegen.

`generated/*.as.d.ts`, `generated/*.as.js`, and `atscript.d.ts` are produced files. Don't
hand-edit; regenerate via `npx asc` or let the unplugin do it at bundle time.

## Subpath exports

| Package              | Subpath                  | What it ships                                                                                       |
| -------------------- | ------------------------ | --------------------------------------------------------------------------------------------------- |
| `@aooth/user`        | `.`                      | `UserService`, stores, password, MFA helpers, `UserAuthError`                                       |
| `@aooth/user`        | `./atscript-db`          | `UsersStoreAtscriptDb`, `AuthUserTable`, `UserCredentialsRow`                                       |
| `@aooth/user`        | `./atscript-db/model.as` | Raw `.as` file — the shipped `AoothUserCredentials` interface                                       |
| `@aooth/auth`        | `.`                      | `AuthCredential`, in-memory + JWT + encapsulated stores, denylists, errors                          |
| `@aooth/auth`        | `./redis`                | `CredentialStoreRedis`, `DenylistStoreRedis` + `RedisLike` interface                                |
| `@aooth/auth`        | `./atscript-db`          | `CredentialStoreAtscriptDb`, `AuthCredentialTable`, `AuthCredentialRow`                             |
| `@aooth/auth`        | `./atscript-db/model.as` | Raw `.as` file — the shipped `AoothAuthCredential` interface                                        |
| `@aooth/arbac-core`  | `.`                      | `Arbac`, types, `arbacPatternToRegex`                                                               |
| `@aooth/arbac`       | `.`                      | `* from arbac-core` + builder + privileges + scope mergers + codegen                                |
| `@aooth/arbac`       | `./bin`                  | `aoothjs-arbac-codegen` CLI (registered via `package.json` `"bin"`)                                 |
| `@aooth/auth-moost`  | `.`                      | Controllers, guards, decorators, composables, workflows, trigger provider                           |
| `@aooth/arbac-moost` | `.`                      | Interceptor, decorators, `useArbac`, `MoostArbac`, base `ArbacUserProvider`, DB controllers         |
| `@aooth/arbac-moost` | `./atscript`             | `AtscriptArbacUserProvider`, `ArbacUserTable`, re-export `AoothArbacUserCredentials`                |
| `@aooth/arbac-moost` | `./atscript/models`      | The `AoothArbacUserCredentials` `.as` interface (raw file export — also via `./atscript/models.as`) |
| `@aooth/arbac-moost` | `./plugin`               | `arbacPlugin()` for `atscript.config.ts` — registers `@arbac.role/.attribute/.userId`               |
