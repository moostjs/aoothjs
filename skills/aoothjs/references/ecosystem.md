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

| Package                | Owns                                                                                                                                                                                                                                                | Does NOT own                                                                                                              |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `@aoothjs/user`        | `UserService` orchestrator, scrypt `PasswordHasher`, `PasswordPolicy` engine + 6 transferable factories, TOTP/HOTP, backup-code generation/hashing, trusted-device HMAC, lockout, `UserStore` abstract + `UserStoreMemory` + `UsersStoreAtscriptDb` | Email/SMS delivery, JWT/session issuance, role storage, MFA challenge state machine                                       |
| `@aoothjs/arbac-core`  | Zero-dep `Arbac` evaluator with deny-wins, wildcard patterns (`*` / `**`), per-resource role pre-compile, lazy user-attrs resolve, `arbacPatternToRegex` utility                                                                                    | Role storage, builder API, scope-merge helpers, framework integration                                                     |
| `@aoothjs/arbac`       | Builder API (`defineRole`), privilege factories (`definePrivilege`, `allowTableRead/Write/Action`), scope mergers (`mergeScopeFilters`, `unionProjections`, `restrictProjection`, `unionControlsPolicy`), codegen lib + CLI                         | The evaluator (re-exports from `arbac-core`), persistence                                                                 |
| `@aoothjs/auth`        | `AuthCredential` issue/validate/refresh/revoke, 5 store impls (`Memory`/`Jwt`/`Encapsulated`/`Redis`/`AtscriptDb`), `DenylistStore` + impls, `generateMagicLinkToken`, transport contracts (`EmailSender`, `SmsSender`), `AuthError`                | Password hashing (delegates to `@aoothjs/user`), MFA verify, workflow orchestration                                       |
| `@aoothjs/auth-moost`  | `AuthController` (`/auth/{logout,refresh,status,trigger}`), `authGuardInterceptor`, `@Public` (dual auth+arbac), `@UserId`, `useAuth`, three workflows (`LoginWorkflow`, `RecoveryWorkflow`, `InviteWorkflow`), `WfTriggerProvider`                 | Email/SMS delivery (consumer ships `EmailSender`/`SmsSender`), authorization (handled by `arbac-moost`)                   |
| `@aoothjs/arbac-moost` | `arbacAuthorizeInterceptor` (GUARD), `useArbac`, `@ArbacResource`/`@ArbacAction`/`@ArbacAuthorize`, `MoostArbac` (DI-injectable), `ArbacUserProvider` abstract, `AsArbacDbController` + `AsArbacDbReadableController`, atscript provider            | Authentication (pair with `authGuardInterceptor`), role/privilege storage, `.as` syntax (only the `@arbac.*` plugin spec) |

## Dependency graph

```
                @aoothjs/arbac-core
                       ▲
                       │ re-export *
                       │
                @aoothjs/arbac ──────────────────┐
                       ▲                          │
                       │                          │
@aoothjs/user          │       @aoothjs/auth      │
   │                   │           │              │
   │ (workspace dep)   │           │              │
   ├───────────────────┼───────────┘              │
   │                   │                          │
   ▼                   ▼                          ▼
@aoothjs/auth ◄─── @aoothjs/auth-moost ◄─── @aoothjs/arbac-moost
                              │                   │
                              ▼                   ▼
                            moost            moost (+ /atscript subpath
                            @moostjs/event-http   needs @atscript/typescript)
                            @moostjs/event-wf
                            @atscript/moost-wf
```

Notable edges:

- `@aoothjs/arbac` has exactly **one** runtime dep: `@aoothjs/arbac-core`. No moost, no atscript.
- `@aoothjs/arbac-core` has **zero** runtime deps. Drop-in for non-moost stacks.
- `@aoothjs/user` and `@aoothjs/auth` only **optionally** peer-depend on `@atscript/db ≥ 0.1.79` — the subpath `./atscript-db` is gated.
- `@aoothjs/auth-moost` and `@aoothjs/arbac-moost` both depend on `moost`, but neither depends on the other directly. They cooperate through the dual-purpose `@Public()` (which writes both `authPublic` and `arbacPublic` mate flags).

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

| Package                | peerDep                | Range             | Optional?                                                          |
| ---------------------- | ---------------------- | ----------------- | ------------------------------------------------------------------ |
| `@aoothjs/user`        | `@atscript/db`         | `≥ 0.1.79`        | yes (only for `./atscript-db` subpath)                             |
| `@aoothjs/auth`        | `@atscript/db`         | `≥ 0.1.79`        | yes (only for `./atscript-db` subpath)                             |
| `@aoothjs/auth`        | `jose` (regular dep)   | `^6.2.3`          | n/a — bundled as a regular dependency, not a peer (auto-installed) |
| `@aoothjs/auth-moost`  | `moost`                | matches workspace | no                                                                 |
| `@aoothjs/auth-moost`  | `@moostjs/event-http`  | matches workspace | no                                                                 |
| `@aoothjs/auth-moost`  | `@moostjs/event-wf`    | matches workspace | no                                                                 |
| `@aoothjs/auth-moost`  | `@atscript/moost-wf`   | matches workspace | no (`formInputInterceptor`, `AsWfStore`)                           |
| `@aoothjs/arbac-moost` | `moost`                | matches workspace | no                                                                 |
| `@aoothjs/arbac-moost` | `@atscript/moost-db`   | matches workspace | yes (only for `AsArbacDbController` subclass)                      |
| `@aoothjs/arbac-moost` | `@atscript/typescript` | matches workspace | yes (only for `./atscript` subpath)                                |

## Build-step requirements

`.as` files require a build step before runtime can `import` from them:

1. **`unplugin-atscript`** in `vite.config.ts` / `rollup.config.js` / `tsdown.config.ts` — typical dev path. Transforms `.as` → `.as.ts` on demand.
2. **`asc -f dts`** as a pre-build script — emits `.as.d.ts` + `.as.js` and an aggregate `atscript.d.ts`. Required when:
   - The build pipeline cannot run the unplugin (e.g. pure tsc, esbuild without plugins).
   - `@aoothjs/arbac-moost/atscript` is in use — the atscript provider reads runtime metadata that `asc` emits.
3. **Codegen** — `aoothjs-arbac-codegen --roles dist/roles.mjs --output src/generated/arbac-types.ts` consumes built JS (NOT TS). Build roles first, then run codegen.

`generated/*.as.d.ts`, `generated/*.as.js`, and `atscript.d.ts` are produced files. Don't
hand-edit; regenerate via `npx asc` or let the unplugin do it at bundle time.

## Subpath exports

| Package                | Subpath                  | What it ships                                                                                       |
| ---------------------- | ------------------------ | --------------------------------------------------------------------------------------------------- |
| `@aoothjs/user`        | `.`                      | `UserService`, stores, password, MFA helpers, `UserAuthError`                                       |
| `@aoothjs/user`        | `./atscript-db`          | `UsersStoreAtscriptDb`, `AuthUserTable`, `UserCredentialsRow`                                       |
| `@aoothjs/user`        | `./atscript-db/model.as` | Raw `.as` file — the shipped `AoothUserCredentials` interface                                       |
| `@aoothjs/auth`        | `.`                      | `AuthCredential`, in-memory + JWT + encapsulated stores, denylists, errors                          |
| `@aoothjs/auth`        | `./redis`                | `CredentialStoreRedis`, `DenylistStoreRedis` + `RedisLike` interface                                |
| `@aoothjs/auth`        | `./atscript-db`          | `CredentialStoreAtscriptDb`, `AuthCredentialTable`, `AuthCredentialRow`                             |
| `@aoothjs/auth`        | `./atscript-db/model.as` | Raw `.as` file — the shipped `AoothAuthCredential` interface                                        |
| `@aoothjs/arbac-core`  | `.`                      | `Arbac`, types, `arbacPatternToRegex`                                                               |
| `@aoothjs/arbac`       | `.`                      | `* from arbac-core` + builder + privileges + scope mergers + codegen                                |
| `@aoothjs/arbac`       | `./bin`                  | `aoothjs-arbac-codegen` CLI (registered via `package.json` `"bin"`)                                 |
| `@aoothjs/auth-moost`  | `.`                      | Controllers, guards, decorators, composables, workflows, trigger provider                           |
| `@aoothjs/arbac-moost` | `.`                      | Interceptor, decorators, `useArbac`, `MoostArbac`, base `ArbacUserProvider`, DB controllers         |
| `@aoothjs/arbac-moost` | `./atscript`             | `AtscriptArbacUserProvider`, `ArbacUserTable`, re-export `AoothArbacUserCredentials`                |
| `@aoothjs/arbac-moost` | `./atscript/models`      | The `AoothArbacUserCredentials` `.as` interface (raw file export — also via `./atscript/models.as`) |
| `@aoothjs/arbac-moost` | `./plugin`               | `arbacPlugin()` for `atscript.config.ts` — registers `@arbac.role/.attribute/.userId`               |
