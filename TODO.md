# aoothjs — Auth & Access Control Monorepo

## Goal

Unified authentication + authorization solution for the moost/atscript ecosystem.
Password management, RBAC, sessions, tokens, DB-backed storage — all in `@aoothjs/*`.

## Packages

| Package                | Name                   | Purpose                                                                                                                                                                                                                                                                                                                     | Deps                                                                             |
| ---------------------- | ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `packages/user`        | `@aoothjs/user`        | User credential primitives: password hashing (salt+pepper), password history & expiry, password policies (string expressions + functions), MFA data model (email/SMS/TOTP), account lockout, `Changeable` base class for efficient partial updates. Abstract `UsersStore<T>` interface + in-memory impl for tests.          | node:crypto, @prostojs/ftring                                                    |
| `packages/arbac-core`  | `@aoothjs/arbac-core`  | Core RBAC engine (migrated from `@prostojs/arbac`). Role registration, resource/action evaluation with wildcard matching (`*`/`**`), deny-first rule processing, dynamic scopes via user attributes, lazy async attr resolution, pre-compiled rule caching. Generic over `<TUserAttrs, TScope>`.                            | zero deps                                                                        |
| `packages/arbac`       | `@aoothjs/arbac`       | Batteries-included RBAC package. Re-exports `@aoothjs/arbac-core`. Adds fluent `defineRole()` builder, composable `definePrivilege()` factories, scope merge utilities (projection union, filter merging — targeting @uniqu/core query abstractions used by atscript-db), resource/action codegen for type-safe decorators. | @aoothjs/arbac-core                                                              |
| `packages/auth`        | `@aoothjs/auth`        | Auth method layer (framework-agnostic). Session-based auth (pluggable session store), token-based auth (JWT/opaque, refresh rotation), password reset flow, MFA verification flow. Produces a common `AuthContext`.                                                                                                         | @aoothjs/user                                                                    |
| `packages/user-as`     | `@aoothjs/user-as`     | `UsersStore` implementation backed by `@atscript/db`. Exports a base `user.as` model that consumers import and extend with custom fields. Translates `Changeable` operations (set/unset/inc) to DB update operations.                                                                                                       | @aoothjs/user, @atscript/db (peer)                                               |
| `packages/arbac-moost` | `@aoothjs/arbac-moost` | Moost framework integration for RBAC (migrated from `@moostjs/arbac`). `MoostArbac` injectable class, `ArbacUserProvider` abstract, `useArbac()` composable, decorators (`@ArbacAuthorize`, `@ArbacPublic`, `@ArbacResource`, `@ArbacAction`, `@ArbacScopes`), authorize interceptor at GUARD priority.                     | @aoothjs/arbac-core, moost (peer)                                                |
| `packages/auth-moost`  | `@aoothjs/auth-moost`  | Moost framework integration for auth. Auth controller (login/logout/refresh/reset/MFA/register endpoints), `AuthGuard` interceptor (cookie sessions + bearer tokens), `useAuth()` composable, concrete `ArbacUserProvider` impl bridging auth context to RBAC.                                                              | @aoothjs/user, @aoothjs/auth, moost (peer), @aoothjs/arbac-moost (optional peer) |

**Future / revisit later:**

| Package                    | Name                       | Purpose                                                                                                                                                                                                                                                                                                                                                                                                    |
| -------------------------- | -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/arbac-as`        | `@aoothjs/arbac-as`        | Dynamic roles/policies storage in DB via @atscript/db. `.as` models for roles + policies, CRUD stores, hot-reload, serialization/deserialization of string-expression policies.                                                                                                                                                                                                                            |
| `packages/atscript-plugin` | `@aoothjs/atscript-plugin` | Atscript plugin registering the `@aooth.*` annotation namespace. Provides annotations for marking auth-relevant fields in `.as` models — e.g. `@aooth.role` (role source), `@aooth.attr` (scope attribute), `@aooth.username` (login identifier). Enables auto-extraction of roles/attrs from user data without manual `ArbacUserProvider` glue code. Design driven by real integration needs in Phase 6+. |

## Dependency Graph

```
@aoothjs/arbac-core      (zero deps)
@aoothjs/user            (node:crypto, @prostojs/ftring)
@aoothjs/arbac           → arbac-core (re-exports core + adds builder)
@aoothjs/auth            → user
@aoothjs/user-as         → user, @atscript/db (peer), atscript-plugin (optional peer)
@aoothjs/arbac-moost     → arbac-core, moost (peer)
@aoothjs/auth-moost      → user, auth, moost (peer), arbac-moost (optional peer)
```

```
       arbac-core (zero deps)              user (zero deps)
            │                               │
     ┌──────┴──────┐                ┌───────┼───────┐
     │             │                │       │       │
   arbac      arbac-moost         auth   user-as  (atscript-plugin)
     │             │                │
     │             └───────┬────────┘
     │                     │
     │                auth-moost
     │
  (arbac-as — future)
```

---

## Roadmap

### Phase 0 — Repo Cleanup & Foundation

> Get the existing code clean and the monorepo scaffolding solid.

- [x] **0.1** Verify monorepo setup: pnpm workspace, tsconfig.base.json, root vite.config.ts, release scripts
- [x] **0.2** Rename `packages/aooth` → `packages/user`, package name `@aoothjs/user`
  - Update all internal imports, tsconfig paths, workspace references
- [x] **0.3** Clean up `@aoothjs/user`
  - ~~Fix typos: `acitvateAccount` → `activateAccount`~~ — already fixed
  - ~~Remove `TAuthWorkflowState` / `TAuthWorkflow` / `TAuthInputMetadata` from types~~ — already removed
  - ~~Audit tests~~ — lockout (lock/unlock), MFA code generation, activation/deactivation all covered
- [x] **0.4** `pnpm run ready` — all green

---

### Phase 1 — Migrate arbac-core

> Move `@prostojs/arbac` into this monorepo as `@aoothjs/arbac-core`. Zero-dep RBAC engine.

- [ ] **1.1** Copy source from `../prostojs/arbac/src/` into `packages/arbac-core/src/`
  - `Arbac<TUserAttrs, TScope>` — evaluate(), registerRole(), registerResource()
  - `TArbacRole`, `TArbacRule` (allow/deny discriminated union), `TArbacEvalResult`
  - `arbacPatternToRegex()` — `*` (single segment) / `**` (multi segment) wildcard matching
- [ ] **1.2** Update package.json: name `@aoothjs/arbac-core`, repo URLs, exports (.mjs/.cjs/.d.mts)
- [ ] **1.3** Add `vite.config.ts` with vp pack block, adapt tests to `vite-plus/test`
- [ ] **1.4** All 6 existing tests pass, build output verified

---

### Phase 2 — arbac (builder + re-export core)

> `@aoothjs/arbac` = batteries-included RBAC. Re-exports arbac-core, adds builder API, scope utilities, codegen.

- [ ] **2.1** Create `packages/arbac/`, scaffold package.json + vite.config.ts
  - Depends on `@aoothjs/arbac-core`, re-exports everything from it

- [ ] **2.2** `defineRole<TUserAttrs, TScope>()` — fluent builder
  - `.id(string)` / `.name(string)` / `.describe(string)`
  - `.allow(resource, action, scope?)` / `.deny(resource, action)`
  - `.use(...privileges)` — compose privilege preset functions into the role
  - `.build()` → `TArbacRole<TUserAttrs, TScope>`
  - Generic enough for custom scopes — the `scope` parameter is a `(attrs: TUserAttrs) => TScope`

- [ ] **2.3** `definePrivilege<TUserAttrs, TScope>()` — reusable rule factory
  - Returns a function `(...args) => TArbacRule<TUserAttrs, TScope>[]`
  - Ship common presets: `canAccess(resource, action)`, `canCrud(resource, scope?)`
  - Consumers define domain-specific privileges, compose into roles via `.use()`

- [ ] **2.4** Scope merge utilities
  - `unionProjections(...projections)` — merge multiple projections (mongo-style `{field: 0|1}`,
    compatible with @uniqu/core's query abstraction used by atscript-db across all DB adapters)
  - `restrictProjection(desired, accessControl)` — intersect user-requested projection with
    access-control projection
  - `mergeScopeFilters(scopes)` — combine filters from multiple scopes via `$or` / `$in`
  - `isFieldAllowed(field, projection)` — check if a field passes a projection

- [ ] **2.5** Resource/action codegen
  - Script that scans role definitions, extracts literal resource/action strings,
    generates a TS file with union types for type-safe decorators
  - Provide as a standalone script or vp plugin

- [ ] **2.6** Tests — builder API, privilege composition, projection merging, filter merging
- [ ] **2.7** Build + verify

---

### Phase 3 — user-as (atscript/db user storage)

> `UsersStore` backed by `@atscript/db`. Exportable `.as` model for consumer extension.

- [ ] **3.1** Create `packages/user-as/`, scaffold

- [ ] **3.2** Define `user.as` — base atscript model mapping `TAoothUserCredentials`
  - All credential fields: id, username, password (nested), account (nested), mfa (nested)
  - **Exported** so consumers can:
    ```
    import { AoothUser } from "@aoothjs/user-as/models"
    // extend in their own .as file with custom fields
    ```
  - The extended model feeds the generic `T` in `Aooth<T>`

- [ ] **3.3** Implement `UsersStoreAs<T>` extending `UsersStore<T>`
  - Constructor takes an `@atscript/db` collection instance
  - `exists(username)` → collection query
  - `read(username)` → collection getOne
  - `create(data)` → collection insert
  - `change(username, changes)` → translate `TCumulativeChanges` { set/unset/inc on dotted paths }
    into `@atscript/db` update/patch operations

- [ ] **3.4** Tests (in-memory adapter or SQLite)
- [ ] **3.5** Build + verify

---

### Phase 4 — auth (sessions, tokens, auth methods)

> Framework-agnostic auth method layer. Design from scratch — proper session/token support first, expand later.

- [ ] **4.1** Create `packages/auth/`, scaffold

- [ ] **4.2** Design core abstractions
  - Common `AuthContext`: `{ userId, sessionId?, method: 'session' | 'token', expiresAt }`
  - Both session and token strategies produce `AuthContext`
  - Keep it minimal — don't over-abstract. Two concrete implementations, not a strategy pattern.

- [ ] **4.3** Session auth
  - `SessionStore` abstract: `create`, `read`, `refresh`, `revoke`, `revokeAllForUser`, `cleanup`
  - `SessionStoreMemory` for dev/testing
  - `AuthSession` class:
    - `login(userId, meta?) → { sessionId, expiresAt }`
    - `validate(sessionId) → AuthContext | null`
    - `logout(sessionId)`, `logoutAll(userId)`
    - Config: expiry, sliding window, max concurrent sessions

- [ ] **4.4** Token auth
  - `AuthToken` class:
    - `issue(userId, claims?) → { accessToken, refreshToken, expiresAt }`
    - `validate(accessToken) → AuthContext | null`
    - `refresh(refreshToken) → { accessToken, refreshToken, expiresAt }` (rotation)
    - `revoke(refreshToken)` — needs a minimal revocation store
    - Config: algorithm (HS256/RS256), access TTL, refresh TTL, issuer, audience

- [ ] **4.5** Password reset flow
  - `requestReset(username) → { resetToken, expiresAt }`
  - `validateReset(resetToken) → userId`
  - `executeReset(resetToken, newPassword, repeatPassword)`
  - Move `resetTokenExpiryHours` from `@aoothjs/user` config into this package

- [ ] **4.6** MFA verification flow
  - `initMfa(userId, method) → { challenge }` — code for email/sms, TOTP setup for totp
  - `verifyMfa(userId, method, code) → boolean`

- [ ] **4.7** Tests — session lifecycle, token issue/validate/refresh/revoke, reset flow, MFA
- [ ] **4.8** Build + verify

---

### Phase 5 — arbac-moost

> Move `@moostjs/arbac` into this monorepo as `@aoothjs/arbac-moost`.

- [ ] **5.1** Copy source from `../moostjs/packages/arbac/src/`
  - `MoostArbac` (Injectable, extends Arbac)
  - `ArbacUserProvider` abstract (getUserId, getRoles, getAttrs)
  - `useArbac()` composable (evaluate, getScopes, setScopes, resource, action, isPublic)
  - Decorators: `@ArbacAuthorize`, `@ArbacPublic`, `@ArbacResource`, `@ArbacAction`, `@ArbacScopes`
  - Authorize interceptor (GUARD priority, deny-first, stores scopes in context)

- [ ] **5.2** Update imports: `@prostojs/arbac` → `@aoothjs/arbac-core`
- [ ] **5.3** Update package.json: name, deps, peer deps (moost, @wooksjs/event-core, @wooksjs/event-http)
- [ ] **5.4** Fix typo: `arbackAuthorizeInterceptor` → `arbacAuthorizeInterceptor`
- [ ] **5.5** Optional: helper to bulk-register roles from `@aoothjs/arbac` builder definitions
- [ ] **5.6** Tests, build, verify

---

### Phase 6 — auth-moost

> Moost controllers + guards for the auth layer. Design properly — this is where session/token meets HTTP.

- [ ] **6.1** Create `packages/auth-moost/`, scaffold

- [ ] **6.2** `AuthGuard` interceptor
  - Runs at GUARD priority, before arbac guard
  - Extracts credentials from request:
    - Cookie → validates via `AuthSession`
    - `Authorization: Bearer <token>` → validates via `AuthToken`
  - Populates request context with `AuthContext`
  - `@Public()` decorator to bypass
  - Two-phase auth: AuthGuard (who are you?) → ArbacAuthorize (are you allowed?)

- [ ] **6.3** `useAuth()` composable
  - `getCurrentUser()`, `getCurrentUserId()`, `isAuthenticated()`
  - Access `AuthContext` from request context

- [ ] **6.4** Auth controller — standard endpoints
  - `POST /auth/login` — username + password → session or token
  - `POST /auth/logout` — revoke
  - `POST /auth/refresh` — refresh session/token
  - `POST /auth/password/reset-request` — initiate reset
  - `POST /auth/password/reset` — execute reset
  - `POST /auth/mfa/verify` — MFA challenge
  - `POST /auth/register` — optional self-registration
  - Configurable: which endpoints enabled, route prefix, auth method

- [ ] **6.5** Concrete `ArbacUserProvider` bridging auth context → RBAC
  - `getUserId()` → from `AuthContext`
  - `getRoles(id)` → from user data
  - `getAttrs(id)` → from user data

- [ ] **6.6** Tests, build, verify

---

### Phase 7 — atscript-plugin (design driven by Phase 6 learnings)

> Atscript plugin for `@aooth.*` annotations. Scope determined by real pain points from Phase 6.

- [ ] **7.1** Create `packages/atscript-plugin/`, scaffold

- [ ] **7.2** Register `@aooth.*` annotation namespace, implement annotations:
  - `@aooth.role` — marks a field as the role source (e.g. `roles: string[]`)
  - `@aooth.attr` — marks a field as a scope attribute for RBAC evaluation
  - `@aooth.username` — marks the login identifier field (default: `username`)
  - `@aooth.password` — marks the password sub-object (default: `password`)
  - (Use `@meta.sensitive` from atscript for sensitive fields — no need to duplicate)

- [ ] **7.3** Runtime introspection helpers:
  - `getRoles(model, userData)` — auto-extract roles from fields marked `@aooth.role`
  - `getAttrs(model, userData)` — auto-collect fields marked `@aooth.attr` into `TUserAttrs` object
  - `getAttrProjection(model)` — generate minimal DB projection for auth-relevant fields
  - These power an auto-generated `ArbacUserProvider` — zero manual glue code

- [ ] **7.4** Integration with `@aoothjs/user-as` — model-aware user store
- [ ] **7.5** Tests, build, verify

---

### Phase 8 — Deprecation & Migration

- [ ] **8.1** Publish final `@prostojs/arbac` with deprecation → `@aoothjs/arbac-core`
- [ ] **8.2** Publish final `@moostjs/arbac` with deprecation → `@aoothjs/arbac-moost`
- [ ] **8.3** Migration guide

---

### Phase 9 — Documentation

- [ ] **9.1** VitePress docs site
- [ ] **9.2** Guides: getting started, password policies, MFA, RBAC, builders, DB integration, moost integration
- [ ] **9.3** API reference per package
- [ ] **9.4** Example app: moost + full auth+authz stack end-to-end

---

## Phase Ordering

```
Phase 0 (cleanup + rename aooth → user)
  │
  ├──→ Phase 1 (arbac-core) ──→ Phase 2 (arbac) ──→ Phase 5 (arbac-moost) ──┐
  │                                                                           │
  ├──→ Phase 3 (user-as)                                                      │
  │                                                                           │
  └──→ Phase 4 (auth) ──────────────────────────────────→ Phase 6 (auth-moost)
                                                                  │
                                                          Phase 7 (atscript-plugin)
                                                                  │
                                                          Phase 8 (deprecation)
                                                                  │
                                                          Phase 9 (docs)
```

**Critical path:** 0 → 1 → 2 → 5 → 6 (working moost app with full auth + authz)

**Parallel tracks after Phase 0:**

- Phase 1 (arbac-core) — no deps on other new packages
- Phase 3 (user-as) — only needs `@aoothjs/user` which already exists
- Phase 4 (auth) — only needs `@aoothjs/user` which already exists

Phase 6 (auth-moost) is the convergence point — needs Phase 4 + Phase 5 done.
Phase 7 (atscript-plugin) follows Phase 6 — design driven by real integration pain points.
