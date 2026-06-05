# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**aoothjs** is a TypeScript authentication + authorization monorepo (pre-release, all packages on `0.0.1-alpha.*`) for the moost / atscript ecosystem. The `@aooth/*` packages cover the full auth stack: user credentials, RBAC engine + builder, sessions/tokens, MFA primitives, and Moost framework integration. An internal `e2e-demo` package exercises the full stack against a real SQLite-backed atscript DB.

## Commands

```bash
# Install / refresh after pulling
pnpm install                  # or `vp install`

# Build, test, type-check across the workspace
pnpm run build                # vp run build -r
pnpm run test                 # vp run test -r
vp check                      # format + lint + tsc on changed files

# Single package
cd packages/<pkg> && pnpm run test
cd packages/<pkg> && pnpm run check
cd packages/<pkg> && pnpm run dev          # vp pack --watch

# Single test file (vitest under vp)
cd packages/<pkg> && pnpm exec vp test src/<file>.spec.ts

# Pre-release quality gate (fmt + lint + test + build across workspace)
pnpm run ready                # vp fmt && vp lint && vp run test -r && vp run build -r

# Release (bumps version, runs ready, publishes, commits + tags)
pnpm run release              # patch — also :minor, :major

# e2e-demo (vite / vite-node, not vp)
cd packages/e2e-demo
pnpm run dev                  # vite — combined SPA + moost backend (mounted as middleware via @moostjs/vite)
DEMO_MODE=test SEED=true pnpm run dev   # boot for the Playwright harness (test endpoints + seeded users)
pnpm run test:e2e             # playwright test — needs `dev` already running on :3001 (see playwright.config.ts)
pnpm run db:init              # vite-node src/scripts/init-db.ts — seed the demo SQLite db
pnpm run gen:atscript         # asc — regenerate .as.d.ts from .as models
```

> `pnpm run dev:api` (`vite-node --watch src/main.ts`) is the legacy standalone backend and is currently broken under vite 8 + the `@moostjs/vite` plugin — both runtimes race to import `src/main.ts` and the synchronous `@atscript/db` schema fetch deadlocks the module-runner transport (~60s timeout). Use `pnpm run dev` for everything; it serves the same backend.

> **e2e blocked? Reinstall + dedupe FIRST.** If `pnpm run dev` boots but every request 500s — e.g. `/__test/reset` throws `Cannot read properties of undefined (reading 'authorization')`, or any wooks composable (`useAuthorization`, `useHeaders`, `useCookies`) reads `undefined` — the cause is almost always a **duplicated `@wooksjs/event-core` / `moost` copy**: the request context is created by one copy and read by another, so the slot ids don't match (the `globalKey` dual-package hazard). It typically shows up as a module resolving from a **sibling project's `node_modules`** (e.g. `/Users/.../<some-other-repo>/node_modules/...@wooksjs+event-http`) — confirm with `cd packages/<pkg> && node -e "console.log(require.resolve('@wooksjs/event-http'))"`; it should resolve under this repo's own `node_modules`. Fix before touching any code:
>
> ```bash
> pnpm install        # re-link the workspace (peer deps that walked up to a sibling repo get re-pinned)
> pnpm dedupe         # collapse duplicate @wooksjs / moost copies to one
> pnpm run build      # refresh dist (the demo runs @aooth/* from dist, not src)
> rm -rf packages/e2e-demo/node_modules/.vite   # drop a stale pre-bundle cache
> ```
>
> The same duplication makes `vp test` resolve native deps (e.g. `better-sqlite3`) from the wrong copy — another tell. Only after a clean install/dedupe should you suspect application code.

> **`vp check` shows `vite.config.ts` TS2321 "Excessive stack depth comparing types … and `UserConfig`" (+ a cascade TS2769)?** The root cause is in vite-plus, not this repo: vite-plus's `PackUserConfig` is a **self-referential augmentation** of its own `UserConfig` (`UserConfig → pack: PackUserConfig → … UserConfig`), and when cross-project linking leaves a **duplicate `vite-plus` virtual-store resolution** (often at the pnpm **peer-hash** level — `ls node_modules/.pnpm/vite-plus@*` can show a single `0.1.24` yet two `_<differentHash>` entries, so a version count won't reveal it, _and_ it can reappear after any `pnpm install`), tsc blows its 50-level instantiation-depth limit comparing the config literal against `UserConfig`. It trips only the `-moost` configs (their `pack.plugins`/`deps` make the literal deep enough), not simpler ones like `packages/auth`. Moost itself is **not** in the type chain — the package name is coincidental.
>
> **Fix (already applied to `packages/auth-moost` + `packages/arbac-moost`): cast the config —** `export default defineConfig(config as any)` with an `oxlint-disable-next-line typescript/no-explicit-any`. This is **resolution-independent**: it holds no matter how the store resolves, unlike a clean reinstall or a `pnpm.overrides` pin (both only fix it transiently — the very next `pnpm install` re-breaks them, _verified_). **Apply the same cast to any NEW package whose `vite.config.ts` sets `pack.plugins`.** (A clean `rm -rf node_modules && pnpm install` is still the remedy for the _runtime_ wooks/moost dual-package hazard above — just not for this type error.)
>
> Aside: a clean reinstall drops the hoisted real-`vite` bin the demo's `dev: "vite"` script relied on (the catalog aliases `vite` → `@voidzero-dev/vite-plus-core`, bin `vp`) — after one, boot the demo with **`pnpm exec vp dev`** instead of `pnpm run dev`.

> **`pnpm ready` (or `vp run --filter './packages/*' <task>`) crashes immediately with `TypeError: ... extname ... Received undefined` at `@atscript/core` `loadConfig` / `unplugin-atscript/dist/vite.mjs`?** The root **`atscript.config.mts`** is missing — keep it. `unplugin-atscript`'s vite plugin probes for an atscript config **eagerly** (walking up from `process.cwd()`) the moment `atscriptVite()` is constructed. When `vp` evaluates the per-package `vite.config.ts` files from the **workspace root** to build its task graph, `cwd` is the repo root, and with no config in the root's ancestry the plugin calls upstream `loadConfig(undefined)` → throws as an **unhandled rejection** → kills the whole `vp` process before any task runs (unplugin-atscript@0.1.69 / @atscript/core@0.1.69, both already latest — the probe has zero error handling). The root `atscript.config.mts` is a deliberate **no-op fallback** that makes the root-cwd probe resolve; it never compiles real `.as` (there are none at the root, and every package resolves its own nearer `packages/<pkg>/atscript.config.mts` first). The fix is **resolution-independent** — it holds whether `@atscript/*` resolves from this repo or gets hoisted into a sibling project's store (the dual-package condition above), since both copies carry the same upstream bug. Do NOT delete the root config to "clean up"; per-package `vp test`/`vp build` (run with `cwd=<pkg>`) won't reveal the breakage, only the workspace-root `vp run --filter` form does.

## Build / Tooling

Uses **vite-plus** (`vp`) as the build/test/lint orchestrator — wraps Vite, Rolldown, Vitest, tsdown, Oxlint, and Oxfmt. Per-package builds are `vp pack`; tests are `vp test`; `vp check` runs fmt + lint + type-check.

- Output per package: ESM + CJS + `.d.mts` declarations under `dist/`.
- Lint/format config lives in the **root** `vite.config.ts` (`lint:` block, oxlint rule categories) and applies to the whole workspace. Per-package `vite.config.ts` files exist only when a package needs build-specific options.
- Pre-commit hook (`staged:`) runs `vp check --fix` on changed files.
- Dependency versions are pinned via the pnpm **catalog** in `pnpm-workspace.yaml` — depend on `"catalog:"` rather than literal versions for any shared atscript / moost / wooks / vite-plus / typescript dep.

## Workspace Layout

pnpm monorepo (`pnpm-workspace.yaml` globs `packages/*`, `explorations/*/{frontend,backend}`, `docs`).

Published packages (all `@aooth/*`):

- `packages/user` — user credential primitives: `UserService` (orchestrator), `UserCredentials` (type), `PasswordHasher` + `PasswordPolicy` (+ `ppHas*` factories), `UserStore` abstract (+ `UserStoreMemory` for tests, `UsersStoreAtscriptDb` for `@atscript/db` via the `./atscript-db` subpath), `UserAuthError`, TOTP / backup-code / trusted-device helpers.
- `packages/arbac-core` — zero-dep RBAC engine (`Arbac` class, role/resource registration, pattern matching, evaluation).
- `packages/arbac` — batteries-included layer over `arbac-core`: `defineRole` builder, `definePrivilege`, DB-table privilege factories (`allowTableRead/Write/Action`), scope primitives (projection / filter / controls / with), codegen for resource-action types.
- `packages/arbac-moost` — Moost integration: `@Arbac` decorator, `useArbac` composable, plugin, `ArbacDbScope<T>` typed scope for atscript-db filter/projection/with, user provider, atscript annotations.
- `packages/auth` — framework-agnostic auth method layer: `AuthCredential` orchestrator, credential stores (memory, JWT, encapsulated), denylist store, email/SMS/magic-link primitives, atscript-db schema, errors.
- `packages/auth-moost` — Moost integration: `authGuardInterceptor`, `AuthGuarded`, `useAuth`, `@Public`, `@UserId`, `AuthController` with default REST + workflows (login, invite, password-reset, MFA), `WfTrigger` decorator + provider, audit hooks, atscript annotations.

Internal:

- `packages/e2e-demo` — `private: true`. Vite-node app that wires all the above against a real SQLite-backed `@atscript/db` schema. Source of truth for cross-package integration tests. Uses `.as` models compiled by `asc`; depends on every workspace package via `workspace:*`.

## Architecture

The stack is layered — each package depends only on the ones below it. Framework-agnostic cores stay portable; Moost integrations live in their own `-moost` packages.

```
        ┌──────────────────────── e2e-demo ────────────────────────┐
        │                                                          │
   auth-moost ──────────────── arbac-moost ─────── @moostjs/* + atscript
        │                          │
      auth                       arbac
        │                          │
      user                     arbac-core
        │
   @atscript/db (peer)
```

Cross-cutting patterns:

- **Pluggable storage everywhere.** `UserStore<T>` (user — note: abstract base is singular; the `@atscript/db` impl is `UsersStoreAtscriptDb` with the legacy plural prefix), `CredentialStore` / `DenylistStore` (auth), and the atscript-db adapters are all abstract; in-memory implementations ship for tests, real adapters live alongside.
- **`UserCredentials` is a TYPE, not a class.** The shape (`{ id, username, password, account, mfa, backupCodes?, trustedDevices? }`) lives in `packages/user/src/types.ts`. `UserService` reads/writes plain rows through the store; partial updates are expressed as `UserStoreUpdate { set, inc }` and applied by the store — there is no internal mutation-tracking class.
- **Transferable password policies.** `PasswordPolicy` rules are string expressions evaluated via `@prostojs/ftring`, so the same policy can validate client- and server-side. Function-form rules are also supported but lose transferability.
- **Generic user schema.** `UserService<T>`, `UserStore<T>`, `AuthCredential<TClaims>`, and the RBAC `TUserAttrs` generic all flow custom shapes through the stack — there is no fixed `User` type.
- **Injectable clock.** `UserServiceConfig.clock` and `AuthCredentialOptions.clock` are top-level fields for deterministic lockout / refresh-grace / TOTP tests.
- **Typed `ArbacDbScope<T>`** (arbac-moost): when an `.as` model is passed via `.as(Model)` on a `defineRole` builder, projection / `with` / controls / set keys autocomplete against the model's own fields and nav relations. The recursive `with` field expands to nested `ArbacDbScope` for joined resources (parent-authority model — no per-joined-resource re-eval).
- **Atscript annotations.** `arbac-moost/src/atscript/` and `auth-moost/src/atscript/` define `.as` annotations consumed by `unplugin-atscript` so `.as` models can declare auth/RBAC metadata that the framework reads at runtime.

## TypeScript

- `tsconfig.base.json`: `target: esnext`, `strict: true`, `module: preserve`, `moduleResolution: bundler`, `verbatimModuleSyntax: true`, `noUnusedLocals: true`, `emitDeclarationOnly: true`.
- Path aliases (root): `@aooth/*` → `./packages/*/src` with explicit overrides for sub-entry-points (`@aooth/user/atscript-db`, `@aooth/arbac-moost/atscript`, `@aooth/arbac-moost/plugin`, `@aooth/auth-moost/atscript`, and `arbac-core` → `./packages/arbac-core/src`). When adding a new sub-entry-point that consumers import, add it here too.
- Node ≥ 22.12.0, `packageManager: pnpm@10.32.1`.
- `pnpm.onlyBuiltDependencies` is restricted to `better-sqlite3`, `@atscript/db`, `@atscript/db-sqlite` — keep it tight when adding native-build deps.

<!--VITE PLUS START-->

# Using Vite+, the Unified Toolchain for the Web

This project is using Vite+, a unified toolchain built on top of Vite, Rolldown, Vitest, tsdown, Oxlint, Oxfmt, and Vite Task. Vite+ wraps runtime management, package management, and frontend tooling in a single global CLI called `vp`. Vite+ is distinct from Vite, and it invokes Vite through `vp dev` and `vp build`. Run `vp help` to print a list of commands and `vp <command> --help` for information about a specific command.

Docs are local at `node_modules/vite-plus/docs` or online at https://viteplus.dev/guide/.

## Review Checklist

- [ ] Run `vp install` after pulling remote changes and before getting started.
- [ ] Run `vp check` and `vp test` to format, lint, type check and test changes.
- [ ] Check if there are `vite.config.ts` tasks or `package.json` scripts necessary for validation, run via `vp run <script>`.
- [ ] If setup, runtime, or package-manager behavior looks wrong, run `vp env doctor` and include its output when asking for help.

<!--VITE PLUS END-->
