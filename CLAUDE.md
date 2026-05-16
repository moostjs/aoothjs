# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**aoothjs** is a TypeScript authentication + authorization monorepo (pre-release) for the moost/atscript ecosystem. The `@aoothjs/*` packages cover the full auth stack: user credentials, RBAC, sessions/tokens, DB-backed storage, and framework integration. See `TODO.md` for the full roadmap.

## Commands

```bash
# Install dependencies
pnpm install

# Build all packages
pnpm run build              # vp run build -r

# Run all tests
pnpm run test               # vp run test -r

# Run a single package's tests
cd packages/<pkg> && pnpm run test

# Run a specific test file
cd packages/<pkg> && pnpm exec vp test src/password.spec.ts

# Type checking
cd packages/<pkg> && pnpm run check   # vp check

# Format + lint + test + build (pre-release quality gate)
pnpm run ready

# Watch mode (dev)
cd packages/<pkg> && pnpm run dev

# Release (bumps version, runs ready, publishes, commits + tags)
pnpm run release             # patch
pnpm run release:minor
pnpm run release:major
```

## Build System

Uses **vite-plus** (`vp`) as the build/test/lint orchestrator. The `vp` CLI wraps Vite, Vitest, and Biome into a single toolchain. Config lives in `vite.config.ts` files (root for linting rules, per-package for build options).

- Output: ESM (`dist/index.mjs`) + CJS (`dist/index.cjs`) + declarations (`dist/index.d.mts`)
- Linter: Biome (configured in root `vite.config.ts` under `lint:` key)
- Formatter: via `vp fmt`
- Pre-commit hook: `vp check --fix` on staged files (configured in root `vite.config.ts` under `stagedHooks:`)

## Architecture (packages/user — `@aoothjs/user`)

```
Aooth (main orchestrator — configures password, lockout, MFA)
├── UserCredentials (per-user account: create/read/save, login flow, MFA)
│   ├── extends Changeable (tracks field mutations as set/unset/inc operations)
│   └── uses UsersStore (abstract storage — dependency-injected)
├── Password (hashing with salt+pepper, history, policy validation, generation)
│   ├── extends Changeable
│   └── uses PasswordPolicy (rule engine — string expressions via @prostojs/ftring or functions)
└── crypto utilities (hash, generateSalt, HMAC, TOTP secret key generation)

UsersStore (abstract) → UsersStoreMemory (in-memory implementation for tests)
base-x/ (base32, base64url encoders used by TOTP key generation)
utils/get-set.ts (deep object get/set helpers for Changeable change tracking)
```

Key design patterns:

- **Changeable base class**: `UserCredentials` and `Password` extend `Changeable` which records all mutations as `{ op, path, value }` operations, enabling efficient partial updates to any backing store.
- **Pluggable storage**: `UsersStore<T>` is abstract. Consumers implement `exists()`, `read()`, `change()`, `create()` for their database. `UsersStoreMemory` ships for testing.
- **Transferable password policies**: Policies defined as string expressions (not functions) can be serialized and sent to clients for pre-validation.
- **Generic user schema**: `Aooth<T>` and related classes accept a generic `T` extending the base credential type, allowing custom user fields.

## Workspace Layout

pnpm monorepo (`pnpm-workspace.yaml`).

Current packages:

- `packages/user` — `@aoothjs/user` — core user credential library

Planned packages (see `TODO.md` for full roadmap):

- `packages/arbac-core` — `@aoothjs/arbac-core` — zero-dep RBAC engine (from @prostojs/arbac)
- `packages/arbac` — `@aoothjs/arbac` — re-exports arbac-core + builder API, privilege factories, scope merge
- `packages/auth` — `@aoothjs/auth` — sessions, tokens, password reset, MFA flows
- `packages/arbac-moost` — `@aoothjs/arbac-moost` — moost RBAC integration (from @moostjs/arbac)
- `packages/auth-moost` — `@aoothjs/auth-moost` — moost auth controllers, guards, composables
- `packages/atscript-plugin` — `@aoothjs/atscript-plugin` — `@aooth.*` annotations for .as models

## TypeScript

- `tsconfig.base.json`: shared config — `target: esnext`, `strict: true`, `moduleResolution: bundler`
- Path aliases: `"@aoothjs/*"` → `./packages/*/src`
- Node ≥ 22.12.0 required (`packageManager: pnpm@10.32.1`)

<!--VITE PLUS START-->

# Using Vite+, the Unified Toolchain for the Web

This project is using Vite+, a unified toolchain built on top of Vite, Rolldown, Vitest, tsdown, Oxlint, Oxfmt, and Vite Task. Vite+ wraps runtime management, package management, and frontend tooling in a single global CLI called `vp`. Vite+ is distinct from Vite, and it invokes Vite through `vp dev` and `vp build`. Run `vp help` to print a list of commands and `vp <command> --help` for information about a specific command.

Docs are local at `node_modules/vite-plus/docs` or online at https://viteplus.dev/guide/.

## Review Checklist

- [ ] Run `vp install` after pulling remote changes and before getting started.
- [ ] Run `vp check` and `vp test` to format, lint, type check and test changes.
- [ ] Check if there are `vite.config.ts` tasks or `package.json` scripts necessary for validation, run via `vp run <script>`.

<!--VITE PLUS END-->
