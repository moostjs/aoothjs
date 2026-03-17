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
- `packages/user-as` — `@aoothjs/user-as` — UsersStore backed by @atscript/db
- `packages/arbac-moost` — `@aoothjs/arbac-moost` — moost RBAC integration (from @moostjs/arbac)
- `packages/auth-moost` — `@aoothjs/auth-moost` — moost auth controllers, guards, composables
- `packages/atscript-plugin` — `@aoothjs/atscript-plugin` — `@aooth.*` annotations for .as models

## TypeScript

- `tsconfig.base.json`: shared config — `target: esnext`, `strict: true`, `moduleResolution: bundler`
- Path aliases: `"@aoothjs/*"` → `./packages/*/src`
- Node ≥ 22.12.0 required (`packageManager: pnpm@10.32.1`)

<!--VITE PLUS START-->

# Using Vite+, the Unified Toolchain for the Web

This project is using Vite+, a unified toolchain built on top of Vite, Rolldown, Vitest, tsdown, Oxlint, Oxfmt, and Vite Task. Vite+ wraps runtime management, package management, and frontend tooling in a single global CLI called `vp`. Vite+ is distinct from Vite, but it invokes Vite through `vp dev` and `vp build`.

## Vite+ Workflow

`vp` is a global binary that handles the full development lifecycle. Run `vp help` to print a list of commands and `vp <command> --help` for information about a specific command.

### Start

- create - Create a new project from a template
- migrate - Migrate an existing project to Vite+
- config - Configure hooks and agent integration
- staged - Run linters on staged files
- install (`i`) - Install dependencies
- env - Manage Node.js versions

### Develop

- dev - Run the development server
- check - Run format, lint, and TypeScript type checks
- lint - Lint code
- fmt - Format code
- test - Run tests

### Execute

- run - Run monorepo tasks
- exec - Execute a command from local `node_modules/.bin`
- dlx - Execute a package binary without installing it as a dependency
- cache - Manage the task cache

### Build

- build - Build for production
- pack - Build libraries
- preview - Preview production build

### Manage Dependencies

Vite+ automatically detects and wraps the underlying package manager such as pnpm, npm, or Yarn through the `packageManager` field in `package.json` or package manager-specific lockfiles.

- add - Add packages to dependencies
- remove (`rm`, `un`, `uninstall`) - Remove packages from dependencies
- update (`up`) - Update packages to latest versions
- dedupe - Deduplicate dependencies
- outdated - Check for outdated packages
- list (`ls`) - List installed packages
- why (`explain`) - Show why a package is installed
- info (`view`, `show`) - View package information from the registry
- link (`ln`) / unlink - Manage local package links
- pm - Forward a command to the package manager

### Maintain

- upgrade - Update `vp` itself to the latest version

These commands map to their corresponding tools. For example, `vp dev --port 3000` runs Vite's dev server and works the same as Vite. `vp test` runs JavaScript tests through the bundled Vitest. The version of all tools can be checked using `vp --version`. This is useful when researching documentation, features, and bugs.

## Common Pitfalls

- **Using the package manager directly:** Do not use pnpm, npm, or Yarn directly. Vite+ can handle all package manager operations.
- **Always use Vite commands to run tools:** Don't attempt to run `vp vitest` or `vp oxlint`. They do not exist. Use `vp test` and `vp lint` instead.
- **Running scripts:** Vite+ commands take precedence over `package.json` scripts. If there is a `test` script defined in `scripts` that conflicts with the built-in `vp test` command, run it using `vp run test`.
- **Do not install Vitest, Oxlint, Oxfmt, or tsdown directly:** Vite+ wraps these tools. They must not be installed directly. You cannot upgrade these tools by installing their latest versions. Always use Vite+ commands.
- **Use Vite+ wrappers for one-off binaries:** Use `vp dlx` instead of package-manager-specific `dlx`/`npx` commands.
- **Import JavaScript modules from `vite-plus`:** Instead of importing from `vite` or `vitest`, all modules should be imported from the project's `vite-plus` dependency. For example, `import { defineConfig } from 'vite-plus';` or `import { expect, test, vi } from 'vite-plus/test';`. You must not install `vitest` to import test utilities.
- **Type-Aware Linting:** There is no need to install `oxlint-tsgolint`, `vp lint --type-aware` works out of the box.

## Review Checklist for Agents

- [ ] Run `vp install` after pulling remote changes and before getting started.
- [ ] Run `vp check` and `vp test` to validate changes.
<!--VITE PLUS END-->
