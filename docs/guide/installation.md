# Installation

`aoothjs` is shipped as six independent packages — install only the ones you need. This page maps common use cases to package sets and lists the peer-dependencies for each.

## Decision table

| Use case                                                                  | aoothjs packages                                                         | Required peer deps                                                                  |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------- |
| Hash passwords / manage credentials, no HTTP                              | `@aoothjs/user`                                                          | —                                                                                   |
| Above + issue/validate JWT tokens, no HTTP                                | `@aoothjs/user`, `@aoothjs/auth`                                         | — (`jose` is a regular dep of `@aoothjs/auth`, auto-installed)                      |
| Full HTTP auth stack on moost (sessions, login/recovery/invite workflows) | `@aoothjs/user`, `@aoothjs/auth`, `@aoothjs/auth-moost`                  | `moost`, `@moostjs/event-http`, `@moostjs/event-wf`, `@atscript/moost-wf`           |
| RBAC only — no auth, no HTTP                                              | `@aoothjs/arbac` (re-exports `arbac-core`)                               | —                                                                                   |
| RBAC + moost integration                                                  | `@aoothjs/arbac`, `@aoothjs/arbac-moost`                                 | `moost`                                                                             |
| atscript-first user model + auto-derived ARBAC                            | above + `@aoothjs/arbac-moost/atscript`                                  | `@atscript/db`, `@atscript/typescript`, `unplugin-atscript`                         |
| Persist users + tokens + workflow state in a database                     | add `@aoothjs/user/atscript-db` and `@aoothjs/auth/atscript-db` subpaths | `@atscript/db` and one driver (`@atscript/db-sqlite`, `@atscript/db-postgres`, ...) |
| Persist tokens in Redis                                                   | use `@aoothjs/auth/redis` subpath                                        | a `RedisLike` client (`ioredis`, `redis`, ...)                                      |

## Recommended starting point

A full moost HTTP app with `.as`-modelled users, sqlite-backed credentials/tokens, JWT issuance, and RBAC:

```bash
# Runtime
pnpm add @aoothjs/user @aoothjs/auth @aoothjs/auth-moost \
         @aoothjs/arbac @aoothjs/arbac-moost \
         moost @moostjs/event-http @moostjs/event-wf \
         @atscript/db @atscript/db-sqlite @atscript/moost-wf \
         better-sqlite3

# Atscript codegen toolchain
pnpm add -D @atscript/core @atscript/typescript unplugin-atscript
```

This is the dependency set used by [`packages/e2e-demo`](https://github.com/moostjs/aoothjs/blob/main/packages/e2e-demo/package.json) and is what the [Quick Start](./quick-start) builds.

## Per-package peer dependencies

The list below names the `peerDependencies` each package declares (versions resolve from your `package.json`). Anything labelled `optional` is only required when you use the matching subpath.

### `@aoothjs/user`

| Peer                   | Required when                                |
| ---------------------- | -------------------------------------------- |
| `@atscript/db ^0.1.79` | optional — using `@aoothjs/user/atscript-db` |

### `@aoothjs/auth`

| Peer                   | Required when                                |
| ---------------------- | -------------------------------------------- |
| `@atscript/db ^0.1.79` | optional — using `@aoothjs/auth/atscript-db` |

`jose ^6.2.3` is shipped as a regular dependency (not a peer) since `CredentialStoreJwt` always uses it — no manual install required.

### `@aoothjs/arbac-core`

Zero dependencies. Pure TypeScript.

### `@aoothjs/arbac`

Single dependency — `@aoothjs/arbac-core`. Re-exports everything from it; no additional peers.

### `@aoothjs/auth-moost`

| Peer                  | Required when                                                                  |
| --------------------- | ------------------------------------------------------------------------------ |
| `moost`               | always                                                                         |
| `@moostjs/event-http` | always                                                                         |
| `@moostjs/event-wf`   | always — workflows are mandatory for the bundled `AuthController`              |
| `@atscript/moost-wf`  | always — provides `formInputInterceptor`, `AsWfStore`, the form-input plumbing |
| `@aoothjs/auth`       | always                                                                         |
| `@aoothjs/user`       | always                                                                         |

### `@aoothjs/arbac-moost`

| Peer                   | Required when                                                          |
| ---------------------- | ---------------------------------------------------------------------- |
| `moost`                | always                                                                 |
| `@aoothjs/arbac-core`  | always                                                                 |
| `@atscript/moost-db`   | optional — using `AsArbacDbController` / `AsArbacDbReadableController` |
| `@atscript/typescript` | optional — using the `/atscript` subpath (`AtscriptArbacUserProvider`) |

::: warning Subpath compile-time deps
`@aoothjs/arbac-moost/plugin` is **compile-time only** — it goes in `atscript.config.ts` so the `@arbac.*` annotations type-check. It contributes no runtime code.
:::

## Atscript codegen

Whenever any `.as` model is used (including the bundled `AoothUserCredentials`, `AoothArbacUserCredentials`, `AoothAuthCredential`), the atscript compiler must run before your app boots. Two options:

::: code-group

```ts [vite via unplugin-atscript]
// vite.config.ts
import { defineConfig } from "vite";
import atscript from "unplugin-atscript/vite";

export default defineConfig({
  plugins: [atscript({ format: "dts" })],
});
```

```bash [explicit CLI]
pnpm exec asc -f dts
```

:::

Both call the same compiler. The CLI form is what [`e2e-demo`](https://github.com/moostjs/aoothjs/blob/main/packages/e2e-demo/package.json) uses (`"gen:atscript": "asc -f dts"`). With `unplugin-atscript` in your bundler, codegen runs automatically on every dev rebuild.

You will also need an `atscript.config.mts` at the project root that registers the plugins for whichever annotations you use:

```ts:line-numbers
import arbacPlugin from '@aoothjs/arbac-moost/plugin'
import { defineConfig } from '@atscript/core'
import dbPlugin from '@atscript/db/plugin'
import wfPlugin from '@atscript/moost-wf/plugin'
import ts from '@atscript/typescript'

export default defineConfig({
  rootDir: 'src',
  plugins: [ts(), dbPlugin(), wfPlugin(), arbacPlugin()],
  format: 'dts',
  unknownAnnotation: 'warn',
})
```

## Storage backends

### atscript-db (recommended for typed apps)

```bash
pnpm add @atscript/db @atscript/db-sqlite       # or db-postgres / db-mysql / db-mongo
```

Use the subpath imports:

```ts
import { UsersStoreAtscriptDb } from "@aoothjs/user/atscript-db";
import { CredentialStoreAtscriptDb } from "@aoothjs/auth/atscript-db";
import { AoothAuthCredential } from "@aoothjs/auth/atscript-db/model.as";
```

### Redis (for tokens / denylist only)

```bash
pnpm add ioredis            # or redis@^4
```

Use the subpath import:

```ts
import { CredentialStoreRedis, DenylistStoreRedis } from "@aoothjs/auth/redis";
```

The package declares a structural `RedisLike` interface (8 methods used) — any client that matches the shape works.

### Memory (testing only)

Ships in the main entry points — no extra install:

```ts
import { UserStoreMemory } from "@aoothjs/user";
import { CredentialStoreMemory, DenylistStoreMemory } from "@aoothjs/auth";
```

::: warning Memory stores in production
`UserStoreMemory` and `CredentialStoreMemory` are for unit tests. Restarting the process drops every credential, and a `CredentialStoreJwt`'s in-memory `epochs` map silently breaks per-user revocation across instances. Use atscript-db or Redis in production.
:::

## Node version

`aoothjs` requires Node `>= 22.12.0` (LTS). The monorepo pins `pnpm@10.32.1` as the package manager; lower pnpm versions will still install, but `pnpm-workspace.yaml` catalog references require pnpm 10.

## Next steps

- [Quick Start](./quick-start) — wire a full moost app step by step.
- [Ecosystem & Packages](./ecosystem) — see the dependency graph and per-package responsibilities.
- [Using atscript-db Models](./atscript-db) — extend the shipped `.as` models.
