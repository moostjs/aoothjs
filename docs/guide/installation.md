# Installation

`aoothjs` is shipped as eight independent packages — install only the ones you need. This page maps common use cases to package sets and lists the peer-dependencies for each.

## Decision table

| Use case                                                                  | aoothjs packages                                                     | Required peer deps                                                                        |
| ------------------------------------------------------------------------- | -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Hash passwords / manage credentials, no HTTP                              | `@aooth/user`                                                        | —                                                                                         |
| Above + issue/validate JWT tokens, no HTTP                                | `@aooth/user`, `@aooth/auth`                                         | — (`jose` is a regular dep of `@aooth/auth`, auto-installed)                              |
| Full HTTP auth stack on moost (sessions, login/recovery/invite workflows) | `@aooth/user`, `@aooth/auth`, `@aooth/auth-moost`                    | `moost`, `@moostjs/event-http`, `@moostjs/event-wf`, `@atscript/moost-wf`                 |
| Above + "Sign in with Google / OIDC" federated login                      | + `@aooth/idp` (on the moost stack)                                  | — (no new peers; `jose` ships with `@aooth/auth`; HTTP wiring via `@aooth/auth-moost`)    |
| RBAC only — no auth, no HTTP                                              | `@aooth/arbac` (re-exports `arbac-core`)                             | —                                                                                         |
| RBAC + moost integration                                                  | `@aooth/arbac`, `@aooth/arbac-moost`                                 | `moost`                                                                                   |
| atscript-first user model + auto-derived ARBAC                            | above + `@aooth/arbac-moost/atscript`                                | `@atscript/db`, `@atscript/typescript`, `unplugin-atscript`                               |
| Persist users + tokens + workflow state in a database                     | add `@aooth/user/atscript-db` and `@aooth/auth/atscript-db` subpaths | `@atscript/db` and one driver (`@atscript/db-sqlite`, `@atscript/db-postgres`, ...)       |
| Persist tokens in Redis                                                   | use `@aooth/auth/redis` subpath                                      | a `RedisLike` client (`ioredis`, `redis`, ...)                                            |
| CLI tool that logs in against an aoothjs authorization server             | `@aooth/login-client` (client side only — zero deps)                 | — (Node built-ins + global `fetch`; server side is `@aooth/auth-moost`'s authorize stack) |

## Recommended starting point

A full moost HTTP app with `.as`-modelled users, sqlite-backed credentials/tokens, JWT issuance, and RBAC:

```bash
# Runtime
pnpm add @aooth/user @aooth/auth @aooth/auth-moost \
         @aooth/arbac @aooth/arbac-moost \
         moost @moostjs/event-http @moostjs/event-wf \
         @atscript/db @atscript/db-sqlite @atscript/moost-wf \
         better-sqlite3

# Atscript codegen toolchain
pnpm add -D @atscript/core @atscript/typescript unplugin-atscript
```

This is the dependency set used by [`packages/e2e-demo`](https://github.com/moostjs/aoothjs/blob/main/packages/e2e-demo/package.json) and is what the [Quick Start](./quick-start) builds.

Federated login is opt-in — add `@aooth/idp` for OAuth2/OIDC "Sign in with Google". It has no new peer deps and mounts through `@aooth/auth-moost` (`OAuthController` + the federated leg of the `auth/login/flow` workflow):

```bash
pnpm add @aooth/idp
```

## Per-package peer dependencies

The list below names the `peerDependencies` each package declares (versions resolve from your `package.json`). Anything labelled `optional` is only required when you use the matching subpath.

### `@aooth/user`

| Peer                   | Required when                              |
| ---------------------- | ------------------------------------------ |
| `@atscript/db ^0.1.79` | optional — using `@aooth/user/atscript-db` |

### `@aooth/auth`

| Peer                   | Required when                              |
| ---------------------- | ------------------------------------------ |
| `@atscript/db ^0.1.79` | optional — using `@aooth/auth/atscript-db` |

`jose ^6.2.3` is shipped as a regular dependency (not a peer) since `CredentialStoreJwt` always uses it — no manual install required.

### `@aooth/idp`

| Peer          | Required when |
| ------------- | ------------- |
| `@aooth/user` | always        |
| `@aooth/auth` | always        |

The framework-agnostic OAuth2/OIDC federated-login core (provider clients, ID-token verification, PKCE/state, `FederatedLoginService.resolveUser`). `jose ^6.2.3` ships as a regular dependency (shared with `@aooth/auth`) — no manual install. It has no HTTP transport of its own: mount it through `@aooth/auth-moost` (`OAuthController` + the federated leg of the `auth/login/flow` workflow). The `(provider, subject) → userId` link store is `FederatedIdentityStoreAtscriptDb` from `@aooth/user/atscript-db`.

### `@aooth/arbac-core`

Zero dependencies. Pure TypeScript.

### `@aooth/arbac`

Single dependency — `@aooth/arbac-core`. Re-exports everything from it; no additional peers.

### `@aooth/auth-moost`

| Peer                  | Required when                                                                  |
| --------------------- | ------------------------------------------------------------------------------ |
| `moost`               | always                                                                         |
| `@moostjs/event-http` | always                                                                         |
| `@moostjs/event-wf`   | always — workflows are mandatory for the bundled `AuthController`              |
| `@atscript/moost-wf`  | always — provides `formInputInterceptor`, `AsWfStore`, the form-input plumbing |
| `@aooth/auth`         | always                                                                         |
| `@aooth/user`         | always                                                                         |

### `@aooth/arbac-moost`

| Peer                   | Required when                                                          |
| ---------------------- | ---------------------------------------------------------------------- |
| `moost`                | always                                                                 |
| `@aooth/arbac-core`    | always                                                                 |
| `@atscript/moost-db`   | optional — using `AsArbacDbController` / `AsArbacDbReadableController` |
| `@atscript/typescript` | optional — using the `/atscript` subpath (`AtscriptArbacUserProvider`) |

::: warning Subpath compile-time deps
`@aooth/arbac-moost/plugin` is **compile-time only** — it goes in `atscript.config.ts` so the `@arbac.*` annotations type-check. It contributes no runtime code.
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
import arbacPlugin from '@aooth/arbac-moost/plugin'
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
import { UsersStoreAtscriptDb } from "@aooth/user/atscript-db";
import { CredentialStoreAtscriptDb } from "@aooth/auth/atscript-db";
import { AoothAuthCredential } from "@aooth/auth/atscript-db/model.as";
```

### Redis (for tokens / denylist only)

```bash
pnpm add ioredis            # or redis@^4
```

Use the subpath import:

```ts
import { CredentialStoreRedis, DenylistStoreRedis } from "@aooth/auth/redis";
```

The package declares a structural `RedisLike` interface (8 methods used) — any client that matches the shape works.

### Memory (testing only)

Ships in the main entry points — no extra install:

```ts
import { UserStoreMemory } from "@aooth/user";
import { CredentialStoreMemory, DenylistStoreMemory } from "@aooth/auth";
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
