# What is aoothjs?

`aoothjs` is the authentication and authorization stack for the [moost](https://moost.org) + [atscript](https://atscript.dev) ecosystem. It ships six packages that split cleanly across two concerns — **who you are** (authn) and **what you can do** (authz) — and two integration layers — **framework-agnostic core** and **moost glue**.

This page sketches the shape of the stack and points you at the right package for each problem. When you are ready to write code, jump to [Quick Start](./quick-start) or [Installation](./installation).

## The 2x3 matrix

```
                  ┌────────────────────────────────┬─────────────────────────────────┐
                  │  Authentication (who)          │  Authorization (what)           │
┌─────────────────┼────────────────────────────────┼─────────────────────────────────┤
│  Core           │  @aooth/user                 │  @aooth/arbac-core            │
│  (no framework) │  @aooth/auth                 │  @aooth/arbac                 │
├─────────────────┼────────────────────────────────┼─────────────────────────────────┤
│  Moost glue     │  @aooth/auth-moost           │  @aooth/arbac-moost           │
└─────────────────┴────────────────────────────────┴─────────────────────────────────┘
```

`@aooth/arbac` is a thin builder + privilege-factory layer on top of `@aooth/arbac-core`. The other four packages have no internal split — `*-moost` packages depend on their core counterpart.

## What each package owns

| Package                                          | Concern       | Owns                                                                                                                                               |
| ------------------------------------------------ | ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`@aooth/user`](../user/)                        | authn         | Credential CRUD, password hashing (scrypt+pepper), password policies, TOTP/MFA primitives, lockout, trusted devices, pluggable `UserStore`.        |
| [`@aooth/auth`](../auth/)                        | authn         | Issue/validate/refresh/revoke bearer credentials (sessions or JWT), refresh rotation with reuse detection, magic-link tokens, email/SMS contracts. |
| [`@aooth/arbac-core`](../arbac/core)             | authz         | Zero-dep RBAC evaluator — `TArbacRole`, `Arbac.evaluate()`, deny-wins, wildcard matching, dynamic scopes.                                          |
| [`@aooth/arbac`](../arbac/)                      | authz         | Fluent `defineRole()` builder, `definePrivilege()` + `allowTable*` factories, scope-merge helpers, type codegen.                                   |
| [`@aooth/auth-moost`](../moost/)                 | authn / moost | `AuthController`, `authGuardInterceptor`, the unified `AuthWorkflow` (login / invite / recovery), `ConsentStore`, `@Public`, `@UserId`, `useAuth`. |
| [`@aooth/arbac-moost`](../moost/arbac-authorize) | authz / moost | `arbacAuthorizeInterceptor`, `@ArbacResource` / `@ArbacAction`, `useArbac`, `AtscriptArbacUserProvider`.                                           |

## How they compose at runtime

A logged-in request to `GET /tasks/:id` walks the stack like this:

```
 HTTP request
     │
     │  Bearer token / aooth_session cookie
     ▼
 ┌─────────────────────────────────────────────────────────────┐
 │  authGuardInterceptor          (@aooth/auth-moost)        │
 │   └─ uses AuthCredential.validate()  (@aooth/auth)        │
 │        └─ JWT / Memory / Redis / atscript-db store          │
 └────────────────────┬────────────────────────────────────────┘
                      │ AuthContext { userId, claims }
                      ▼
 ┌─────────────────────────────────────────────────────────────┐
 │  arbacAuthorizeInterceptor     (@aooth/arbac-moost)       │
 │   └─ resolves @ArbacResource / @ArbacAction                 │
 │   └─ uses Arbac.evaluate(user, request)  (arbac-core)       │
 │        └─ user fetched via AtscriptArbacUserProvider        │
 │             └─ reads @arbac.role + @arbac.attribute        │
 └────────────────────┬────────────────────────────────────────┘
                      │ scopes set on event
                      ▼
                  handler runs
                  useArbac().getScopes()  →  apply to DB query
```

The two interceptors are independent — the auth guard never returns 403, and the arbac interceptor never returns 401. You can wire either one alone.

## Why two layers (core vs moost)

Every `*-moost` package adapts a framework-agnostic core into moost's event chain — interceptors, decorators, DI tokens, the `useAuth` / `useArbac` composables. If your runtime is not moost (`@wooksjs/event-cli`, a bare HTTP server, a job worker), you stop at the core packages:

- `@aooth/user` + `@aooth/auth` is a complete bearer-credential stack with no HTTP dependency.
- `@aooth/arbac` + `@aooth/arbac-core` is a pure RBAC evaluator.

When you do use moost, the `*-moost` packages are the only places that touch `@moostjs/event-http`, `defineBeforeInterceptor`, or `getMoostInfact`. The split is deliberate — non-HTTP consumers should not pay for the HTTP integration.

## The atscript line

`aoothjs` is designed to be driven from `.as` annotated types:

- `@aooth/user/atscript-db/model.as` ships `AoothUserCredentials` — the base interface with `username`, `password`, `account`, `mfa`, `trustedDevices`.
- `@aooth/arbac-moost/atscript/models.as` ships `AoothArbacUserCredentials` — extends `AoothUserCredentials` with `@arbac.role roles: string[]`.
- `@aooth/auth/atscript-db/model.as` ships `AoothAuthCredential` — the bearer-token row.

You extend them in your app's `.as` files with `@meta.id`, `@db.table`, and any custom columns (`tenantId`, `departmentId`, ...). `syncSchema()` materialises the tables. `AtscriptArbacUserProvider` reads the same annotations to compute the user's roles and attributes at request time.

See [Using atscript-db Models](./atscript-db).

## When to use which package

::: tip Decision shortcut

- I need to **hash passwords / store credentials**: [`@aooth/user`](../user/).
- I need to **issue session or JWT tokens**: [`@aooth/user`](../user/) + [`@aooth/auth`](../auth/).
- I need to **define roles and evaluate access**: [`@aooth/arbac`](../arbac/).
- I want to **wire all of the above into a moost HTTP app**: add [`@aooth/auth-moost`](../moost/) and [`@aooth/arbac-moost`](../moost/arbac-authorize).
- I want **`.as`-driven users with auto-derived role/attribute extraction**: add `@aooth/arbac-moost/atscript`.
  :::

## Next steps

- [Quick Start](./quick-start) — smallest working moost app, built on the real `e2e-demo` wiring.
- [Installation](./installation) — which packages to install for which use case.
- [Ecosystem & Packages](./ecosystem) — package map, dependency graph, codegen requirements.
- [Using atscript-db Models](./atscript-db) — extend the bundled `.as` models for your app.
