---
name: aoothjs
description: >-
  Use when adding authentication or authorization to a Moost app — login,
  JWT / session tokens, password + MFA (TOTP, backup codes), RBAC roles,
  route guards, magic links, password reset, invites. Covers `@aoothjs/user`,
  `@aoothjs/auth`, `@aoothjs/arbac-core`, `@aoothjs/arbac`,
  `@aoothjs/auth-moost`, `@aoothjs/arbac-moost` — the aoothjs auth + authz
  stack for moost / atscript apps. Triggers on `.as` user models extending
  `AoothUserCredentials` / `AoothArbacUserCredentials`, `@arbac.role` /
  `@arbac.attribute` / `@arbac.userId` annotations, refresh-token rotation,
  scope merging, deny-wins evaluation, `WfFinished` envelopes, login /
  recovery / invite workflows, or wiring `authGuardInterceptor` /
  `arbacAuthorizeInterceptor` into Moost. Out of scope: moost framework
  internals (use `moostjs`), `.as` syntax / `@meta.*` / `asc` (use
  `atscript`), `@atscript/db` adapters and `moost-db` controllers (use
  `atscript-db`), UI / `@ui.*` annotations (use `atscript-ui`).
---

# aoothjs

## Install

```bash
npx skills add moostjs/aoothjs            # this skill — full aoothjs stack
npx skills add moostjs/moostjs            # sibling — moost framework
npx skills add moostjs/atscript           # sibling — .as syntax
npx skills add moostjs/atscript-db        # sibling — @atscript/db
```

```bash
# Core (always needed)
pnpm add @aoothjs/user @aoothjs/arbac

# Credential layer (sessions, JWT, magic links, refresh)
pnpm add @aoothjs/auth
pnpm add ioredis                                     # opt: Redis store
pnpm add @atscript/db                                # opt: DB-backed store

# Moost integration
pnpm add @aoothjs/auth-moost @aoothjs/arbac-moost moost
pnpm add @moostjs/event-http @moostjs/event-wf @atscript/moost-wf

# Atscript build (for .as models)
pnpm add -D unplugin-atscript @atscript/typescript @atscript/core
```

## Packages

```
@aoothjs/arbac-core              zero-dep RBAC engine: Arbac, evaluate(), wildcard patterns, deny-wins
    └── @aoothjs/arbac           re-exports core + defineRole, definePrivilege, allowTable*, scope mergers, codegen
            └── @aoothjs/arbac-moost   moost guard + interceptor + AsArbacDbController + ArbacUserProvider
                       │                  └── /atscript     AtscriptArbacUserProvider, AoothArbacUserCredentials
                       │                  └── /plugin       arbacPlugin() — @arbac.role/.attribute/.userId
                       │
@aoothjs/user                    UserService, password (scrypt), policy, TOTP/HOTP, backup codes, lockout
    │   └── /atscript-db         UsersStoreAtscriptDb + AoothUserCredentials .as model
    │
    └── @aoothjs/auth            AuthCredential, stores (Memory/JWT/Encapsulated/Redis/AtscriptDb), denylist, magic links
            │   └── /redis        CredentialStoreRedis, DenylistStoreRedis
            │   └── /atscript-db  CredentialStoreAtscriptDb + AoothAuthCredential .as model
            │
            └── @aoothjs/auth-moost   AuthController, authGuardInterceptor, @Public, @UserId, useAuth,
                                       LoginWorkflow, RecoveryWorkflow, InviteWorkflow, WfTriggerProvider
```

## Quick start

```ts
// src/app-user.as
import { AoothArbacUserCredentials } from '@aoothjs/arbac-moost/atscript/models'

@db.table 'users'
export interface AppUser extends AoothArbacUserCredentials {
    @meta.id @db.default.uuid
    id: string

    @arbac.attribute
    department?: string
}
```

```ts
// src/main.ts
import { Moost, createProvideRegistry, createReplaceRegistry } from "moost";
import { MoostHttp } from "@moostjs/event-http";
import { MoostWf } from "@moostjs/event-wf";
import { formInputInterceptor } from "@atscript/moost-wf";
import { DbSpace, syncSchema } from "@atscript/db";
import { SqliteAdapter, BetterSqlite3Driver } from "@atscript/db-sqlite";
import { UserService } from "@aoothjs/user";
import { UsersStoreAtscriptDb, type AuthUserTable } from "@aoothjs/user/atscript-db";
import { AuthCredential, CredentialStoreJwt } from "@aoothjs/auth";
import { AuthController, authGuardInterceptor, LoginWorkflow, useAuth } from "@aoothjs/auth-moost";
import {
  MoostArbac,
  arbacAuthorizeInterceptor,
  ArbacUserProviderToken,
  type ArbacDbScope,
} from "@aoothjs/arbac-moost";
import { AtscriptArbacUserProvider } from "@aoothjs/arbac-moost/atscript";
import { defineRole, allowTableRead } from "@aoothjs/arbac";
import { Injectable, getMoostInfact } from "moost";
import { AppUser } from "./app-user.as";

const db = new DbSpace(() => new SqliteAdapter(new BetterSqlite3Driver(":memory:")));
await syncSchema(db, [AppUser]);
const userStore = new UsersStoreAtscriptDb<AppUser>({
  table: db.getTable(AppUser) as unknown as AuthUserTable<AppUser>,
});
const userService = new UserService<AppUser>(userStore, {
  password: { pepper: process.env.AOOTH_PEPPER ?? "" },
});
const auth = new AuthCredential({
  store: new CredentialStoreJwt({ secret: process.env.AOOTH_JWT_SECRET! }),
  accessTtl: 3_600_000,
  refresh: { ttl: 7 * 24 * 3_600_000, rotation: "always" },
});
@Injectable()
class AppUserProvider extends AtscriptArbacUserProvider<AppUser> {
  constructor() {
    // AtscriptArbacUserProvider expects an `ArbacUserTable<T>` shim with
    // `findOne({ filter })` — not a raw `AtscriptDbTable`. See e2e-demo
    // `src/app.ts` for the canonical wrapper.
    super(AppUser, {
      async findOne(q: { filter: Record<string, unknown> }) {
        const id = q.filter.id as string | undefined;
        if (!id) return null;
        return (await userStore.findByUsername(id)) as AppUser | null;
      },
    });
  }
  getUserId() {
    return useAuth().getUserId();
  }
}

const app = new Moost();
app.adapter(new MoostHttp());
app.adapter(new MoostWf());
app.setProvideRegistry(
  createProvideRegistry([UserService, () => userService], [AuthCredential, () => auth]),
);
app.setReplaceRegistry(createReplaceRegistry([ArbacUserProviderToken, AppUserProvider]));
app.applyGlobalInterceptors(
  authGuardInterceptor(),
  arbacAuthorizeInterceptor,
  formInputInterceptor(),
);
app.registerControllers(AuthController);
await app.init();

// Grab the singleton MoostArbac from moost's IoC container and register roles.
const arbac = (await getMoostInfact().get(MoostArbac)) as MoostArbac<
  { department?: string },
  ArbacDbScope
>;
arbac.registerRole(defineRole().id("reader").use(allowTableRead("articles")).build());
```

## Invariants

Engine-internals — see [references/invariants.md](references/invariants.md) for the full 18-row table covering deny-wins, scope-union sentinels, refresh-rotation degradation, moost@0.6.x DI quirks, and the dual-purpose `@Public()`. Load when debugging silent-deny / refresh / scope-merge issues.

## Key imports

```ts
// — @aoothjs/user
import {
  UserService,
  UserStore,
  UserStoreMemory,
  PasswordHasher,
  PasswordPolicy,
  normalizePolicies,
  ppHasMinLength,
  ppHasUpperCase,
  ppHasLowerCase,
  ppHasNumber,
  ppHasSpecialChar,
  ppMaxRepeatedChars,
  generateTotpSecret,
  generateTotpUri,
  generateTotpCode,
  verifyTotpCode,
  generateMfaCode,
  hashMfaCode,
  verifyMfaCode,
  generateBackupCodePlaintext,
  maskEmail,
  maskPhone,
  maskMfaValue,
  setAtPath,
  UserAuthError,
} from "@aoothjs/user";
import type {
  UserCredentials,
  PasswordData,
  AccountData,
  MfaData,
  MfaMethod,
  UserServiceConfig,
  PasswordConfig,
  LockoutConfig,
  PasswordPolicyDef,
  PasswordPolicyInstance,
  UserStoreUpdate,
  DeepPartial,
  LoginResult,
  LockStatus,
  PolicyCheckResult,
  TransferablePolicy,
  MfaMethodInfo,
  TotpConfig,
  TrustedDeviceRecord,
  UserAuthErrorType,
} from "@aoothjs/user";

// — @aoothjs/user/atscript-db
import { UsersStoreAtscriptDb } from "@aoothjs/user/atscript-db";
import type { UserCredentialsRow, AuthUserTable } from "@aoothjs/user/atscript-db";
import { AoothUserCredentials } from "@aoothjs/user/atscript-db/model.as";

// — @aoothjs/arbac (re-exports @aoothjs/arbac-core)
import {
  Arbac,
  arbacPatternToRegex,
  defineRole,
  definePrivilege,
  allowTableRead,
  allowTableWrite,
  allowTableAction,
  mergeScopeFilters,
  unionProjections,
  restrictProjection,
  getProjectionMode,
  isFieldAllowed,
  unionControlsPolicy,
  extractResourceActions,
  generateResourceTypes,
} from "@aoothjs/arbac";
import type {
  TArbacRole,
  TArbacRule,
  TArbacEvalResult,
  RoleBuilder,
  TPrivilegeFunction,
  TProjection,
  TProjectionMode,
  TScopeFilter,
  ControlGate,
  TCodegenOptions,
  TResourceActionMap,
} from "@aoothjs/arbac";

// — @aoothjs/auth + subpaths
import {
  AuthCredential,
  AuthError,
  CredentialStoreMemory,
  CredentialStoreJwt,
  CredentialStoreEncapsulated,
  DenylistStoreMemory,
  generateMagicLinkToken,
  defaultClock,
} from "@aoothjs/auth";
import type {
  AuthContext,
  CredentialMetadata,
  CredentialState,
  IssueResult,
  RefreshConfig,
  CredentialStore,
  DenylistStore,
  EmailSender,
  AuthEmailEvent,
  AuthEmailKind,
  SmsSender,
  AuthSmsEvent,
  AuthSmsKind,
  BuildMagicLinkUrl,
  Clock,
  AuthErrorType,
} from "@aoothjs/auth";
import { CredentialStoreRedis, DenylistStoreRedis } from "@aoothjs/auth/redis";
import { CredentialStoreAtscriptDb } from "@aoothjs/auth/atscript-db";
import type { AuthCredentialRow, AuthCredentialTable } from "@aoothjs/auth/atscript-db";
import { AoothAuthCredential } from "@aoothjs/auth/atscript-db/model.as";

// — @aoothjs/auth-moost
import {
  AuthController,
  authGuardInterceptor,
  AuthGuarded,
  Public,
  UserId,
  useAuth,
  LoginWorkflow,
  RecoveryWorkflow,
  InviteWorkflow,
  WfTrigger,
  WfTriggerProvider,
  createAuthEmailOutlet,
  DEFAULT_AUTH_WORKFLOWS,
} from "@aoothjs/auth-moost";
import type {
  AuthOptions,
  ResolvedAuthOptions,
  AuthBindings,
  AuthLoginResponse,
  AuthLogoutBody,
  AuthRefreshBody,
  AuthOkResponse,
  AuditEvent,
  AuditEmitter,
  LoginWorkflowOpts,
  RecoveryWorkflowOpts,
  InviteWorkflowOpts,
} from "@aoothjs/auth-moost";

// — @aoothjs/arbac-moost + subpaths
import {
  MoostArbac,
  arbacAuthorizeInterceptor,
  ArbacResource,
  ArbacAction,
  ArbacAuthorize,
  useArbac,
  ArbacUserProvider,
  ArbacUserProviderToken,
  AsArbacDbController,
  AsArbacDbReadableController,
} from "@aoothjs/arbac-moost";
import type { TArbacMeta, ArbacBindings, ArbacDbScope } from "@aoothjs/arbac-moost";
import { AtscriptArbacUserProvider } from "@aoothjs/arbac-moost/atscript";
import type { ArbacUserTable } from "@aoothjs/arbac-moost/atscript";
import { AoothArbacUserCredentials } from "@aoothjs/arbac-moost/atscript/models";
import arbacPlugin from "@aoothjs/arbac-moost/plugin";
```

## References — load only what's needed

| Domain                   | File                                                | When                                                                                                                        |
| ------------------------ | --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| First contact            | [getting-started.md](references/getting-started.md) | Install matrix, minimum wiring (with + without moost), atscript-db wiring, choosing token/user stores, testing patterns     |
| Ecosystem map            | [ecosystem.md](references/ecosystem.md)             | Package responsibility matrix, dep graph, peer-dep requirements, subpath export map                                         |
| Annotation reference     | [annotations.md](references/annotations.md)         | Every `@arbac.*` annotation + how aoothjs reads `@db.*` / `@meta.*` / `@ui.form.*` / `@expect.*` / `@wf.*` from atscript    |
| **User domain**          | [user.md](references/user.md)                       | `@aoothjs/user` overview: `UserService` quick start, full invariants table, key imports                                     |
| `UserService` reference  | [user-service.md](references/user-service.md)       | Every public method, config defaults, login flow, lockout, MFA methods, backup codes, trusted devices                       |
| Password subsystem       | [password.md](references/password.md)               | Scrypt + pepper + history, `generatePassword`, `PasswordPolicy` DSL, transferable policies, built-in `ppHas*` factories     |
| MFA primitives           | [mfa.md](references/mfa.md)                         | TOTP secret/URI/code/verify, MFA-code helpers, backup codes, trusted-device tokens                                          |
| User stores              | [user-stores.md](references/user-stores.md)         | `UserStore` contract, `UserStoreMemory`, custom-store skeleton, `UsersStoreAtscriptDb` wiring                               |
| **ARBAC domain**         | [arbac.md](references/arbac.md)                     | `@aoothjs/arbac` + `arbac-core` overview: quick start, full invariants, key imports                                         |
| Engine + builder         | [builder.md](references/builder.md)                 | `Arbac` class, `defineRole` chain, `definePrivilege` double-call, `allowTable*` helpers + action vocabulary                 |
| Scope merging            | [scopes.md](references/scopes.md)                   | `ArbacDbScope` shape, `mergeScopeFilters`, `unionProjections` truth table, `restrictProjection`, `unionControlsPolicy`      |
| Codegen                  | [codegen.md](references/codegen.md)                 | Library API + CLI: `extractResourceActions`, `generateResourceTypes`, `aoothjs-arbac-codegen --roles ... --output ...`      |
| **Auth domain**          | [auth.md](references/auth.md)                       | `@aoothjs/auth` overview: quick start, full invariants, key imports                                                         |
| Tokens & sessions        | [tokens.md](references/tokens.md)                   | `CredentialStoreJwt` algorithms, claim layout, `CredentialStoreEncapsulated`, sessions vs tokens                            |
| Refresh & rotation       | [refresh.md](references/refresh.md)                 | `RefreshConfig`, three rotation modes, reuse detection, stateless degradation, `maxConcurrent`, epoch revocation            |
| Magic links              | [magic-links.md](references/magic-links.md)         | `generateMagicLinkToken`, single-use guarantees, stateless `DenylistStore` requirement, recovery recipe                     |
| Auth stores              | [auth-stores.md](references/auth-stores.md)         | `CredentialStore` + `DenylistStore` contracts, Memory / Redis / atscript-db, shipped `AoothAuthCredential` model            |
| **Moost domain**         | [moost.md](references/moost.md)                     | `@aoothjs/auth-moost` + `@aoothjs/arbac-moost` overview: quick start, full invariants, key imports                          |
| Controllers + decorators | [controllers.md](references/controllers.md)         | `AuthController` REST surface, `authGuardInterceptor`, `useAuth`, `useArbac`, all decorators, 401-vs-403 split              |
| Workflows                | [workflows.md](references/workflows.md)             | `LoginWorkflow` / `RecoveryWorkflow` / `InviteWorkflow` phase tables, options, hooks, `WfFinished` helpers, forms catalogue |
| DB controllers           | [db-controllers.md](references/db-controllers.md)   | `AsArbacDbController` hooks, `ArbacDbScope`, control-gate semantics, `DENY_FILTER`, identifier auto-preservation            |
| Atscript provider        | [moost-atscript.md](references/moost-atscript.md)   | `arbacPlugin()`, `@arbac.*` annotations, user-id resolution, `AtscriptArbacUserProvider`, bundled `.as` models              |
| Engine invariants        | [invariants.md](references/invariants.md)           | 18-row table of cross-package rules — deny-wins, refresh-degradation, `@Public()` dual-purpose, `@Injectable()` inheritance |

## See also

Reference docs: https://aoothjs.dev. Source: https://github.com/moostjs/aoothjs.
