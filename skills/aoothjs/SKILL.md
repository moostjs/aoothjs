---
name: aoothjs
description: >-
  Use when adding authentication or authorization to a Moost app — login,
  JWT / session tokens, password + MFA (TOTP), RBAC roles, route guards,
  magic links, password reset, invites, active sessions / per-device revoke.
  Covers `@aooth/user`, `@aooth/auth`,
  `@aooth/arbac-core`, `@aooth/arbac`, `@aooth/auth-moost`,
  `@aooth/arbac-moost` — the aoothjs auth + authz stack for moost / atscript
  apps. Triggers on `.as` user models extending `AoothUserCredentials` /
  `AoothArbacUserCredentials`, `@arbac.role` / `@arbac.attribute` /
  `@arbac.userId` annotations, refresh-token rotation, scope merging,
  deny-wins evaluation, the unified `AuthWorkflow` (login / invite /
  recovery), `ConsentStore`, `WfFinished` envelopes, or wiring
  `authGuardInterceptor` / `arbacAuthorizeInterceptor` into Moost. Out of
  scope: moost internals (use `moostjs`), `.as` syntax / `@meta.*` / `asc`
  (use `atscript`), `@atscript/db` / `moost-db` (use `atscript-db`),
  `@ui.*` / SPA components (use `atscript-ui`).
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
pnpm add @aooth/user @aooth/arbac

# Credential layer (sessions, JWT, magic links, refresh)
pnpm add @aooth/auth
pnpm add ioredis                                     # opt: Redis store
pnpm add @atscript/db                                # opt: DB-backed store

# Moost integration
pnpm add @aooth/auth-moost @aooth/arbac-moost moost
pnpm add @moostjs/event-http @moostjs/event-wf @atscript/moost-wf

# Atscript build (for .as models)
pnpm add -D unplugin-atscript @atscript/typescript @atscript/core
```

## Packages

```
@aooth/arbac-core              zero-dep RBAC engine: Arbac, evaluate(), wildcard patterns, deny-wins
    └── @aooth/arbac           re-exports core + defineRole, definePrivilege, allowTable*, scope mergers, codegen
            └── @aooth/arbac-moost   moost guard + interceptor + AsArbacDbController + ArbacUserProvider
                       │                  └── /atscript     AtscriptArbacUserProvider, AoothArbacUserCredentials
                       │                  └── /plugin       arbacPlugin() — @arbac.role/.attribute/.userId
                       │
@aooth/user                    UserService, password (scrypt), policy, TOTP/HOTP, backup codes, lockout
    │   └── /atscript-db         UsersStoreAtscriptDb + AoothUserCredentials .as model
    │
    └── @aooth/auth            AuthCredential, stores (Memory/JWT/Encapsulated/Redis/AtscriptDb), denylist, magic links
            │   └── /redis        CredentialStoreRedis, DenylistStoreRedis
            │   └── /atscript-db  CredentialStoreAtscriptDb + AoothAuthCredential .as model
            │
            └── @aooth/auth-moost   AuthController, authGuardInterceptor, @Public, @UserId, useAuth,
                                       AuthWorkflow (login/invite/recovery), ConsentStore, WfTriggerProvider
```

## Quick start

```ts
// src/app-user.as
import { AoothArbacUserCredentials } from '@aooth/arbac-moost/atscript/models'
import { AoothUserCredentials } from '@aooth/user/atscript-db/model'

// Tag the inherited `username` as the arbac user id. `useAuth().getUserId()`
// returns the username string (the auth subject passed to UserService.login),
// so the provider must look up by `username` — not by AppUser's `@meta.id` uuid.
// Mutating `annotate` is the only way to patch an inherited prop; `extends`
// can't redeclare. See atscript skill `as-syntax.md#annotate`.
annotate AoothUserCredentials {
    @arbac.userId
    username
}

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
import { UserService } from "@aooth/user";
import { UsersStoreAtscriptDb, type AuthUserTable } from "@aooth/user/atscript-db";
import { AuthCredential, CredentialStoreJwt } from "@aooth/auth";
import { AuthController, authGuardInterceptor, AuthWorkflow, useAuth } from "@aooth/auth-moost";
import {
  MoostArbac,
  arbacAuthorizeInterceptor,
  ArbacUserProviderToken,
  type ArbacDbScope,
} from "@aooth/arbac-moost";
import { AtscriptArbacUserProvider, type ArbacUserTable } from "@aooth/arbac-moost/atscript";
import { defineRole, allowTableRead } from "@aooth/arbac";
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
    // `AppUser`'s `@arbac.userId username` (added via the `annotate
    // AoothUserCredentials { ... }` block in app-user.as) lets the provider
    // hit the table directly — no shim. The cast is needed because
    // `AtscriptDbTable.findOne` is typed wider than `ArbacUserTable.findOne`
    // (engine-specific `controls.*` keys); they're structurally compatible
    // at runtime.
    super(AppUser, db.getTable(AppUser) as unknown as ArbacUserTable<AppUser>);
  }
  override getUserId() {
    // `useAuth().getUserId()` returns the username string — the auth subject
    // set by `UserService.login(username, password)`. The provider's
    // `@arbac.userId` chain points at `username`, so the lookup just works.
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
// — @aooth/user
import {
  UserService,
  UserStore,
  UserStoreMemory,
  PasswordHasher,
  PasswordPolicy,
  definePasswordPolicy,
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
  maskEmail,
  maskPhone,
  maskMfaValue,
  setAtPath,
  UserAuthError,
} from "@aooth/user";
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
} from "@aooth/user";

// — @aooth/user/atscript-db
import { UsersStoreAtscriptDb } from "@aooth/user/atscript-db";
import type { UserCredentialsRow, AuthUserTable } from "@aooth/user/atscript-db";
import { AoothUserCredentials } from "@aooth/user/atscript-db/model.as";

// — @aooth/arbac (re-exports @aooth/arbac-core)
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
} from "@aooth/arbac";
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
} from "@aooth/arbac";

// — @aooth/auth + subpaths
import {
  AuthCredential,
  AuthError,
  CredentialStoreMemory,
  CredentialStoreJwt,
  CredentialStoreEncapsulated,
  DenylistStoreMemory,
  generateMagicLinkToken,
  defaultClock,
} from "@aooth/auth";
import type {
  AuthContext,
  CredentialMetadata,
  CredentialState,
  IssueResult,
  IssueOptions,
  RefreshConfig,
  CredentialStore,
  DenylistStore,
  SessionInfo,
  EnrichedSession,
  SessionEnricher,
  EmailSender,
  AuthEmailEvent,
  AuthEmailKind,
  SmsSender,
  AuthSmsEvent,
  AuthSmsKind,
  BuildMagicLinkUrl,
  Clock,
  AuthErrorType,
} from "@aooth/auth";
import { CredentialStoreRedis, DenylistStoreRedis } from "@aooth/auth/redis";
import { CredentialStoreAtscriptDb } from "@aooth/auth/atscript-db";
import type { AuthCredentialRow, AuthCredentialTable } from "@aooth/auth/atscript-db";
import { AoothAuthCredential } from "@aooth/auth/atscript-db/model.as";

// — @aooth/auth-moost
import {
  AuthController,
  authGuardInterceptor,
  AuthGuarded,
  Public,
  UserId,
  useAuth,
  getAuthMate,
  AuthWorkflow,
  ConsentStore,
  SessionsController,
  SessionEnricherProvider,
  deriveWfStateSecret,
  WfTrigger,
  WfTriggerProvider,
  createAuthEmailOutlet,
  DEFAULT_AUTH_WORKFLOWS,
  buildInviteAlreadyAcceptedEnvelope,
  parseInviteRoles,
  stripReservedUserKeys,
  RESERVED_USER_KEYS,
} from "@aooth/auth-moost";
import type {
  AuthOptions,
  ResolvedAuthOptions,
  ResolvedAuthCookieConfig,
  AuthBindings,
  AuthLoginResponse,
  AuthLogoutBody,
  AuthRefreshBody,
  AuthOkResponse,
  AuditEvent,
  AuditEmitter,
  AuthDeliveryPayload,
  AuthWorkflowOpts,
  ResolvedAuthWorkflowOpts,
  AuthWfCtx,
  ConsentDescriptor,
  ConsentEvent,
  WfTriggerOpts,
} from "@aooth/auth-moost";

// — @aooth/arbac-moost + subpaths
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
} from "@aooth/arbac-moost";
import type { TArbacMeta, ArbacBindings, ArbacDbScope } from "@aooth/arbac-moost";
import { AtscriptArbacUserProvider } from "@aooth/arbac-moost/atscript";
import type { ArbacUserTable } from "@aooth/arbac-moost/atscript";
import { AoothArbacUserCredentials } from "@aooth/arbac-moost/atscript/models";
import arbacPlugin from "@aooth/arbac-moost/plugin";
```

## References — load only what's needed

| Domain                   | File                                                | When                                                                                                                                                                                                      |
| ------------------------ | --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| First contact            | [getting-started.md](references/getting-started.md) | Install matrix, minimum wiring (with + without moost), atscript-db wiring, choosing token/user stores, testing patterns                                                                                   |
| Ecosystem map            | [ecosystem.md](references/ecosystem.md)             | Package responsibility matrix, dep graph, peer-dep requirements, subpath export map                                                                                                                       |
| Annotation reference     | [annotations.md](references/annotations.md)         | Every `@arbac.*` annotation + how aoothjs reads `@db.*` / `@meta.*` / `@ui.form.*` / `@expect.*` / `@wf.*` from atscript                                                                                  |
| **User domain**          | [user.md](references/user.md)                       | `@aooth/user` overview: `UserService` quick start, full invariants table, key imports                                                                                                                     |
| `UserService` reference  | [user-service.md](references/user-service.md)       | Every public method, config defaults, login flow, lockout, MFA methods, backup codes, trusted devices                                                                                                     |
| Password subsystem       | [password.md](references/password.md)               | Scrypt + pepper + history, `generatePassword`, `PasswordPolicy` DSL, transferable policies, built-in `ppHas*` factories                                                                                   |
| MFA primitives           | [mfa.md](references/mfa.md)                         | TOTP secret/URI/code/verify, MFA-code helpers, backup codes, trusted-device tokens                                                                                                                        |
| User stores              | [user-stores.md](references/user-stores.md)         | `UserStore` contract, `UserStoreMemory`, custom-store skeleton, `UsersStoreAtscriptDb` wiring                                                                                                             |
| **ARBAC domain**         | [arbac.md](references/arbac.md)                     | `@aooth/arbac` + `arbac-core` overview: quick start, full invariants, key imports                                                                                                                         |
| Engine + builder         | [builder.md](references/builder.md)                 | `Arbac` class, `defineRole` chain, `definePrivilege` double-call, `allowTable*` helpers + action vocabulary                                                                                               |
| Scope merging            | [scopes.md](references/scopes.md)                   | `ArbacDbScope` shape, `mergeScopeFilters`, `unionProjections` truth table, `restrictProjection`, `unionControlsPolicy`                                                                                    |
| Codegen                  | [codegen.md](references/codegen.md)                 | Library API + CLI: `extractResourceActions`, `generateResourceTypes`, `aoothjs-arbac-codegen --roles ... --output ...`                                                                                    |
| **Auth domain**          | [auth.md](references/auth.md)                       | `@aooth/auth` overview: quick start, full invariants, key imports                                                                                                                                         |
| Tokens & sessions        | [tokens.md](references/tokens.md)                   | `CredentialStoreJwt` algorithms, claim layout, `CredentialStoreEncapsulated`, sessions vs tokens                                                                                                          |
| Refresh & rotation       | [refresh.md](references/refresh.md)                 | `RefreshConfig`, three rotation modes, reuse detection, stateless degradation, `maxConcurrent`, epoch revocation                                                                                          |
| Magic links              | [magic-links.md](references/magic-links.md)         | `generateMagicLinkToken`, single-use guarantees, stateless `DenylistStore` requirement, recovery recipe                                                                                                   |
| Auth stores              | [auth-stores.md](references/auth-stores.md)         | `CredentialStore` + `DenylistStore` contracts, Memory / Redis / atscript-db, shipped `AoothAuthCredential` model                                                                                          |
| Sessions / devices       | [sessions.md](references/sessions.md)               | Active-sessions screen: `sessionId` token-family, `listSessions` / `revokeSession` / `revokeOtherSessions`, `SessionEnricher`, `trackLastSeen`, `SessionsController` + `useAuth()` facade, `getSessionId` |
| **Moost domain**         | [moost.md](references/moost.md)                     | `@aooth/auth-moost` + `@aooth/arbac-moost` overview: quick start, full invariants, key imports                                                                                                            |
| Controllers + decorators | [controllers.md](references/controllers.md)         | `AuthController` REST surface, `authGuardInterceptor`, `useAuth`, `useArbac`, all decorators, 401-vs-403 split                                                                                            |
| Workflows                | [workflows.md](references/workflows.md)             | unified `AuthWorkflow` (3 schemas), `AuthWorkflowOpts` vs `resolveXxx` policy, `ConsentStore`, `WfTriggerProvider` + `storeStrategy`, `deliver`, error posture, forms                                     |
| SPA components           | [spa-components.md](references/spa-components.md)   | render workflow forms client-side: `<AsWfForm>` + `@atscript/vue-aooth` (`AsQrCode`/`AsConsentArray`/`AsPasswordRules`), magic-link resume, `@ui.form.component`                                          |
| DB controllers           | [db-controllers.md](references/db-controllers.md)   | `AsArbacDbController` hooks, `ArbacDbScope`, control-gate semantics, `DENY_FILTER`, identifier auto-preservation                                                                                          |
| Atscript provider        | [moost-atscript.md](references/moost-atscript.md)   | `arbacPlugin()`, `@arbac.*` annotations, user-id resolution, `AtscriptArbacUserProvider`, bundled `.as` models                                                                                            |
| Engine invariants        | [invariants.md](references/invariants.md)           | 18-row table of cross-package rules — deny-wins, refresh-degradation, `@Public()` dual-purpose, `@Injectable()` inheritance                                                                               |

## See also

Reference docs: https://aoothjs.dev. Source: https://github.com/moostjs/aoothjs.
