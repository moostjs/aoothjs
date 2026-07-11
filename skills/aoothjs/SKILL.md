---
name: aoothjs
description: >-
  Use when adding authentication or authorization to a Moost app — login,
  JWT/session tokens, password+MFA (TOTP), SMS OTP login/recovery, RBAC
  roles/guards, magic links, password reset, invites, session revoke,
  OAuth2/OIDC federated login, or BE the OAuth/OIDC provider (CLI SSO,
  `@aooth/login-client`; MCP-connector DCR RFC 7591 + client_secret_post,
  refresh_token grant, oauth-authorization-server / protected-resource
  metadata). Covers `@aooth/user`, `@aooth/auth`, `@aooth/idp`,
  `@aooth/arbac`, `@aooth/auth-moost`, `@aooth/arbac-moost` — the aoothjs
  auth+authz stack for moost/atscript apps. Triggers on `.as` models extending
  `AoothUserCredentials` / `AoothArbacUserCredentials`, `@arbac.*` /
  `@aooth.user.*` annotations, refresh rotation, `AuthWorkflow` seams,
  `FederatedLoginService`, `ConsentStore`, or `authGuardInterceptor` /
  `arbacAuthorizeInterceptor`. Out of scope: moost internals (`moostjs`),
  `.as`/`asc` (`atscript`), `@atscript/db`/`moost-db` (`atscript-db`),
  `@ui.*`/SPA components (`atscript-ui`).
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

# Federated login (OAuth2 / OIDC — Sign in with Google)
pnpm add @aooth/idp                                  # opt: federated-login core

# CLI loopback login (client half of the authorization server; zero deps)
pnpm add @aooth/login-client

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
@aooth/user                    UserService, password (scrypt), policy, TOTP/HOTP, backup codes, lockout, FederatedIdentityStore (account linking)
    │   └── /atscript-db         UsersStoreAtscriptDb + AoothUserCredentials .as model; FederatedIdentityStoreAtscriptDb + AoothFederatedIdentity .as model
    │
    └── @aooth/auth            AuthCredential, stores (Memory/JWT/Encapsulated/Redis/AtscriptDb), denylist, magic links
            │   └── /redis        CredentialStoreRedis, DenylistStoreRedis
            │   └── /atscript-db  CredentialStoreAtscriptDb + AoothAuthCredential .as model
            │   └── /authz        authorization-server core: IdTokenSigner, Loopback/Registered/Dynamic/Composite client policies, OidcClaimsResolver, pending/auth-code/dynamic-client stores, DynamicClientRegistration (RFC 7591), RFC 8414/9728 metadata + WWW-Authenticate builders
            │
            ├── @aooth/idp     federated-login core (depends on user+auth): OidcProvider/GoogleProvider/FakeIdentityProvider, OAuthProviderRegistry,
            │                     FederatedLoginService.resolveUser, PKCE + signState/verifyState, OAuthError. HTTP/workflow wiring is in auth-moost (OAuthController + federated leg of auth/login/flow)
            │
            └── @aooth/auth-moost   AuthController, SessionsController, OAuthController, AuthorizeController (authorization server: /auth/authorize + /auth/token + OIDC discovery/JWKS), authGuardInterceptor, @Public, @UserId, useAuth,
                                       AuthWorkflow (login [+federated sso-callback/prove-control] /invite/recovery/signup/change-password/add-mfa), ConsentStore, WfTriggerProvider

@aooth/login-client            ZERO-dep CLI half of the authorization server: authorize() — browser + PKCE + one-shot loopback callback → token. Depends on nothing (not even @aooth/*)
```

## Quick start

```ts
// src/app-user.as
import { AoothArbacUserCredentials } from '@aooth/arbac-moost/atscript/models'

// id (PK / @meta.id — the token subject), username + email (unique handles),
// version — all inherited. The auth subject IS @meta.id, so the provider's
// default lookup chain resolves to it: NO @arbac.userId annotate needed.
@db.table 'users'
export interface AppUser extends AoothArbacUserCredentials {
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
    // Provider resolves users by `@meta.id` (= `id` = the auth subject) — no
    // @arbac.userId, no shim. The cast is needed because `AtscriptDbTable.findOne`
    // is typed wider than `ArbacUserTable.findOne` (engine-specific `controls.*`
    // keys); they're structurally compatible at runtime.
    super(AppUser, db.getTable(AppUser) as unknown as ArbacUserTable<AppUser>);
  }
  override getUserId() {
    // Returns the stable `id` — the token `sub` claim `auth.issue(subject)` set.
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
  generateOpaqueToken, // the shared CSPRNG mint (magic links / client secrets / one-shot tokens)
  defaultClock,
} from "@aooth/auth";
import type {
  AuthContext,
  CredentialMetadata, // framework keys: credentialKind, authzClientId, accessTtl, refreshRotation
  CredentialState,
  IssueResult,
  RefreshResult, // refresh()'s return — IssueResult + userId
  IssueOptions, // per-mint ttl/expiresAt/kind/refresh (refresh: false | { ttl? })
  RefreshCallOptions, // refresh(token, { guard }) — pre-rotation gate
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

// — @aooth/idp (federated login — see references/idp.md for the full surface)
import {
  OidcProvider,
  GoogleProvider,
  FakeIdentityProvider,
  OAuthProviderRegistry,
  FederatedLoginService,
  createPkcePair,
  generateNonce,
  signState,
  verifyState,
  resolveFederatedPolicy,
  OAuthError,
} from "@aooth/idp";
import type {
  IdentityProvider,
  NormalizedProfile,
  FederatedPolicy,
  ResolveOutcome,
  OidcProviderOptions,
  OAuthProviderRegistryOptions,
  FederatedLoginServiceDeps,
  OAuthStatePayload,
  OAuthErrorType,
} from "@aooth/idp";
// account-linking store ships in @aooth/user (NOT @aooth/idp):
import {
  FederatedIdentityStore,
  FederatedIdentityStoreMemory,
  pickDefinedProfile,
} from "@aooth/user";
import type {
  FederatedIdentity,
  NewFederatedIdentity,
  FederatedProfileSnapshot,
} from "@aooth/user";
import { FederatedIdentityStoreAtscriptDb } from "@aooth/user/atscript-db";

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
  haversineKm,
  humanizeUserAgent,
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

// — @aooth/login-client (CLI side — zero deps, see references/login-client.md)
import { authorize, AuthorizeError } from "@aooth/login-client";
import type { AuthorizeOptions, AuthorizeResult, AuthorizeErrorCode } from "@aooth/login-client";
```

## References — load only what's needed

| Domain                    | File                                                          | When                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ------------------------- | ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| First contact             | [getting-started.md](references/getting-started.md)           | Install matrix, minimum wiring (with + without moost), atscript-db wiring, choosing token/user stores, testing patterns                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Ecosystem map             | [ecosystem.md](references/ecosystem.md)                       | Package responsibility matrix, dep graph, peer-dep requirements, subpath export map                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Annotation reference      | [annotations.md](references/annotations.md)                   | Every `@arbac.*` annotation + how aoothjs reads `@db.*` / `@meta.*` / `@ui.form.*` / `@expect.*` / `@wf.*` from atscript                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| **User domain**           | [user.md](references/user.md)                                 | `@aooth/user` overview: `UserService` quick start, full invariants table, key imports                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `UserService` reference   | [user-service.md](references/user-service.md)                 | Every public method, config defaults, login flow, lockout, MFA methods, backup codes, trusted devices, seen-device recognition ledger, correspondence email (`setVerifiedEmail` / `getCorrespondenceEmail`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Password subsystem        | [password.md](references/password.md)                         | Scrypt + pepper + history, `generatePassword`, `PasswordPolicy` DSL, transferable policies, built-in `ppHas*` factories                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| MFA primitives            | [mfa.md](references/mfa.md)                                   | TOTP secret/URI/code/verify, MFA-code helpers, backup codes, trusted-device tokens                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| User stores               | [user-stores.md](references/user-stores.md)                   | `UserStore` contract, `UserStoreMemory`, custom-store skeleton, `UsersStoreAtscriptDb` wiring                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| **ARBAC domain**          | [arbac.md](references/arbac.md)                               | `@aooth/arbac` + `arbac-core` overview: quick start, full invariants, key imports                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Engine + builder          | [builder.md](references/builder.md)                           | `Arbac` class, `defineRole` chain, `definePrivilege` double-call, `allowTable*` helpers + action vocabulary                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Scope merging             | [scopes.md](references/scopes.md)                             | `ArbacDbScope` shape, `mergeScopeFilters`, `unionProjections` truth table, `restrictProjection`, `unionControlsPolicy`; attenuation conjunction (`conjoinScopeFilters` / `intersectControlsPolicy` / `conjoinArbacDbScopes` / `extractAttenuation` — scoped tokens / PATs)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Codegen                   | [codegen.md](references/codegen.md)                           | Library API + CLI: `extractResourceActions`, `generateResourceTypes`, `aoothjs-arbac-codegen --roles ... --output ...`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| **Auth domain**           | [auth.md](references/auth.md)                                 | `@aooth/auth` overview: quick start, full invariants, key imports                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Tokens & sessions         | [tokens.md](references/tokens.md)                             | `CredentialStoreJwt` algorithms, claim layout, `CredentialStoreEncapsulated`, sessions vs tokens                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Refresh & rotation        | [refresh.md](references/refresh.md)                           | `RefreshConfig`, three rotation modes, per-mint `IssueOptions.refresh` (the `refresh()` guard, `RefreshResult`, `metadata.refreshRotation`/`accessTtl` stamps), reuse detection, stateless degradation, `maxConcurrent`, epoch revocation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Client (silent refresh)   | [client.md](references/client.md)                             | `@aooth/auth/client` browser subpath: `createAuthedFetch` — credentials forwarding, single-flight `/auth/refresh` on 401, retry-once, `onLogout`, status probe                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Magic links               | [magic-links.md](references/magic-links.md)                   | `generateMagicLinkToken`, single-use guarantees, stateless `DenylistStore` requirement, recovery recipe                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Auth stores               | [auth-stores.md](references/auth-stores.md)                   | `CredentialStore` + `DenylistStore` contracts, Memory / Redis / atscript-db, shipped `AoothAuthCredential` model                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Sessions / devices        | [sessions.md](references/sessions.md)                         | Active-sessions screen: `sessionId` token-family, `listSessions` / `revokeSession` / `revokeOtherSessions`, `SessionEnricher`, `trackLastSeen`, `SessionsController` + `useAuth()` facade, `getSessionId`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| **Federated login (IdP)** | [idp.md](references/idp.md)                                   | `@aooth/idp` OAuth2/OIDC: `OidcProvider`/`GoogleProvider`/`FakeIdentityProvider`, ID-token §7 validation, `OAuthProviderRegistry`, `FederatedLoginService.resolveUser` + `FederatedPolicy`, `linkIdentity`, PKCE/signState, the `FederatedIdentityStore` (from `@aooth/user`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| **Moost domain**          | [moost.md](references/moost.md)                               | `@aooth/auth-moost` + `@aooth/arbac-moost` overview: quick start, full invariants, key imports                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Controllers + decorators  | [controllers.md](references/controllers.md)                   | `AuthController` REST surface, `authGuardInterceptor`, `useAuth`, `useArbac`, all decorators, 401-vs-403 split                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Workflows                 | [workflows.md](references/workflows.md)                       | unified `AuthWorkflow` (6 schemas: login [federated merged in] / invite / recovery / signup / change-password / add-mfa), `AuthWorkflowOpts` vs `resolveXxx` policy, the full extension-point catalog, `ConsentStore`, `WfTriggerProvider` + `storeStrategy`, `deliver`, error posture, forms, device recognition vs trust + the "new sign-in" notice gate, verified correspondence email capture                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Phone / recovery channels | [recovery-and-handles.md](references/recovery-and-handles.md) | login by phone (`@aooth.user.phone` handle), recovery OTP channel M1 (`resolveRecoveryChannel`) vs registered-channel M2 (`resolveRecoveryDeliverySource` + `selectRecoveryRegisteredMethod`), auto-promote a confirmed channel to a login handle (`resolvePromoteHandleField` + `promote-to-handle`). Load when wiring SMS recovery, phone login, or handle promotion                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Federated login (moost)   | [oauth.md](references/oauth.md)                               | `@aooth/auth-moost` OAuth wiring: login-form SSO button + `beginSso`, `OAuthController` (identities/link/unlink), federated leg of `auth/login/flow` (`sso-callback` + `needs-link` `prove-control` w/ OTP fallback + resend), stateless PKCE, connected accounts, callback bridge, CSRF/redirect/gate invariants                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Authorization server      | [authorization-server.md](references/authorization-server.md) | aoothjs AS an OAuth/OIDC PROVIDER (`@aooth/auth/authz` + `@aooth/auth-moost`): `AuthorizeController` (`/auth/authorize` + `/auth/token` [authorization_code + refresh_token grants] + discovery + JWKS + `/auth/register` + RFC 8414 `oauth-authorization-server` metadata), Tier 1 `LoopbackClientPolicy` (CLI) vs Tier 2 `RegisteredClientPolicy` vs MCP-connector `DynamicClientPolicy`/`DynamicClientRegistration` (RFC 7591 DCR — public `"none"` + confidential `client_secret_post` w/ one-time secret disclosure, RFC 9728 PRM + `WWW-Authenticate` builders, RFC 8707 `resource`), OAuth 2.1 `refresh_token` grant (`TokenPolicy.refresh`, `metadata.authzClientId` binding, fixed-ceiling rotation, family revocation on replay), `CompositeClientPolicy` ownership dispatch, `IdTokenSigner` + `OidcClaimsResolver` + `getIssuer` getter-override seam (NOT DI), authority-fixed-at-authorize, pending/auth-code/dynamic-client stores, the consent gate + `aooth_authz` browser-binding cookie (`AuthorizeConsentForm` / `AUTHZ_BINDING_COOKIE`), bare-origin discovery + CORS deployment pitfalls, consuming it via `OidcProvider` |
| CLI loopback login        | [login-client.md](references/login-client.md)                 | `@aooth/login-client` `authorize()` — building a CLI that logs in against an aoothjs authorization server (browser + PKCE + loopback callback), headless/SSH mode, `AuthorizeError` codes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| SPA components            | [spa-components.md](references/spa-components.md)             | render workflow forms client-side: `<AsWfForm>` + `@atscript/vue-aooth` (`AsQrCode`/`AsConsentArray`/`AsPasswordRules`/`AsSsoProviders`), magic-link resume, `@ui.form.component`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| DB controllers            | [db-controllers.md](references/db-controllers.md)             | `AsArbacDbController` hooks, `ArbacDbScope`, control-gate semantics, `DENY_FILTER`, identifier auto-preservation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Atscript provider         | [moost-atscript.md](references/moost-atscript.md)             | `arbacPlugin()`, `@arbac.*` annotations, user-id resolution, `AtscriptArbacUserProvider`, bundled `.as` models                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Engine invariants         | [invariants.md](references/invariants.md)                     | 18-row table of cross-package rules — deny-wins, refresh-degradation, `@Public()` dual-purpose, `@Injectable()` inheritance                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |

## See also

Reference docs: https://aoothjs.dev. Source: https://github.com/moostjs/aoothjs.
