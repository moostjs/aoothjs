# Setup

This page is the full app-bootstrap recipe — everything you must wire into a fresh Moost app to get the auth guard, ARBAC, the REST controller, and the unified `AuthWorkflow` all online. It is loosely modeled on `packages/e2e-demo/src/app.ts`, which is the canonical end-to-end reference.

## Install

```bash
pnpm add moost @moostjs/event-http @moostjs/event-wf
pnpm add @atscript/moost-wf
pnpm add @aooth/user @aooth/auth @aooth/auth-moost
pnpm add @aooth/arbac @aooth/arbac-moost
```

`@aooth/auth-moost` peer-depends on the first three rows. The atscript-driven user provider (`@aooth/arbac-moost/atscript`) additionally requires `@atscript/typescript` and a working atscript codegen step — see [Atscript Models](./atscript).

## Wiring order

There are four things to wire, and they must happen in this order:

| Step | What                                                                                                                                                                                                       | Why                                                                                                                              |
| ---- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| 1    | **Provide registry** — bind `AuthCredential`, `UserService`, `EmailSender` (string token), and a concrete `MoostArbac` if you customize roles.                                                             | The auth guard pulls `AuthCredential`. The trigger route's email outlet pulls `EmailSender`. ARBAC pulls `MoostArbac`.           |
| 2    | **Replace registry** — bind `ArbacUserProviderToken` to your concrete provider, and (for durable workflow state) `WfTriggerProvider` to your subclass overriding `storeStrategy()`.                        | The base provider is abstract; the default trigger provider persists nothing durable (encapsulated state only).                  |
| 3    | **Global interceptors** — `authGuardInterceptor(opts)`, `arbacAuthorizeInterceptor`, `formInputInterceptor()`.                                                                                             | Guards must run on every event; the form input interceptor is required by every workflow form pause.                             |
| 4    | **Register controllers** — `AuthController` (or your subclass), the `AuthWorkflow` (register it directly for default opts, or a subclass to set opts / override `resolveXxx` hooks), your own controllers. | Subclassing is only needed when you want custom infra opts or to override `protected` policy hooks (`deliver`, `resolveXxx`, …). |

::: warning Order matters
`setProvideRegistry` must happen before any controller is instantiated (the workflows pull `AuthCredential` and `UserService` from the registry). `setReplaceRegistry` for the ARBAC user provider must happen before `applyGlobalInterceptors(arbacAuthorizeInterceptor)` is followed by `app.init()`.
:::

## End-to-end snippet

```ts
// minimal
import { AuthCredential, CredentialStoreJwt } from "@aooth/auth";
import { UserService } from "@aooth/user";
import { arbacAuthorizeInterceptor, ArbacUserProviderToken, MoostArbac } from "@aooth/arbac-moost";
import { AtscriptArbacUserProvider } from "@aooth/arbac-moost/atscript";
import {
  AuthController,
  authGuardInterceptor,
  AuthWorkflow,
  ConsentStore,
  createAuthEmailOutlet,
  Public,
  UserId,
  useAuth,
  WfTriggerProvider,
} from "@aooth/auth-moost";
import { AsWfStore, formInputInterceptor } from "@atscript/moost-wf";
import { HandleStateStrategy, MoostWf, type WfStateStrategy } from "@moostjs/event-wf";
import { MoostHttp, Get } from "@moostjs/event-http";
import {
  Controller,
  Inherit,
  Injectable,
  Moost,
  createProvideRegistry,
  createReplaceRegistry,
  getMoostInfact,
} from "moost";

// 1. Bootstrap the framework-agnostic primitives
const credentialStore = new CredentialStoreJwt({
  algorithm: "HS256",
  secret: process.env.JWT_SECRET!,
});
const authCredential = new AuthCredential({ store: credentialStore, method: "token" });
const userService = new UserService(userStore, {
  /* ... */
});
const emailSender = new MyEmailSender();

// 2. AuthWorkflow subclass
//
// Register `AuthWorkflow` directly if the default opts are fine. Subclass when
// you want custom infrastructure opts or to override `protected` policy hooks
// (`deliver`, `resolveXxx`, ...). Re-declare the 4-arg constructor so TS emits
// design-paramtypes against the subclass — the 4th param is the ConsentStore.

@Inherit()
@Controller() // SINGLETON — AuthWorkflow holds no per-event state on `this`
class MyAuth extends AuthWorkflow {
  constructor(users: UserService, auth: AuthCredential, consentStore: ConsentStore) {
    super({ totpIssuer: "MyApp", loginUrl: "/sign-in" }, users, auth, consentStore);
  }
  protected override async deliver(payload) {
    await emailSender.send({
      /* map payload → your sender, routed by payload.kind + payload.channel */
    });
  }
  protected override resolveMfaPolicy(ctx) {
    return { required: true, transports: ["email", "totp"] };
  }
}

// 3. WfTriggerProvider subclass — make state durable + add the email outlet
@Injectable()
class MyWfTriggerProvider extends WfTriggerProvider {
  constructor(wf: MoostWf, auth: AuthCredential) {
    super(wf, auth);
    this.outlets = [
      ...this.outlets,
      createAuthEmailOutlet({
        emailSender,
        buildMagicLinkUrl: (kind, token, ctx) =>
          `${env.FRONTEND_URL}/redeem?wfs=${token}${ctx?.userId ? `&uid=${ctx.userId}` : ""}`,
        magicLinkTtlMs: () => 60 * 60_000,
      }),
    ];
  }
  protected override storeStrategy(): WfStateStrategy {
    return new HandleStateStrategy({ store: new AsWfStore({ table: wfStatesTable }) });
  }
}

// 4. ARBAC user provider — bridge JWT subject → user record
@Injectable()
class MyArbacUserProvider extends AtscriptArbacUserProvider<MyUser> {
  constructor() {
    super(MyUser /* the .as type */, arbacUserTable);
  }
  override getUserId(): string {
    return useAuth().getUserId();
  }
}

// 5. Your own controllers
@Controller("me")
class MeController {
  @Get()
  whoami(@UserId() userId: string) {
    return { userId };
  }
}

// 6. Wire the app
const app = new Moost();
app.adapter(new MoostHttp());
app.adapter(new MoostWf());

app.setProvideRegistry(
  createProvideRegistry(
    [AuthCredential, () => authCredential],
    [UserService, () => userService],
    ["EmailSender", () => emailSender],
  ),
);

app.setReplaceRegistry(
  createReplaceRegistry(
    [WfTriggerProvider, MyWfTriggerProvider],
    [ArbacUserProviderToken, MyArbacUserProvider],
  ),
);

app.applyGlobalInterceptors(authGuardInterceptor({ cookie: { secure: false } }));
app.applyGlobalInterceptors(arbacAuthorizeInterceptor);
app.applyGlobalInterceptors(formInputInterceptor());

app.registerControllers(AuthController, MyAuth, MeController);

await app.init();

// 7. Register your ARBAC roles after init (MoostArbac is a singleton)
const arbac = await getMoostInfact().get(MoostArbac);
for (const role of allRoles) arbac.registerRole(role);

new MoostHttp(/* listen here */);
```

See [`packages/e2e-demo/src/app.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/e2e-demo/src/app.ts) for the working version of this recipe with the demo-specific extras stripped out here.

## What gets exposed

The wiring above produces these routes:

| Method | Path                           | Source           | Notes                                                                                                       |
| ------ | ------------------------------ | ---------------- | ----------------------------------------------------------------------------------------------------------- |
| `GET`  | `/me`                          | `MeController`   | Protected by both guards. Requires a token and an ARBAC grant for `(resource=MeController, action=whoami)`. |
| `GET`  | `/auth/status`                 | `AuthController` | `@Public()` — runs anonymously, 401 if no context.                                                          |
| `POST` | `/auth/logout`                 | `AuthController` | `@Public()` — clears cookies, best-effort revokes both tokens.                                              |
| `POST` | `/auth/refresh`                | `AuthController` | `@Public()` — exchanges refresh for new access+refresh.                                                     |
| `POST` | `/auth/trigger`                | `AuthController` | `@Public()` — single entry point for `auth/login/flow` / `auth/invite/start` / `auth/recovery/flow`.        |
| `GET`  | `/auth/invite/post-redemption` | `AuthController` | `@Public()` — idempotent "already accepted" envelope for re-clicked invite links.                           |

The `AuthWorkflow` itself does **not** expose new HTTP routes — its public `@Workflow` schemas (login / invite / recovery / signup) are driven through `/auth/trigger`; the guarded `change-password` flow runs via its own `POST /auth/change-password` route. The body `{ wfs?, input: { action?, formData? } }` and the `WfFinished` envelope are the entire wire protocol.

## DI tokens you can override

| Token                    | Default                                                     | Override pattern                                                                                              |
| ------------------------ | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `AuthCredential`         | none — must be provided                                     | `setProvideRegistry([AuthCredential, () => myInstance])`                                                      |
| `UserService`            | none — must be provided                                     | `setProvideRegistry([UserService, () => myInstance])`                                                         |
| `"EmailSender"` (string) | none — must be provided when wiring `createAuthEmailOutlet` | `setProvideRegistry(["EmailSender", () => mySender])`                                                         |
| `ArbacUserProviderToken` | base class is `abstract`                                    | `setReplaceRegistry([ArbacUserProviderToken, MyProvider])`                                                    |
| `WfTriggerProvider`      | encapsulated state (no durable store) + http outlet only    | `setReplaceRegistry([WfTriggerProvider, MyTriggerProvider])` — override `storeStrategy()` for durable state   |
| `MoostArbac`             | default singleton                                           | rarely overridden — `setReplaceRegistry([MoostArbac, MyArbac])` if you need typed `evaluate<TScope>` defaults |

::: warning No DI tokens for senders, audit sinks, or trust stores
Phase 4 of the auth-moost reshape removed `EmailSenderToken`, `SmsSenderToken`, `AuditEmitterToken`, `TrustedDeviceStoreToken`, etc. Overrides happen via `protected` workflow methods — see [Workflows](./workflows). The only string DI token surviving is `"EmailSender"`, consumed solely by `createAuthEmailOutlet`.
:::

## Public surface re-exports

The top-level `@aooth/auth-moost` import gives you everything you need at the framework seam:

```ts
import {
  // type primitives
  type AuthContext,
  type IssueResult,
  type EmailSender,
  type BuildMagicLinkUrl,
  type AuthEmailEvent,
  type AuthEmailKind,
  type AuthDeliveryPayload,
  type AuditEvent,
  type AuditEmitter,
  // unified workflow
  AuthWorkflow,
  type AuthWorkflowOpts,
  type AuthWfCtx,
  ConsentStore,
  type ConsentDescriptor,
  type ConsentEvent,
  // moost machinery
  AuthController,
  authGuardInterceptor,
  AuthGuarded,
  Public,
  UserId,
  useAuth,
  WfTrigger,
  WfTriggerProvider,
  createAuthEmailOutlet,
  DEFAULT_AUTH_WORKFLOWS,
} from "@aooth/auth-moost";
```

```ts
import {
  // engine + token
  MoostArbac,
  arbacAuthorizeInterceptor,
  ArbacUserProvider,
  ArbacUserProviderToken,
  // composable + decorators
  useArbac,
  ArbacResource,
  ArbacAction,
  ArbacAuthorize,
  // DB
  AsArbacDbController,
  AsArbacDbReadableController,
  type ArbacDbScope,
  type ControlGate,
} from "@aooth/arbac-moost";
```

```ts
// atscript-driven user provider (separate subpath)
import { AtscriptArbacUserProvider, type ArbacUserTable } from "@aooth/arbac-moost/atscript";
```
