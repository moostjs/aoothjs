# @aooth/auth-moost & @aooth/arbac-moost

## Quick start

```ts
import { AuthCredential, CredentialStoreJwt, type EmailSender } from "@aooth/auth";
import {
  AuthController,
  authGuardInterceptor,
  createAuthEmailOutlet,
  DEFAULT_AUTH_WORKFLOWS,
  InviteWorkflow,
  LoginWorkflow,
  Public,
  RecoveryWorkflow,
  useAuth,
  WfTrigger,
  WfTriggerProvider,
} from "@aooth/auth-moost";
import {
  arbacAuthorizeInterceptor,
  ArbacAction,
  ArbacAuthorize,
  ArbacResource,
  ArbacUserProviderToken,
  MoostArbac,
} from "@aooth/arbac-moost";
import { AtscriptArbacUserProvider } from "@aooth/arbac-moost/atscript";
import { UserService } from "@aooth/user";
import { formInputInterceptor } from "@atscript/moost-wf";
import { HandleStateStrategy, MoostWf } from "@moostjs/event-wf";
import { Get, MoostHttp, Post } from "@moostjs/event-http";
import {
  Controller,
  createProvideRegistry,
  createReplaceRegistry,
  getMoostInfact,
  Inherit,
  Injectable,
  Moost,
} from "moost";
import { AppUser } from "./app-user.as";

const app = new Moost();
app.adapter(new MoostHttp());
app.adapter(new MoostWf());

app.setProvideRegistry(
  createProvideRegistry(
    [AuthCredential, () => authCredential],
    [UserService, () => userService],
    ["EmailSender", () => emailSender], // string token — used by createAuthEmailOutlet
  ),
);
app.applyGlobalInterceptors(authGuardInterceptor({ cookie: { secure: false } }));
app.applyGlobalInterceptors(formInputInterceptor());
app.applyGlobalInterceptors(arbacAuthorizeInterceptor);

// Workflow subclass — @Inherit() carries base @Workflow/@Step metadata,
// @Injectable("FOR_EVENT") MUST be re-applied (moost@0.6.x does not inherit).
@Inherit()
@Injectable("FOR_EVENT")
@Controller()
class AppLoginWorkflow extends LoginWorkflow {
  constructor(users: UserService, auth: AuthCredential) {
    super({ mfa: { transports: ["email", "totp"] } }, users, auth);
  }
  protected override async deliver(p) {
    await emailSender.send({ ...p } as any);
  }
}

// Trigger provider subclass — wires DB state store + magic-link email outlet.
@Injectable()
class AppWfTriggerProvider extends WfTriggerProvider {
  constructor(wf: MoostWf) {
    super(wf);
    this.state = new HandleStateStrategy({ store: wfStateStore });
    this.outlets = [
      ...this.outlets,
      createAuthEmailOutlet({
        emailSender,
        buildMagicLinkUrl,
        magicLinkTtlMs: (kind) => (kind === "invite.magicLink" ? 7 * 86_400_000 : 3_600_000),
      }),
    ];
  }
}

// Atscript-driven user provider — extracts roles + attrs from .as model.
@Injectable()
class AppArbacUserProvider extends AtscriptArbacUserProvider<AppUser> {
  constructor() {
    super(AppUser, userTable);
  }
  override getUserId(): string {
    return useAuth().getUserId();
  }
}

app.setReplaceRegistry(
  createReplaceRegistry(
    [WfTriggerProvider, AppWfTriggerProvider],
    [ArbacUserProviderToken, AppArbacUserProvider],
  ),
);
app.registerControllers(AuthController, AppLoginWorkflow, RecoveryWorkflow, InviteWorkflow);

@Controller("reports")
@ArbacResource("reports")
class ReportsController {
  @Get(":id")
  @ArbacAction("read")
  @ArbacAuthorize()
  read(@UserId() userId: string) {
    return { userId };
  }
}
app.registerControllers(ReportsController);

await app.init();

// Register roles AFTER init — MoostArbac is a singleton.
const arbac = await getMoostInfact().get(MoostArbac);
for (const role of allRoles) arbac.registerRole(role);
```

## Invariants

| #   | Rule                                                                                                                                                                                                                                                                                                                                |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **`@Public()` is dual-purpose.** Imported from `@aooth/auth-moost`, it writes BOTH `authPublic=true` AND `arbacPublic=true` on the same mate. You cannot ARBAC-gate an `@Public()` route. Splitting was deliberately rejected as a foot-gun.                                                                                        |
| 2   | **Workflow class needs `@Public()`** — without it the global `arbacAuthorizeInterceptor` resolves WF events to `(resource=class-name, action=step-name)` and denies anonymous logins. `LoginWorkflow`/`RecoveryWorkflow` already carry it; `InviteWorkflow` does not (phase A is ARBAC-gated). Subclasses inherit via `@Inherit()`. |
| 3   | **Phase-B invite steps are `@Public()`.** Anonymous magic-link resume fires on a token, not a session. Don't strip these flags when subclassing.                                                                                                                                                                                    |
| 4   | **`useArbac` is NOT a wook.** It re-resolves resource/action per call. A wook cache would inherit the originating HTTP `EventContext` through WF `parent` and silently bypass workflow-class `@ArbacResource`.                                                                                                                      |
| 5   | **`useAuth()` outside the guard chain throws `HttpError(500)`.** Configuration error, not runtime fallback — the guard stashes resolved options onto an event slot; reads without the guard mean the guard isn't installed.                                                                                                         |
| 6   | **`@Injectable()` does NOT inherit across `extends`** in moost@0.6.x. Every concrete subclass of `LoginWorkflow` / `RecoveryWorkflow` / `InviteWorkflow` / `WfTriggerProvider` / `ArbacUserProvider` / `AtscriptArbacUserProvider` MUST re-decorate `@Injectable(...)` itself.                                                      |
| 7   | **Workflow constructor MUST be re-declared in every subclass.** TypeScript emits fresh design-paramtypes per class — without an explicit ctor signature, moost cannot resolve DI for `UserService` / `AuthCredential`.                                                                                                              |
| 8   | **`ArbacUserProviderToken` is the DI key, not the abstract class.** Wire your provider with `setReplaceRegistry(createReplaceRegistry([ArbacUserProviderToken, MyProvider]))`. The abstract `ArbacUserProvider` does not satisfy moost's `TClassConstructor`.                                                                       |
| 9   | **`ctx.aborted` gating** — every terminal workflow step conditions on `!ctx.aborted`. Without this, an abort alt-action (`finishWfAborted(...)`) would be overwritten by token issuance.                                                                                                                                            |
| 10  | **Use `delete ctx.field`, not `ctx.field = undefined`,** in workflow contexts. `AsWfStore` validates `state.context` against a JSON `anyOf` schema and rejects entries explicitly set to `undefined`.                                                                                                                               |
| 11  | **Refresh cookie path is narrow** (`/auth/refresh`). Browsers won't send it elsewhere — `/auth/logout` accepts `{ refreshToken? }` body fallback.                                                                                                                                                                                   |
| 12  | **Bearer wins over cookie.** When both `enableBearer` and `enableCookie` are true, the guard returns Bearer first; cookie is fallback only.                                                                                                                                                                                         |
| 13  | **`enableBearer: false`** suppresses tokens from `AuthLoginResponse` bodies (only `userId` + `accessExpiresAt`). Browser must rely on cookies.                                                                                                                                                                                      |
| 14  | **DB scope+user filter merge is `$and: [scope, user]`, never spread.** `@uniqu/core`'s `walkFilter` short-circuits on logical operators; object-spread silently merges away the scope predicate.                                                                                                                                    |
| 15  | **`assertInScope` runs BEFORE `applyAllowedFieldsAndSet`** on writes. Otherwise a caller knowing a row's PK could mutate it past their scope filter (BUG-1 in arbac-moost).                                                                                                                                                         |
| 16  | **`applyAllowedFieldsAndSet` auto-preserves identifier fields** — PK + every `@db.index.unique` group column is unconditionally kept in the patch even when not in `allowedFields` (BUG-8).                                                                                                                                         |
| 17  | **`AsArbacDbController.transformFilter` returns match-nothing (`{ $or: [] }`) on a deny verdict** — the constant is internal; behavior is observable as zero rows on reads + zero affected rows on writes.                                                                                                                          |
| 18  | **Form classes are stripped from `ctx.opts` via `snapshotOpts()`** before workflow state is persisted — `.as` class refs are not JSON-serializable.                                                                                                                                                                                 |
| 19  | **CSRF is consumer-supplied.** Package ships only SameSite=Lax on the access cookie. Add a CSRF interceptor if you accept state-changing requests from browsers.                                                                                                                                                                    |
| 20  | **`createAuthEmailOutlet` `await`s `emailSender.send()`.** Slow SMTP blocks the workflow response. Wrap your sender in a queue/transport that returns once accepted, not once delivered.                                                                                                                                            |
| 21  | **No `@ArbacPublic` / `@ArbacScopes` decorator** is exported. Use `@Public()` for both auth+arbac bypass; read scopes via `useArbac().getScopes<T>()` inside the handler.                                                                                                                                                           |
| 22  | **`arbacAuthorizeInterceptor` enforces authz only.** Decorated with `__authTransports: {}` — swagger treats it as an auth-guard but it does not authenticate. Pair with `authGuardInterceptor` upstream; a missing user provider raises `HttpError(401)`.                                                                           |

## Key imports

```ts
// — @aooth/auth-moost (runtime + types)
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
} from "@aooth/auth-moost";
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
  DeliverPayload,
  BuildMagicLinkUrl,
  LoginWorkflowOpts,
  RecoveryWorkflowOpts,
  InviteWorkflowOpts,
} from "@aooth/auth-moost";

// — @aooth/arbac-moost
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
import type { TArbacMeta, ArbacDbScope } from "@aooth/arbac-moost";

// — @aooth/arbac-moost/atscript (atscript-driven user provider)
import { AtscriptArbacUserProvider } from "@aooth/arbac-moost/atscript";
import type { ArbacUserTable } from "@aooth/arbac-moost/atscript";
import { AoothArbacUserCredentials } from "@aooth/arbac-moost/atscript/models";

// — @aooth/arbac-moost/plugin (build-time only, in atscript.config.ts)
import arbacPlugin from "@aooth/arbac-moost/plugin";

// — Workflow finish-envelope helpers (re-exported via @atscript/moost-wf)
import {
  finishWfWithData,
  finishWfWithMessage,
  finishWfWithRedirect,
  finishWfWithChoice,
  finishWfAborted,
  isWfFinished,
  formInputInterceptor,
} from "@atscript/moost-wf";
import type { WfFinished } from "@atscript/moost-wf";

// NOTE: `expectFinished` / `expectRedirect` are **test-only helpers** that
// live in `packages/auth-moost/src/__test__/workflow-utils.ts` and are NOT
// exported from `@aooth/auth-moost`. Don't import them in app code.
// NOTE: `DENY_FILTER` and the `ArbacBindings` interface are **internal**
// to `@aooth/arbac-moost` and not re-exported from `./index.ts`.
// Read the `useArbac()` return value via `ReturnType<typeof useArbac>`.

// — Moost framework (re-stated for grep-friendliness)
import {
  Controller,
  Inherit,
  Injectable,
  Moost,
  createProvideRegistry,
  createReplaceRegistry,
  getMoostInfact,
} from "moost";
import { MoostHttp, Get, Post } from "@moostjs/event-http";
import { MoostWf, HandleStateStrategy } from "@moostjs/event-wf";

// — Peer types from @aooth/auth / @aooth/user (commonly imported together)
import { AuthCredential } from "@aooth/auth";
import type { EmailSender, AuthEmailKind, SmsSender } from "@aooth/auth";
import { UserService } from "@aooth/user";
```

## References — load only what's needed

| Domain               | File                                     | When                                                                                                                                                                        |
| -------------------- | ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| First contact        | [getting-started.md](getting-started.md) | Install matrix, full app-bootstrap recipe, hello-world protected route, the four canonical wiring steps, common pitfalls                                                    |
| Controllers + guards | [controllers.md](./controllers.md)       | `AuthController` REST surface, `authGuardInterceptor` options, `useAuth` / `useArbac` API, decorators (`@Public`, `@UserId`, `@ArbacResource`/`@ArbacAction`)               |
| Workflows            | [workflows.md](./workflows.md)           | `LoginWorkflow` / `RecoveryWorkflow` / `InviteWorkflow` phases + hooks, `WfFinished` envelope helpers, `WfTrigger` + `createAuthEmailOutlet`, forms catalogue               |
| DB controllers       | [db-controllers.md](./db-controllers.md) | `AsArbacDbController` hook table, `ArbacDbScope<T>.{filter,projection,set,allowedFields,controls,with}`, multi-role union, match-nothing deny, identifier auto-preservation |
| Atscript user model  | [moost-atscript.md](./moost-atscript.md) | `arbacPlugin()` registration, `@arbac.{role,attribute,userId}` semantics, `AtscriptArbacUserProvider` subclass seam, per-event memoization, `AoothArbacUserCredentials`     |

## See also

Reference docs: https://aoothjs.dev. Source: https://github.com/moostjs/aoothjs.
