# Quick Start

This walkthrough builds a minimal moost HTTP app with:

- A `.as`-modelled user table backed by `@atscript/db-sqlite`.
- JWT-issued sessions managed by `AuthCredential`.
- The unified `AuthWorkflow` (login / invite / recovery) mounted under `/auth/trigger`.
- An ARBAC-aware `GET /me` route guarded by both the auth and arbac interceptors.

Every snippet below is lifted from the working `packages/e2e-demo/` app — wire each block in order and you have a runnable server. Source references: [`e2e-demo/src/app.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/e2e-demo/src/app.ts) and [`e2e-demo/src/aooth.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/e2e-demo/src/aooth.ts).

## 1. Install packages

```bash
pnpm add @aooth/user @aooth/auth @aooth/auth-moost \
         @aooth/arbac @aooth/arbac-moost \
         moost @moostjs/event-http @moostjs/event-wf \
         @atscript/db @atscript/db-sqlite @atscript/moost-wf \
         better-sqlite3
pnpm add -D @atscript/core @atscript/typescript unplugin-atscript
```

::: info Catalogued versions
The aoothjs monorepo pins `moost`, `@moostjs/*`, `@atscript/*`, and `vite-plus` in `pnpm-workspace.yaml`. Match those versions when consuming the `@aooth/*` workspace packages out-of-tree.
:::

## 2. Configure atscript

Create `atscript.config.mts` so the compiler understands the `@arbac.*` annotations used by the bundled `AoothArbacUserCredentials` model.

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

Add `"gen:atscript": "asc -f dts"` to `package.json` and run it once: it emits `*.as.d.ts` siblings next to every `.as` file.

## 3. Define your user model

Extend `AoothArbacUserCredentials` to add the columns your app needs. Mark one `@arbac.attribute` per scope key (here, `tenantId`) — those become the keys the role's `scope` functions can read.

::: code-group

```ts [src/models/user.as]
import { AoothArbacUserCredentials } from '@aooth/arbac-moost/atscript/models'
import { AoothUserCredentials } from '@aooth/user/atscript-db/model'

// Tag the inherited `username` as the arbac user id so the provider looks
// users up by `username` — the string `useAuth().getUserId()` returns.
// `extends` can't redeclare inherited props; a mutating `annotate` block
// patches the parent's prop in place. See atscript's `as-syntax.md#annotate`.
annotate AoothUserCredentials {
    @arbac.userId
    username
}

@db.table 'users'
export interface AppUser extends AoothArbacUserCredentials {
    @meta.id
    @db.default.uuid
    id: string

    @arbac.attribute
    @meta.required
    tenantId: string

    @expect.maxLength 128
    email?: string

    @db.default.now
    createdAt: number.timestamp
}
```

:::

::: tip Why `AoothArbacUserCredentials` and not `AoothUserCredentials`
`AoothArbacUserCredentials` is just `AoothUserCredentials` + `@arbac.role roles: string[]`. If you only need authentication (no RBAC) you can extend `@aooth/user/atscript-db/model.as`'s `AoothUserCredentials` directly. See [Using atscript-db Models](./atscript-db).
:::

## 4. Wire the database

```ts:line-numbers
import { DbSpace } from '@atscript/db'
import { syncSchema } from '@atscript/db/sync'
import { BetterSqlite3Driver, SqliteAdapter } from '@atscript/db-sqlite'
import { AoothAuthCredential } from '@aooth/auth/atscript-db/model.as'
import { AppUser } from './models/user.as'

const driver = new BetterSqlite3Driver('./app.db')
const db = new DbSpace(() => new SqliteAdapter(driver))

const tables = {
  users: db.getTable(AppUser),
  credentials: db.getTable(AoothAuthCredential),
}

await syncSchema(db, [AppUser, AoothAuthCredential])
```

::: warning Schema sync
`syncSchema()` is idempotent and safe to run on every boot. It acquires the `__atscript_control` lock so multi-process startup is also safe.
:::

## 5. Compose `UserService` + `AuthCredential`

The pattern below mirrors [`createAooth()`](https://github.com/moostjs/aoothjs/blob/main/packages/e2e-demo/src/aooth.ts) in the demo.

```ts:line-numbers
import { AuthCredential, CredentialStoreJwt, DenylistStoreMemory } from '@aooth/auth'
import { UserService } from '@aooth/user'
import { UsersStoreAtscriptDb, type AuthUserTable } from '@aooth/user/atscript-db'
import { CredentialStoreAtscriptDb } from '@aooth/auth/atscript-db'
import type { AppUser } from './models/user.as'

const denylist = new DenylistStoreMemory()

const userStore = new UsersStoreAtscriptDb<AppUser>({
  table: tables.users as unknown as AuthUserTable<AppUser>,
})

const userService = new UserService<AppUser>(userStore, {
  password: {
    historyLength: 5,
    policies: [
      { rule: 'v.length >= 8', description: 'At least 8 characters' },
      { rule: '/[A-Za-z]/.test(v)', description: 'Contains a letter' },
      { rule: '/[0-9]/.test(v)', description: 'Contains a digit' },
    ],
  },
  lockout: { threshold: 5, duration: 15 * 60_000 },
})

const credentialStore = new CredentialStoreJwt<Record<string, unknown>>({
  algorithm: 'HS256',
  secret: process.env.JWT_SECRET!,
  denylist,
})

const authCredential = new AuthCredential<Record<string, unknown>>({
  store: credentialStore,
  method: 'token',
  accessTtl: 60 * 60_000,
  refresh: { ttl: 30 * 24 * 3600_000, rotation: 'always' },
  denylist,
})
```

The cast on `tables.users` bridges atscript-db's generic row shape (`Record<string, unknown>`) into the narrower `AuthUserTable<AppUser>` surface that `UsersStoreAtscriptDb` actually calls — copy as-is, no runtime cost. See [`aooth.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/e2e-demo/src/aooth.ts).

## 6. Define a role

```ts:line-numbers
import { allowTableRead, defineRole } from '@aooth/arbac'
import type { ArbacDbScope } from '@aooth/arbac-moost'

type UserAttrs = { tenantId: string }

export const memberRole = defineRole<UserAttrs, ArbacDbScope>()
  .id('member')
  .name('Member')
  .allow('me', 'read')
  .use(
    allowTableRead<UserAttrs, ArbacDbScope>('users', {
      scope: (attrs) => ({ filter: { tenantId: attrs.tenantId } }),
    }),
  )
  .build()
```

`allow('me', 'read')` matches the controller below — `@ArbacResource('me')` on the class and `@ArbacAction('read')` on the method are what `arbacAuthorizeInterceptor` looks up against the role's rule list. (If you omit them the interceptor falls back to `@Controller(id)` and the method name, but explicit is safer — a typo'd handler name silently denies.)

## 7. Build the moost app

```ts:line-numbers
import {
  ArbacAction,
  arbacAuthorizeInterceptor,
  ArbacResource,
  ArbacUserProviderToken,
  MoostArbac,
  type ArbacDbScope,
} from '@aooth/arbac-moost'
import { AtscriptArbacUserProvider } from '@aooth/arbac-moost/atscript'
import {
  AuthController,
  authGuardInterceptor,
  AuthWorkflow,
  ConsentStore,
  createAuthEmailOutlet,
  useAuth,
  UserId,
  WfTrigger,
  WfTriggerProvider,
} from '@aooth/auth-moost'
import { AuthCredential } from '@aooth/auth'
import { UserService } from '@aooth/user'
import { AsWfStore, formInputInterceptor } from '@atscript/moost-wf'
import { HandleStateStrategy, MoostWf, type WfStateStrategy } from '@moostjs/event-wf'
import { Get, MoostHttp } from '@moostjs/event-http'
import {
  Controller, createProvideRegistry, createReplaceRegistry,
  getMoostInfact, Inherit, Injectable, Moost,
} from 'moost'
import { AppUser } from './models/user.as'
import { memberRole } from './roles/member'

@Controller('me')
@ArbacResource('me')
class MeController {
  @Get()
  @ArbacAction('read')
  whoami(@UserId() userId: string) {
    return { userId }
  }
}
```

::: warning `@Public()` is dual-purpose
`@Public()` from `@aooth/auth-moost` writes BOTH `authPublic=true` AND `arbacPublic=true`. There is no separate `@ArbacPublic` — bypassing one without the other was a deliberately-removed footgun.
:::

### 7a. The workflow

There is **one** workflow class — `AuthWorkflow` — declaring three `@Workflow` schemas (`auth/login/flow`, `auth/invite/start`, `auth/recovery/flow`). If the default opts suit you, register it directly:

```ts
app.registerControllers(AuthController, AuthWorkflow);
```

When you need custom infrastructure opts or to override `protected` policy hooks (`deliver`, `resolveXxx`), subclass it. Re-declare the **4-arg** constructor (the 4th param is the `ConsentStore`) so TS emits `design:paramtypes`:

```ts:line-numbers
import type { AuthDeliveryPayload, AuthWfCtx } from '@aooth/auth-moost'

@Inherit()
@Controller() // SINGLETON
class AppAuth extends AuthWorkflow {
  constructor(users: UserService, auth: AuthCredential, consents: ConsentStore) {
    super({ totpIssuer: 'AcmeCorp' }, users, auth, consents)
  }
  protected override resolveMfaPolicy(_ctx: AuthWfCtx) {
    return { mode: 'optional' as const, availableTransports: ['email', 'totp'] as const }
  }
  protected override async deliver(payload: AuthDeliveryPayload) {
    // forward to your EmailSender / SmsSender, routed by payload.kind + payload.channel
  }
}

app.setReplaceRegistry(createReplaceRegistry([AuthWorkflow, AppAuth]))
app.registerControllers(AuthController, AppAuth)
```

::: warning Re-apply decorators + re-declare the constructor
TypeScript emits fresh `design:paramtypes` per class — without the explicit 4-arg constructor, moost cannot resolve DI on the subclass. `@Inherit()` carries the parent's `@Workflow` / `@WorkflowSchema` / `@Step` / `@Public` metadata; `@Controller()` re-applies the SINGLETON scope (moost@0.6.x does not inherit it). Add `@Injectable("FOR_EVENT")` ONLY if the constructor reads request-scoped composables.
:::

### 7b. ARBAC user provider

```ts:line-numbers
import type { ArbacUserTable } from '@aooth/arbac-moost/atscript'

@Injectable()
class AppArbacUserProvider extends AtscriptArbacUserProvider<AppUser> {
  constructor() {
    // With `@arbac.userId username` (declared via the `annotate
    // AoothUserCredentials { ... }` block in src/models/user.as), the
    // provider looks up by `username` directly — no shim needed.
    super(AppUser, db.getTable(AppUser) as unknown as ArbacUserTable<AppUser>)
  }
  override getUserId(): string {
    // `useAuth().getUserId()` returns the username string — the auth subject
    // `UserService.login(username, password)` set. The annotated
    // `@arbac.userId username` makes the provider's lookup match.
    return useAuth().getUserId()
  }
}
```

The provider reads `@arbac.role` and `@arbac.attribute` from the user model and turns each request into `{ roles: string[], attrs: UserAttrs }` for the evaluator. The cast on `db.getTable(AppUser)` is required because `AtscriptDbTable.findOne` is typed wider (engine-specific `controls.*` keys) than `ArbacUserTable.findOne` — structurally compatible at runtime.

### 7c. WF trigger provider

The default `WfTriggerProvider` persists nothing durable (state rides inside the SPA-held encapsulated token) and has no email outlet. Subclass it to make state durable via `storeStrategy()` and add the magic-link mailer. The constructor is `(wf, auth)`.

```ts:line-numbers
@Injectable()
class AppWfTriggerProvider extends WfTriggerProvider {
  constructor(wf: MoostWf, auth: AuthCredential) {
    super(wf, auth)
    this.outlets = [
      ...this.outlets,
      createAuthEmailOutlet({
        emailSender,
        buildMagicLinkUrl: (kind, token, ctx) =>
          `${process.env.FRONTEND_URL}/${kind === 'recovery.magicLink' ? 'recover' : 'accept-invite'}?wfs=${token}${ctx?.userId ? `&uid=${ctx.userId}` : ''}`,
        magicLinkTtlMs: () => 60 * 60_000,
      }),
    ]
  }
  // Make the durable `store` strategy real — override storeStrategy(), do NOT assign `this.state`.
  protected override storeStrategy(): WfStateStrategy {
    return new HandleStateStrategy({ store: new AsWfStore({ table: tables.wfStates }) })
  }
}
```

### 7d. Boot

```ts:line-numbers
const app = new Moost()
const http = new MoostHttp()
app.adapter(http)
app.adapter(new MoostWf())

app.setProvideRegistry(createProvideRegistry(
  [AuthCredential, () => authCredential],
  [UserService,    () => userService],
  ['EmailSender',  () => emailSender],
))

app.setReplaceRegistry(createReplaceRegistry(
  [WfTriggerProvider,      AppWfTriggerProvider],
  [ArbacUserProviderToken, AppArbacUserProvider],
  [AuthWorkflow,           AppAuth],
))

app.applyGlobalInterceptors(authGuardInterceptor({ cookie: { secure: false } }))
app.applyGlobalInterceptors(formInputInterceptor())
app.applyGlobalInterceptors(arbacAuthorizeInterceptor)

app.registerControllers(AuthController, AppAuth, MeController)
await app.init()
await http.listen(3000)

const arbac = (await getMoostInfact().get(MoostArbac)) as MoostArbac<UserAttrs, ArbacDbScope>
arbac.registerRole(memberRole)
```

::: info Why register roles after `init()`
`MoostArbac` is `@Injectable()` and constructed lazily by moost's IoC container. Grabbing it via `getMoostInfact().get(MoostArbac)` after `init()` is the simple form — roles registered this way persist for the process lifetime. For larger role sets, prefer providing a pre-populated `MoostArbac` from your `setProvideRegistry` factory so the role list is set before any request hits the interceptor.
:::

## 8. Create a user and log in

Seed a user — the workflow is the production path, but for first boot you can call the service directly:

```ts:line-numbers
await userService.createUser('alice', 'CorrectHorse123', {
  tenantId: 't1',
  roles: ['member'],
} as Partial<AppUser>)
await userService.activateAccount('alice')
```

::: warning `createUser` writes `account.active: false`
`AuthWorkflow`'s invite accept phase relies on this default — pending invitees stay inactive until accept. For seed scripts and admin-create flows, **call `activateAccount(username)` after** or `login()` throws `UserAuthError("INACTIVE")`, which the login workflow deliberately re-maps to `"Invalid credentials"` (anti-enumeration). The client-side failure looks identical to a wrong password.
:::

Trigger the login workflow (this is the same wire your frontend's `<AsWfForm>` posts). **Start** a run by naming the workflow id in `wfid`; **resume** by sending back the `wfs` token plus `input`:

```bash
# Start — `wfid` names the workflow to start (no wfs yet)
curl -X POST http://localhost:3000/auth/trigger \
  -H 'content-type: application/json' \
  -d '{"wfid":"auth/login/flow"}'
```

The first call returns a paused-form envelope containing `LoginCredentialsForm` and a `wfs` token — the workflow-session handle, **reused on every subsequent step until the run finishes**. Submit credentials (form values go under `input.formData`):

```bash
curl -X POST http://localhost:3000/auth/trigger \
  -H 'content-type: application/json' \
  -d '{"wfs":"<wfs-from-initial-response>","input":{"formData":{"username":"alice","password":"CorrectHorse123"}}}'
```

::: tip `wfid` starts, `wfs` resumes
On **start** there is no token — the body carries `wfid` (the workflow id). On every later step the body carries the `wfs` token instead; the engine resumes the in-flight run. The `wfs` value stays the same across `wf.requireInput` re-renders, refresh, bookmark, and multi-tab — it only changes when the run finishes or a different workflow starts. See [Workflows — state tokens](../moost/workflows#workflow-state-tokens-wfs).
:::

On success the envelope's `type` is `"data"` and the response carries `aooth_session` + `aooth_refresh` cookies plus an `accessToken` in the body (because `enableBearer` defaults to `true`).

Hit the protected route:

```bash
curl http://localhost:3000/me -H 'Authorization: Bearer <accessToken>'
# → { "userId": "alice" }
```

## What the request just did

1. `authGuardInterceptor` validated the bearer token via `AuthCredential.validate()` and stashed `AuthContext { userId: 'alice' }` onto the event.
2. `arbacAuthorizeInterceptor` resolved `resource = 'me'` (from class-level `@ArbacResource('me')`), `action = 'read'` (from method-level `@ArbacAction('read')`), instantiated `AppArbacUserProvider`, fetched alice's `{ roles: ['member'], attrs: { tenantId: 't1' } }`, and called `Arbac.evaluate(...)`.
3. The `memberRole`'s `.allow('me', 'read')` rule matched. Scopes were set on the event.
4. The handler ran, `useAuth().getUserId()` returned `'alice'`, and moost serialised the response.

## What else `/auth/*` ships

`AuthController` mounts five routes under `@Controller('auth')`. All five are `@Public()` (the auth guard does not block them — they validate their own inputs):

| Method + path                      | Body / Query                   | Purpose                                                                                                               |
| ---------------------------------- | ------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| `POST /auth/logout`                | `{ refreshToken? }` (optional) | Revokes the current access token + refresh (cookie or body). Always clears `aooth_session` / `aooth_refresh` cookies. |
| `POST /auth/refresh`               | `{ refreshToken? }` (optional) | Trades a refresh token for a fresh access + refresh pair. Reads cookie if no body field.                              |
| `GET /auth/status`                 | —                              | Returns the resolved `AuthContext { userId, claims }` if the guard could validate; 401 otherwise.                     |
| `POST /auth/trigger`               | `{ wfid?, wfs?, input? }`      | Drives any workflow in `DEFAULT_AUTH_WORKFLOWS = ['auth/login/flow', 'auth/invite/start', 'auth/recovery/flow']`.     |
| `GET /auth/invite/post-redemption` | `?uid=<userId>`                | Idempotent "already accepted" envelope for re-clicked invite links (needs a `UserService`).                           |

Subclass `AuthController` to widen the trigger allow-list (override `triggerWf()` with your own `@WfTrigger({ allow })`).

Self-signup, password reset, and invite acceptance are all flows of the same `AuthWorkflow` — drive them through the same `/auth/trigger` wire by starting `auth/recovery/flow` or `auth/invite/start`. See the [Moost integration guide](../moost/) for the option + resolver surface.

## Common flows

End-to-end snippets for the four most-asked Day-1 recipes. Each one assumes the Quick Start app is running with `AppAuth` (the `AuthWorkflow` subclass) registered — all three flows live on that one class.

### Guard a single route by role

```ts:line-numbers
import { ArbacAction, ArbacResource, useArbac } from '@aooth/arbac-moost'
import { Controller, Get } from '@moostjs/event-http'
import { allowTableRead, defineRole } from '@aooth/arbac'

// Role: editors see only their own tenant's tasks.
export const editorRole = defineRole<UserAttrs, ArbacDbScope>()
  .id('editor')
  .allow('tasks', 'read')
  .use(allowTableRead<UserAttrs, ArbacDbScope>('tasks', {
    scope: (attrs) => ({ filter: { tenantId: attrs.tenantId } }),
  }))
  .build()

@Controller('tasks')
@ArbacResource('tasks')
class TasksController {
  @Get()
  @ArbacAction('read')
  async list() {
    // Pull the scope union from the request — apply it to your DB filter.
    const scopes = useArbac().getScopes<ArbacDbScope>() ?? []
    return tables.tasks.findMany({ filter: scopes[0]?.filter ?? {} })
  }
}
```

A request from a user whose `@arbac.attribute tenantId` is `'t1'` will see `scopes[0].filter = { tenantId: 't1' }` — apply it directly to the query.

### Password reset (recovery flow)

The recovery flow (`auth/recovery/flow`) is a multi-step run that pauses on each user interaction. The envelope's `wfs` is the **workflow-session handle** — the same value is reused across every step until the flow finishes. The magic-link email carries a distinct token because it crosses an out-of-band boundary; once clicked, the FE posts that token back as the new `wfs`.

```bash
# 1. Start: name the workflow with `wfid`; server returns wfs + the identifier form
curl -X POST http://localhost:3000/auth/trigger \
  -H 'content-type: application/json' \
  -d '{"wfid":"auth/recovery/flow"}'

# 2. Submit identifier (username or email) — server emits the magic-link email.
#    Same wfs from step 1 — the handle stays live across the pause.
curl -X POST http://localhost:3000/auth/trigger \
  -H 'content-type: application/json' \
  -d '{"wfs":"<wfs-from-step-1>","input":{"formData":{"identifier":"alice"}}}'

# 3. User clicks the magic-link URL from email; FE posts that token back as wfs
#    (this one IS a fresh token — it crossed the email outlet)
curl -X POST http://localhost:3000/auth/trigger \
  -H 'content-type: application/json' \
  -d '{"wfs":"<token-from-magic-link>","input":{"formData":{"newPassword":"NewCorrectHorse42!"}}}'
```

Wire `createAuthEmailOutlet({ emailSender, buildMagicLinkUrl })` into your `WfTriggerProvider` (step 7c above) — the outlet receives the kind `'recovery.magicLink'` and turns it into a clickable URL.

### Refresh-token flow

After login, the response carries `aooth_refresh` (HTTP-only cookie, path `/auth/refresh`) and the access token. To rotate before expiry:

```bash
# Browsers send the cookie automatically:
curl -X POST http://localhost:3000/auth/refresh \
  -b 'aooth_refresh=<refresh-token-from-login>'

# Or pass it explicitly in the body (for non-browser clients):
curl -X POST http://localhost:3000/auth/refresh \
  -H 'content-type: application/json' \
  -d '{"refreshToken":"<refresh-token-from-login>"}'
# → { accessToken, refreshToken, expiresIn, userId, ... }
```

With `refresh: { rotation: 'always' }` (the Quick Start setting) every call mints a NEW refresh and invalidates the previous one — replaying the old refresh raises `REFRESH_REUSE_DETECTED` and revokes all credentials for the user.

### Magic-link login

The login flow supports passwordless entry through the same email outlet — the recovery recipe above doubles as the magic-link primitive; the only difference is which `kind` the outlet receives (`recovery.magicLink` vs the invite kind). Your `buildMagicLinkUrl` callback branches on `kind` (and reads the optional `{ userId }` third arg for invites):

```ts
buildMagicLinkUrl: (kind, token, ctx) => {
  const path = kind === "invite.magicLink" ? "accept-invite" : "recover";
  return `${process.env.FRONTEND_URL}/${path}?wfs=${token}${ctx?.userId ? `&uid=${ctx.userId}` : ""}`;
};
```

The clicked URL's `wfs` query parameter is resumed identically (it's a resume token, so no `wfid`):

```bash
curl -X POST http://localhost:3000/auth/trigger \
  -H 'content-type: application/json' \
  -d '{"wfs":"<token-from-clicked-link>"}'
```

A successful resume drops the same cookies + access token as the password path.

## Next steps

- [Ecosystem & Packages](./ecosystem) — see what every package contributes and how they depend on each other.
- [Using atscript-db Models](./atscript-db) — add custom columns, layer in `@arbac.attribute`, and wire `syncSchema`.
- [Moost integration](../moost/) — the unified `AuthWorkflow`, its `resolveXxx` policy hooks, MFA, invites, password reset.
- [SPA Components](../moost/spa-components) — render the workflow forms (QR, consents, password rules) in your frontend.
- [ARBAC / Scopes](../arbac/scopes) — write scopes that filter DB queries automatically.
