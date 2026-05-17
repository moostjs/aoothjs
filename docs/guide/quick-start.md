# Quick Start

This walkthrough builds a minimal moost HTTP app with:

- A `.as`-modelled user table backed by `@atscript/db-sqlite`.
- JWT-issued sessions managed by `AuthCredential`.
- `LoginWorkflow` / `RecoveryWorkflow` / `InviteWorkflow` mounted under `/auth/trigger`.
- An ARBAC-aware `GET /me` route guarded by both the auth and arbac interceptors.

Every snippet below is lifted from the working `packages/e2e-demo/` app — wire each block in order and you have a runnable server. Source references: [`e2e-demo/src/app.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/e2e-demo/src/app.ts) and [`e2e-demo/src/aooth.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/e2e-demo/src/aooth.ts).

## 1. Install packages

```bash
pnpm add @aoothjs/user @aoothjs/auth @aoothjs/auth-moost \
         @aoothjs/arbac @aoothjs/arbac-moost \
         moost @moostjs/event-http @moostjs/event-wf \
         @atscript/db @atscript/db-sqlite @atscript/moost-wf \
         better-sqlite3
pnpm add -D @atscript/core @atscript/typescript unplugin-atscript
```

::: info Catalogued versions
The aoothjs monorepo pins `moost`, `@moostjs/*`, `@atscript/*`, and `vite-plus` in `pnpm-workspace.yaml`. Match those versions when consuming the `@aoothjs/*` workspace packages out-of-tree.
:::

## 2. Configure atscript

Create `atscript.config.mts` so the compiler understands the `@arbac.*` annotations used by the bundled `AoothArbacUserCredentials` model.

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

Add `"gen:atscript": "asc -f dts"` to `package.json` and run it once: it emits `*.as.d.ts` siblings next to every `.as` file.

## 3. Define your user model

Extend `AoothArbacUserCredentials` to add the columns your app needs. Mark one `@arbac.attribute` per scope key (here, `tenantId`) — those become the keys the role's `scope` functions can read.

::: code-group

```ts [src/models/user.as]
import { AoothArbacUserCredentials } from '@aoothjs/arbac-moost/atscript/models'

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
`AoothArbacUserCredentials` is just `AoothUserCredentials` + `@arbac.role roles: string[]`. If you only need authentication (no RBAC) you can extend `@aoothjs/user/atscript-db/model.as`'s `AoothUserCredentials` directly. See [Using atscript-db Models](./atscript-db).
:::

## 4. Wire the database

```ts:line-numbers
import { DbSpace } from '@atscript/db'
import { syncSchema } from '@atscript/db/sync'
import { BetterSqlite3Driver, SqliteAdapter } from '@atscript/db-sqlite'
import { AoothAuthCredential } from '@aoothjs/auth/atscript-db/model.as'
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
import { AuthCredential, CredentialStoreJwt, DenylistStoreMemory } from '@aoothjs/auth'
import { UserService } from '@aoothjs/user'
import { UsersStoreAtscriptDb, type AuthUserTable } from '@aoothjs/user/atscript-db'
import { CredentialStoreAtscriptDb } from '@aoothjs/auth/atscript-db'
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
import { allowTableRead, defineRole } from '@aoothjs/arbac'
import type { ArbacDbScope } from '@aoothjs/arbac-moost'

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
} from '@aoothjs/arbac-moost'
import { AtscriptArbacUserProvider } from '@aoothjs/arbac-moost/atscript'
import {
  AuthController,
  authGuardInterceptor,
  createAuthEmailOutlet,
  InviteWorkflow,
  LoginWorkflow,
  RecoveryWorkflow,
  useAuth,
  UserId,
  WfTrigger,
  WfTriggerProvider,
} from '@aoothjs/auth-moost'
import { AuthCredential } from '@aoothjs/auth'
import { UserService } from '@aoothjs/user'
import { formInputInterceptor } from '@atscript/moost-wf'
import { HandleStateStrategy, MoostWf } from '@moostjs/event-wf'
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
`@Public()` from `@aoothjs/auth-moost` writes BOTH `authPublic=true` AND `arbacPublic=true`. There is no separate `@ArbacPublic` — bypassing one without the other was a deliberately-removed footgun.
:::

### 7a. Workflow subclasses

`LoginWorkflow` is configured by **subclassing** — the constructor accepts your options and you override `protected` methods for delivery, audit, role inference, etc.

```ts:line-numbers
import type { DeliverPayload } from '@aoothjs/auth-moost'

@Inherit()
@Injectable('FOR_EVENT')
@Controller()
class AppLoginWorkflow extends LoginWorkflow {
  constructor(users: UserService, auth: AuthCredential) {
    super({ mfa: { transports: ['email', 'totp'] } }, users, auth)
  }
  protected override async deliver(payload: DeliverPayload) {
    // forward to your EmailSender / SmsSender
  }
}
```

::: warning Re-declare the constructor
TypeScript emits fresh `design:paramtypes` per class. Without the explicit constructor, moost cannot resolve the parent's DI dependencies on the subclass. The `@Inherit()` decorator carries the parent class's `@Workflow` / `@WorkflowSchema` / `@Step` metadata down.
:::

Do the same for `RecoveryWorkflow` and `InviteWorkflow`. For brevity this Quick Start mounts only `AppLoginWorkflow`.

::: warning Workflows not registered → 400 on trigger
`AuthController.triggerWf` accepts `DEFAULT_AUTH_WORKFLOWS = ['auth.login', 'auth.recovery', 'auth.invite']`. With only `AppLoginWorkflow` registered, a `POST /auth/trigger` with `{"wfs":"auth.recovery"}` will 400 because the workflow id is not registered with `MoostWf`. Register the matching subclass before exposing the corresponding flow.
:::

### 7b. ARBAC user provider

```ts:line-numbers
@Injectable()
class AppArbacUserProvider extends AtscriptArbacUserProvider<AppUser> {
  constructor() {
    super(AppUser, {
      async findOne(q: { filter: Record<string, unknown> }) {
        const userId = q.filter.id as string | undefined
        if (!userId) return null
        return (await userStore.findByUsername(userId)) as AppUser | null
      },
    })
  }
  override getUserId(): string {
    return useAuth().getUserId()
  }
}
```

The provider reads `@arbac.role` and `@arbac.attribute` from the user model and turns each request into `{ roles: string[], attrs: UserAttrs }` for the evaluator.

### 7c. WF trigger provider

The default `WfTriggerProvider` uses an in-memory state store and no email outlet. Subclass it to swap in your DB-backed state store and add the magic-link mailer.

```ts:line-numbers
import { AsWfStore } from '@atscript/moost-wf/store'

@Injectable()
class AppWfTriggerProvider extends WfTriggerProvider {
  constructor(wf: MoostWf) {
    super(wf)
    this.state = new HandleStateStrategy({
      store: new AsWfStore({ table: tables.wfStates }),
    })
    this.outlets = [
      ...this.outlets,
      createAuthEmailOutlet({
        emailSender,
        buildMagicLinkUrl: (kind, token) =>
          `${process.env.FRONTEND_URL}/${kind === 'recovery.magicLink' ? 'recover' : 'accept-invite'}?wfs=${token}`,
        magicLinkTtlMs: () => 60 * 60_000,
      }),
    ]
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
  [WfTriggerProvider,    AppWfTriggerProvider],
  [ArbacUserProviderToken, AppArbacUserProvider],
))

app.applyGlobalInterceptors(authGuardInterceptor({ cookie: { secure: false } }))
app.applyGlobalInterceptors(formInputInterceptor())
app.applyGlobalInterceptors(arbacAuthorizeInterceptor)

app.registerControllers(AuthController, AppLoginWorkflow, MeController)
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
```

Trigger the login workflow (this is the same envelope your frontend posts):

```bash
curl -X POST http://localhost:3000/auth/trigger \
  -H 'content-type: application/json' \
  -d '{"wfs":"auth.login"}'
```

The first call returns a paused-form envelope (`type: "wait"`) containing `LoginCredentialsForm`. Submit credentials:

```bash
curl -X POST http://localhost:3000/auth/trigger \
  -H 'content-type: application/json' \
  -d '{"wfs":"<token-from-previous>","input":{"username":"alice","password":"CorrectHorse123"}}'
```

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

`AuthController` mounts four routes under `@Controller('auth')`. All four are `@Public()` (the auth guard does not block them — they validate their own inputs):

| Method + path        | Body                           | Purpose                                                                                                               |
| -------------------- | ------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| `POST /auth/logout`  | `{ refreshToken? }` (optional) | Revokes the current access token + refresh (cookie or body). Always clears `aooth_session` / `aooth_refresh` cookies. |
| `POST /auth/refresh` | `{ refreshToken? }` (optional) | Trades a refresh token for a fresh access + refresh pair. Reads cookie if no body field.                              |
| `GET /auth/status`   | —                              | Returns the resolved `AuthContext { userId, claims }` if the guard could validate; 401 otherwise.                     |
| `POST /auth/trigger` | `{ wfs, input? }`              | Drives any workflow in `DEFAULT_AUTH_WORKFLOWS = ['auth.login', 'auth.recovery', 'auth.invite']`.                     |

Subclass `AuthController` to widen the trigger allow-list (override `triggerWf()` with your own `@WfTrigger({ allow })`).

For self-signup, password reset, or invite acceptance use `RecoveryWorkflow` / `InviteWorkflow` — same subclass pattern as `LoginWorkflow`, mounted via the same `/auth/trigger` envelope. See the [Moost integration guide](../moost/) for the per-workflow option surface.

## Common flows

End-to-end snippets for the four most-asked Day-1 recipes. Each one assumes the Quick Start app is running and `AppRecoveryWorkflow` / `AppInviteWorkflow` are registered when relevant.

### Guard a single route by role

```ts:line-numbers
import { ArbacAction, ArbacResource, useArbac } from '@aoothjs/arbac-moost'
import { Controller, Get } from '@moostjs/event-http'
import { allowTableRead, defineRole } from '@aoothjs/arbac'

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

`RecoveryWorkflow` is a multi-step workflow that pauses on each user interaction. The envelope's `wfs` is the resume token.

```bash
# 1. Start: server returns wfs + RecoveryRequestForm
curl -X POST http://localhost:3000/auth/trigger \
  -H 'content-type: application/json' \
  -d '{"wfs":"auth.recovery"}'

# 2. Submit identifier (username or email) — server emits the magic-link email
curl -X POST http://localhost:3000/auth/trigger \
  -H 'content-type: application/json' \
  -d '{"wfs":"<token-from-step-1>","input":{"identifier":"alice"}}'

# 3. User clicks the magic-link URL from email; FE posts it back as the new wfs
curl -X POST http://localhost:3000/auth/trigger \
  -H 'content-type: application/json' \
  -d '{"wfs":"<token-from-magic-link>","input":{"newPassword":"NewCorrectHorse42!"}}'
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

`LoginWorkflow` supports passwordless entry through the same email outlet. The recovery recipe above doubles as the magic-link primitive — the only difference is which `kind` the outlet receives (`login.magicLink` vs `recovery.magicLink`). Your `buildMagicLinkUrl` callback should branch on the `kind`:

```ts
buildMagicLinkUrl: (kind, token) => {
  const path = kind === "login.magicLink" ? "login" : "recover";
  return `${process.env.FRONTEND_URL}/${path}?wfs=${token}`;
};
```

The clicked URL's `wfs` query parameter is resumed identically:

```bash
curl -X POST http://localhost:3000/auth/trigger \
  -H 'content-type: application/json' \
  -d '{"wfs":"<token-from-clicked-link>"}'
# → final envelope: { type: "data", end: { action: "data", data: { accessToken, ... } } }
```

A successful resume drops the same cookies + access token as the password path.

## Next steps

- [Ecosystem & Packages](./ecosystem) — see what every package contributes and how they depend on each other.
- [Using atscript-db Models](./atscript-db) — add custom columns, layer in `@arbac.attribute`, and wire `syncSchema`.
- [Moost integration](../moost/) — extend `LoginWorkflow` / `RecoveryWorkflow` / `InviteWorkflow` with MFA, invites, password reset.
- [ARBAC / Scopes](../arbac/scopes) — write scopes that filter DB queries automatically.
