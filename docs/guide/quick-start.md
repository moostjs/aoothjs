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
         jose better-sqlite3
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

The cast on `tables.users` is required: `AtscriptDbTable<T>` returns `Record<string, unknown>` from its structural reads — `AuthUserTable<T>` narrows that surface to what `UsersStoreAtscriptDb` actually calls. See [`aooth.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/e2e-demo/src/aooth.ts).

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

`allow('me', 'read')` matches the controller below — `@ArbacResource('me')` + `@ArbacAction('read')` lookups against the role's rule list.

## 7. Build the moost app

```ts:line-numbers
import {
  arbacAuthorizeInterceptor,
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
class MeController {
  @Get()
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
`MoostArbac` is `@Injectable()` and constructed lazily by moost's IoC container. Grabbing it via `getMoostInfact().get(MoostArbac)` after `init()` is the supported way to get the singleton instance for `registerRole(...)`. Roles registered this way persist for the process lifetime.
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
2. `arbacAuthorizeInterceptor` resolved `resource = 'me'` (from `@ArbacResource` defaulting to controller `id`), `action = 'read'` (from the method name), instantiated `AppArbacUserProvider`, fetched alice's `{ roles: ['member'], attrs: { tenantId: 't1' } }`, and called `Arbac.evaluate(...)`.
3. The `memberRole`'s `.allow('me', 'read')` rule matched. Scopes were set on the event.
4. The handler ran, `useAuth().getUserId()` returned `'alice'`, and moost serialised the response.

## Next steps

- [Ecosystem & Packages](./ecosystem) — see what every package contributes and how they depend on each other.
- [Using atscript-db Models](./atscript-db) — add custom columns, layer in `@arbac.attribute`, and wire `syncSchema`.
- [Moost integration](../moost/) — extend `LoginWorkflow` / `RecoveryWorkflow` / `InviteWorkflow` with MFA, invites, password reset.
- [ARBAC / Scopes](../arbac/scopes) — write scopes that filter DB queries automatically.
