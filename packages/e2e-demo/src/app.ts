import {
  applyArbacGuardGlobally,
  type ArbacDbScope,
  ArbacUserProvider,
  MoostArbac,
} from "@aoothjs/arbac-moost"
import {
  AutoArbacUserProvider,
  setUserRecordFetcher,
} from "@aoothjs/arbac-moost/atscript"
import type { EmailSender } from "@aoothjs/auth"
import {
  setupAuthMoost,
  setupAuthWorkflows,
  useAuth,
} from "@aoothjs/auth-moost"
import { MoostHttp } from "@moostjs/event-http"
import { MoostWf } from "@moostjs/event-wf"
import {
  createReplaceRegistry,
  getMoostInfact,
  Injectable,
  Moost,
} from "moost"
import type { AddressInfo } from "node:net"

import { type AppAuth, createAooth } from "./aooth"
import { type AppDb, createAppDb, syncAppSchema } from "./db"
import { ConsoleEmailSender } from "./email/console-email-sender"
import { type AppEnv, ENV } from "./env"
import {
  HealthController,
  makeAuditController,
  makeCommentsController,
  makeDepartmentsController,
  makeDocumentsController,
  makeProjectsController,
  makeTasksController,
  makeTenantsController,
  makeUsersController,
  makeWfTriggerController,
} from "./controllers"
import { DemoUser } from "./models/user.as"
import { allRoles, type UserAttrs } from "./roles"
import { createWfStore } from "./wf-store"
import { makeHandoverWorkflow } from "./workflows/handover.workflow"

export interface BuildAppOptions {
  emailSender?: EmailSender
  dbPath?: string
  port?: number
  envOverrides?: Partial<AppEnv>
  /**
   * Per-workflow registration toggles forwarded to
   * `setupAuthWorkflows({ workflows })`. Defaults to all enabled. Used by
   * DX-07 to assert that a disabled workflow (`auth.invite`) is unreachable.
   */
  workflowsEnabled?: { login?: boolean; recovery?: boolean; invite?: boolean }
  /**
   * Forwarded to `setupAuthMoost({ endpoints })`. When `false`, the bundled
   * `AuthController` (login/logout/refresh/status/password) is NOT registered;
   * the auth GUARD is still installed globally. Used by DX-08.
   */
  authEndpointsEnabled?: boolean
}

export interface AppHandle {
  app: Moost
  appDb: AppDb
  baseUrl: string
  emailSender: EmailSender
  aooth: AppAuth
  close: () => Promise<void>
}

export async function buildApp(opts: BuildAppOptions = {}): Promise<AppHandle> {
  const env: AppEnv = { ...ENV, ...opts.envOverrides }
  const dbPath = opts.dbPath ?? env.DB_PATH
  const port = opts.port ?? env.PORT

  const appDb = createAppDb(dbPath)
  await syncAppSchema(appDb)

  const emailSender: EmailSender = opts.emailSender ?? new ConsoleEmailSender()
  const aooth = createAooth({ tables: appDb.tables, env })
  const wfStateStore = createWfStore(appDb)

  const app = new Moost()
  const moostHttp = new MoostHttp()
  app.adapter(moostHttp)
  app.adapter(new MoostWf())

  setupAuthMoost(app, {
    authCredential: aooth.authCredential,
    userService: aooth.userService,
    cookie: { secure: false },
    endpoints: opts.authEndpointsEnabled,
  })
  setupAuthWorkflows(app, {
    emailSender,
    buildMagicLinkUrl: aooth.buildMagicLinkUrl,
    wfStateStore,
    recoveryTokenTtlMs: env.RECOVERY_TTL_MS,
    inviteTokenTtlMs: env.INVITE_TTL_MS,
    workflows: opts.workflowsEnabled,
    // Demonstrates the `prepareUser` hook: populate the consumer-required
    // `tenantId` field before `userService.createUser` runs. Admins re-tenant
    // invitees later via the user-management UI.
    prepareUser: () => ({ tenantId: "_global" }),
    // Demonstrates the `emailToUserId` resolver: maps a recovery-step email
    // to the canonical username. In this demo `DemoUser.username` happens to
    // equal `DemoUser.email` for seeded users, so a direct email lookup is
    // enough — but the indirection is what makes recovery work for any user
    // model where `username !== email`.
    emailToUserId: async (email) => {
      const user = await aooth.userStore.findByUsername(email)
      return user ? user.username : null
    },
  })

  setUserRecordFetcher((userId) => aooth.arbacUserReader.read(userId))

  // Bind the atscript-driven user provider to the JWT subject for ARBAC.
  @Injectable()
  class DemoArbacUserProvider extends AutoArbacUserProvider {
    constructor() {
      super(DemoUser, () => useAuth().getCurrentUserId())
    }
  }
  app.setReplaceRegistry(
    createReplaceRegistry([ArbacUserProvider, DemoArbacUserProvider]),
  )

  applyArbacGuardGlobally(app)

  app.registerControllers(...buildAppControllers(appDb, wfStateStore))

  await app.init()
  await moostHttp.listen(port)

  const arbac = (await getMoostInfact().get(MoostArbac)) as MoostArbac<UserAttrs, ArbacDbScope>
  for (const role of allRoles) arbac.registerRole(role)

  const baseUrl = `http://localhost:${resolveListeningPort(moostHttp, port)}`
  const close = async (): Promise<void> => {
    const server = moostHttp.getHttpApp().getServer()
    if (server) {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()))
      })
    }
    appDb.close()
  }

  return { app, appDb, baseUrl, emailSender, aooth, close }
}

function buildAppControllers(
  appDb: AppDb,
  wfStateStore: ReturnType<typeof createWfStore>,
): ReadonlyArray<new (...args: never[]) => unknown> {
  const t = appDb.tables
  return [
    HealthController,
    makeTenantsController(t.tenants),
    makeUsersController(t.users),
    makeDepartmentsController(t.departments),
    makeProjectsController(t.projects),
    makeTasksController(t.tasks),
    makeCommentsController(t.comments),
    makeDocumentsController(t.documents),
    makeAuditController(t.audit),
    makeWfTriggerController(wfStateStore),
    makeHandoverWorkflow({
      projectsTable: t.projects,
      usersTable: t.users,
      auditTable: t.audit,
    }),
  ]
}

function resolveListeningPort(moostHttp: MoostHttp, fallback: number): number {
  const addr = moostHttp.getHttpApp().getServer()?.address() as
    | AddressInfo
    | string
    | null
  return addr && typeof addr === "object" && "port" in addr ? addr.port : fallback
}
