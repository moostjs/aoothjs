import {
  arbacAuthorizeInterceptor,
  type ArbacDbScope,
  ArbacUserProvider,
  MoostArbac,
} from "@aoothjs/arbac-moost";
import { AtscriptArbacUserProvider } from "@aoothjs/arbac-moost/atscript";
import { AuthCredential, type EmailSender } from "@aoothjs/auth";
import {
  AuthController,
  authGuardInterceptor,
  MoostAuthConfig,
  setupAuthWorkflows,
  useAuth,
} from "@aoothjs/auth-moost";
import { UserService } from "@aoothjs/user";
import { MoostHttp } from "@moostjs/event-http";
import { MoostWf } from "@moostjs/event-wf";
import {
  createProvideRegistry,
  createReplaceRegistry,
  getMoostInfact,
  Injectable,
  Moost,
} from "moost";
import type { AddressInfo } from "node:net";

import { type AppAuth, createAooth } from "./aooth";
import { type AppDb, createAppDb, syncAppSchema } from "./db";
import { ConsoleEmailSender } from "./email/console-email-sender";
import { type AppEnv, ENV } from "./env";
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
} from "./controllers";
import { DemoUser } from "./models/user.as";
import { allRoles, type UserAttrs } from "./roles";
import { createWfStore } from "./wf-store";
import { makeHandoverWorkflow } from "./workflows/handover.workflow";

export interface BuildAppOptions {
  emailSender?: EmailSender;
  dbPath?: string;
  port?: number;
  envOverrides?: Partial<AppEnv>;
  /**
   * Per-workflow registration toggles forwarded to
   * `setupAuthWorkflows({ workflows })`. Defaults to all enabled. Used by
   * DX-07 to assert that a disabled workflow (`auth.invite`) is unreachable.
   */
  workflowsEnabled?: { login?: boolean; recovery?: boolean; invite?: boolean };
  /**
   * When `false`, the bundled `AuthController` (login/logout/refresh/status/
   * password) is NOT registered; the auth GUARD is still installed globally.
   * Used by DX-08.
   */
  authEndpointsEnabled?: boolean;
}

export interface AppHandle {
  app: Moost;
  appDb: AppDb;
  baseUrl: string;
  emailSender: EmailSender;
  aooth: AppAuth;
  close: () => Promise<void>;
}

export async function buildApp(opts: BuildAppOptions = {}): Promise<AppHandle> {
  const env: AppEnv = { ...ENV, ...opts.envOverrides };
  const dbPath = opts.dbPath ?? env.DB_PATH;
  const port = opts.port ?? env.PORT;

  const appDb = createAppDb(dbPath);
  await syncAppSchema(appDb);

  const emailSender: EmailSender = opts.emailSender ?? new ConsoleEmailSender();
  const aooth = createAooth({ tables: appDb.tables, env });
  const wfStateStore = createWfStore(appDb);

  const app = new Moost();
  const moostHttp = new MoostHttp();
  app.adapter(moostHttp);
  app.adapter(new MoostWf());

  // Canonical REST + guard wiring: DI providers (`AuthCredential`,
  // `UserService`, `MoostAuthConfig`) + global `authGuardInterceptor` +
  // optional `AuthController`. `UserService` is only consumed by
  // `AuthController`; skipping the controller leaves the guard active for
  // the rest of the app (used by DX-08).
  const authProviders: Parameters<typeof createProvideRegistry> = [
    [AuthCredential, () => aooth.authCredential],
    [UserService, () => aooth.userService],
    [MoostAuthConfig, () => new MoostAuthConfig({ cookie: { secure: false } })],
  ];
  app.setProvideRegistry(createProvideRegistry(...authProviders));
  app.applyGlobalInterceptors(authGuardInterceptor);
  if (opts.authEndpointsEnabled !== false) {
    app.registerControllers(AuthController);
  }

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
      const user = await aooth.userStore.findByUsername(email);
      return user ? user.username : null;
    },
  });

  // Bind the atscript-driven user provider to the JWT subject for ARBAC.
  // `DemoUser.@meta.id` is a UUID but the JWT subject is `username`;
  // `userStore.findByUsername` resolves either, so wrap it in the minimal
  // `ArbacUserTable` shim and ignore the projection (small fixture, low
  // payoff to optimize). This is the consumer-side override seam.
  const arbacUserTable = {
    async findOne(query: { filter: Record<string, unknown> }): Promise<DemoUser | null> {
      const userId = query.filter.id as string | undefined;
      if (!userId) return null;
      const user = await aooth.userStore.findByUsername(userId);
      return (user as DemoUser | null) ?? null;
    },
  };

  // `@Injectable()` (SINGLETON) — moost@0.6.x does NOT inherit injectable
  // metadata across `extends`, so each consumer subclass must re-apply it.
  // Per-event memoization happens via a wooks-slot cache inside
  // `AtscriptArbacUserProvider`.
  @Injectable()
  class DemoArbacUserProvider extends AtscriptArbacUserProvider<DemoUser> {
    constructor() {
      super(DemoUser, arbacUserTable);
    }
    override getUserId(): string {
      return useAuth().getCurrentUserId();
    }
  }
  app.setReplaceRegistry(createReplaceRegistry([ArbacUserProvider, DemoArbacUserProvider]));

  app.applyGlobalInterceptors(arbacAuthorizeInterceptor);

  app.registerControllers(...buildAppControllers(appDb, wfStateStore));

  await app.init();
  await moostHttp.listen(port);

  const arbac = (await getMoostInfact().get(MoostArbac)) as MoostArbac<UserAttrs, ArbacDbScope>;
  for (const role of allRoles) arbac.registerRole(role);

  const baseUrl = `http://localhost:${resolveListeningPort(moostHttp, port)}`;
  const close = async (): Promise<void> => {
    const server = moostHttp.getHttpApp().getServer();
    if (server) {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    }
    appDb.close();
  };

  return { app, appDb, baseUrl, emailSender, aooth, close };
}

function buildAppControllers(
  appDb: AppDb,
  wfStateStore: ReturnType<typeof createWfStore>,
): ReadonlyArray<new (...args: never[]) => unknown> {
  const t = appDb.tables;
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
  ];
}

function resolveListeningPort(moostHttp: MoostHttp, fallback: number): number {
  const addr = moostHttp.getHttpApp().getServer()?.address() as AddressInfo | string | null;
  return addr && typeof addr === "object" && "port" in addr ? addr.port : fallback;
}
