import {
  arbacAuthorizeInterceptor,
  type ArbacDbScope,
  ArbacUserProviderToken,
  MoostArbac,
} from "@aoothjs/arbac-moost";
import { AtscriptArbacUserProvider } from "@aoothjs/arbac-moost/atscript";
import { AuthCredential, type EmailSender, type SmsSender } from "@aoothjs/auth";
import {
  type AuthEmailOutletDeps,
  AuthController,
  authGuardInterceptor,
  type DeliverPayload,
  InviteWorkflow,
  type InviteWorkflowOpts,
  LoginWorkflow,
  type LoginWorkflowOpts,
  RecoveryWorkflow,
  type RecoveryWorkflowOpts,
  useAuth,
} from "@aoothjs/auth-moost";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { UserService } from "@aoothjs/user";
import { formInputInterceptor } from "@atscript/moost-wf";
import { MoostHttp } from "@moostjs/event-http";
import { MoostWf } from "@moostjs/event-wf";
import {
  Controller,
  createProvideRegistry,
  createReplaceRegistry,
  getMoostInfact,
  Inherit,
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
import { DemoUser, InviteAcceptProfileForm } from "./models/user.as";
import { allRoles, type UserAttrs } from "./roles";
import { createWfStore } from "./wf-store";
import { makeHandoverWorkflow } from "./workflows/handover.workflow";

export interface BuildAppOptions {
  emailSender?: EmailSender;
  dbPath?: string;
  port?: number;
  envOverrides?: Partial<AppEnv>;
  /**
   * Per-workflow registration toggles. Defaults to all enabled. Used by
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

  // Console-stub SMS sender — kept here as a closure for the workflow
  // overrides. Defaults strip 'sms' from mfa.transports, so this only fires
  // if a consumer flips it back on.
  const demoSmsSender: SmsSender = {
    async send(event) {
      console.log("[demo SMS]", event.kind, event.recipient, event.code);
    },
  };

  // Shared `deliver()` body for both workflow subclasses below. The
  // discriminated `DeliverPayload` narrows `kind` to the matching transport
  // type, so no casts are needed when forwarding to EmailSender / SmsSender.
  const forwardDeliver = async (payload: DeliverPayload): Promise<void> => {
    if (payload.channel === "email") {
      await emailSender.send({
        kind: payload.kind,
        recipient: payload.recipient,
        ...(payload.code !== undefined && { code: payload.code }),
        ...(payload.url !== undefined && { url: payload.url }),
        expiresAt: payload.expiresAt ?? Date.now(),
        ...(payload.userId !== undefined && { username: payload.userId }),
        ...(payload.metadata && { metadata: payload.metadata }),
      });
      return;
    }
    await demoSmsSender.send({
      kind: payload.kind,
      recipient: payload.recipient,
      code: payload.code,
      ttlMs: payload.ttlMs ?? 0,
      ...(payload.userId !== undefined && { userId: payload.userId }),
    });
  };

  // Phase-2 reshape: `LoginWorkflow` is configured via a consumer subclass
  // that overrides `protected` methods. `@Inherit()` carries the base
  // class's `@Workflow` / `@WorkflowSchema` / `@Step` metadata; the
  // re-declared ctor is required because TS emits fresh design-paramtypes per
  // class.
  const demoLoginOpts: LoginWorkflowOpts = {
    // Representative demo subset — no SMS gateway in the demo, so we strip
    // 'sms' from the default mfa.transports list.
    mfa: { transports: ["email", "totp"] },
    alternateCredentials: { forgotPassword: true },
    guards: { passwordInitial: true },
  };
  @Inherit()
  @Injectable("FOR_EVENT")
  @Controller()
  class DemoLoginWorkflow extends LoginWorkflow {
    constructor(users: UserService, authCred: AuthCredential) {
      super(demoLoginOpts, users, authCred);
    }
    protected override deliver(payload: DeliverPayload) {
      return forwardDeliver(payload);
    }
  }

  // Phase-3 reshape: `RecoveryWorkflow` is configured via a consumer subclass
  // that overrides `protected` methods. The demo overrides `deliver` for OTP
  // emails (magic-link mode uses the email outlet on the trigger route) and
  // `emailToUserId` to map a recovery-step email to the canonical username.
  const demoRecoveryOpts: RecoveryWorkflowOpts = {
    delivery: { magicLinkTtlMs: env.RECOVERY_TTL_MS },
    // BIG 3.2 defaults flipped `freshLoginRequired` to true (redirect to
    // /login after reset) and `revokeAllSessions` to true (kick every active
    // session). The demo preserves the prior behavior (auto-login;
    // pre-existing sessions left intact) so the existing e2e tests keep
    // asserting the same outcomes; production consumers should leave the
    // secure defaults on.
    postReset: { freshLoginRequired: false, revokeAllSessions: false },
  };
  @Inherit()
  @Injectable("FOR_EVENT")
  @Controller()
  class DemoRecoveryWorkflow extends RecoveryWorkflow {
    constructor(users: UserService, authCred: AuthCredential) {
      super(demoRecoveryOpts, users, authCred);
    }
    protected override deliver(payload: DeliverPayload) {
      return forwardDeliver(payload);
    }
    // Maps a recovery-step email to the canonical username. In this demo
    // `DemoUser.username` happens to equal `DemoUser.email` for seeded users,
    // so a direct email lookup is enough — but the indirection is what makes
    // recovery work for any user model where `username !== email`.
    protected override async emailToUserId(email: string): Promise<string | null> {
      const user = await aooth.userStore.findByUsername(email);
      return user ? user.username : null;
    }
  }

  // Phase-4 reshape: `InviteWorkflow` is also configured via a consumer
  // subclass that overrides `protected` methods — matching login + recovery.
  const demoInviteOpts: InviteWorkflowOpts = {
    send: { tokenTtlMs: env.INVITE_TTL_MS },
    // Existing demo tests assert the auto-login response payload — pre-dating
    // the BIG 3.3 confirmation pause. Off here so the demo matches today's
    // behavior; production should keep the default ON.
    accept: { showConfirmation: false },
  };
  @Inherit()
  @Injectable("FOR_EVENT")
  @Controller()
  class DemoInviteWorkflow extends InviteWorkflow {
    constructor(users: UserService, authCred: AuthCredential) {
      super(demoInviteOpts, users, authCred);
    }
    protected override deliver(payload: DeliverPayload) {
      // Invite's default send path uses `outletEmail` (handled by the
      // createAuthEmailOutlet at the trigger route); deliver() runs only if a
      // future override drives a manual send. Reuse the shared forwarder for
      // parity with login/recovery.
      return forwardDeliver(payload);
    }
    // Demonstrates the `prepareUser` hook: populate the consumer-required
    // `tenantId` field before `userService.createUser` runs.
    protected override async prepareUser(): Promise<Record<string, unknown>> {
      return { tenantId: "_global" };
    }
    // Demonstrates the consumer-supplied profile form. `applyProfile` defaults
    // to `users.update(username, profile)` when not overridden; the explicit
    // override below proves the escape hatch reaches user-supplied code.
    protected override getProfileForm(): TAtscriptAnnotatedType {
      return InviteAcceptProfileForm as unknown as TAtscriptAnnotatedType;
    }
    protected override async applyProfile(input: {
      username: string;
      profile: Record<string, unknown>;
    }): Promise<void> {
      await aooth.userService.update(input.username, input.profile as Record<string, never>);
    }
  }

  // Canonical REST + guard wiring + per-workflow providers registered via DI.
  // `UserService` is only consumed by `AuthController`; skipping the controller
  // leaves the guard active for the rest of the app (used by DX-08).
  const authProviders: Parameters<typeof createProvideRegistry> = [
    [AuthCredential, () => aooth.authCredential],
    [UserService, () => aooth.userService],
    // `EmailSender` is still consumed by `createAuthEmailOutlet` (the
    // trigger-side mailer for magic-link outlets). The three auth workflows
    // themselves no longer consume DI for senders/audit/trust/rate-limit —
    // they use `protected` method overrides (see the subclasses above).
    ["EmailSender", () => emailSender],
  ];
  app.setProvideRegistry(createProvideRegistry(...authProviders));
  app.applyGlobalInterceptors(authGuardInterceptor({ cookie: { secure: false } }));
  app.applyGlobalInterceptors(formInputInterceptor());
  if (opts.authEndpointsEnabled !== false) {
    app.registerControllers(AuthController);
  }

  const wfEnabled = opts.workflowsEnabled ?? {};
  const wfControllers: Array<new (...args: never[]) => unknown> = [];
  if (wfEnabled.login !== false) wfControllers.push(DemoLoginWorkflow);
  if (wfEnabled.recovery !== false) wfControllers.push(DemoRecoveryWorkflow);
  if (wfEnabled.invite !== false) wfControllers.push(DemoInviteWorkflow);
  if (wfControllers.length > 0) {
    app.registerControllers(...wfControllers);
  }

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
      return useAuth().getUserId();
    }
  }
  app.setReplaceRegistry(createReplaceRegistry([ArbacUserProviderToken, DemoArbacUserProvider]));

  app.applyGlobalInterceptors(arbacAuthorizeInterceptor);

  app.registerControllers(
    ...buildAppControllers(appDb, wfStateStore, {
      emailSender,
      buildMagicLinkUrl: aooth.buildMagicLinkUrl,
      magicLinkTtlMs: (kind) =>
        kind === "invite.magicLink" ? env.INVITE_TTL_MS : env.RECOVERY_TTL_MS,
    }),
  );

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
  emailOutletDeps: AuthEmailOutletDeps,
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
    makeWfTriggerController(wfStateStore, emailOutletDeps),
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
