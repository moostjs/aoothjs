import {
  arbacAuthorizeInterceptor,
  type ArbacDbScope,
  ArbacUserProviderToken,
  MoostArbac,
} from "@aooth/arbac-moost";
import { AtscriptArbacUserProvider } from "@aooth/arbac-moost/atscript";
import { AuthCredential, type EmailSender, type SmsSender } from "@aooth/auth";
import {
  AuthController,
  authGuardInterceptor,
  createAuthEmailOutlet,
  DEFAULT_AUTH_WORKFLOWS,
  type DeliverPayload,
  InviteWorkflow,
  type InviteWorkflowOpts,
  LoginWorkflow,
  type LoginWorkflowOpts,
  Public,
  RecoveryWorkflow,
  type RecoveryWorkflowOpts,
  useAuth,
  WfTrigger,
  WfTriggerProvider,
} from "@aooth/auth-moost";
import { HandleStateStrategy } from "@moostjs/event-wf";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { UserService } from "@aooth/user";
import { MoostHttp, Post } from "@moostjs/event-http";
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
  /**
   * E2E coverage hook — per-workflow option overrides deep-merged into the
   * demo defaults (one nested group at a time, e.g. `{ mfa: { enabled: false } }`
   * replaces only `mfa.enabled` and preserves `mfa.transports`). Used by the
   * workflow-options e2e specs to flip a single flag without forking the
   * whole demo wiring.
   */
  loginOpts?: LoginWorkflowOpts;
  recoveryOpts?: RecoveryWorkflowOpts;
  inviteOpts?: InviteWorkflowOpts;
}

/** Two-level deep merge — sufficient for the nested-pojo workflow opts. */
function mergeWfOpts<T>(base: T, over?: T): T {
  if (!over) return base;
  const baseRec = base as unknown as Record<string, unknown>;
  const overRec = over as unknown as Record<string, unknown>;
  const out: Record<string, unknown> = { ...baseRec };
  for (const [k, v] of Object.entries(overRec)) {
    const prev = out[k];
    if (
      prev &&
      typeof prev === "object" &&
      !Array.isArray(prev) &&
      v &&
      typeof v === "object" &&
      !Array.isArray(v)
    ) {
      out[k] = { ...(prev as Record<string, unknown>), ...(v as Record<string, unknown>) };
    } else {
      out[k] = v;
    }
  }
  return out as T;
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
  const demoLoginOpts: LoginWorkflowOpts = mergeWfOpts(
    {
      // SMS is exercised via `demoSmsSender` which console-logs the code — fine for the UI harness.
      mfa: {
        transports: ["email", "sms", "totp"],
        backupCodes: true,
      },
      alternateCredentials: { forgotPassword: true, signup: true },
      guards: { passwordInitial: true },
    },
    opts.loginOpts,
  );
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
  const demoRecoveryOpts: RecoveryWorkflowOpts = mergeWfOpts(
    {
      delivery: { magicLinkTtlMs: env.RECOVERY_TTL_MS },
      // The library default for `revokeAllSessions` is `true` (kick every
      // active session after a password reset). The demo opts out so
      // WF-RECOVERY-05 can keep documenting the "pre-existing session stays
      // valid" branch; production consumers should leave the secure default
      // on. `freshLoginRequired` defaults to false (auto-login), which is what
      // this SPA demo wants — no override needed.
      postReset: { revokeAllSessions: false },
    },
    opts.recoveryOpts,
  );
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
  const demoInviteOpts: InviteWorkflowOpts = mergeWfOpts(
    {
      send: { tokenTtlMs: env.INVITE_TTL_MS },
      // Existing demo tests assert the auto-login response payload — pre-dating
      // the BIG 3.3 confirmation pause. Off here so the demo matches today's
      // behavior; production should keep the default ON.
      accept: { showConfirmation: false },
    },
    opts.inviteOpts,
  );
  // ARBAC is carried by the base `InviteWorkflow`: class-level
  // `@ArbacResource('auth.invite') @ArbacAction('start')` gates phase A,
  // per-method `@Public()` opens phase B (post magic-link send) so the
  // anonymous resume isn't denied. `@Inherit()` flows the class meta down.
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

  // AUTH-MOOST-5: `DemoWfTriggerProvider` is the consumer subclass of
  // `WfTriggerProvider` that wires this app's DB-backed wf state store and
  // adds the magic-link email outlet. Bound to `WfTriggerProvider` via the
  // replace registry so `AuthController.triggerWf()` (and the subclass
  // `DemoAuthController.triggerWf()`) picks it up automatically.
  const demoEmailOutletDeps = {
    emailSender,
    buildMagicLinkUrl: aooth.buildMagicLinkUrl,
    magicLinkTtlMs: (kind: import("@aooth/auth").AuthEmailKind) =>
      kind === "invite.magicLink" ? env.INVITE_TTL_MS : env.RECOVERY_TTL_MS,
  };
  @Injectable()
  class DemoWfTriggerProvider extends WfTriggerProvider {
    constructor(wf: MoostWf) {
      super(wf);
      this.state = new HandleStateStrategy({ store: wfStateStore });
      this.outlets = [...this.outlets, createAuthEmailOutlet(demoEmailOutletDeps)];
    }
  }

  // Extend the bundled `AuthController.triggerWf()` allow-list with the
  // demo-only `project.handover` workflow — the spec's recommended consumer
  // subclass pattern for adding app-specific workflows to the single trigger.
  // `@Inherit()` carries the parent's `@Get('status')` / `@Post('logout')` /
  // `@Post('refresh')` metadata; without it moost re-scans method decorators
  // only on the subclass and the unoverridden endpoints disappear.
  @Inherit()
  @Controller("auth")
  class DemoAuthController extends AuthController {
    constructor(auth: AuthCredential) {
      super(auth);
    }
    @Post("trigger")
    @Public()
    @WfTrigger({
      allow: [...DEFAULT_AUTH_WORKFLOWS, "auth.reInvite", "auth.cancelInvite", "project.handover"],
    })
    override triggerWf(): void {
      // see AuthController.triggerWf — body intentionally empty.
    }
  }
  app.setReplaceRegistry(createReplaceRegistry([WfTriggerProvider, DemoWfTriggerProvider]));

  if (opts.authEndpointsEnabled !== false) {
    app.registerControllers(DemoAuthController);
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

  app.registerControllers(...buildAppControllers(appDb));

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

function buildAppControllers(appDb: AppDb): ReadonlyArray<new (...args: never[]) => unknown> {
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
