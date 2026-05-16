// `@prostojs/router` injects dye color tokens via build-time constants
// (`__DYE_YELLOW__`, etc). Vitest's transform does not substitute them, so
// any path that hits `consoleWarn`/`consoleError` in the router throws
// `ReferenceError`. We pre-populate the globals as empty strings — this only
// affects test-time logs (they lose ANSI coloring).
const g = globalThis as Record<string, unknown>;
for (const key of [
  "__DYE_YELLOW__",
  "__DYE_RED_BRIGHT__",
  "__DYE_GREEN__",
  "__DYE_DIM__",
  "__DYE_DIM_OFF__",
  "__DYE_COLOR_OFF__",
]) {
  if (!(key in g)) g[key] = "";
}

import { AuthCredential, type AuthCredentialOptions, CredentialStoreMemory } from "@aoothjs/auth";
import { UserService, type UserServiceConfig, UserStoreMemory } from "@aoothjs/user";
import { formInputInterceptor } from "@atscript/moost-wf";
import { Body, MoostHttp, Post } from "@moostjs/event-http";
import {
  createHttpOutlet,
  HandleStateStrategy,
  handleWfOutletRequest,
  MoostWf,
  WfStateStoreMemory,
  type WfOutletTriggerDeps,
  type WfStateStrategy,
} from "@moostjs/event-wf";
import { current } from "@wooksjs/event-core";
import { createWfApp } from "@wooksjs/event-wf";
import { createHttpApp } from "@wooksjs/event-http";
import {
  Controller,
  createProvideRegistry,
  getMoostInfact,
  Inherit,
  Injectable,
  Moost,
} from "moost";
import { Wooks } from "wooks";

import type { AuthEmailKind, BuildMagicLinkUrl, EmailSender, SmsSender } from "@aoothjs/auth";

import { type AuditEmitter, type AuditEvent } from "../audit/index";
import { MoostAuthConfig } from "../auth.config";
import { AuthController } from "../auth.controller";
import { authGuardInterceptor } from "../auth.guard";
import { Public } from "../auth.decorator";
import {
  type DeviceTrustRecord,
  type DeviceTrustStore,
  DeviceTrustStoreMemory,
} from "../device-trust/index";
import { createAuthEmailOutlet } from "../workflows/auth-email-outlet";
import { DEFAULT_INVITE_TOKEN_TTL_MS } from "../workflows/invite.workflow.options";
import type { DeliverPayload } from "../workflows/login.workflow";
import { DEFAULT_RECOVERY_TOKEN_TTL_MS } from "../workflows/recovery.workflow.options";
import {
  type DuplicateAction,
  InviteWorkflow,
  type InviteWorkflowOpts,
  type PreparedUserInput,
  LoginWorkflow,
  type LoginWorkflowOpts,
  RecoveryWorkflow,
  type RecoveryWorkflowOpts,
} from "../workflows/index";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import type { UserCredentials } from "@aoothjs/user";

export interface CapturedEmail {
  kind: string;
  recipient: string;
  url?: string;
  code?: string;
  expiresAt: number;
  username?: string;
  metadata?: Record<string, unknown>;
}

export interface CapturedSms {
  kind: string;
  recipient: string;
  code: string;
  ttlMs: number;
  userId?: string;
}

export interface WfRequestBody {
  wfid?: string;
  wfs?: string;
  input?: unknown;
  action?: string;
}

export interface WfResponse {
  status: number;
  body: Record<string, unknown> | null;
  setCookies: string[];
  /** `Location` header value when the workflow finished with a redirect. */
  location?: string;
}

export interface PreparedWfApp {
  moost: Moost;
  http: MoostHttp;
  wf: MoostWf;
  auth: AuthCredential;
  users: UserService;
  store: WfStateStoreMemory;
  strategy: HandleStateStrategy;
  emails: CapturedEmail[];
  sms: CapturedSms[];
  /** Captured audit events when an `AuditEmitter` was wired by the test. */
  auditEvents: AuditEvent[];
  /** The `DeviceTrustStore` instance wired by the test (when `deviceTrust` is enabled). */
  deviceTrustStore?: DeviceTrustStore;
  buildMagicLinkUrl: BuildMagicLinkUrl;
  /** Submit a request to the trigger endpoint. Resolves with parsed body. */
  trigger: (body: WfRequestBody) => Promise<WfResponse>;
  /**
   * Submit a request to the trigger endpoint with extra request headers
   * (e.g. `Referer`, `Cookie`). Same response shape as `trigger`.
   */
  triggerWithHeaders: (body: WfRequestBody, headers: Record<string, string>) => Promise<WfResponse>;
  /** Resume a paused workflow via `?wfs=<token>`. */
  resumeViaQuery: (token: string, body?: WfRequestBody) => Promise<WfResponse>;
}

export interface PrepareWfOpts {
  authOptions?: Partial<AuthCredentialOptions<Record<string, unknown>>>;
  userConfig?: UserServiceConfig;
  /** Inject a custom buildMagicLinkUrl. Default: synthetic URL. */
  buildMagicLinkUrl?: BuildMagicLinkUrl;
  /** Inject a custom emailSender. Default: captures into `emails`. */
  emailSender?: EmailSender;
  /** Workflow registration toggles — omit a workflow to skip its controller. */
  workflows?: { login?: boolean; recovery?: boolean; invite?: boolean };
  /** Override the recovery / invite TTLs (e.g. for expiry tests). */
  recoveryTokenTtlMs?: number;
  inviteTokenTtlMs?: number;
  /**
   * Forwarded to the invite harness — pre-bound as the subclass's
   * `prepareUser()` override so existing tests can supply extras without
   * declaring a full subclass.
   */
  prepareUser?: (
    input: PreparedUserInput,
  ) => Promise<Record<string, unknown>> | Record<string, unknown>;
  /**
   * Maps a recovery-step `email` to the canonical username. When supplied,
   * the harness builds a tiny `RecoveryWorkflow` subclass that overrides
   * `emailToUserId` to call this function. Tests that need richer overrides
   * pass a full subclass via `recoveryWorkflowClass` instead.
   */
  emailToUserId?: (email: string) => Promise<string | null> | string | null;
  /**
   * Nested-pojo opts handed to `LoginWorkflow`'s constructor. Per-test feature
   * combinations supply their own here.
   */
  loginOpts?: LoginWorkflowOpts;
  /**
   * Consumer subclass of `LoginWorkflow` registered in place of the base
   * class. Use this when a test needs to override a `protected` method
   * (`assessRiskStepUp`, `buildRecoveryUrl`, `resolveRedirect`, etc.). The
   * subclass MUST re-apply `@Inherit() @Injectable('FOR_EVENT') @Controller()`
   * and re-declare the ctor signature — see TASKS.md §"Probe outcomes".
   */
  loginWorkflowClass?: typeof LoginWorkflow;
  /**
   * When `false`, the `SmsSender` DI token is NOT registered — used by the
   * boot-time fail-loud test for `mfaTransports: ['sms']`.
   */
  registerSmsSender?: boolean;
  /**
   * When `false`, the `EmailSender` DI token is NOT registered — used by the
   * boot-time fail-loud tests for `mfaTransports: ['email']` and
   * `finalize.notifyNewDevice: true`. The capture array (`emails`) is still
   * returned but stays empty because nothing is wired.
   */
  registerEmailSender?: boolean;
  /**
   * Inject a `DeviceTrustStore` against the `DeviceTrustStore` DI token. When
   * omitted, defaults to a fresh `DeviceTrustStoreMemory('test-trust-secret')`
   * IF `loginOpts.deviceTrust.enabled === true` — otherwise unregistered (so the
   * boot-time validator throws for misconfigured opts).
   */
  deviceTrustStore?: DeviceTrustStore | null;
  /**
   * Inject an `AuditEmitter`. The captured-events array is also returned on
   * `app.auditEvents` for assertions. When omitted, NO emitter is registered
   * (workflows skip emission when no `AuditEmitter` is supplied).
   */
  auditEmitter?: AuditEmitter;
  /**
   * Nested-pojo opts handed to `RecoveryWorkflow`'s constructor. When omitted,
   * the harness builds a magicLink-mode opts object from the per-test
   * `recoveryTokenTtlMs` (passes as `delivery.magicLinkTtlMs`).
   */
  recoveryOpts?: RecoveryWorkflowOpts;
  /**
   * Consumer subclass of `RecoveryWorkflow` registered in place of the base
   * class. Use this when a test needs to override a `protected` method
   * (`emailToUserId`, `verifyRecoveryFactor`). The subclass MUST re-apply
   * `@Inherit() @Injectable('FOR_EVENT') @Controller()` and re-declare the
   * ctor signature — see the Phase-2 LoginWorkflow subclass spec for shape.
   */
  recoveryWorkflowClass?: typeof RecoveryWorkflow;
  /**
   * Nested-pojo opts handed to `InviteWorkflow`'s constructor. When omitted,
   * defaults to `{ send: { tokenTtlMs: inviteTokenTtlMs }, accept: { showConfirmation: false } }`
   * for parity with existing tests.
   */
  inviteOpts?: InviteWorkflowOpts;
  /**
   * Consumer subclass of `InviteWorkflow` registered in place of the base
   * class. Use this when a test needs to override a `protected` method
   * (`prepareUser`, `applyProfile`, `duplicateCheck`, `getProfileForm`, …).
   * The subclass MUST re-apply `@Inherit() @Injectable('FOR_EVENT') @Controller()`
   * and re-declare the ctor signature.
   */
  inviteWorkflowClass?: typeof InviteWorkflow;
  /**
   * Per-test override map for the invite harness subclass's protected hooks
   * (handier than building a full subclass for every options test). These all
   * default to the workflow's built-in behavior.
   */
  inviteHooks?: {
    prepareUser?: (
      input: PreparedUserInput,
    ) => Promise<Record<string, unknown>> | Record<string, unknown>;
    getAvailableRoles?: () =>
      | Promise<Array<{ id: string; label: string }> | undefined>
      | Array<{ id: string; label: string }>
      | undefined;
    inferRoles?: (input: {
      email: string;
      firstName?: string;
      lastName?: string;
    }) => Promise<string[]> | string[];
    applyProfile?: (input: {
      username: string;
      profile: Record<string, unknown>;
    }) => Promise<void> | void;
    duplicateCheck?: (input: {
      email: string;
      existingUser: UserCredentials | null;
    }) => Promise<DuplicateAction> | DuplicateAction;
    getProfileForm?: () => TAtscriptAnnotatedType | undefined;
  };
}

/**
 * Spins up a Moost app wired with HTTP + WF adapters, the auth REST controller,
 * the three workflow controllers via explicit DI (per WF.md), and a
 * `POST /wf/trigger` endpoint that calls `wf.handleOutlet({...})`.
 */
export async function prepareWfApp(opts: PrepareWfOpts = {}): Promise<PreparedWfApp> {
  // Moost's Infact is a process-global singleton; instances cached by class
  // identity leak across tests. Reset before every spin-up.
  (getMoostInfact() as unknown as { _cleanup?: () => void })._cleanup?.();

  const moost = new Moost();
  const wooksHttp = createHttpApp(undefined, new Wooks());
  const http = moost.adapter(new MoostHttp(wooksHttp));
  const wooksWf = createWfApp(undefined, new Wooks());
  const wf = moost.adapter(new MoostWf(wooksWf));

  const credStore = new CredentialStoreMemory();
  const auth = new AuthCredential({
    store: credStore,
    method: "token",
    accessTtl: 60_000,
    refresh: { ttl: 600_000, rotation: "always" },
    ...opts.authOptions,
  });

  const userStore = new UserStoreMemory();
  const users = new UserService(userStore, opts.userConfig);

  const emails: CapturedEmail[] = [];
  const emailSender: EmailSender = opts.emailSender ?? {
    async send(event) {
      emails.push({ ...event });
    },
  };
  const sms: CapturedSms[] = [];
  const smsSender: SmsSender = {
    async send(event) {
      sms.push({ ...event });
    },
  };
  const buildMagicLinkUrl: BuildMagicLinkUrl =
    opts.buildMagicLinkUrl ?? ((kind, token) => `https://app.test/wf/${kind}?wfs=${token}`);

  const store = new WfStateStoreMemory();
  const strategy: WfStateStrategy = new HandleStateStrategy({ store });

  const recoveryTokenTtlMs = opts.recoveryTokenTtlMs ?? DEFAULT_RECOVERY_TOKEN_TTL_MS;
  const inviteTokenTtlMs = opts.inviteTokenTtlMs ?? DEFAULT_INVITE_TOKEN_TTL_MS;

  const loginOpts: LoginWorkflowOpts = opts.loginOpts ?? {};
  const registerSms = opts.registerSmsSender !== false;
  const registerEmail = opts.registerEmailSender !== false;
  // When loginOpts.deviceTrust.enabled is on, default-wire a fresh memory
  // store so tests that just flip the flag don't have to construct one too.
  // Tests explicitly passing `deviceTrustStore: null` skip registration to
  // exercise the boot-time fail-loud path (legacy semantics — now the
  // override returns false / throws when the store is missing).
  const deviceTrustEnabled = loginOpts.deviceTrust?.enabled === true;
  const deviceTrustStore: DeviceTrustStore | undefined =
    opts.deviceTrustStore === null
      ? undefined
      : (opts.deviceTrustStore ??
        (deviceTrustEnabled ? new DeviceTrustStoreMemory("test-trust-secret") : undefined));

  const auditEvents: AuditEvent[] = [];
  // Default auditLogin in `mergeLoginOpts` is `true`, so unless the test
  // explicitly disables it, auto-capture audit events for assertions.
  const auditLoginEnabled = loginOpts.finalize?.auditLogin !== false;
  const auditEmitter: AuditEmitter | undefined =
    opts.auditEmitter ??
    (auditLoginEnabled
      ? {
          emit(event) {
            auditEvents.push({ ...event });
          },
        }
      : undefined);

  // Build harness subclasses that wire the per-test capture arrays through
  // `protected` method overrides — replacing the pre-reshape DI registrations
  // for EmailSender / SmsSender / DeviceTrustStore / AuditEmitter.
  const LoginCtor = buildHarnessLoginClass({
    base: opts.loginWorkflowClass ?? LoginWorkflow,
    opts: loginOpts,
    emails,
    sms,
    emailSender,
    smsSender,
    registerEmail,
    registerSms,
    deviceTrustStore,
    auditEmitter,
  }) as unknown as new (
    users: UserService,
    auth: AuthCredential,
    authConfig: MoostAuthConfig,
  ) => LoginWorkflow;

  const recoveryOpts: RecoveryWorkflowOpts = opts.recoveryOpts ?? {
    delivery: { magicLinkTtlMs: recoveryTokenTtlMs },
  };
  const RecoveryCtor = buildHarnessRecoveryClass({
    base: opts.recoveryWorkflowClass ?? RecoveryWorkflow,
    opts: recoveryOpts,
    emails,
    sms,
    emailSender,
    smsSender,
    registerEmail,
    registerSms,
    auditEmitter,
    emailToUserId: opts.emailToUserId,
  }) as unknown as new (
    users: UserService,
    auth: AuthCredential,
    authConfig: MoostAuthConfig,
  ) => RecoveryWorkflow;

  const inviteOpts: InviteWorkflowOpts = opts.inviteOpts ?? {
    send: { tokenTtlMs: inviteTokenTtlMs },
    // Existing tests assert the auto-login response shape directly,
    // pre-dating the confirmation pause introduced by BIG 3.3. New
    // tests that exercise the confirmation step set this to true.
    accept: { showConfirmation: false },
  };
  // Layer the per-test `prepareUser` shortcut onto `inviteHooks.prepareUser`
  // so existing tests that only need to populate extras don't have to
  // assemble the full `inviteHooks` object.
  const inviteHooks = { ...opts.inviteHooks };
  if (opts.prepareUser && !inviteHooks.prepareUser) {
    inviteHooks.prepareUser = opts.prepareUser;
  }
  const InviteCtor = buildHarnessInviteClass({
    base: opts.inviteWorkflowClass ?? InviteWorkflow,
    opts: inviteOpts,
    emails,
    sms,
    emailSender,
    smsSender,
    registerEmail,
    registerSms,
    auditEmitter,
    hooks: inviteHooks,
  }) as unknown as new (
    users: UserService,
    auth: AuthCredential,
    authConfig: MoostAuthConfig,
  ) => InviteWorkflow;

  const moostAuthConfig = new MoostAuthConfig({ cookie: { secure: false } });
  type ProvideEntry = Parameters<typeof createProvideRegistry>[number];
  const providers: ProvideEntry[] = [
    [AuthCredential, () => auth],
    [UserService, () => users],
    [MoostAuthConfig, () => moostAuthConfig],
    [LoginCtor, () => new LoginCtor(users, auth, moostAuthConfig)],
    [RecoveryCtor, () => new RecoveryCtor(users, auth, moostAuthConfig)],
    [InviteCtor, () => new InviteCtor(users, auth, moostAuthConfig)],
  ];
  // The three workflows now all use `protected` method overrides for
  // sender/store/audit hooks — no DI registrations needed for them. The
  // `EmailSender` token is still consumed by `createAuthEmailOutlet` (the
  // trigger-side mailer for magic-link outlets), so the email-outlet deps
  // object below takes it directly via closure.
  moost.setProvideRegistry(createProvideRegistry(...providers));
  moost.applyGlobalInterceptors(authGuardInterceptor);
  moost.applyGlobalInterceptors(formInputInterceptor());
  moost.registerControllers(AuthController);

  const wfEnabled = opts.workflows ?? {};
  const wfControllers: Array<new (...args: never[]) => unknown> = [];
  if (wfEnabled.login !== false) wfControllers.push(LoginCtor);
  if (wfEnabled.recovery !== false) wfControllers.push(RecoveryCtor);
  if (wfEnabled.invite !== false) wfControllers.push(InviteCtor);
  if (wfControllers.length > 0) {
    moost.registerControllers(...wfControllers);
  }

  // Mount a single trigger endpoint that calls `wf.handleOutlet` with our
  // strategy + outlets. Consumers do the same in their app.
  const emailOutletDeps = {
    emailSender,
    buildMagicLinkUrl,
    magicLinkTtlMs: (kind: AuthEmailKind) =>
      kind === "invite.magicLink" ? inviteTokenTtlMs : recoveryTokenTtlMs,
  };

  @Controller("wf")
  @Public()
  // biome-ignore lint/correctness/noUnusedVariables: registered via registerControllers below
  class WfTriggerController {
    @Post("trigger")
    async trigger(@Body() _body: WfRequestBody): Promise<unknown> {
      const wfApp = wf.getWfApp();
      const deps: WfOutletTriggerDeps = {
        start: (schemaId, context, opts) =>
          wfApp.start(schemaId, context as never, {
            input: opts?.input,
            eventContext: (opts?.eventContext ?? current()) as never,
          }),
        resume: (state, opts) =>
          wfApp.resume(state as { schemaId: string; indexes: number[]; context: never }, {
            input: opts?.input,
            eventContext: (opts?.eventContext ?? current()) as never,
          }),
      };
      return handleWfOutletRequest(
        {
          allow: [
            "auth.login",
            "auth.recovery",
            "auth.invite",
            "auth.reInvite",
            "auth.cancelInvite",
          ],
          state: strategy,
          outlets: [createHttpOutlet(), createAuthEmailOutlet(emailOutletDeps)],
          token: { read: ["body", "query"], write: "body", name: "wfs" },
        },
        deps,
      );
    }
  }
  moost.registerControllers(WfTriggerController);

  await moost.init();

  async function readResponse(response: Response | null | undefined): Promise<WfResponse> {
    if (!response) return { status: 0, body: null, setCookies: [] };
    const text = await response.text();
    let parsed: Record<string, unknown> | null = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      parsed = { _raw: text };
    }
    const setCookies = response.headers.getSetCookie?.() ?? [];
    const loc = response.headers.get("location") ?? undefined;
    return {
      status: response.status,
      body: parsed,
      setCookies,
      ...(loc && { location: loc }),
    };
  }

  async function trigger(body: WfRequestBody): Promise<WfResponse> {
    const response = await http.request("/wf/trigger", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return readResponse(response);
  }

  async function triggerWithHeaders(
    body: WfRequestBody,
    extraHeaders: Record<string, string>,
  ): Promise<WfResponse> {
    const response = await http.request("/wf/trigger", {
      method: "POST",
      headers: { "content-type": "application/json", ...extraHeaders },
      body: JSON.stringify(body),
    });
    return readResponse(response);
  }

  async function resumeViaQuery(token: string, body: WfRequestBody = {}): Promise<WfResponse> {
    const response = await http.request(`/wf/trigger?wfs=${encodeURIComponent(token)}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return readResponse(response);
  }

  return {
    moost,
    http,
    wf,
    auth,
    users,
    store,
    strategy: strategy as HandleStateStrategy,
    emails,
    sms,
    auditEvents,
    ...(deviceTrustStore && { deviceTrustStore }),
    buildMagicLinkUrl,
    trigger,
    triggerWithHeaders,
    resumeViaQuery,
  };
}

/** Seed an active user. */
export async function seedActiveUser(
  users: UserService,
  username: string,
  password: string,
): Promise<void> {
  await users.createUser(username, password);
  await users.activateAccount(username);
}

// ── Harness subclass builders ────────────────────────────────────────────────
//
// All three workflows (`LoginWorkflow`, `RecoveryWorkflow`, `InviteWorkflow`)
// have ctor shape `(opts, users, auth, authConfig)` after the protected-method
// refactor. Tests still hand-roll opts per-case, so each harness pre-binds
// opts and exposes a re-declared 3-arg ctor `(users, auth, authConfig)` to the
// moost DI factory. Each builder layers on the per-test capture overrides
// (`deliver` / `audit` / device-trust hooks / invite hooks / `emailToUserId`).

interface HarnessLoginDeps {
  base: typeof LoginWorkflow;
  opts: LoginWorkflowOpts;
  emails: CapturedEmail[];
  sms: CapturedSms[];
  emailSender: EmailSender;
  smsSender: SmsSender;
  registerEmail: boolean;
  registerSms: boolean;
  deviceTrustStore: DeviceTrustStore | undefined;
  auditEmitter: AuditEmitter | undefined;
}

function buildHarnessLoginClass(deps: HarnessLoginDeps): new (...args: never[]) => LoginWorkflow {
  const {
    base: Base,
    opts: loginOpts,
    emails,
    sms,
    emailSender,
    smsSender,
    registerEmail,
    registerSms,
    deviceTrustStore,
    auditEmitter,
  } = deps;

  @Inherit()
  @Injectable("FOR_EVENT")
  @Controller()
  class HarnessLogin extends Base {
    constructor(usersDep: UserService, authDep: AuthCredential, authConfigDep: MoostAuthConfig) {
      super(loginOpts, usersDep, authDep, authConfigDep);
    }

    protected override async deliver(payload: DeliverPayload): Promise<void> {
      await harnessDeliver(payload, {
        emails,
        sms,
        emailSender,
        smsSender,
        registerEmail,
        registerSms,
        label: "LoginWorkflow",
      });
    }

    protected override async audit(event: AuditEvent): Promise<void> {
      if (auditEmitter) await auditEmitter.emit(event);
    }

    protected override async loadTrustedDevice(
      userId: string,
      token: string,
      ip?: string,
    ): Promise<boolean> {
      if (!deviceTrustStore) return false;
      return deviceTrustStore.verify(userId, token, ip);
    }

    protected override async storeTrustedDevice(record: DeviceTrustRecord): Promise<void> {
      if (!deviceTrustStore) return;
      await deviceTrustStore.add(record);
    }

    protected override async revokeTrustedDevice(userId: string, token: string): Promise<void> {
      if (!deviceTrustStore) return;
      await deviceTrustStore.revoke(userId, token);
    }

    protected override async issueTrustedDevice(
      userId: string,
      ip: string | undefined,
      ttlMs: number,
    ): Promise<DeviceTrustRecord> {
      if (deviceTrustStore) {
        return deviceTrustStore.issue(userId, ip, ttlMs);
      }
      return super.issueTrustedDevice(userId, ip, ttlMs);
    }
  }
  return HarnessLogin;
}

/**
 * Shared deliver implementation for both `LoginWorkflow` and `RecoveryWorkflow`
 * harness subclasses. Routes via the test-supplied EmailSender / SmsSender
 * (the default captures into the shared `emails` / `sms` arrays so a single
 * call here populates both an HTTP wire payload AND the test assertion buffer).
 * When the consumer passed a custom `opts.emailSender`, that sender is called
 * instead and we push manually for the test's assertion buffer.
 */
async function harnessDeliver(
  payload: DeliverPayload,
  deps: {
    emails: CapturedEmail[];
    sms: CapturedSms[];
    emailSender: EmailSender;
    smsSender: SmsSender;
    registerEmail: boolean;
    registerSms: boolean;
    label: string;
  },
): Promise<void> {
  if (payload.channel === "email") {
    if (!deps.registerEmail) {
      throw new Error(`${deps.label}.deliver: EmailSender required`);
    }
    await deps.emailSender.send({
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
  if (!deps.registerSms) {
    throw new Error(`${deps.label}.deliver: SmsSender required`);
  }
  await deps.smsSender.send({
    kind: payload.kind,
    recipient: payload.recipient,
    code: payload.code,
    ttlMs: payload.ttlMs ?? 0,
    ...(payload.userId !== undefined && { userId: payload.userId }),
  });
}

interface HarnessRecoveryDeps {
  base: typeof RecoveryWorkflow;
  opts: RecoveryWorkflowOpts;
  emails: CapturedEmail[];
  sms: CapturedSms[];
  emailSender: EmailSender;
  smsSender: SmsSender;
  registerEmail: boolean;
  registerSms: boolean;
  auditEmitter: AuditEmitter | undefined;
  emailToUserId?: (email: string) => Promise<string | null> | string | null;
}

function buildHarnessRecoveryClass(
  deps: HarnessRecoveryDeps,
): new (...args: never[]) => RecoveryWorkflow {
  const {
    base: Base,
    opts: recoveryOpts,
    emails,
    sms,
    emailSender,
    smsSender,
    registerEmail,
    registerSms,
    auditEmitter,
    emailToUserId,
  } = deps;

  @Inherit()
  @Injectable("FOR_EVENT")
  @Controller()
  class HarnessRecovery extends Base {
    constructor(usersDep: UserService, authDep: AuthCredential, authConfigDep: MoostAuthConfig) {
      super(recoveryOpts, usersDep, authDep, authConfigDep);
    }

    protected override async deliver(payload: DeliverPayload): Promise<void> {
      await harnessDeliver(payload, {
        emails,
        sms,
        emailSender,
        smsSender,
        registerEmail,
        registerSms,
        label: "RecoveryWorkflow",
      });
    }

    protected override async audit(event: AuditEvent): Promise<void> {
      if (auditEmitter) await auditEmitter.emit(event);
    }

    protected override async emailToUserId(email: string): Promise<string | null> {
      if (emailToUserId) {
        return await emailToUserId(email);
      }
      return super.emailToUserId(email);
    }
  }
  return HarnessRecovery;
}

interface HarnessInviteDeps {
  base: typeof InviteWorkflow;
  opts: InviteWorkflowOpts;
  emails: CapturedEmail[];
  sms: CapturedSms[];
  emailSender: EmailSender;
  smsSender: SmsSender;
  registerEmail: boolean;
  registerSms: boolean;
  auditEmitter: AuditEmitter | undefined;
  hooks: NonNullable<PrepareWfOpts["inviteHooks"]>;
}

function buildHarnessInviteClass(
  deps: HarnessInviteDeps,
): new (...args: never[]) => InviteWorkflow {
  const {
    base: Base,
    opts: inviteOpts,
    emails,
    sms,
    emailSender,
    smsSender,
    registerEmail,
    registerSms,
    auditEmitter,
    hooks,
  } = deps;

  @Inherit()
  @Injectable("FOR_EVENT")
  @Controller()
  class HarnessInvite extends Base {
    constructor(usersDep: UserService, authDep: AuthCredential, authConfigDep: MoostAuthConfig) {
      super(inviteOpts, usersDep, authDep, authConfigDep);
    }

    protected override async deliver(payload: DeliverPayload): Promise<void> {
      await harnessDeliver(payload, {
        emails,
        sms,
        emailSender,
        smsSender,
        registerEmail,
        registerSms,
        label: "InviteWorkflow",
      });
    }

    protected override async audit(event: AuditEvent): Promise<void> {
      if (auditEmitter) await auditEmitter.emit(event);
    }

    protected override async prepareUser(
      input: PreparedUserInput,
    ): Promise<Record<string, unknown>> {
      if (hooks.prepareUser) return await hooks.prepareUser(input);
      return super.prepareUser(input);
    }

    protected override async getAvailableRoles(): Promise<
      Array<{ id: string; label: string }> | undefined
    > {
      if (hooks.getAvailableRoles) return await hooks.getAvailableRoles();
      return super.getAvailableRoles();
    }

    protected override async inferRoles(input: {
      email: string;
      firstName?: string;
      lastName?: string;
    }): Promise<string[]> {
      if (hooks.inferRoles) return await hooks.inferRoles(input);
      return super.inferRoles(input);
    }

    protected override async applyProfile(input: {
      username: string;
      profile: Record<string, unknown>;
    }): Promise<void> {
      if (hooks.applyProfile) {
        await hooks.applyProfile(input);
        return;
      }
      await super.applyProfile(input);
    }

    protected override async duplicateCheck(input: {
      email: string;
      existingUser: UserCredentials | null;
    }): Promise<DuplicateAction> {
      if (hooks.duplicateCheck) return await hooks.duplicateCheck(input);
      return super.duplicateCheck(input);
    }

    protected override getProfileForm(): TAtscriptAnnotatedType | undefined {
      if (hooks.getProfileForm) return hooks.getProfileForm();
      return super.getProfileForm();
    }
  }
  return HarnessInvite;
}
