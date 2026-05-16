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
import { Controller, createProvideRegistry, getMoostInfact, Moost } from "moost";
import { Wooks } from "wooks";

import type { BuildMagicLinkUrl, EmailSender, SmsSender } from "@aoothjs/auth";

import { type AuditEmitter, type AuditEvent } from "../audit/index";
import { MoostAuthConfig } from "../auth.config";
import { AuthController } from "../auth.controller";
import { authGuardInterceptor } from "../auth.guard";
import { Public } from "../auth.decorator";
import { type DeviceTrustStore, DeviceTrustStoreMemory } from "../device-trust/index";
import { type WorkflowRateLimitStore, WorkflowRateLimitStoreMemory } from "../rate-limit/index";
import { createAuthEmailOutlet } from "../workflows/auth-email-outlet";
import {
  DEFAULT_INVITE_TOKEN_TTL_MS,
  DEFAULT_RECOVERY_TOKEN_TTL_MS,
  InviteWorkflow,
  InviteWorkflowOptions,
  LoginWorkflow,
  LoginWorkflowOptions,
  RecoveryWorkflow,
  RecoveryWorkflowOptions,
} from "../workflows/index";

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
  /** The `WorkflowRateLimitStore` instance wired by the test (default in-memory). */
  rateLimitStore?: WorkflowRateLimitStore;
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
  /** Forwarded to InviteWorkflowOptions — populates extras on invite-accept. */
  prepareUser?: InviteWorkflowOptions["prepareUser"];
  /** Forwarded to RecoveryWorkflowOptions — maps recovery email → username. */
  emailToUserId?: RecoveryWorkflowOptions["emailToUserId"];
  /**
   * Replace the default `LoginWorkflowOptions` instance. The provider is
   * registered via DI exactly once per app spin-up, so each test that needs a
   * different feature combination supplies its own here.
   */
  loginOptions?: LoginWorkflowOptions;
  /**
   * When `false`, the `SmsSender` DI token is NOT registered — used by the
   * boot-time fail-loud test for `mfaTransports: ['sms']`.
   */
  registerSmsSender?: boolean;
  /**
   * Inject a `DeviceTrustStore` against the `DeviceTrustStore` DI token. When
   * omitted, defaults to a fresh `DeviceTrustStoreMemory('test-trust-secret')`
   * IF `loginOptions.deviceTrust === true` — otherwise unregistered (so the
   * boot-time validator throws for misconfigured opts).
   */
  deviceTrustStore?: DeviceTrustStore | null;
  /**
   * Inject an `AuditEmitter`. The captured-events array is also returned on
   * `app.auditEvents` for assertions. When omitted, NO emitter is registered
   * (workflows fall back to `NoopAuditEmitter`).
   */
  auditEmitter?: AuditEmitter;
  /**
   * Replace the `WorkflowRateLimitStore` registration. When `null`, the store
   * is NOT registered — used by tests that exercise the boot-time fail-loud
   * path when `RecoveryWorkflowOptions.rateLimit` is non-null.
   */
  rateLimitStore?: WorkflowRateLimitStore | null;
  /**
   * Override the recovery options instance entirely (for OTP / choice mode
   * variants). When omitted, defaults to a magicLink-mode instance built from
   * the per-test `recoveryTokenTtlMs` + `emailToUserId`.
   */
  recoveryOptions?: RecoveryWorkflowOptions;
  /**
   * Override the invite options instance entirely. When omitted, defaults to
   * the back-compat instance built from `inviteTokenTtlMs` + `prepareUser`
   * with `requireAdminAuth: false` + `showConfirmation: false` for parity
   * with existing tests.
   */
  inviteOptions?: InviteWorkflowOptions;
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

  const loginOptions = opts.loginOptions ?? new LoginWorkflowOptions();
  const registerSms = opts.registerSmsSender !== false;
  // When loginOptions.deviceTrust is on, default-wire a fresh memory store so
  // tests that just flip the flag don't have to construct one too. Tests
  // explicitly passing `deviceTrustStore: null` skip registration to exercise
  // the boot-time fail-loud path.
  const deviceTrustStore: DeviceTrustStore | undefined =
    opts.deviceTrustStore === null
      ? undefined
      : (opts.deviceTrustStore ??
        (loginOptions.deviceTrust ? new DeviceTrustStoreMemory("test-trust-secret") : undefined));

  const auditEvents: AuditEvent[] = [];
  const auditEmitter: AuditEmitter | undefined =
    opts.auditEmitter ??
    (loginOptions.auditLogin
      ? {
          emit(event) {
            auditEvents.push({ ...event });
          },
        }
      : undefined);

  // Rate-limit store — RecoveryWorkflowOptions defaults to a non-null
  // `rateLimit`, so the workflow constructor fails loud unless a store is
  // wired. Default-register an in-memory store so tests don't need to
  // re-derive opts; tests can pass `rateLimitStore: null` to exercise the
  // fail-loud path or supply a custom store to test the rate-limit cap.
  const rateLimitStore: WorkflowRateLimitStore | undefined =
    opts.rateLimitStore === null
      ? undefined
      : (opts.rateLimitStore ?? new WorkflowRateLimitStoreMemory());

  // Canonical REST wiring + per-workflow options classes registered via DI.
  // `createProvideRegistry` takes a variadic tuple — build it conditionally so
  // tests can omit SmsSender / DeviceTrustStore / AuditEmitter.
  type ProvideEntry = Parameters<typeof createProvideRegistry>[number];
  const providers: ProvideEntry[] = [
    [AuthCredential, () => auth],
    [UserService, () => users],
    [MoostAuthConfig, () => new MoostAuthConfig({ cookie: { secure: false } })],
    [LoginWorkflowOptions, () => loginOptions],
    ["EmailSender", () => emailSender],
    [
      RecoveryWorkflowOptions,
      () =>
        opts.recoveryOptions ??
        new RecoveryWorkflowOptions({
          recoveryTokenTtlMs,
          emailToUserId: opts.emailToUserId,
        }),
    ],
    [
      InviteWorkflowOptions,
      () =>
        opts.inviteOptions ??
        new InviteWorkflowOptions({
          inviteTokenTtlMs,
          prepareUser: opts.prepareUser,
          // Existing invite tests pre-date the admin-auth contract — they
          // exercise the workflow without an auth context. New tests that
          // need the admin gate construct their own InviteWorkflowOptions.
          requireAdminAuth: false,
          // Existing tests assert the auto-login response shape directly,
          // pre-dating the confirmation pause introduced by BIG 3.3. New
          // tests that exercise the confirmation step set this to true.
          showConfirmation: false,
        }),
    ],
  ];
  if (registerSms) providers.push(["SmsSender", () => smsSender]);
  if (deviceTrustStore) providers.push(["DeviceTrustStore", () => deviceTrustStore]);
  if (auditEmitter) providers.push(["AuditEmitter", () => auditEmitter]);
  if (rateLimitStore) providers.push(["WorkflowRateLimitStore", () => rateLimitStore]);
  moost.setProvideRegistry(createProvideRegistry(...providers));
  moost.applyGlobalInterceptors(authGuardInterceptor);
  moost.applyGlobalInterceptors(formInputInterceptor());
  moost.registerControllers(AuthController);

  const wfEnabled = opts.workflows ?? {};
  const wfControllers: Array<new (...args: never[]) => unknown> = [];
  if (wfEnabled.login !== false) wfControllers.push(LoginWorkflow);
  if (wfEnabled.recovery !== false) wfControllers.push(RecoveryWorkflow);
  if (wfEnabled.invite !== false) wfControllers.push(InviteWorkflow);
  if (wfControllers.length > 0) {
    moost.registerControllers(...wfControllers);
  }

  // Mount a single trigger endpoint that calls `wf.handleOutlet` with our
  // strategy + outlets. Consumers do the same in their app.
  const emailOutletDeps = { emailSender, buildMagicLinkUrl, recoveryTokenTtlMs };

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
    ...(rateLimitStore && { rateLimitStore }),
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
