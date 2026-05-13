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
import { Controller, getMoostInfact, Moost, useControllerContext } from "moost";
import { Wooks } from "wooks";

import { setupAuthMoost } from "../auth.setup";
import { Public } from "../auth.decorator";
import type { EmailSender } from "../email";
import type { BuildMagicLinkUrl } from "../magic-link";
import { setupAuthWorkflows } from "../workflow-setup";
import { createAuthEmailOutlet } from "../workflows/auth-email-outlet";
import { MoostAuthWorkflowConfig } from "../workflow-config";

export interface CapturedEmail {
  kind: string;
  recipient: string;
  url?: string;
  expiresAt: number;
  username?: string;
  metadata?: Record<string, unknown>;
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
  buildMagicLinkUrl: BuildMagicLinkUrl;
  /** Submit a request to the trigger endpoint. Resolves with parsed body. */
  trigger: (body: WfRequestBody) => Promise<WfResponse>;
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
  /** Workflow enable/disable map. */
  workflows?: { login?: boolean; recovery?: boolean; invite?: boolean };
  /** Override the recovery / invite / mfa TTLs (e.g. for expiry tests). */
  recoveryTokenTtlMs?: number;
  inviteTokenTtlMs?: number;
}

/**
 * Spins up a Moost app wired with:
 *   - `MoostHttp` (fresh Wooks per test)
 *   - `MoostWf` (workflow adapter)
 *   - `setupAuthMoost` (REST endpoints + guard; we keep the guard so we can
 *     test "the workflow endpoints are still reachable as `@Public()` once we
 *     mount them")
 *   - `setupAuthWorkflows` (registers `LoginWorkflow` / `RecoveryWorkflow`
 *     / `InviteWorkflow`)
 *   - `WfStateStoreMemory` + `HandleStateStrategy` (single-use tokens)
 *   - A `WfTriggerController` exposing `POST /wf` that calls
 *     `wf.handleOutlet({...})`. This is the same shape consumers will mount
 *     in their app.
 */
export async function prepareWfApp(opts: PrepareWfOpts = {}): Promise<PreparedWfApp> {
  // Moost's Infact is a process-global singleton; instances cached by class
  // identity leak across tests (test 1's UserService gets resolved when
  // test 2 calls `useControllerContext().instantiate(UserService)`). Reset
  // its private registry before every spin-up to keep test isolation.
  (getMoostInfact() as unknown as { _cleanup?: () => void })._cleanup?.();

  const moost = new Moost();
  const wooksHttp = createHttpApp(undefined, new Wooks());
  const http = moost.adapter(new MoostHttp(wooksHttp));
  // Fresh Wooks instance for the workflow router too — otherwise the global
  // shared router accumulates duplicate `WF_STEP:/credentials` registrations
  // across tests and refuses subsequent setups.
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
  const buildMagicLinkUrl: BuildMagicLinkUrl =
    opts.buildMagicLinkUrl ?? ((kind, token) => `https://app.test/wf/${kind}?wfs=${token}`);

  const store = new WfStateStoreMemory();
  const strategy: WfStateStrategy = new HandleStateStrategy({ store });

  // `setupAuthMoost` applies the guard and registers `AuthController`.
  // The workflow trigger endpoint we add below is `@Public()` already (no
  // existing user is authenticated when login or recovery start).
  setupAuthMoost(moost, {
    authCredential: auth,
    userService: users,
    cookie: { secure: false }, // dev-friendly in test (no Secure attribute required)
  });

  setupAuthWorkflows(moost, {
    emailSender,
    buildMagicLinkUrl,
    wfStateStore: store,
    workflows: opts.workflows,
    recoveryTokenTtlMs: opts.recoveryTokenTtlMs,
    inviteTokenTtlMs: opts.inviteTokenTtlMs,
  });

  // Mount a single trigger endpoint that calls `wf.handleOutlet` with our
  // strategy + outlets. Consumers do the same in their app.
  @Controller("wf")
  @Public()
  // biome-ignore lint/correctness/noUnusedVariables: registered via registerControllers below
  class WfTriggerController {
    @Post("trigger")
    async trigger(@Body() _body: WfRequestBody): Promise<unknown> {
      const wfConfig = await useControllerContext().instantiate(MoostAuthWorkflowConfig);
      // Calling `handleWfOutletRequest` directly (instead of `wf.handleOutlet`)
      // so we can forward the HTTP eventContext into the workflow. Otherwise
      // `useWfFinished().set({ value, cookies })` writes to the WF's isolated
      // context and `handleWfOutletRequest` (which reads from the HTTP ctx)
      // can't see it back. `MoostWf.handleOutlet()` drops the eventContext
      // param — known upstream issue.
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
          allow: ["auth.login", "auth.recovery", "auth.invite"],
          state: strategy,
          outlets: [createHttpOutlet(), createAuthEmailOutlet(wfConfig)],
          token: { read: ["body", "query"], write: "body", name: "wfs" },
        },
        deps,
      );
    }
  }
  moost.registerControllers(WfTriggerController);

  await moost.init();

  async function trigger(body: WfRequestBody): Promise<WfResponse> {
    const response = await http.request("/wf/trigger", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!response) return { status: 0, body: null, setCookies: [] };
    const text = await response.text();
    let parsed: Record<string, unknown> | null = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      parsed = { _raw: text };
    }
    const setCookies = response.headers.getSetCookie?.() ?? [];
    return { status: response.status, body: parsed, setCookies };
  }

  async function resumeViaQuery(token: string, body: WfRequestBody = {}): Promise<WfResponse> {
    const response = await http.request(`/wf/trigger?wfs=${encodeURIComponent(token)}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!response) return { status: 0, body: null, setCookies: [] };
    const text = await response.text();
    let parsed: Record<string, unknown> | null = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      parsed = { _raw: text };
    }
    const setCookies = response.headers.getSetCookie?.() ?? [];
    return { status: response.status, body: parsed, setCookies };
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
    buildMagicLinkUrl,
    trigger,
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
