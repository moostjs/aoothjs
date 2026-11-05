import { expect } from "vite-plus/test";

import {
  type Arbac,
  arbacAuthorizeInterceptor,
  ArbacUserProviderToken,
  MoostArbac,
  type TArbacRole,
} from "@aooth/arbac-moost";
import { AuthCredential, CredentialStoreMemory } from "@aooth/auth";
import {
  AuthCodeStoreMemory,
  LoopbackClientPolicy,
  PendingAuthorizationStoreMemory,
} from "@aooth/auth/authz";
import { UserService, UserStoreMemory } from "@aooth/user";
import type { UserServiceConfig } from "@aooth/user";
import { MoostHttp } from "@moostjs/event-http";
import {
  HandleStateStrategy,
  MoostWf,
  type WfOutlet,
  type WfStateStrategy,
  WfStateStoreMemory,
} from "@moostjs/event-wf";
import { createEventContext, useLocale } from "@wooksjs/event-core";
import { createHttpApp, type TWooksHttpOptions, useAcceptLanguage } from "@wooksjs/event-http";
import {
  clearGlobalWooks,
  Controller,
  createProvideRegistry,
  createReplaceRegistry,
  getMoostInfact,
  Inherit,
  Injectable,
  Moost,
  translateErrorBody,
} from "moost";
import { Wooks } from "wooks";

import type { AuthOptions } from "../auth.config";
import { AuthController } from "../auth.controller";
import { authGuardInterceptor } from "../auth.guard";
import { AuthorizeController } from "../authz/authorize.controller";
import {
  AUTH_CODE_STORE_TOKEN,
  CLIENT_REDIRECT_POLICY_TOKEN,
  PENDING_AUTHORIZATION_STORE_TOKEN,
} from "../authz/authz-tokens";
import { ConsentStore } from "../consent.store";
import {
  deriveWfStateSecret,
  WfTriggerProvider,
  type WfTriggerHooks,
} from "../wf-trigger/provider";
import { AuthWorkflow } from "../workflow/auth-workflow";
import type { AuthWorkflowOpts } from "../workflow/auth-workflow.opts";
import {
  type HarnessResponse,
  requestVia,
  setTestArbacUserRoles,
  TestArbacUserProvider,
} from "./test-harness";

/**
 * In-process full-stack harness: `AuthController` triggers + a real
 * `AuthWorkflow` on `MoostWf`, memory user/credential stores and a durable
 * memory wf-state store. Drives flows through `POST /auth/trigger` exactly as
 * the SPA does (`{ wfid }` to start, `{ wfs, input }` to resume).
 */

export const quietLogger = { info() {}, warn() {}, error() {}, debug() {}, log() {} };

/** Runs `fn` in a bare event context whose locale is `locale`. */
export function inLocale<R>(locale: string | undefined, fn: () => R): R {
  return createEventContext({ logger: quietLogger }, () => {
    useLocale().set(locale);
    return fn();
  });
}

/** The HTTP app options `MoostHttp` installs when it creates the app itself (`en` / `de`). */
export const localizedHttpApp: TWooksHttpOptions = {
  resolveLocale: () => useAcceptLanguage().negotiate(["en", "de"], "en"),
  transformErrorBody: (body, _error, ctx) => translateErrorBody(body, ctx),
};

/** A memory wf-state store that also keeps a copy of every state it persists. */
class RecordingStateStore extends WfStateStoreMemory {
  readonly saved: unknown[] = [];
  override set(...args: Parameters<WfStateStoreMemory["set"]>): Promise<void> {
    this.saved.push(structuredClone(args[1]));
    return super.set(...args);
  }
}

// Per-boot workflow opts, read by the workflow subclass constructor.
let activeOpts: Partial<AuthWorkflowOpts> = {};

/** One `outletEmail(...)` pause captured by the harness's email outlet. */
export interface CapturedEmail {
  target?: string;
  template?: string;
  context?: Record<string, unknown>;
  /** The resume token a real mailer would embed in the link. */
  token: string;
}

@Injectable()
class FlowTriggerProvider extends WfTriggerProvider {
  static store = new RecordingStateStore();
  static emails: CapturedEmail[] = [];
  static hooks: WfTriggerHooks = {};
  constructor(wf: MoostWf, auth: AuthCredential) {
    super(wf, auth);
    const outbox: WfOutlet = {
      name: "email",
      tokenDelivery: "out-of-band",
      deliver: async (request, token) => {
        FlowTriggerProvider.emails.push({
          target: request.target,
          template: request.template,
          context: request.context,
          token,
        });
        return { response: { sent: true } };
      },
    };
    this.outlets = [...this.outlets, outbox];
  }
  protected override wfStateSecret(): Buffer {
    return deriveWfStateSecret("flow-utils-secret");
  }
  protected override storeStrategy(): WfStateStrategy {
    return new HandleStateStrategy({ store: FlowTriggerProvider.store });
  }
  protected override triggerHooks(): WfTriggerHooks {
    return FlowTriggerProvider.hooks;
  }
}

/**
 * The harness's `AuthWorkflow` subclass, bound to each boot's `workflowOpts`.
 * Tests extend it (with `@Inherit() @Injectable() @Controller()`) to override
 * hooks and pass the subclass as `workflowClass`.
 */
@Inherit()
@Injectable()
@Controller()
export class FlowWorkflow extends AuthWorkflow {
  constructor(users: UserService, auth: AuthCredential, consentStore: ConsentStore) {
    super(activeOpts, users, auth, consentStore);
  }
}

export interface PrepareFlowOpts extends AuthOptions {
  workflowOpts?: Partial<AuthWorkflowOpts>;
  workflowClass?: typeof FlowWorkflow;
  userConfig?: UserServiceConfig;
  controllerClass?: typeof AuthController;
  /** Use this credential orchestrator instead of the default memory-store one. */
  credential?: AuthCredential;
  /** Also mount `AuthorizeController` (loopback clients, memory pending/code stores). */
  authorizationServer?: boolean;
  /** App-wide workflow-trigger hooks (`WfTriggerProvider.triggerHooks()`). */
  triggerHooks?: WfTriggerHooks;
  /** Wire ARBAC (the authorize interceptor runs on every event, workflow steps included). */
  arbac?: { roles: TArbacRole<object, object>[]; userRoles: Map<string, string[]> };
  /** Options of the HTTP app (e.g. `resolveLocale`, `transformErrorBody`). */
  httpApp?: TWooksHttpOptions;
}

export type FlowResponse = HarnessResponse;

export interface PreparedFlowApp {
  moost: Moost;
  /** Emails the workflow paused on (`outletEmail`), oldest first. */
  emails: CapturedEmail[];
  /** Every workflow state the durable store persisted, oldest first (copies). */
  savedStates: unknown[];
  users: UserService;
  auth: AuthCredential;
  /** Create an ACTIVE user with a password; returns its id. */
  seedUser: (
    username: string,
    password: string,
    extras?: Record<string, unknown>,
  ) => Promise<string>;
  post: (path: string, json: unknown, headers?: Record<string, string>) => Promise<FlowResponse>;
  get: (path: string, headers?: Record<string, string>) => Promise<FlowResponse>;
  /** Start a workflow on `/auth/trigger` (`{ wfid, input? }`). */
  start: (wfid: string, headers?: Record<string, string>, input?: unknown) => Promise<FlowResponse>;
  /** Resume a workflow on `/auth/trigger` (`{ wfs, input }`). */
  submit: (wfs: string, input?: unknown, headers?: Record<string, string>) => Promise<FlowResponse>;
  /** Start `auth/login/flow` and submit the credentials form. */
  login: (username: string, password: string) => Promise<FlowResponse>;
}

export async function prepareFlowApp(opts: PrepareFlowOpts = {}): Promise<PreparedFlowApp> {
  (getMoostInfact() as unknown as { _cleanup?: () => void })._cleanup?.();
  // MoostWf registers steps on the global Wooks router, where the first
  // registration wins — reset it so each boot runs its own workflow instance.
  clearGlobalWooks();
  FlowTriggerProvider.store = new RecordingStateStore();
  FlowTriggerProvider.emails = [];
  FlowTriggerProvider.hooks = opts.triggerHooks ?? {};
  activeOpts = opts.workflowOpts ?? {};
  const {
    workflowOpts: _w,
    workflowClass,
    userConfig,
    controllerClass,
    arbac: arbacOpts,
    credential,
    authorizationServer,
    triggerHooks: _h,
    httpApp,
    ...authOptions
  } = opts;

  const moost = new Moost();
  const http = moost.adapter(new MoostHttp(createHttpApp(httpApp, new Wooks())));
  moost.adapter(new MoostWf());

  const auth =
    credential ??
    new AuthCredential({
      store: new CredentialStoreMemory(),
      method: "token",
      accessTtl: 60_000,
      refresh: { ttl: 600_000, rotation: "always" },
    });
  const users = new UserService(new UserStoreMemory(), userConfig);
  const consentStore = new ConsentStore();
  const pending = new PendingAuthorizationStoreMemory();
  const codes = new AuthCodeStoreMemory();
  const clientPolicy = new LoopbackClientPolicy();
  moost.setProvideRegistry(
    createProvideRegistry(
      [AuthCredential, () => auth],
      [UserService, () => users],
      [ConsentStore, () => consentStore],
      [CLIENT_REDIRECT_POLICY_TOKEN, () => clientPolicy],
      [PENDING_AUTHORIZATION_STORE_TOKEN, () => pending],
      [AUTH_CODE_STORE_TOKEN, () => codes],
    ),
  );
  moost.setReplaceRegistry(
    arbacOpts
      ? createReplaceRegistry(
          [WfTriggerProvider, FlowTriggerProvider],
          [ArbacUserProviderToken, TestArbacUserProvider],
        )
      : createReplaceRegistry([WfTriggerProvider, FlowTriggerProvider]),
  );
  moost.applyGlobalInterceptors(authGuardInterceptor({ enableCookie: false, ...authOptions }));
  if (arbacOpts) {
    setTestArbacUserRoles(arbacOpts.userRoles);
    moost.applyGlobalInterceptors(arbacAuthorizeInterceptor);
  }
  moost.registerControllers(
    controllerClass ?? AuthController,
    workflowClass ?? FlowWorkflow,
    ...(authorizationServer ? [AuthorizeController] : []),
  );
  await moost.init();
  if (arbacOpts) {
    const arbac = (await getMoostInfact().get(MoostArbac)) as Arbac<object, object>;
    for (const role of arbacOpts.roles) arbac.registerRole(role);
  }

  const request = requestVia(http);
  const post = (path: string, json: unknown, headers?: Record<string, string>) =>
    request(path, { method: "POST", json, headers });
  const start = (wfid: string, headers?: Record<string, string>, input?: unknown) =>
    post("/auth/trigger", input === undefined ? { wfid } : { wfid, input }, headers);
  const submit = (wfs: string, input: unknown = {}, headers?: Record<string, string>) =>
    post("/auth/trigger", { wfs, input }, headers);

  return {
    moost,
    emails: FlowTriggerProvider.emails,
    savedStates: FlowTriggerProvider.store.saved,
    users,
    auth,
    seedUser: async (username, password, extras) => {
      const user = await users.createUser(username, password, extras);
      await users.activateAccount(user.id);
      return user.id;
    },
    post,
    get: (path, headers) => request(path, { method: "GET", headers }),
    start,
    submit,
    login: async (username, password) => {
      const started = await start("auth/login/flow");
      return submit(started.body.wfs, { formData: { username, password } });
    },
  };
}

/**
 * Seed `username` with an initial (must-change) password and sign in: returns
 * the durable (`store.`) token paused at the set-password form.
 */
export async function pauseOnForcedPasswordChange(
  app: PreparedFlowApp,
  username = "alice",
  password = "Password123!",
): Promise<string> {
  const userId = await app.seedUser(username, password);
  await app.users.update(userId, { password: { isInitial: true } } as never);
  const atForm = await app.login(username, password);
  expect(atForm.status).toBe(201);
  expect(atForm.body.inputRequired).toBeDefined();
  expect(atForm.body.wfs).toMatch(/^store\./);
  return atForm.body.wfs as string;
}

/** Valid input for the set-password form (new password `NewPassword456!`). */
export const setPasswordInput = {
  formData: { newPassword: "NewPassword456!", confirmPassword: "NewPassword456!", consents: [] },
};
