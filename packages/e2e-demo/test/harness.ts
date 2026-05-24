import {
  type AuthLoginResponse,
  type InviteWfCtx,
  InviteWorkflow,
  type InviteWorkflowOpts,
  type LoginWfCtx,
  LoginWorkflow,
  type LoginWorkflowOpts,
  type MfaTransport,
  Public,
  type RecoveryWorkflowOpts,
} from "@aooth/auth-moost";
import type { WfFinished } from "@atscript/moost-wf";
import { AuthCredential } from "@aooth/auth";
import { generateTotpCode, UserService } from "@aooth/user";
import { Step, WorkflowParam } from "@moostjs/event-wf";
import { clearGlobalWooks, Controller, getMoostInfact, Inherit, Injectable } from "moost";
import { expect } from "vite-plus/test";

import { type AppHandle, buildApp } from "../src/app";
import { CaptureEmailSender } from "../src/email/capture-email-sender";
import type { AppEnv } from "../src/env";
import { type SeededUser, seedAll, type SeedFixtures } from "../src/seed";

export const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/** Asserts a 2xx (200 or 201). Wooks emits either depending on handler shape. */
export function expectOk(res: Response): void {
  expect([200, 201]).toContain(res.status);
}

/**
 * Reads the response JSON and asserts it is a `WfFinished<T>` envelope.
 * Throws (surfacing status + body) when the body is missing or not finished
 * so failing tests don't bottom out in `undefined` chains downstream.
 */
export async function expectFinished<T = Record<string, unknown>>(
  res: Response,
): Promise<WfFinished<T>> {
  const body = (await res.json()) as { finished?: unknown } | null;
  if (!body || (body as { finished?: unknown }).finished !== true) {
    throw new Error(
      `expected WfFinished envelope, got status=${res.status} body=${JSON.stringify(body)}`,
    );
  }
  return body as WfFinished<T>;
}

/**
 * Narrows a `WfFinished` envelope to its redirect next. Throws when the
 * envelope is in `manual` trigger (no action) or the action isn't a redirect.
 * Saves the inline `trigger !== 'manual' && action.type === 'redirect'`
 * narrowing dance at every assertion site.
 */
export function expectRedirect(env: WfFinished): {
  trigger: "immediate" | "auto";
  target: string;
  reason?: string;
} {
  const next = env.next;
  if (!next || next.trigger === "manual") {
    throw new Error(`expected redirect-bearing next, got trigger=${next?.trigger ?? "undefined"}`);
  }
  if (next.action.type !== "redirect") {
    throw new Error(`expected redirect action, got type=${next.action.type}`);
  }
  return { trigger: next.trigger, target: next.action.target, reason: next.action.reason };
}

type LoginPause = {
  wfs: string;
  inputRequired: { payload?: { type?: { props?: { code?: unknown } } } };
};
type LoginBody = LoginPause | WfFinished<AuthLoginResponse>;
const isPause = (b: LoginBody): b is LoginPause => "inputRequired" in b;

/** Extract `inputRequired.context` from a paused workflow body, asserting presence. */
export function wfContext(body: WfFormPause & Record<string, unknown>): Record<string, unknown> {
  const ir = body.inputRequired;
  if (!ir) throw new Error(`wfContext: body has no inputRequired (got ${JSON.stringify(body)})`);
  return ir.context;
}

/** Extract `inputRequired.context.errors` (record of field → message). */
export function wfErrors(body: WfFormPause & Record<string, unknown>): Record<string, string> {
  return (wfContext(body).errors ?? {}) as Record<string, string>;
}

export interface BuildTestAppOptions {
  envOverrides?: Partial<AppEnv>;
  seed?: boolean;
  dbPath?: string;
  workflowsEnabled?: { login?: boolean; recovery?: boolean; invite?: boolean };
  authEndpointsEnabled?: boolean;
  /** Deep-merged into the demo's `demoLoginOpts` — see `buildApp`. */
  loginOpts?: LoginWorkflowOpts;
  /** Deep-merged into the demo's `demoRecoveryOpts` — see `buildApp`. */
  recoveryOpts?: RecoveryWorkflowOpts;
  /** Deep-merged into the demo's `demoInviteOpts` — see `buildApp`. */
  inviteOpts?: InviteWorkflowOpts;
  /**
   * Replace the default `DemoInviteWorkflow` with a consumer-supplied class —
   * lets override-pattern tests wire their own `InviteWorkflow` subclass
   * through the full HTTP+DI stack instead of monkey-patching opts.
   */
  inviteWorkflowClass?: new (...args: never[]) => unknown;
  /**
   * Replace the default `DemoLoginWorkflow` with a consumer-supplied class.
   * Mirrors `inviteWorkflowClass`. Most tests want the demo's `loadTenants` /
   * `loadPersonas` / `credentials`-injection overrides preserved — prefer
   * `loginMfaCtx` (below) for the common "just set mfa values" case, and
   * use this knob only when you also need a full subclass override.
   */
  loginWorkflowClass?: new (...args: never[]) => unknown;
  /**
   * Inject static MFA ctx values into the login workflow without forking a
   * subclass. PR9 stripped `mfa.mode` / `mfa.transports` from
   * `LoginWorkflowOpts`; tests that previously did
   * `loginOpts: { mfa: { mode: 'required', transports: ['totp'] } }` now pass
   * `loginMfaCtx: { mfaMode: 'required', availableMfaTransports: ['totp'] }`.
   * `buildApp` wraps the demo (or `loginWorkflowClass`, if provided) with
   * `withLoginMfaCtx(...)`.
   */
  loginMfaCtx?: WithLoginMfaCtxOverrides;
  /** Invite-side counterpart of `loginMfaCtx`. */
  inviteMfaCtx?: WithInviteMfaCtxOverrides;
}

export interface FetchInit extends RequestInit {
  token?: string;
  json?: unknown;
}

export interface AuthedFetch {
  (path: string, init?: Omit<FetchInit, "token">): Promise<Response>;
}

export interface LoginTokens {
  accessToken: string;
  refreshToken: string;
  userId: string;
  accessExpiresAt: number;
  refreshExpiresAt: number;
}

export interface TestApp {
  appHandle: AppHandle;
  fixtures: SeedFixtures;
  emailSender: CaptureEmailSender;
  baseUrl: string;
  close: () => Promise<void>;
  fetch: (path: string, init?: FetchInit) => Promise<Response>;
  loginAs: (user: SeededUser) => Promise<LoginTokens>;
  /**
   * Drives the `auth.login` workflow via `/auth/trigger` and returns the
   * raw final `Response` — used by tests that assert on status / body
   * shape (e.g. "wrong password → 401", "locked account → 423"). Tests that
   * just need a token pair should use `loginAs(user)` instead.
   */
  loginRequest: (username: string, password: string) => Promise<Response>;
  authedFetch: (token: string) => AuthedFetch;
  triggerWf: (
    route: "public" | "admin",
    body: unknown,
    opts?: { token?: string },
  ) => Promise<Response>;
  resumeWfFromUrl: (url: string, body?: unknown, opts?: { token?: string }) => Promise<Response>;
}

const SENTINEL_FIXTURES = {} as SeedFixtures;

// Legacy harness shim: existing spec callsites pre-date the new
// `@atscript/moost-wf` wire envelope `{ wfs, input: { action?, formData? } }`
// and write `input` as a flat data bag (sometimes with an inline `action`
// key, e.g. `{ input: { username, action: "forgotPassword" } }`). Split
// those into the new shape inside the harness so the ~100 spec callsites
// don't need a global rewrite. Bodies already in the new shape (whose
// `input` keys are only `action` / `formData`) pass through unchanged.
// Mirrors `normalize()` in packages/auth-moost/src/__test__/workflow-utils.ts.
function normalizeWfBody(body: unknown): unknown {
  if (!body || typeof body !== "object" || Array.isArray(body)) return body;
  const obj = body as Record<string, unknown>;
  const rawInput = obj.input;
  if (!rawInput || typeof rawInput !== "object" || Array.isArray(rawInput)) return body;
  const inputObj = rawInput as Record<string, unknown>;
  const keys = Object.keys(inputObj);
  const isNewShape = keys.length > 0 && keys.every((k) => k === "action" || k === "formData");
  if (isNewShape) return body;
  const { action: innerAction, ...formData } = inputObj;
  const wrapped: { action?: string; formData?: Record<string, unknown> } = {};
  if (typeof innerAction === "string") wrapped.action = innerAction;
  if (Object.keys(formData).length > 0) wrapped.formData = formData;
  return { ...obj, input: wrapped };
}

export async function buildTestApp(opts: BuildTestAppOptions = {}): Promise<TestApp> {
  // Wooks defaults to a process-global router (`getGlobalWooks`). Without this
  // reset, a second buildApp() in the same worker re-registers all routes onto
  // the previous app's router — requests then hit the dead Moost instance and
  // return stale 423/500 responses. Clearing forces each app to install a
  // fresh `Wooks` (with an empty ProstoRouter) on the next `getGlobalWooks()`.
  clearGlobalWooks();
  // Moost's Infact is also a process-global singleton that caches @Injectable
  // instances by class identity. Without a reset, DI singletons created in a
  // previous app (holding the prior `wfStateStore` whose better-sqlite3
  // connection has since closed) are re-handed-out to handlers in the next
  // app, producing "TypeError: The database connection is not open" on
  // workflow trigger.
  (getMoostInfact() as unknown as { _cleanup?: () => void })._cleanup?.();
  const emailSender = new CaptureEmailSender();
  const appHandle = await buildApp({
    emailSender,
    port: 0,
    dbPath: opts.dbPath ?? ":memory:",
    envOverrides: opts.envOverrides,
    workflowsEnabled: opts.workflowsEnabled,
    authEndpointsEnabled: opts.authEndpointsEnabled,
    loginOpts: opts.loginOpts,
    recoveryOpts: opts.recoveryOpts,
    inviteOpts: opts.inviteOpts,
    inviteWorkflowClass: opts.inviteWorkflowClass,
    loginWorkflowClass: opts.loginWorkflowClass,
    loginMfaCtx: opts.loginMfaCtx,
    inviteMfaCtx: opts.inviteMfaCtx,
  });

  const fixtures = opts.seed === false ? SENTINEL_FIXTURES : await seedAll(appHandle);

  const baseUrl = appHandle.baseUrl;

  const doFetch = async (path: string, init: FetchInit = {}): Promise<Response> => {
    const url = path.startsWith("http")
      ? path
      : `${baseUrl}${path.startsWith("/") ? path : `/${path}`}`;
    const headers = new Headers(init.headers);
    let body = init.body;
    if (init.json !== undefined) {
      body = JSON.stringify(init.json);
      if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    }
    if (init.token) headers.set("Authorization", `Bearer ${init.token}`);

    const requestInit: RequestInit = {
      ...init,
      headers,
      body: body ?? undefined,
    };
    delete (requestInit as { token?: unknown }).token;
    delete (requestInit as { json?: unknown }).json;

    // Brief retry guards against ECONNREFUSED windows when many test files run
    // in parallel and sockets briefly stall on macOS.
    let lastErr: unknown;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        return await globalThis.fetch(url, requestInit);
      } catch (err) {
        lastErr = err;
        const code =
          (err as { cause?: { code?: string }; code?: string }).cause?.code ??
          (err as { code?: string }).code;
        if (code !== "ECONNREFUSED" && code !== "ECONNRESET") throw err;
        await sleep(50);
      }
    }
    throw lastErr;
  };

  // AUTH-MOOST-5 dropped `/auth/login` — minting tokens for tests now drives
  // the `auth.login` workflow through `/auth/trigger`. Three-step protocol
  // for users with TOTP (e.g. `t1_grace`); two steps otherwise:
  //   1. POST /auth/trigger { wfid: 'auth.login' } → returns `{ wfs }`.
  //   2. POST /auth/trigger { wfs, input: { username, password } } →
  //      either the finalized AuthLoginResponse (no MFA) OR another `{ wfs }`
  //      payload prompting for an MFA code.
  //   3. (MFA only) POST /auth/trigger { wfs, input: { code } } → AuthLoginResponse.
  const loginAs = async (user: SeededUser): Promise<LoginTokens> => {
    const initRes = await doFetch("/auth/trigger", {
      method: "POST",
      json: { wfid: "auth.login" },
    });
    if (initRes.status >= 400) {
      const text = await initRes.text().catch(() => "<unreadable>");
      throw new Error(
        `loginAs(${user.username}) init failed: HTTP ${initRes.status} ${initRes.statusText} — ${text}`,
      );
    }
    const initBody = (await initRes.json()) as { wfs?: string };
    if (!initBody.wfs) {
      throw new Error(
        `loginAs(${user.username}): expected wfs in init response, got ${JSON.stringify(initBody)}`,
      );
    }
    const credRes = await doFetch("/auth/trigger", {
      method: "POST",
      json: normalizeWfBody({
        wfs: initBody.wfs,
        input: { username: user.username, password: user.password },
      }),
    });
    if (credRes.status >= 400) {
      const text = await credRes.text().catch(() => "<unreadable>");
      throw new Error(
        `loginAs(${user.username}) credentials failed: HTTP ${credRes.status} ${credRes.statusText} — ${text}`,
      );
    }
    let body = (await credRes.json()) as LoginBody;
    // MFA branch: the workflow prompts with `MfaCodeForm` (a `code` field).
    // Seeded users that have a confirmed TOTP secret submit a freshly
    // generated code; users without one cannot finish this branch.
    if (isPause(body)) {
      if (!user.totpSecret) {
        throw new Error(
          `loginAs(${user.username}): MFA prompted but seeded user has no totpSecret`,
        );
      }
      const code = generateTotpCode(user.totpSecret);
      const mfaRes = await doFetch("/auth/trigger", {
        method: "POST",
        json: normalizeWfBody({ wfs: body.wfs, input: { code } }),
      });
      if (mfaRes.status >= 400) {
        const text = await mfaRes.text().catch(() => "<unreadable>");
        throw new Error(
          `loginAs(${user.username}) MFA failed: HTTP ${mfaRes.status} ${mfaRes.statusText} — ${text}`,
        );
      }
      body = (await mfaRes.json()) as LoginBody;
    }
    if (isPause(body) || !body.finished || !body.data) {
      throw new Error(
        `loginAs(${user.username}): expected WfFinished envelope with data, got ${JSON.stringify(body)}`,
      );
    }
    const data = body.data;
    if (!data.accessToken || !data.refreshToken) {
      throw new Error(
        `loginAs(${user.username}): expected accessToken+refreshToken in envelope data, got ${JSON.stringify(body)}`,
      );
    }
    return {
      accessToken: data.accessToken,
      refreshToken: data.refreshToken,
      userId: data.userId,
      accessExpiresAt: data.accessExpiresAt,
      refreshExpiresAt: data.refreshExpiresAt as number,
    };
  };

  // Drives `auth.login` end-to-end (init → submit credentials) and returns
  // the raw final Response. The workflow's HTTP outlet maps status codes
  // through: 423 on locked accounts, 4xx on form errors with `errors`
  // payload, 2xx with `userId`/`accessToken` on success. The wf trigger
  // returns 401 on bad credentials by re-raising the `HttpError(401)` the
  // credentials step throws — preserving the legacy `/auth/login` shape
  // tests assert on.
  const loginRequest = async (username: string, password: string): Promise<Response> => {
    const init = await doFetch("/auth/trigger", {
      method: "POST",
      json: { wfid: "auth.login" },
    });
    if (init.status >= 400) return init;
    const { wfs } = (await init.json()) as { wfs?: string };
    if (!wfs) return init;
    return doFetch("/auth/trigger", {
      method: "POST",
      json: normalizeWfBody({ wfs, input: { username, password } }),
    });
  };

  const authedFetch = (token: string): AuthedFetch => {
    return (path, init = {}) => doFetch(path, { ...init, token });
  };

  // AUTH-MOOST-5: the bundled `AuthController.triggerWf()` covers all three
  // auth workflows (`auth.login`, `auth.recovery`, `auth.invite`) plus the
  // demo's `project.handover` via the `DemoAuthController` subclass — single
  // `/auth/trigger` endpoint. The legacy `route: "public" | "admin"` arg is
  // accepted for now (the demo binds both paths to the same handler) but
  // ignored — kept on the signature so existing call sites compile while
  // tests get migrated to the single-arg form.
  const triggerWf = (
    _route: "public" | "admin",
    body: unknown,
    triggerOpts: { token?: string } = {},
  ): Promise<Response> => {
    return doFetch("/auth/trigger", {
      method: "POST",
      json: normalizeWfBody(body),
      token: triggerOpts.token,
    });
  };

  const resumeWfFromUrl = (
    url: string,
    body: unknown = {},
    resumeOpts: { token?: string } = {},
  ): Promise<Response> => {
    const parsed = new URL(url, "http://placeholder");
    const wfs = parsed.searchParams.get("wfs");
    if (!wfs) throw new Error(`resumeWfFromUrl: no ?wfs= in URL: ${url}`);
    const merged =
      body && typeof body === "object" && !Array.isArray(body)
        ? { ...(body as Record<string, unknown>), wfs }
        : { wfs, input: body };
    return doFetch("/auth/trigger", {
      method: "POST",
      json: normalizeWfBody(merged),
      token: resumeOpts.token,
    });
  };

  const close = async (): Promise<void> => {
    await appHandle.close();
  };

  return {
    appHandle,
    fixtures,
    emailSender,
    baseUrl,
    close,
    fetch: doFetch,
    loginAs,
    loginRequest,
    authedFetch,
    triggerWf,
    resumeWfFromUrl,
  };
}

/**
 * Common shorthand: `loginAs(user)` then build an `authedFetch(token)`. Returns
 * both — most tests want just `fetch`, but a few also need the raw `userId` /
 * expiry timestamps from `tokens` (e.g. AUTH-06 refresh tests).
 */
export async function loginAndFetch(
  app: TestApp,
  user: SeededUser,
): Promise<{ tokens: LoginTokens; fetch: AuthedFetch }> {
  const tokens = await app.loginAs(user);
  return { tokens, fetch: app.authedFetch(tokens.accessToken) };
}

/** Asserts every row's `tenantId` matches the expected tenant id. */
export function expectAllInTenant<T extends { tenantId?: string }>(
  rows: readonly T[],
  tenantId: string,
): void {
  for (const r of rows) expect(r.tenantId).toBe(tenantId);
}

/**
 * Direct read against the underlying app DB (bypasses Moost/ARBAC). Used by
 * write tests to confirm what actually landed in the row, independent of what
 * the HTTP layer reports. Returns `unknown` — caller casts to the row shape it
 * expects (per-test interfaces are still useful for documentation).
 */
export function dbFindOne(
  app: TestApp,
  table: keyof AppHandle["appDb"]["tables"],
  filter: Record<string, unknown>,
): Promise<unknown> {
  const tbl = app.appHandle.appDb.tables[table] as {
    findOne: (q: { filter: Record<string, unknown> }) => Promise<unknown>;
  };
  return tbl.findOne({ filter });
}

/**
 * Direct partial-update against the underlying app DB (bypasses Moost/ARBAC).
 * Used by mutating tests to set up preconditions (e.g. reassign a task to a
 * specific user) without going through the HTTP layer.
 */
export function dbUpdateOne(
  app: TestApp,
  table: keyof AppHandle["appDb"]["tables"],
  patch: Record<string, unknown>,
): Promise<unknown> {
  const tbl = app.appHandle.appDb.tables[table] as {
    updateOne: (p: Record<string, unknown>) => Promise<unknown>;
  };
  return tbl.updateOne(patch);
}

export interface WfFormPause {
  wfs?: string;
  inputRequired?: {
    payload: unknown;
    transport: string;
    context: Record<string, unknown>;
  };
}

export async function readWfPause(res: Response): Promise<WfFormPause & Record<string, unknown>> {
  const body = (await res.json()) as Record<string, unknown>;
  return body as WfFormPause & Record<string, unknown>;
}

/**
 * Drives the auth.recovery workflow up to (but not including) the
 * `SetPasswordForm` submission: start → submit email → wait for the
 * magic-link email → resume from URL → return the paused body so the caller
 * can inspect or submit the password step.
 */
export async function startRecoveryAndResume(
  app: TestApp,
  email: string,
): Promise<{
  emailEvent: Awaited<ReturnType<CaptureEmailSender["next"]>>;
  resumedBody: WfFormPause & Record<string, unknown>;
}> {
  const start = await app.triggerWf("public", { wfid: "auth.recovery" });
  const startBody = await readWfPause(start);
  await app.triggerWf("public", {
    wfid: "auth.recovery",
    wfs: startBody.wfs,
    input: { email },
  });
  const emailEvent = await app.emailSender.next(
    (e) => e.kind === "recovery.magicLink" && e.recipient === email,
    2000,
  );
  const resumed = await app.resumeWfFromUrl(emailEvent.url as string);
  const resumedBody = await readWfPause(resumed);
  return { emailEvent, resumedBody };
}

/** Submits the SetPasswordForm step of an in-flight auth.recovery workflow. */
export function submitRecoveryPassword(
  app: TestApp,
  wfs: string | undefined,
  newPassword: string,
  opts: { confirmPassword?: string; token?: string } = {},
): Promise<Response> {
  return app.triggerWf(
    "public",
    {
      wfid: "auth.recovery",
      wfs,
      input: { newPassword, confirmPassword: opts.confirmPassword ?? newPassword },
    },
    { token: opts.token },
  );
}

/**
 * Drives the auth.login workflow end-to-end for a TOTP-protected user:
 * start → submit credentials → submit a freshly generated TOTP code. Returns
 * the final response (caller asserts/parses) so it can be reused for replay,
 * brute-force, or happy-path tests.
 */
export async function runTotpLoginWorkflow(
  app: TestApp,
  user: { username: string; password: string; totpSecret?: string },
  opts: { code?: string } = {},
): Promise<Response> {
  const start = await app.triggerWf("public", { wfid: "auth.login" });
  const startBody = await readWfPause(start);
  const credResp = await app.triggerWf("public", {
    wfid: "auth.login",
    wfs: startBody.wfs,
    input: { username: user.username, password: user.password },
  });
  const credBody = await readWfPause(credResp);
  const code = opts.code ?? generateTotpCode(user.totpSecret as string);
  return app.triggerWf("public", {
    wfid: "auth.login",
    wfs: credBody.wfs,
    input: { code },
  });
}

// ── Static-ctx setter overrides ──────────────────────────────────────────────
//
// PR9 stripped `mfa.mode` / `mfa.transports` from `LoginWorkflowOpts` and
// `InviteWorkflowOpts`. Those values are now produced by ONE atomic `@Step`
// setter per workflow — `prepareMfaSetup` on `LoginWorkflow`, `inviteSetupMfa`
// on `InviteWorkflow` — whose default bodies hardcode the library defaults.
// Consumers (and tests) override the whole step to inject different values.
//
// The two helpers below generate a tiny override subclass for the common
// "set static MFA ctx values" case so e2e tests don't have to declare a
// full subclass each. The override calls `super.X(ctx)` first and then writes
// only the fields the test supplied — so test-supplied values win over the
// base setter's defaults (currentMfa / enrollMethod auto-pick) while
// unsupplied fields keep the wrapped base class's behaviour. These helpers
// mirror the ones in `packages/auth-moost/src/__test__/workflow-utils.ts`
// (test-only — not on the public surface) and are recreated here because
// `e2e-demo` is itself `private: true`, so its harness can carry its own copy.

export interface WithLoginMfaCtxOverrides {
  mfaMode?: "required" | "optional" | "disabled";
  availableMfaTransports?: MfaTransport[];
  currentMfa?: MfaTransport;
}

/**
 * Wrap a `LoginWorkflow` subclass with a tiny sub-subclass that statically
 * sets the supplied MFA ctx fields. Useful for tests that previously did
 * `loginOpts: { mfa: { mode: 'required' } }` — that opts shape was stripped
 * in PR9; the value now lives on ctx, populated by the `prepareMfaSetup` step.
 *
 * Stacks cleanly on top of consumer subclasses (e.g. `DemoLoginWorkflow`):
 *   loginWorkflowClass: withLoginMfaCtx(DemoLoginWorkflow, { mfaMode: 'disabled' })
 */
export function withLoginMfaCtx<W extends typeof LoginWorkflow>(
  Base: W,
  ctx: WithLoginMfaCtxOverrides,
): W {
  @Inherit()
  @Injectable("FOR_EVENT")
  @Controller()
  class WithLoginCtx extends (Base as unknown as new (
    users: UserService,
    auth: AuthCredential,
  ) => LoginWorkflow) {
    // Forwarding ctor required so TS emits design:paramtypes metadata for moost DI.
    // eslint-disable-next-line no-useless-constructor
    constructor(users: UserService, auth: AuthCredential) {
      super(users, auth);
    }

    @Step("prepareMfaSetup")
    @Public()
    override prepareMfaSetup(
      @WorkflowParam("context") c: LoginWfCtx,
    ): undefined | Promise<undefined> {
      const baseResult = super.prepareMfaSetup(c);
      const apply = (): undefined => {
        if (ctx.mfaMode !== undefined) c.mfaMode = ctx.mfaMode;
        if (ctx.availableMfaTransports !== undefined) {
          c.availableMfaTransports = [...ctx.availableMfaTransports];
        }
        if (ctx.currentMfa !== undefined) c.currentMfa = ctx.currentMfa;
        if (!c.currentMfa && c.availableMfaTransports?.length === 1) {
          c.currentMfa = c.availableMfaTransports[0];
        }
        return undefined;
      };
      return baseResult instanceof Promise ? baseResult.then(apply) : apply();
    }
  }
  return WithLoginCtx as unknown as W;
}

export interface WithInviteMfaCtxOverrides {
  mfaMode?: "required" | "optional" | "disabled";
  availableMfaTransports?: MfaTransport[];
  enrollMethod?: MfaTransport;
}

/**
 * Invite-side counterpart of `withLoginMfaCtx`. Overrides the single
 * `inviteSetupMfa` setter step, writing whichever fields are supplied AFTER
 * `super.inviteSetupMfa(ctx)` runs so the test-supplied values win.
 */
export function withInviteMfaCtx<W extends typeof InviteWorkflow>(
  Base: W,
  ctx: WithInviteMfaCtxOverrides,
): W {
  @Inherit()
  @Injectable("FOR_EVENT")
  @Controller()
  class WithInviteCtx extends (Base as unknown as new (
    users: UserService,
    auth: AuthCredential,
  ) => InviteWorkflow) {
    // eslint-disable-next-line no-useless-constructor -- see withLoginMfaCtx for why
    constructor(users: UserService, auth: AuthCredential) {
      super(users, auth);
    }

    @Step("inviteSetupMfa")
    @Public()
    override inviteSetupMfa(
      @WorkflowParam("context") c: InviteWfCtx,
    ): undefined | Promise<undefined> {
      const baseResult = super.inviteSetupMfa(c);
      const apply = (): undefined => {
        if (ctx.mfaMode !== undefined) c.mfaMode = ctx.mfaMode;
        if (ctx.availableMfaTransports !== undefined) {
          c.availableMfaTransports = [...ctx.availableMfaTransports];
        }
        if (ctx.enrollMethod !== undefined) c.enrollMethod = ctx.enrollMethod;
        if (!c.enrollMethod && c.availableMfaTransports?.length === 1) {
          c.enrollMethod = c.availableMfaTransports[0];
        }
        return undefined;
      };
      return baseResult instanceof Promise ? baseResult.then(apply) : apply();
    }
  }
  return WithInviteCtx as unknown as W;
}
