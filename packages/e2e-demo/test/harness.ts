import type { AuthLoginResponse } from "@aoothjs/auth-moost"
import { generateTotpCode } from "@aoothjs/user"
import { clearGlobalWooks, getMoostInfact } from "moost"
import { expect } from "vite-plus/test"

import { type AppHandle, buildApp } from "../src/app"
import { CaptureEmailSender } from "../src/email/capture-email-sender"
import type { AppEnv } from "../src/env"
import { type SeededUser, seedAll, type SeedFixtures } from "../src/seed"

/**
 * @prostojs/router emits route-conflict warnings via build-time-injected
 * `__DYE_*` colour-code constants. In a Vitest worker those globals are
 * undefined and a single warn call throws `ReferenceError`. Booting more
 * than one Moost app per worker (we do via `beforeEach`) reproduces it
 * deterministically because Moost shares a process-global Infact DI
 * registry. Stub the lot once per worker.
 */
export function installDyeStubs(): void {
  for (const k of [
    "__DYE_YELLOW__",
    "__DYE_RED_BRIGHT__",
    "__DYE_GREEN__",
    "__DYE_GREEN_BRIGHT__",
    "__DYE_CYAN__",
    "__DYE_BOLD__",
    "__DYE_BOLD_OFF__",
    "__DYE_DIM__",
    "__DYE_DIM_OFF__",
    "__DYE_COLOR_OFF__",
  ]) {
    if ((globalThis as Record<string, unknown>)[k] === undefined) {
      ;(globalThis as Record<string, unknown>)[k] = ""
    }
  }
}

export const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms))

/** Asserts a 2xx (200 or 201). Wooks emits either depending on handler shape. */
export function expectOk(res: Response): void {
  expect([200, 201]).toContain(res.status)
}

/** Extract `inputRequired.context` from a paused workflow body, asserting presence. */
export function wfContext(body: WfFormPause & Record<string, unknown>): Record<string, unknown> {
  const ir = body.inputRequired
  if (!ir) throw new Error(`wfContext: body has no inputRequired (got ${JSON.stringify(body)})`)
  return ir.context as Record<string, unknown>
}

/** Extract `inputRequired.context.errors` (record of field → message). */
export function wfErrors(body: WfFormPause & Record<string, unknown>): Record<string, string> {
  return (wfContext(body).errors ?? {}) as Record<string, string>
}

export interface BuildTestAppOptions {
  envOverrides?: Partial<AppEnv>
  seed?: boolean
  dbPath?: string
  workflowsEnabled?: { login?: boolean; recovery?: boolean; invite?: boolean }
  authEndpointsEnabled?: boolean
}

export interface FetchInit extends RequestInit {
  token?: string
  json?: unknown
}

export interface AuthedFetch {
  (path: string, init?: Omit<FetchInit, "token">): Promise<Response>
}

export interface LoginTokens {
  accessToken: string
  refreshToken: string
  userId: string
  accessExpiresAt: number
  refreshExpiresAt: number
}

export interface TestApp {
  appHandle: AppHandle
  fixtures: SeedFixtures
  emailSender: CaptureEmailSender
  baseUrl: string
  close: () => Promise<void>
  fetch: (path: string, init?: FetchInit) => Promise<Response>
  loginAs: (user: SeededUser) => Promise<LoginTokens>
  authedFetch: (token: string) => AuthedFetch
  triggerWf: (
    route: "public" | "admin",
    body: unknown,
    opts?: { token?: string },
  ) => Promise<Response>
  resumeWfFromUrl: (
    url: string,
    body?: unknown,
    opts?: { token?: string },
  ) => Promise<Response>
}

const SENTINEL_FIXTURES = {} as SeedFixtures

export async function buildTestApp(opts: BuildTestAppOptions = {}): Promise<TestApp> {
  // Wooks defaults to a process-global router (`getGlobalWooks`). Without this
  // reset, a second buildApp() in the same worker re-registers all routes onto
  // the previous app's router — requests then hit the dead Moost instance and
  // return stale 423/500 responses. Clearing forces each app to install a
  // fresh `Wooks` (with an empty ProstoRouter) on the next `getGlobalWooks()`.
  clearGlobalWooks()
  // Moost's Infact is also a process-global singleton that caches @Injectable
  // instances by class identity. Without a reset, DI singletons created in a
  // previous app (notably MoostAuthWorkflowConfig holding the prior
  // `wfStateStore` whose better-sqlite3 connection has since closed) are
  // re-handed-out to handlers in the next app, producing
  // "TypeError: The database connection is not open" on workflow trigger.
  ;(getMoostInfact() as unknown as { _cleanup?: () => void })._cleanup?.()
  const emailSender = new CaptureEmailSender()
  const appHandle = await buildApp({
    emailSender,
    port: 0,
    dbPath: opts.dbPath ?? ":memory:",
    envOverrides: opts.envOverrides,
    workflowsEnabled: opts.workflowsEnabled,
    authEndpointsEnabled: opts.authEndpointsEnabled,
  })

  const fixtures = opts.seed === false ? SENTINEL_FIXTURES : await seedAll(appHandle)

  const baseUrl = appHandle.baseUrl

  const doFetch = async (path: string, init: FetchInit = {}): Promise<Response> => {
    const url = path.startsWith("http") ? path : `${baseUrl}${path.startsWith("/") ? path : `/${path}`}`
    const headers = new Headers(init.headers)
    let body = init.body
    if (init.json !== undefined) {
      body = JSON.stringify(init.json)
      if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json")
    }
    if (init.token) headers.set("Authorization", `Bearer ${init.token}`)

    const requestInit: RequestInit = {
      ...init,
      headers,
      body: body ?? undefined,
    }
    delete (requestInit as { token?: unknown }).token
    delete (requestInit as { json?: unknown }).json

    // Brief retry guards against ECONNREFUSED windows when many test files run
    // in parallel and sockets briefly stall on macOS.
    let lastErr: unknown
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        return await globalThis.fetch(url, requestInit)
      } catch (err) {
        lastErr = err
        const code = (err as { cause?: { code?: string }; code?: string }).cause?.code
          ?? (err as { code?: string }).code
        if (code !== "ECONNREFUSED" && code !== "ECONNRESET") throw err
        await sleep(50)
      }
    }
    throw lastErr
  }

  const loginAs = async (user: SeededUser): Promise<LoginTokens> => {
    const res = await doFetch("/auth/login", {
      method: "POST",
      json: { username: user.username, password: user.password },
    })
    if (res.status >= 400) {
      const text = await res.text().catch(() => "<unreadable>")
      throw new Error(
        `loginAs(${user.username}) failed: HTTP ${res.status} ${res.statusText} — ${text}`,
      )
    }
    const body = (await res.json()) as AuthLoginResponse
    if (!body.accessToken || !body.refreshToken) {
      throw new Error(
        `loginAs(${user.username}): expected accessToken+refreshToken in response, got ${JSON.stringify(body)}`,
      )
    }
    return {
      accessToken: body.accessToken,
      refreshToken: body.refreshToken,
      userId: body.userId,
      accessExpiresAt: body.accessExpiresAt,
      refreshExpiresAt: body.refreshExpiresAt as number,
    }
  }

  const authedFetch = (token: string): AuthedFetch => {
    return (path, init = {}) => doFetch(path, { ...init, token })
  }

  const triggerWf = (
    route: "public" | "admin",
    body: unknown,
    triggerOpts: { token?: string } = {},
  ): Promise<Response> => {
    return doFetch(`/wf/${route}`, {
      method: "POST",
      json: body,
      token: triggerOpts.token,
    })
  }

  const resumeWfFromUrl = (
    url: string,
    body: unknown = {},
    resumeOpts: { token?: string } = {},
  ): Promise<Response> => {
    const parsed = new URL(url, "http://placeholder")
    const wfs = parsed.searchParams.get("wfs")
    if (!wfs) throw new Error(`resumeWfFromUrl: no ?wfs= in URL: ${url}`)
    const merged =
      body && typeof body === "object" && !Array.isArray(body)
        ? { ...(body as Record<string, unknown>), wfs }
        : { wfs, input: body }
    return doFetch("/wf/public", {
      method: "POST",
      json: merged,
      token: resumeOpts.token,
    })
  }

  const close = async (): Promise<void> => {
    await appHandle.close()
  }

  return {
    appHandle,
    fixtures,
    emailSender,
    baseUrl,
    close,
    fetch: doFetch,
    loginAs,
    authedFetch,
    triggerWf,
    resumeWfFromUrl,
  }
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
  const tokens = await app.loginAs(user)
  return { tokens, fetch: app.authedFetch(tokens.accessToken) }
}

/** Asserts every row's `tenantId` matches the expected tenant id. */
export function expectAllInTenant<T extends { tenantId?: string }>(
  rows: readonly T[],
  tenantId: string,
): void {
  for (const r of rows) expect(r.tenantId).toBe(tenantId)
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
    findOne: (q: { filter: Record<string, unknown> }) => Promise<unknown>
  }
  return tbl.findOne({ filter })
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
    updateOne: (p: Record<string, unknown>) => Promise<unknown>
  }
  return tbl.updateOne(patch)
}

export interface WfFormPause {
  wfs?: string
  inputRequired?: {
    payload: unknown
    transport: string
    context: Record<string, unknown>
  }
}

export async function readWfPause(res: Response): Promise<WfFormPause & Record<string, unknown>> {
  const body = (await res.json()) as Record<string, unknown>
  return body as WfFormPause & Record<string, unknown>
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
  emailEvent: Awaited<ReturnType<CaptureEmailSender["next"]>>
  resumedBody: WfFormPause & Record<string, unknown>
}> {
  const start = await app.triggerWf("public", { wfid: "auth.recovery" })
  const startBody = await readWfPause(start)
  await app.triggerWf("public", {
    wfid: "auth.recovery",
    wfs: startBody.wfs,
    input: { email },
  })
  const emailEvent = await app.emailSender.next(
    (e) => e.kind === "recovery.magicLink" && e.recipient === email,
    2000,
  )
  const resumed = await app.resumeWfFromUrl(emailEvent.url as string)
  const resumedBody = await readWfPause(resumed)
  return { emailEvent, resumedBody }
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
  )
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
  const start = await app.triggerWf("public", { wfid: "auth.login" })
  const startBody = await readWfPause(start)
  const credResp = await app.triggerWf("public", {
    wfid: "auth.login",
    wfs: startBody.wfs,
    input: { username: user.username, password: user.password },
  })
  const credBody = await readWfPause(credResp)
  const code = opts.code ?? generateTotpCode(user.totpSecret as string)
  return app.triggerWf("public", {
    wfid: "auth.login",
    wfs: credBody.wfs,
    input: { code },
  })
}
