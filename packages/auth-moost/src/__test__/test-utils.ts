import type { AuthCredential, AuthContext } from "@aoothjs/auth";
import { AuthCredential as AuthCredentialClass, CredentialStoreMemory } from "@aoothjs/auth";
import { prepareTestHttpContext } from "@wooksjs/event-http";
import type { TMoostAdapter, TMoostAdapterOptions } from "moost";
import {
  Controller,
  current,
  getMoostMate,
  Moost,
  setControllerContext,
  TInterceptorPriority,
} from "moost";

import { useAuth } from "../auth.composables";
import { authGuardInterceptor } from "../auth.guard";
import { setupAuthMoost, type SetupAuthMoostOptions } from "../auth.setup";

/**
 * Synthesizes a `handlers` entry on a method so `moost.init()` walks our test
 * controllers without requiring `@moostjs/event-http` (not a dep of this package).
 */
export function TestHandler(): MethodDecorator {
  return getMoostMate().decorate(
    "handlers" as never,
    { type: "TEST", path: "" } as never,
    true,
  ) as MethodDecorator;
}

export interface MyClaims extends Record<string, unknown> {
  roles?: string[];
}

export type ControllerClass = new () => object;

export interface CapturedHandler {
  method: string;
  controllerName?: string;
  getInstance: () => Promise<object>;
  fakeInstance: object;
}

/** Minimal moost adapter that records bound handlers for test invocation. */
export class TestAdapter implements TMoostAdapter<unknown> {
  name = "test-adapter";
  handlers: CapturedHandler[] = [];

  bindHandler<T extends object>(opts: TMoostAdapterOptions<unknown, T>): void {
    for (const handler of opts.handlers) {
      void handler;
      this.handlers.push({
        method: String(opts.method),
        controllerName: opts.controllerName,
        getInstance: async () => (await opts.getInstance()) as object,
        fakeInstance: opts.fakeInstance as object,
      });
    }
  }
}

export interface PreparedTestApp {
  moost: Moost;
  adapter: TestAdapter;
  auth: AuthCredential<MyClaims>;
}

export async function prepareTestApp(
  controllers: ControllerClass[],
  opts: Omit<SetupAuthMoostOptions<MyClaims>, "authCredential"> = {},
): Promise<PreparedTestApp> {
  const moost = new Moost();
  const adapter = new TestAdapter();
  moost.adapter(adapter);
  moost.registerControllers(...controllers);

  const store = new CredentialStoreMemory<MyClaims>();
  const auth = new AuthCredentialClass<MyClaims>({ store, method: "token", accessTtl: 60_000 });
  // Existing guard-focused tests don't care about endpoints; default off here
  // so callers don't have to pass a UserService. They can still opt-in by
  // setting `endpoints: true` in opts.
  setupAuthMoost(moost, { authCredential: auth, endpoints: false, ...opts });

  await moost.init();
  return { moost, adapter, auth };
}

export interface GuardRunResult {
  ok: boolean;
  thrown?: Error;
  authContext: AuthContext<MyClaims> | null;
  isAuthenticated: boolean;
}

/**
 * Invokes the guard's `before` phase inside an HTTP test context with the
 * requested headers/cookies, against the named controller.method handler.
 */
export async function runGuardForHandler(
  app: PreparedTestApp,
  controllerName: string,
  method: string,
  httpOpts: {
    headers?: Record<string, string>;
    cookies?: string;
  },
): Promise<GuardRunResult> {
  const entry = app.adapter.handlers.find(
    (h) => h.controllerName === controllerName && h.method === method,
  );
  if (!entry) throw new Error(`No bound handler for ${controllerName}.${method}`);
  const instance = await entry.getInstance();
  const headers: Record<string, string> = { ...httpOpts.headers };
  if (httpOpts.cookies) headers.cookie = httpOpts.cookies;
  const run = prepareTestHttpContext({ url: "/test", method: "GET", headers });
  return await run(async (): Promise<GuardRunResult> => {
    const ctx = current();
    setControllerContext(instance, entry.method as never, "/test", { prefix: "", ctx });
    try {
      // Functional interceptor's `before` may receive a `reply` arg in moost
      // pipelines; we pass a no-op since we only care about throw vs no-throw.
      await authGuardInterceptor.before?.(() => {});
      const auth = useAuth(ctx);
      return {
        ok: true,
        authContext: auth.getCurrentUser<MyClaims>(),
        isAuthenticated: auth.isAuthenticated(),
      };
    } catch (err) {
      return { ok: false, thrown: err as Error, authContext: null, isAuthenticated: false };
    }
  });
}

export { Controller, Moost, TInterceptorPriority };
