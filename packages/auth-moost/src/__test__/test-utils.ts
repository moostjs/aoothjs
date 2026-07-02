import type { AuthCredential, AuthContext } from "@aooth/auth";
import { AuthCredential as AuthCredentialClass, CredentialStoreMemory } from "@aooth/auth";
import { UserService } from "@aooth/user";
import { prepareTestHttpContext } from "@wooksjs/event-http";
import type { TInterceptorDef, TMoostAdapter, TMoostAdapterOptions } from "moost";
import {
  Controller,
  createProvideRegistry,
  current,
  getMoostMate,
  Moost,
  setControllerContext,
  TInterceptorPriority,
} from "moost";

import type { AuthOptions } from "../auth.config";
import { useAuth } from "../auth.composables";
import { authGuardInterceptor } from "../auth.guard";

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

// Typed credential payload — flat root fields (replacing the dropped `claims`
// container). Surfaces on the AuthContext by name.
export interface MyClaims {
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
  /** Configured interceptor — captured so `runGuardForHandler` can invoke its `before` directly. */
  guard: TInterceptorDef;
}

export interface PrepareTestAppOpts extends AuthOptions {
  /** Optional UserService; when omitted, login + password endpoints are not exercised. */
  userService?: UserService;
}

export async function prepareTestApp(
  controllers: ControllerClass[],
  opts: PrepareTestAppOpts = {},
): Promise<PreparedTestApp> {
  const moost = new Moost();
  const adapter = new TestAdapter();
  moost.adapter(adapter);
  moost.registerControllers(...controllers);

  const store = new CredentialStoreMemory<MyClaims>();
  const auth = new AuthCredentialClass<MyClaims>({ store, method: "token", accessTtl: 60_000 });

  const { userService, ...cfg } = opts;
  const providers: Parameters<typeof createProvideRegistry> = [[AuthCredentialClass, () => auth]];
  if (userService) providers.push([UserService, () => userService]);
  moost.setProvideRegistry(createProvideRegistry(...providers));
  const guard = authGuardInterceptor(cfg);
  moost.applyGlobalInterceptors(guard);

  await moost.init();
  return { moost, adapter, auth, guard };
}

export interface GuardRunResult {
  ok: boolean;
  thrown?: Error;
  authContext: AuthContext<MyClaims> | null;
  isAuthenticated: boolean;
}

/**
 * Runs `fn` inside an HTTP test context prepared with the requested
 * headers/cookies, with the controller context set to the named
 * controller.method handler — the shared scaffolding for exercising
 * interceptors against bound test handlers.
 */
export async function withHandlerContext<T>(
  app: PreparedTestApp,
  controllerName: string,
  method: string,
  httpOpts: {
    headers?: Record<string, string>;
    cookies?: string;
  },
  fn: () => Promise<T>,
): Promise<T> {
  const entry = app.adapter.handlers.find(
    (h) => h.controllerName === controllerName && h.method === method,
  );
  if (!entry) throw new Error(`No bound handler for ${controllerName}.${method}`);
  const instance = await entry.getInstance();
  const headers: Record<string, string> = { ...httpOpts.headers };
  if (httpOpts.cookies) headers.cookie = httpOpts.cookies;
  const run = prepareTestHttpContext({ url: "/test", method: "GET", headers });
  return await run(async (): Promise<T> => {
    setControllerContext(instance, entry.method as never, "/test", { prefix: "", ctx: current() });
    return fn();
  });
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
  return withHandlerContext(app, controllerName, method, httpOpts, async () => {
    try {
      // Functional interceptor's `before` may receive a `reply` arg in moost
      // pipelines; we pass a no-op since we only care about throw vs no-throw.
      await app.guard.before?.(() => {});
      const auth = useAuth(current());
      return {
        ok: true,
        authContext: auth.getAuthContext<MyClaims>(),
        isAuthenticated: auth.isAuthenticated(),
      };
    } catch (err) {
      return { ok: false, thrown: err as Error, authContext: null, isAuthenticated: false };
    }
  });
}

export { Controller, Moost, TInterceptorPriority };
