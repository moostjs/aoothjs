import {
  Arbac,
  arbacAuthorizeInterceptor,
  ArbacUserProviderToken,
  MoostArbac,
  type TArbacRole,
} from "@aooth/arbac-moost";
import { AuthCredential, type AuthCredentialOptions, CredentialStoreMemory } from "@aooth/auth";
import { UserService, UserStoreMemory } from "@aooth/user";
import type { UserServiceConfig } from "@aooth/user";
import { MoostHttp } from "@moostjs/event-http";
import { createHttpApp } from "@wooksjs/event-http";
import { createProvideRegistry, createReplaceRegistry, getMoostInfact, Moost } from "moost";
import { Wooks } from "wooks";

import { AuthController } from "../auth.controller";
import type { AuthOptions } from "../auth.config";
import { authGuardInterceptor } from "../auth.guard";
import { requestVia, setTestArbacUserRoles, TestArbacUserProvider } from "./test-harness";

export interface MyClaims extends Record<string, unknown> {
  roles?: string[];
}

export interface PreparedControllerApp {
  moost: Moost;
  http: MoostHttp;
  auth: AuthCredential<MyClaims>;
  users: UserService;
  userStore: UserStoreMemory;
  request: (
    input: string,
    init?: RequestInit & { json?: unknown },
  ) => Promise<{ status: number; body: unknown; setCookies: string[]; response: Response | null }>;
}

export interface PrepareControllerOpts extends AuthOptions {
  /** Override the AuthCredential constructor options. */
  authOptions?: Partial<AuthCredentialOptions<MyClaims>>;
  /** UserService config (lockout threshold, password policies, etc). */
  userConfig?: UserServiceConfig;
  /** When set, skip wiring `userService` into setup (for negative tests). */
  withoutUserService?: boolean;
  /** When `false`, skip auto-registering `AuthController`. Default: `true`. */
  endpoints?: boolean;
  /**
   * Mount `AuthController` under this prefix (e.g. `'api/auth'`) instead of at
   * the root. Drives the refresh-cookie-path derivation tests.
   */
  controllerPrefix?: string;
  /**
   * Register this class instead of `AuthController` for the bundled endpoints
   * (must extend `AuthController`). Lets the refresh-cookie-path tests cover a
   * subclassed controller — the downstream consumer's case.
   */
  controllerClass?: typeof AuthController;
  /**
   * Extra controllers to register alongside (or instead of, when
   * `endpoints=false`) `AuthController`. Registered BEFORE `moost.init()` so
   * routes are wired during the same boot pass — registering after init
   * silently no-ops on the HTTP adapter (the route table is frozen).
   */
  extraControllers?: Array<new (...args: never[]) => unknown>;
  /**
   * When set, wires `MoostArbac` + a test `ArbacUserProvider` + the
   * `arbacAuthorizeInterceptor` globally. The provider resolves the current
   * user id from `useAuth().getUserId()` and reads roles from the
   * `userRoles` map. Roles are registered via `roles`. Used by ISSUE-4
   * integration tests that verify `@Public()` and `public.*` action grants.
   */
  arbac?: {
    /** `userId -> roles[]`. The test `ArbacUserProvider` reads from this. */
    userRoles: Map<string, string[]>;
    /** Roles registered on the shared MoostArbac singleton. */
    roles: TArbacRole<object, object>[];
  };
}

/**
 * Spins up a `Moost + MoostHttp` instance with real `AuthCredential` (memory
 * store) and real `UserService` (memory store). Returns a typed `request()`
 * helper that wraps `MoostHttp.request()` for ergonomic JSON + cookie checks.
 */
export async function prepareControllerApp(
  opts: PrepareControllerOpts = {},
): Promise<PreparedControllerApp> {
  // Moost's Infact is a process-global singleton; instances cached by class
  // identity leak across tests. Reset its private registry before every
  // spin-up — same pattern as `workflow-utils.ts`. Without this, ISSUE-4
  // ARBAC integration tests see the first test's `TestArbacUserProvider`
  // singleton (with its frozen `activeUserRoles` snapshot) for the rest of
  // the run, masking per-test role variation.
  (getMoostInfact() as unknown as { _cleanup?: () => void })._cleanup?.();

  const moost = new Moost();
  // `new MoostHttp()` with no args would use the global Wooks singleton, which
  // shares its router across tests and produces "Duplicate route registered"
  // warnings on subsequent setups. Pass a fresh `WooksHttp` per test to isolate.
  const wooksHttp = createHttpApp(undefined, new Wooks());
  const http = moost.adapter(new MoostHttp(wooksHttp));

  const store = new CredentialStoreMemory<MyClaims>();
  const auth = new AuthCredential<MyClaims>({
    store,
    method: "token",
    accessTtl: 60_000,
    refresh: { ttl: 600_000, rotation: "always" },
    ...opts.authOptions,
  });

  const userStore = new UserStoreMemory();
  const users = new UserService(userStore, opts.userConfig);

  const {
    authOptions: _a,
    userConfig: _u,
    withoutUserService,
    endpoints = true,
    controllerPrefix,
    controllerClass,
    arbac: arbacOpts,
    extraControllers,
    ...cfg
  } = opts;
  const providers: Parameters<typeof createProvideRegistry> = [[AuthCredential, () => auth]];
  if (!withoutUserService) {
    providers.push([UserService, () => users]);
  }
  moost.setProvideRegistry(createProvideRegistry(...providers));
  moost.applyGlobalInterceptors(authGuardInterceptor(cfg));

  if (arbacOpts) {
    // Set the active user→roles map BEFORE the moost wiring runs. The
    // SINGLETON `TestArbacUserProvider` (defined once at module scope, see
    // bottom of this file) reads from this module-level ref each invocation,
    // so per-test overrides take effect even though infact's global
    // registry returns the same instance across tests. This is the only way
    // to keep a per-test role map under the moost@0.6.x + infact@0.4.x
    // singleton model — see comment on `TestArbacUserProvider` below.
    setTestArbacUserRoles(arbacOpts.userRoles);
    moost.setReplaceRegistry(
      createReplaceRegistry([ArbacUserProviderToken, TestArbacUserProvider]),
    );
    moost.applyGlobalInterceptors(arbacAuthorizeInterceptor);
  }

  if (endpoints) {
    const Ctrl = controllerClass ?? AuthController;
    // biome-ignore lint/suspicious/noExplicitAny: registerControllers takes the
    // package-internal prefixed-tuple shape; tests pass a plain class/tuple.
    moost.registerControllers(controllerPrefix ? [controllerPrefix, Ctrl] : Ctrl);
  }
  if (extraControllers && extraControllers.length > 0) {
    // biome-ignore lint/suspicious/noExplicitAny: moost.registerControllers takes the
    // package-internal `TClassConstructor` shape; tests pass plain constructors.
    moost.registerControllers(...(extraControllers as any[]));
  }

  await moost.init();

  if (arbacOpts) {
    // Register roles on the singleton MoostArbac instance after init so the
    // arbac-core engine sees them at evaluation time.
    const arbac = (await getMoostInfact().get(MoostArbac)) as Arbac<object, object>;
    for (const role of arbacOpts.roles) arbac.registerRole(role);
  }

  const request = requestVia(http);

  return { moost, http, auth, users, userStore, request };
}

/**
 * Convenience helper to parse the value of a Set-Cookie header (`name=value`
 * portion only).
 */
export function parseCookieValue(setCookie: string, name: string): string | null {
  const parts = setCookie.split(";")[0]?.trim();
  if (!parts) return null;
  const [n, v] = parts.split("=");
  if (n !== name) return null;
  return v ?? "";
}
