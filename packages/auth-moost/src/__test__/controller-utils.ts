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

import {
  Arbac,
  arbacAuthorizeInterceptor,
  ArbacUserProvider,
  ArbacUserProviderToken,
  MoostArbac,
  type TArbacRole,
} from "@aooth/arbac-moost";
import { AuthCredential, type AuthCredentialOptions, CredentialStoreMemory } from "@aooth/auth";
import { UserService, UserStoreMemory } from "@aooth/user";
import type { UserServiceConfig } from "@aooth/user";
import { MoostHttp } from "@moostjs/event-http";
import { createHttpApp } from "@wooksjs/event-http";
import {
  createProvideRegistry,
  createReplaceRegistry,
  getMoostInfact,
  Injectable,
  Moost,
} from "moost";
import { Wooks } from "wooks";

import { useAuth } from "../auth.composables";
import { AuthController } from "../auth.controller";
import type { AuthOptions } from "../auth.config";
import { authGuardInterceptor } from "../auth.guard";

// Module-level mutable role map consumed by `TestArbacUserProvider`. Updated
// by each `prepareControllerApp({ arbac })` call BEFORE Moost wires up. The
// SINGLETON provider class is also defined at module scope so its
// `Symbol.for(class.toString())` is stable across tests (two locally-defined
// classes with identical bodies collapse to the same Symbol, which would
// freeze the FIRST test's closure-captured map). Pairing module-scope class
// with module-scope ref keeps per-test overrides observable. The
// `getMoostInfact()._cleanup()` call below also wipes the cached instance
// so a fresh provider is allocated per test — both layers of defense are
// kept because either alone is insufficient: cleanup alone wouldn't help
// if the user later inlined the class, and the ref alone leaks state if
// other tests in the same process call into the provider out-of-band.
let activeUserRoles = new Map<string, string[]>();

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
    activeUserRoles = arbacOpts.userRoles;
    moost.setReplaceRegistry(
      createReplaceRegistry([ArbacUserProviderToken, TestArbacUserProvider]),
    );
    moost.applyGlobalInterceptors(arbacAuthorizeInterceptor);
  }

  if (endpoints) {
    const Ctrl = controllerClass ?? AuthController;
    // biome-ignore lint/suspicious/noExplicitAny: registerControllers takes the
    // package-internal prefixed-tuple shape; tests pass a plain class/tuple.
    moost.registerControllers((controllerPrefix ? [controllerPrefix, Ctrl] : Ctrl) as any);
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

  async function request(
    input: string,
    init: RequestInit & { json?: unknown } = {},
  ): Promise<{ status: number; body: unknown; setCookies: string[]; response: Response | null }> {
    const { json, ...rest } = init;
    const headers = new Headers(rest.headers);
    let body = rest.body;
    if (json !== undefined) {
      body = JSON.stringify(json);
      if (!headers.has("content-type")) headers.set("content-type", "application/json");
    }
    const response = await http.request(input, { ...rest, headers, body });
    if (!response) {
      return { status: 0, body: null, setCookies: [], response: null };
    }
    const text = await response.text();
    let parsed: unknown = text;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      // not JSON; leave as text
    }
    const setCookies = response.headers.getSetCookie?.() ?? [];
    return { status: response.status, body: parsed, setCookies, response };
  }

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

/**
 * Singleton test `ArbacUserProvider` — defined once at module scope so its
 * `classSymbol` (computed by `Symbol.for(class.toString())` inside infact) is
 * stable across tests. Reads roles from the module-level `activeUserRoles`
 * ref, which each `prepareControllerApp({ arbac })` call mutates BEFORE
 * Moost initialization. See the comment on `activeUserRoles` above.
 */
@Injectable()
class TestArbacUserProvider extends ArbacUserProvider {
  override getUserId(): string {
    return useAuth().getUserId();
  }
  override getRoles(id: string): string[] {
    return activeUserRoles.get(id) ?? [];
  }
  override getAttrs(): object {
    return {};
  }
}
