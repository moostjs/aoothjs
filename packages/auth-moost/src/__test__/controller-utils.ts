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
import { UserService, UserStoreMemory } from "@aoothjs/user";
import type { UserServiceConfig } from "@aoothjs/user";
import { MoostHttp } from "@moostjs/event-http";
import { createHttpApp } from "@wooksjs/event-http";
import { Moost } from "moost";
import { Wooks } from "wooks";

import { setupAuthMoost, type SetupAuthMoostOptions } from "../auth.setup";

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

export interface PrepareControllerOpts extends Omit<
  SetupAuthMoostOptions<MyClaims>,
  "authCredential" | "userService"
> {
  /** Override the AuthCredential constructor options. */
  authOptions?: Partial<AuthCredentialOptions<MyClaims>>;
  /** UserService config (lockout threshold, password policies, etc). */
  userConfig?: UserServiceConfig;
  /** When set, skip wiring `userService` into setup (for negative tests). */
  withoutUserService?: boolean;
}

/**
 * Spins up a `Moost + MoostHttp` instance with real `AuthCredential` (memory
 * store) and real `UserService` (memory store). Returns a typed `request()`
 * helper that wraps `MoostHttp.request()` for ergonomic JSON + cookie checks.
 */
export async function prepareControllerApp(
  opts: PrepareControllerOpts = {},
): Promise<PreparedControllerApp> {
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

  const { authOptions: _a, userConfig: _u, withoutUserService, ...setupOpts } = opts;
  setupAuthMoost(moost, {
    authCredential: auth,
    userService: withoutUserService ? undefined : users,
    ...setupOpts,
  });

  await moost.init();

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
