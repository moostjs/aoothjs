// `@aooth/auth/client` — browser-safe client helpers.
//
// This entry intentionally imports NOTHING from the rest of `@aooth/auth`
// (which pulls in `jose` / Node crypto). Keep it dependency-free and free of
// any server-only import so it stays safe to bundle into a browser app.

/** Minimal structural view of a fetch `Response` this helper reads. The DOM `Response` satisfies it. */
export interface MinimalResponse {
  readonly ok: boolean;
  readonly status: number;
}

/**
 * Subset of `RequestInit` this helper sets or forwards. The DOM `RequestInit`
 * (and Node's) is assignable to it: fields the helper never inspects are typed
 * `unknown` so `Headers` instances, `AbortSignal`s and any body type pass through.
 */
export interface MinimalRequestInit {
  method?: string;
  headers?: unknown;
  body?: unknown;
  credentials?: "omit" | "same-origin" | "include";
  signal?: unknown;
  // The rest of the standard `RequestInit` keys, forwarded untouched — so a
  // project without the DOM lib can still pass them.
  cache?: unknown;
  mode?: unknown;
  redirect?: unknown;
  referrer?: unknown;
  referrerPolicy?: unknown;
  integrity?: unknown;
  keepalive?: unknown;
  priority?: unknown;
  window?: unknown;
  duplex?: unknown;
  dispatcher?: unknown;
}

/**
 * A `fetch`-compatible function. The global `fetch` (DOM or Node) satisfies it.
 * Declared method-style so its parameters are compared bivariantly — the DOM
 * `fetch`'s wider `RequestInfo` / `RequestInit` parameters still match.
 */
export type FetchFn = {
  fetch(input: string | URL, init?: MinimalRequestInit): Promise<MinimalResponse>;
}["fetch"];

/**
 * Resolves to the ambient `fetch` type when the consumer's tsconfig includes the
 * DOM lib — so the returned wrapper yields a real `Response` with `.json()` etc.
 * — and falls back to the structural {@link FetchFn} otherwise. This keeps
 * `@aooth/auth/client` free of a hard DOM-lib dependency while preserving great
 * DX in browser projects.
 */
export type DefaultFetch = typeof globalThis extends { fetch: infer F extends FetchFn }
  ? F
  : FetchFn;

/**
 * Why a refresh failed: `status` is the refresh endpoint's HTTP status when it
 * answered; `error` is the thrown value when the request itself failed
 * (offline, aborted, DNS, CORS).
 */
export interface AuthedFetchRefreshFailure {
  status?: number;
  error?: unknown;
}

export interface CreateAuthedFetchOptions<TFetch extends FetchFn = DefaultFetch> {
  /** Refresh endpoint path or URL. Default `'/auth/refresh'`. Match your `AuthController` mount. */
  refreshPath?: string;
  /**
   * Which refresh failures end the session (fire {@link onLogout}):
   * - `'auth-failure'` (default) — only when the refresh endpoint answers
   *   400, 401 or 403 (the refresh token is missing, invalid, expired or revoked).
   *   A network error, abort, 429 or 5xx is transient: the session is kept and
   *   {@link onRefreshError} fires instead.
   * - `'any-failure'` — every failed refresh logs out (the pre-0.2 behaviour).
   */
  logoutOn?: "auth-failure" | "any-failure";
  /**
   * Called exactly once per failed single-flight refresh that ends the session
   * (see {@link logoutOn}). Use it to redirect to login / clear app state.
   * Never called on a successful refresh.
   */
  onLogout?: (reason: AuthedFetchRefreshFailure) => void;
  /**
   * Called once per failed single-flight refresh that does NOT end the session
   * (a transient failure under `logoutOn: 'auth-failure'`). The original
   * failing response is returned to the caller; the next 401 tries again.
   */
  onRefreshError?: (reason: AuthedFetchRefreshFailure) => void;
  /** Underlying fetch implementation. Default: the global `fetch`, resolved on every call. */
  fetch?: TFetch;
  /** Response status codes that trigger a refresh + single retry. Default `[401]`. */
  refreshOn?: number[];
}

/**
 * Wraps `fetch` with cookie-session silent refresh. Every call forwards
 * credentials; a response whose status is in `refreshOn` (401 by default)
 * triggers a **single-flight** refresh — N concurrent failing requests share
 * exactly one `POST {refreshPath}` — and, on success, the original request is
 * retried **once**. A refresh rejected with 400/401/403 fires `onLogout()` once;
 * a transient failure (offline, 429, 5xx) fires `onRefreshError()` and keeps the
 * session. Either way the original failing response is returned (no retry, no
 * refresh storm).
 *
 * Browser-safe: pairs with the bundled `@aooth/auth-moost` httpOnly-cookie
 * transport, so the SPA never touches token material. The retried request reuses
 * the original `init`; passing a one-shot body (a consumed `ReadableStream`) is
 * not retry-safe — prefer string / `FormData` / `Blob` bodies.
 *
 * @example
 * ```ts
 * import { createAuthedFetch } from '@aooth/auth/client'
 * const api = createAuthedFetch({ refreshPath: '/auth/refresh', onLogout: () => location.assign('/login') })
 * const res = await api('/api/me')   // 401 → silent refresh → retried once
 * ```
 */
export function createAuthedFetch<TFetch extends FetchFn = DefaultFetch>(
  options: CreateAuthedFetchOptions<TFetch> = {},
): TFetch {
  const refreshPath = options.refreshPath ?? "/auth/refresh";
  const { onLogout, onRefreshError } = options;
  const logoutOnAny = options.logoutOn === "any-failure";
  const refreshOn = options.refreshOn ?? [401];
  const resolveFetch = (): FetchFn => {
    const f = options.fetch ?? (globalThis as { fetch?: FetchFn }).fetch;
    if (typeof f !== "function") {
      throw new Error("createAuthedFetch: no fetch implementation available — pass options.fetch");
    }
    return f;
  };

  // Single-flight: while a refresh is in flight, every other 401 awaits the same
  // promise instead of firing its own refresh. Cleared on settle so the next
  // fresh 401 starts a new refresh.
  let refreshInFlight: Promise<boolean> | null = null;

  const failed = (reason: AuthedFetchRefreshFailure): false => {
    const authFailure = reason.status === 400 || reason.status === 401 || reason.status === 403;
    // Fired once per failed single-flight refresh, not per caller.
    if (authFailure || logoutOnAny) onLogout?.(reason);
    else onRefreshError?.(reason);
    return false;
  };

  const runRefresh = (): Promise<boolean> => {
    if (refreshInFlight) return refreshInFlight;
    refreshInFlight = (async () => {
      let res: MinimalResponse;
      try {
        res = await resolveFetch()(refreshPath, { method: "POST", credentials: "include" });
      } catch (error) {
        return failed({ error });
      }
      return res.ok || failed({ status: res.status });
    })().finally(() => {
      refreshInFlight = null;
    });
    return refreshInFlight;
  };

  const authedFetch = async (
    input: string | URL,
    init?: MinimalRequestInit,
  ): Promise<MinimalResponse> => {
    const withCreds: MinimalRequestInit = { credentials: "include", ...init };
    const res = await resolveFetch()(input, withCreds);
    if (!refreshOn.includes(res.status)) return res;
    const refreshed = await runRefresh();
    if (!refreshed) return res; // original failing response; onLogout / onRefreshError already fired
    return resolveFetch()(input, withCreds); // retry once — the retry never re-enters refresh
  };

  return authedFetch as unknown as TFetch;
}
