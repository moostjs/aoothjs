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

/** Subset of `RequestInit` this helper sets or forwards. The DOM `RequestInit` satisfies it. */
export interface MinimalRequestInit {
  method?: string;
  headers?: Record<string, string>;
  body?: unknown;
  credentials?: "omit" | "same-origin" | "include";
  signal?: unknown;
  [key: string]: unknown;
}

/** A `fetch`-compatible function. The global `fetch` satisfies this. */
export type FetchFn = (input: string | URL, init?: MinimalRequestInit) => Promise<MinimalResponse>;

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

export interface CreateAuthedFetchOptions<TFetch extends FetchFn = DefaultFetch> {
  /** Refresh endpoint path or URL. Default `'/auth/refresh'`. Match your `AuthController` mount. */
  refreshPath?: string;
  /**
   * Called exactly once per failed refresh attempt (non-OK response or network
   * error). Use it to redirect to login / clear app state. Never called on a
   * successful refresh.
   */
  onLogout?: () => void;
  /** Underlying fetch implementation. Default: the global `fetch`. */
  fetch?: TFetch;
  /** Response status codes that trigger a refresh + single retry. Default `[401]`. */
  refreshOn?: number[];
}

/**
 * Wraps `fetch` with cookie-session silent refresh. Every call forwards
 * credentials; a response whose status is in `refreshOn` (401 by default)
 * triggers a **single-flight** refresh — N concurrent failing requests share
 * exactly one `POST {refreshPath}` — and, on success, the original request is
 * retried **once**. A failed refresh fires `onLogout()` once and returns the
 * original failing response (no retry, no refresh storm).
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
  const onLogout = options.onLogout;
  const refreshOn = options.refreshOn ?? [401];
  const baseFetch = options.fetch ?? (globalThis as { fetch?: FetchFn }).fetch;
  if (typeof baseFetch !== "function") {
    throw new Error("createAuthedFetch: no fetch implementation available — pass options.fetch");
  }

  // Single-flight: while a refresh is in flight, every other 401 awaits the same
  // promise instead of firing its own refresh. Cleared on settle so the next
  // fresh 401 starts a new refresh.
  let refreshInFlight: Promise<boolean> | null = null;

  const runRefresh = (): Promise<boolean> => {
    if (refreshInFlight) return refreshInFlight;
    refreshInFlight = (async () => {
      try {
        const res = await baseFetch(refreshPath, { method: "POST", credentials: "include" });
        if (res.ok) return true;
      } catch {
        // network error during refresh — treat as a failed refresh below
      }
      onLogout?.(); // fired once per failed single-flight refresh, not per caller
      return false;
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
    const res = await baseFetch(input, withCreds);
    if (!refreshOn.includes(res.status)) return res;
    const refreshed = await runRefresh();
    if (!refreshed) return res; // original failing response; onLogout already fired
    return baseFetch(input, withCreds); // retry once — the retry never re-enters refresh
  };

  return authedFetch as unknown as TFetch;
}
