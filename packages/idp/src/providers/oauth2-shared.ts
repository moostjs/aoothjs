import { OAuthError, type OAuthErrorType } from "../errors";
import type { AuthorizationUrlArgs, FetchLike } from "../types";

/** Resolve the effective `fetch`: an injected impl, else the global `fetch`. */
export function resolveFetch(impl?: FetchLike): FetchLike {
  return impl ?? (globalThis.fetch as unknown as FetchLike);
}

/**
 * `fetch` a JSON endpoint, failing CLOSED as an {@link OAuthError} on a network
 * error, a non-2xx status, or a non-JSON body. `label` names the call in the
 * thrown message; `errorType` selects the error class — token / provider-API
 * failures are `EXCHANGE_FAILED`, OIDC discovery fails as `JWKS_FAILED`.
 *
 * Returns the parsed body as `unknown` — the caller narrows / applies any
 * provider-specific post-checks (GitHub's HTTP-200 `{ error }`, an
 * `access_token` presence guard, the OIDC discovery issuer match, …).
 */
export async function fetchJson(
  fetchFn: FetchLike,
  url: string,
  init: Parameters<FetchLike>[1],
  opts: { label: string; errorType?: OAuthErrorType },
): Promise<unknown> {
  const errorType = opts.errorType ?? "EXCHANGE_FAILED";
  let res: Awaited<ReturnType<FetchLike>>;
  try {
    res = await fetchFn(url, init);
  } catch (err) {
    throw new OAuthError(errorType, `${opts.label} request failed`, { cause: String(err) });
  }
  if (!res.ok) {
    throw new OAuthError(errorType, `${opts.label} returned ${res.status}`, { status: res.status });
  }
  try {
    return await res.json();
  } catch {
    throw new OAuthError(errorType, `${opts.label} returned a non-JSON body`);
  }
}

/** Optional knobs layered onto the shared authorization-code + PKCE request. */
export interface BuildAuthorizeUrlOptions {
  /** Set `response_type=code` (real OAuth2/OIDC IdPs; the test fake omits it). */
  responseType?: boolean;
  /** Set `client_id`. Omit for providers that don't need it (the test fake). */
  clientId?: string;
  /** Provider default scopes; `args.scopes` overrides. Omit to send no `scope`. */
  scopes?: string[];
  /** Append `nonce` when `args.nonce` is set. OIDC-family only — pure OAuth2 (GitHub) leaves this off. */
  nonce?: boolean;
  /** Extra provider-specific params (e.g. Apple's `response_mode=form_post`). */
  extraParams?: Record<string, string>;
}

/**
 * Build the `302`-target authorization URL shared by every provider:
 * `redirect_uri` + `state` + the PKCE S256 `code_challenge`. The OAuth2/OIDC
 * extras (`response_type`, `client_id`, `scope`, `nonce`, provider params) are
 * layered on via {@link BuildAuthorizeUrlOptions}.
 */
export function buildAuthorizeUrl(
  endpoint: string,
  args: AuthorizationUrlArgs,
  opts: BuildAuthorizeUrlOptions = {},
): string {
  const url = new URL(endpoint);
  if (opts.responseType) url.searchParams.set("response_type", "code");
  if (opts.clientId) url.searchParams.set("client_id", opts.clientId);
  url.searchParams.set("redirect_uri", args.redirectUri);
  if (opts.scopes) url.searchParams.set("scope", (args.scopes ?? opts.scopes).join(" "));
  url.searchParams.set("state", args.state);
  url.searchParams.set("code_challenge", args.codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  if (opts.nonce && args.nonce) url.searchParams.set("nonce", args.nonce);
  for (const [k, v] of Object.entries(opts.extraParams ?? {})) url.searchParams.set(k, v);
  return url.toString();
}
