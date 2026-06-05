import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

/**
 * `@aooth/login-client` — a zero-dependency helper that obtains a token from an
 * aoothjs authorization server by driving the user through a **browser login**
 * and catching the result on an ephemeral **loopback** redirect (the
 * `gh auth login` pattern). Built on Node built-ins + global `fetch` only, so it
 * drops into any CLI with no transitive deps.
 *
 * It is also usable as a generic "Sign in with <main app>" hatch for a
 * first-party service: only the `redirect_uri` differs (a real loopback URL on a
 * developer machine vs. — in a hosted relying service — that service's own
 * callback). The flow (authorization-code + PKCE + back-channel token exchange)
 * is identical.
 */

/** Error codes surfaced by {@link authorize}. */
export type AuthorizeErrorCode =
  /** The provider returned `?error=` on the callback (e.g. the user declined). */
  | "provider_denied"
  /** The callback `state` did not match the one we generated (CSRF / instance mismatch). */
  | "state_mismatch"
  /** The `POST /token` exchange failed (non-2xx, network, or malformed body). */
  | "exchange_failed"
  /** No callback arrived before `timeoutMs` (or the `signal` aborted). */
  | "timeout"
  /** The optional `statusUrl` confirmation did not return 200. */
  | "status_check_failed";

/** A typed failure of the loopback login flow. */
export class AuthorizeError extends Error {
  readonly code: AuthorizeErrorCode;
  constructor(code: AuthorizeErrorCode, message: string) {
    super(message);
    this.name = "AuthorizeError";
    this.code = code;
  }
}

export interface AuthorizeOptions {
  /** The authorization server's `GET /auth/authorize` URL. */
  authorizeUrl: string;
  /** The authorization server's `POST /auth/token` URL. */
  tokenUrl: string;
  /** Client id for a registered client; omit for a public/loopback client (PKCE is the binding). */
  clientId?: string;
  /** Requested scopes, joined with spaces into the `scope` param. */
  scope?: string[];
  /**
   * Open the system browser to the authorize URL automatically. Default `true`.
   * Set `false` for headless/SSH and use {@link onUrl} to surface the URL.
   */
  openBrowser?: boolean;
  /**
   * Called with the full authorize URL before (or instead of) opening a browser.
   * Use it to print the URL for the user to open elsewhere — the loopback
   * listener still catches the callback. Always invoked, even when
   * `openBrowser` is `true`, so a CLI can print a fallback line.
   */
  onUrl?: (url: string) => void;
  /**
   * Optional `GET` URL hit with the returned bearer to confirm the token works
   * (e.g. `/auth/status`). On a 200 the helper adopts its `userId` when the
   * token response did not carry one. A non-200 throws `status_check_failed`.
   */
  statusUrl?: string;
  /** How long to wait for the browser callback before failing. Default 300_000 (5 min). */
  timeoutMs?: number;
  /** Abort the wait early (e.g. on SIGINT). */
  signal?: AbortSignal;
}

export interface AuthorizeResult {
  /** The bearer access token to send as `Authorization: Bearer <accessToken>`. */
  accessToken: string;
  /** Access-token lifetime in seconds, as reported by the token endpoint. */
  expiresIn?: number;
  /** An OIDC id_token, when the server is acting as a Tier-2 OIDC provider. Opaque here. */
  idToken?: string;
  /** The authenticated user id, from the token response or the `statusUrl` confirmation. */
  userId?: string;
}

/** Token-endpoint JSON contract (the subset this helper reads). */
interface TokenResponse {
  access_token: string;
  token_type?: string;
  expires_in?: number;
  id_token?: string;
  userId?: string;
}

const DEFAULT_TIMEOUT_MS = 5 * 60_000;

/** RFC 4648 §5 base64url (no padding) of raw bytes. */
function base64url(bytes: Buffer): string {
  return bytes.toString("base64url");
}

/** A PKCE verifier + its S256 challenge, plus a fresh anti-CSRF `state`. */
function newPkceAndState(): { verifier: string; challenge: string; state: string } {
  const verifier = base64url(randomBytes(32));
  const challenge = base64url(createHash("sha256").update(verifier).digest());
  const state = base64url(randomBytes(16));
  return { verifier, challenge, state };
}

function buildAuthorizeUrl(
  opts: AuthorizeOptions,
  redirectUri: string,
  p: ReturnType<typeof newPkceAndState>,
): string {
  const url = new URL(opts.authorizeUrl);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("state", p.state);
  url.searchParams.set("code_challenge", p.challenge);
  url.searchParams.set("code_challenge_method", "S256");
  if (opts.clientId !== undefined) url.searchParams.set("client_id", opts.clientId);
  if (opts.scope && opts.scope.length > 0) url.searchParams.set("scope", opts.scope.join(" "));
  return url.toString();
}

/** Spawn the platform browser opener, detached; never throws (best-effort). */
function openInBrowser(url: string): void {
  try {
    const platform = process.platform;
    const [cmd, args] =
      platform === "darwin"
        ? (["open", [url]] as const)
        : platform === "win32"
          ? (["cmd", ["/c", "start", "", url]] as const)
          : (["xdg-open", [url]] as const);
    const child = spawn(cmd, [...args], { stdio: "ignore", detached: true });
    child.on("error", () => {
      /* opener missing — the printed URL (onUrl) is the fallback */
    });
    child.unref();
  } catch {
    /* never let a missing opener crash the flow */
  }
}

const DONE_HTML =
  "<!doctype html><meta charset=utf-8><title>Signed in</title>" +
  '<body style="font:16px system-ui;margin:3rem;text-align:center">' +
  "<h1>✓ Signed in</h1><p>You can close this tab and return to the terminal.</p></body>";

/**
 * Stand up a one-shot loopback listener, return its `redirect_uri` and a promise
 * that resolves with the `{ code }` from the first `/callback` hit (after the
 * `state` CSRF check) or rejects with an {@link AuthorizeError}.
 */
function awaitLoopbackCallback(
  expectedState: string,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<{ redirectUri: string; ready: Promise<string> }> {
  return new Promise((resolveSetup, rejectSetup) => {
    let settle: ((code: string) => void) | undefined;
    let fail: ((err: AuthorizeError) => void) | undefined;
    const ready = new Promise<string>((res, rej) => {
      settle = res;
      fail = rej;
    });

    const server = createServer((req: IncomingMessage, res: ServerResponse) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      if (url.pathname !== "/callback") {
        res.writeHead(404).end();
        return;
      }
      const error = url.searchParams.get("error");
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      if (error) {
        res.writeHead(400, { "content-type": "text/plain" }).end("Sign-in failed.");
        fail?.(
          new AuthorizeError("provider_denied", `Authorization server returned error=${error}`),
        );
      } else if (state !== expectedState) {
        res.writeHead(400, { "content-type": "text/plain" }).end("Sign-in failed.");
        fail?.(new AuthorizeError("state_mismatch", "Callback state did not match the request"));
      } else if (!code) {
        res.writeHead(400, { "content-type": "text/plain" }).end("Sign-in failed.");
        fail?.(new AuthorizeError("exchange_failed", "Callback carried no authorization code"));
      } else {
        res.writeHead(200, { "content-type": "text/html" }).end(DONE_HTML);
        settle?.(code);
      }
    });

    const cleanup = (): void => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      server.close();
    };
    const onAbort = (): void => fail?.(new AuthorizeError("timeout", "Login aborted"));
    const timer = setTimeout(
      () => fail?.(new AuthorizeError("timeout", `No callback within ${timeoutMs}ms`)),
      timeoutMs,
    );
    // The timer must not keep the event loop alive on its own.
    timer.unref?.();
    signal?.addEventListener("abort", onAbort, { once: true });
    // Run cleanup on BOTH outcomes (and swallow here) — `ready`'s rejection is
    // already surfaced to the caller via `await ready`; observing it a second
    // time with `.finally` would leak an unhandled rejection.
    void ready.then(cleanup, cleanup);

    server.on("error", rejectSetup);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as AddressInfo;
      resolveSetup({ redirectUri: `http://127.0.0.1:${addr.port}/callback`, ready });
    });
  });
}

/** Back-channel `code` → token exchange (PKCE-verified at the server). */
async function exchangeCode(
  opts: AuthorizeOptions,
  code: string,
  verifier: string,
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    code_verifier: verifier,
  });
  if (opts.clientId !== undefined) body.set("client_id", opts.clientId);

  let resp: Response;
  try {
    resp = await fetch(opts.tokenUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body,
      signal: opts.signal,
    });
  } catch (e) {
    throw new AuthorizeError("exchange_failed", `Token endpoint unreachable: ${String(e)}`);
  }
  if (!resp.ok) {
    throw new AuthorizeError("exchange_failed", `Token endpoint returned ${resp.status}`);
  }
  let json: TokenResponse;
  try {
    json = (await resp.json()) as TokenResponse;
  } catch {
    throw new AuthorizeError("exchange_failed", "Token endpoint returned a non-JSON body");
  }
  if (!json.access_token) {
    throw new AuthorizeError("exchange_failed", "Token endpoint returned no access_token");
  }
  return json;
}

/** Optional `GET statusUrl` confirmation; returns the reported `userId` if any. */
async function confirmStatus(
  statusUrl: string,
  accessToken: string,
  signal?: AbortSignal,
): Promise<string | undefined> {
  let resp: Response;
  try {
    resp = await fetch(statusUrl, {
      headers: { authorization: `Bearer ${accessToken}`, accept: "application/json" },
      signal,
    });
  } catch (e) {
    throw new AuthorizeError("status_check_failed", `Status endpoint unreachable: ${String(e)}`);
  }
  if (!resp.ok) {
    throw new AuthorizeError("status_check_failed", `Status endpoint returned ${resp.status}`);
  }
  try {
    const json = (await resp.json()) as { userId?: string };
    return json.userId;
  } catch {
    return undefined;
  }
}

/**
 * Run the full browser-login round trip and return a token:
 *
 * 1. open a one-shot `127.0.0.1` loopback listener (ephemeral port),
 * 2. generate `state` + PKCE, open the browser to `authorizeUrl?...`,
 * 3. await the single loopback callback and verify `state` (the CSRF check),
 * 4. `POST tokenUrl { code, code_verifier, ... }` and return the token,
 * 5. optionally confirm it against `statusUrl`.
 *
 * The helper does NOT cryptographically validate the token — it is an opaque,
 * server-owned credential; the TLS token endpoint + PKCE + the `state` check are
 * the binding. (Tier-2 `id_token` signature verification is the relying
 * service's job via an OIDC client, not a CLI's.)
 */
export async function authorize(opts: AuthorizeOptions): Promise<AuthorizeResult> {
  const pkce = newPkceAndState();
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const { redirectUri, ready } = await awaitLoopbackCallback(pkce.state, timeoutMs, opts.signal);

  const authUrl = buildAuthorizeUrl(opts, redirectUri, pkce);
  opts.onUrl?.(authUrl);
  if (opts.openBrowser !== false) openInBrowser(authUrl);

  const code = await ready;
  const token = await exchangeCode(opts, code, pkce.verifier);

  let userId = token.userId;
  if (opts.statusUrl) {
    const confirmed = await confirmStatus(opts.statusUrl, token.access_token, opts.signal);
    userId = userId ?? confirmed;
  }

  return {
    accessToken: token.access_token,
    ...(token.expires_in !== undefined && { expiresIn: token.expires_in }),
    ...(token.id_token !== undefined && { idToken: token.id_token }),
    ...(userId !== undefined && { userId }),
  };
}
