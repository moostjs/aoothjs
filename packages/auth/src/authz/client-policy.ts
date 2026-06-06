import { AuthorizeError } from "./authz-errors";
import type { TokenPolicy } from "./token-policy";

/**
 * The client + redirect resolved at `GET /auth/authorize` — what the grant is
 * allowed to deliver and where.
 */
export interface ResolvedClient {
  /** Registered client id (Tier 2), absent for a public/loopback client. */
  clientId?: string;
  /** The validated `redirect_uri` the code will be delivered to. */
  redirectUri: string;
  /** What the grant mints (fixed here, recorded on the pending authorization). */
  tokenPolicy: TokenPolicy;
  /**
   * Tier 2 (OIDC): mint an `id_token` with `aud` = {@link audience}. Omitted ⇒
   * no `id_token` (Tier-1 loopback).
   */
  idToken?: boolean;
  /**
   * Mint an access token. **Omitted ⇒ minted** (preserves Tier-1 loopback,
   * where the CLI gets an access token); set `false` for a pure-OIDC sign-in
   * client that should receive identity only.
   */
  accessToken?: boolean;
  /** The `id_token` `aud` (the registered `client_id`). */
  audience?: string;
  /** Granted scope (space-joined) — `requested ∩ allowed`; drives the `id_token` profile claims. */
  scope?: string;
}

/**
 * The pluggable trust boundary of the authorization server (AUTH-SERVER.md §4.5):
 * decide whether a client + `redirect_uri` may start a grant and what it may
 * receive. The flow is otherwise identical across tiers — only this policy
 * varies. Tier 1 ships {@link LoopbackClientPolicy}; a `RegisteredClientPolicy`
 * (static client registry, exact/prefix redirect allowlist, `id_token`) is the
 * Tier-2 addition.
 */
export interface ClientRedirectPolicy {
  /**
   * Authorize the client + `redirect_uri` and resolve the token policy; THROW
   * an {@link AuthorizeError} on a miss (`invalid_redirect` / `invalid_client`).
   * This is THE open-redirect / token-theft gate — never reflect an unvalidated
   * `redirect_uri`.
   */
  resolveClient(args: {
    clientId?: string;
    redirectUri: string;
    scope?: string;
  }): ResolvedClient | Promise<ResolvedClient>;
  /**
   * Tier 2: authenticate the client at `POST /auth/token` — verify the
   * `client_secret` of a confidential client (PKCE is the binding for a public
   * one). THROW an {@link AuthorizeError} (`invalid_client`) on failure. Optional:
   * a public-only policy (loopback) omits it.
   */
  authenticateClient?(args: { clientId?: string; clientSecret?: string }): void | Promise<void>;
}

/**
 * `true` when `uri` is a syntactically valid http(s) URL whose host is a
 * **loopback literal** — `127.0.0.1`, `::1`, or `localhost` — on any port (RFC
 * 8252 §7.3). Rejects everything else, including the classic bypasses: a
 * host-suffix (`127.0.0.1.evil.com`, `localhost.evil.com`), embedded credentials
 * (`http://127.0.0.1@evil.com` → host `evil.com`), a non-http scheme, and a bare
 * `0.0.0.0`. Only a local process can receive a loopback redirect, which is why
 * an arbitrary port is safe — the binding is the loopback host + PKCE.
 */
export function isLoopbackRedirectUri(uri: string): boolean {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return false;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return false;
  // Embedded credentials shift the real host after `@`; reject outright.
  if (url.username !== "" || url.password !== "") return false;
  // `hostname` excludes port + userinfo but KEEPS the brackets on an IPv6 literal
  // (`[::1]`), so strip them before the loopback comparison.
  const host = url.hostname.replace(/^\[|\]$/g, "");
  return host === "127.0.0.1" || host === "::1" || host === "localhost";
}

export interface LoopbackClientPolicyOptions {
  /**
   * What a loopback grant mints. Default: a full-authority `cli-session` with a
   * 30-day TTL (un-attenuated — see {@link TokenPolicy}). Override to scope or
   * re-label CLI tokens.
   */
  tokenPolicy?: TokenPolicy;
}

const DEFAULT_CLI_TOKEN_POLICY: TokenPolicy = {
  kind: "cli-session",
  ttl: 30 * 24 * 60 * 60_000, // 30 days
};

/**
 * Tier-1 policy: accept any **loopback** `redirect_uri`, treat the client as a
 * public client (no `client_id` / secret — PKCE is the binding), and mint the
 * configured CLI token policy. Rejects every non-loopback redirect.
 */
export class LoopbackClientPolicy implements ClientRedirectPolicy {
  private readonly tokenPolicy: TokenPolicy;

  constructor(opts?: LoopbackClientPolicyOptions) {
    this.tokenPolicy = opts?.tokenPolicy ?? DEFAULT_CLI_TOKEN_POLICY;
  }

  resolveClient(args: { clientId?: string; redirectUri: string; scope?: string }): ResolvedClient {
    if (!isLoopbackRedirectUri(args.redirectUri)) {
      throw new AuthorizeError("invalid_redirect", "redirect_uri must be a loopback address");
    }
    // A loopback grant is full-authority (no id_token, access token minted); pass
    // the requested scope through informationally.
    return {
      redirectUri: args.redirectUri,
      tokenPolicy: structuredClone(this.tokenPolicy),
      ...(args.scope !== undefined && { scope: args.scope }),
    };
  }
}
