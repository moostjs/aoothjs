import { AuthorizeError } from "./authz-errors";
import {
  type ClientRedirectPolicy,
  isLoopbackRedirectUri,
  type ResolvedClient,
} from "./client-policy";
import { verifyClientSecret } from "./client-secret";
import { type DynamicClient, type DynamicClientStore } from "./dynamic-client-store";
import type { TokenPolicy } from "./token-policy";
import { type Clock, defaultClock } from "../utils/clock";

export interface DynamicClientPolicyOptions {
  store: DynamicClientStore;
  /**
   * What a dynamic-client grant mints. Default: a `dynamic-session` access
   * token with a 30-day TTL. Override to re-label or scope connector tokens
   * (e.g. `{ kind: "mcp-session", ttl: 30 * 24 * 60 * 60_000 }`).
   */
  tokenPolicy?: TokenPolicy;
  /**
   * Server-side scope allow-list: the granted scope is
   * `requested ∩ allowedScopes` (∩ the registration's `scope` when set).
   * Omit to fall back to `requested ∩ registration scope` alone. NEVER treat
   * the registration's self-declared `scope` as the allow-set by itself — it
   * is attacker-supplied and also feeds the consent copy.
   */
  allowedScopes?: string[];
  /** Injectable clock for deterministic `lastUsedAt` stamps. Defaults to wall-clock. */
  clock?: Clock;
}

const DEFAULT_DYNAMIC_TOKEN_POLICY: TokenPolicy = {
  kind: "dynamic-session",
  ttl: 30 * 24 * 60 * 60_000, // 30 days
};

/**
 * Policy for RFC 7591 dynamically-registered clients (OAUTH.md R2) on the
 * `ClientRedirectPolicy` seam. `resolveClient` authorizes the client +
 * `redirect_uri` against ITS registered allowlist and resolves the granted
 * scope + token policy; `authenticateClient` re-checks existence at `/token`
 * (a registration garbage-collected mid-flight fails closed) and, for a
 * `client_secret_post` registration, validates the presented secret against
 * the stored digest (public `"none"` clients: PKCE is the binding). Dynamic
 * clients receive an access token only — NO `id_token` in v1 (OAUTH.md R6).
 *
 * INVARIANT: the returned {@link ResolvedClient} always carries `clientId`, so
 * the minted code records it and the token endpoint's symmetric client binding
 * applies — a dynamic code redeemed without (or with another) `client_id` is
 * rejected exactly like a Tier-2 code.
 */
export class DynamicClientPolicy implements ClientRedirectPolicy {
  private readonly store: DynamicClientStore;
  private readonly tokenPolicy: TokenPolicy;
  private readonly allowedScopes?: string[];
  private readonly clock: Clock;

  constructor(opts: DynamicClientPolicyOptions) {
    this.store = opts.store;
    this.tokenPolicy = opts.tokenPolicy ?? DEFAULT_DYNAMIC_TOKEN_POLICY;
    this.allowedScopes = opts.allowedScopes;
    this.clock = opts.clock ?? defaultClock;
  }

  async resolveClient(args: {
    clientId?: string;
    redirectUri: string;
    scope?: string;
  }): Promise<ResolvedClient> {
    const client = await this.requireClient(args.clientId);
    if (!redirectAllowed(client, args.redirectUri)) {
      throw new AuthorizeError(
        "invalid_redirect",
        "redirect_uri is not registered for this client",
      );
    }
    const scope = this.grantScope(client, args.scope);
    // Best-effort usage stamp — marks the registration as used (exempt from
    // never-used GC). A write hiccup must never fail an authorize request.
    try {
      await this.store.touch(client.clientId, this.clock.now());
    } catch {
      /* best-effort */
    }
    return {
      clientId: client.clientId,
      redirectUri: args.redirectUri,
      accessToken: true,
      tokenPolicy: structuredClone(this.tokenPolicy),
      ...(client.clientName !== undefined && { clientName: client.clientName }),
      ...(scope !== undefined && { scope }),
    };
  }

  /**
   * `/token`-side check: the client must still exist (fail closed when the
   * registration was deleted/GC'd between authorize and redemption). A client
   * registered with `token_endpoint_auth_method: "client_secret_post"` must
   * additionally present its minted `client_secret` (constant-time check
   * against the stored digest). For a public (`"none"`) client no secret is
   * checked — PKCE is the binding; a spurious `client_secret` is ignored.
   */
  async authenticateClient(args: { clientId?: string; clientSecret?: string }): Promise<void> {
    const client = await this.requireClient(args.clientId);
    if (client.tokenEndpointAuthMethod !== "client_secret_post") return;
    if (
      client.clientSecretHash === undefined ||
      args.clientSecret === undefined ||
      !verifyClientSecret(args.clientSecret, client.clientSecretHash)
    ) {
      throw new AuthorizeError("invalid_client", "client authentication failed");
    }
  }

  /** Known-ness probe for `CompositeClientPolicy` dispatch. */
  async hasClient(clientId: string): Promise<boolean> {
    return (await this.store.get(clientId)) !== null;
  }

  private async requireClient(clientId: string | undefined): Promise<DynamicClient> {
    const client = clientId ? await this.store.get(clientId) : null;
    if (!client) throw new AuthorizeError("invalid_client", "unknown client");
    return client;
  }

  private grantScope(client: DynamicClient, requested: string | undefined): string | undefined {
    if (!requested) return undefined;
    let granted = requested.split(/\s+/u).filter(Boolean);
    if (this.allowedScopes) granted = granted.filter((s) => this.allowedScopes!.includes(s));
    if (client.scope !== undefined) {
      const registered = new Set(client.scope.split(/\s+/u).filter(Boolean));
      granted = granted.filter((s) => registered.has(s));
    }
    return granted.length > 0 ? granted.join(" ") : undefined;
  }
}

/**
 * Exact match against the registered allowlist, with ONE relaxation: for a
 * loopback redirect the PORT is ignored (RFC 8252 §7.3 — native/CLI clients
 * bind an ephemeral port per run, so the AS MUST allow a variable port).
 * Scheme, host, path and query still must match a registered loopback entry
 * exactly; `https` entries never get the relaxation.
 */
function redirectAllowed(client: DynamicClient, uri: string): boolean {
  if (client.redirectUris.includes(uri)) return true;
  if (!isLoopbackRedirectUri(uri)) return false;
  let presented: URL;
  try {
    presented = new URL(uri);
  } catch {
    return false;
  }
  if (presented.hash !== "") return false;
  return client.redirectUris.some((registered) => {
    if (!isLoopbackRedirectUri(registered)) return false;
    const reg = new URL(registered);
    return (
      reg.protocol === presented.protocol &&
      reg.hostname === presented.hostname &&
      reg.pathname === presented.pathname &&
      reg.search === presented.search
    );
  });
}
