import { timingSafeEqualStr } from "../utils/timing-safe";
import { AuthorizeError } from "./authz-errors";
import type { ClientRedirectPolicy, ResolvedClient } from "./client-policy";
import { scopeGrants } from "./oidc-claims-resolver";
import type { TokenPolicy } from "./token-policy";

/**
 * One registered first-party client (AUTH-SERVER.md §4.5). The registry is the
 * open-redirect / token-theft boundary, so a client's `redirect_uri` allowlist
 * and what it may receive are declared HERE, never inferred from the request.
 */
export interface RegisteredClient {
  /** Stable client identifier; the `id_token` `aud`. */
  clientId: string;
  /** Display name for the consent prompt (rendered as text). Falls back to `clientId`. */
  clientName?: string;
  /** Exact-match `redirect_uri` allowlist (the safe default). */
  redirectUris?: string[];
  /**
   * Strict-prefix `redirect_uri` allowlist (an entry must be a non-empty prefix
   * of the request). Looser than exact match — only use for a tightly-scoped
   * path prefix on a trusted origin.
   */
  redirectPrefixes?: string[];
  /** `"public"` (PKCE only) or `"confidential"` (PKCE + `client_secret`). Default `"public"`. */
  type?: "public" | "confidential";
  /** Shared secret for a confidential client (compared in constant time at `/token`). */
  clientSecret?: string;
  /** Mint an `id_token` (requires the granted scope to include `openid`). Default `true`. */
  idToken?: boolean;
  /** Also mint an access token for the main API. Default `false` — a pure sign-in client gets identity only. */
  accessToken?: boolean;
  /** Allowed scopes; the granted scope is `requested ∩ allowed`. Omit to allow any requested scope. */
  scopes?: string[];
  /** Token policy for the access token, when `accessToken` is set. */
  tokenPolicy?: TokenPolicy;
}

export interface RegisteredClientPolicyOptions {
  clients: RegisteredClient[];
}

/**
 * Tier-2 policy: a static registry of first-party clients. `resolveClient`
 * authorizes the client + `redirect_uri` (against the registered allowlist) and
 * resolves the granted scope + what the grant delivers (`id_token`/`access_token`,
 * `aud = client_id`); `authenticateClient` authenticates the client at `/token`
 * (`client_secret` for confidential clients; PKCE is the binding for public ones).
 * An unregistered client or an unlisted redirect is rejected.
 */
export class RegisteredClientPolicy implements ClientRedirectPolicy {
  private readonly clients = new Map<string, RegisteredClient>();

  constructor(opts: RegisteredClientPolicyOptions) {
    for (const c of opts.clients) this.clients.set(c.clientId, c);
  }

  resolveClient(args: { clientId?: string; redirectUri: string; scope?: string }): ResolvedClient {
    const client = this.requireClient(args.clientId);
    if (!this.redirectAllowed(client, args.redirectUri)) {
      throw new AuthorizeError(
        "invalid_redirect",
        "redirect_uri is not registered for this client",
      );
    }
    const scope = this.grantScope(client, args.scope);
    const idToken = client.idToken !== false && scopeGrants(scope, "openid");
    return {
      clientId: client.clientId,
      redirectUri: args.redirectUri,
      audience: client.clientId,
      idToken,
      accessToken: client.accessToken === true,
      tokenPolicy: client.tokenPolicy ? structuredClone(client.tokenPolicy) : {},
      ...(client.clientName !== undefined && { clientName: client.clientName }),
      ...(scope !== undefined && { scope }),
    };
  }

  /** Known-ness probe for `CompositeClientPolicy` dispatch (static registry, sync). */
  hasClient(clientId: string): boolean {
    return this.clients.has(clientId);
  }

  authenticateClient(args: { clientId?: string; clientSecret?: string }): void {
    const client = this.requireClient(args.clientId);
    if ((client.type ?? "public") !== "confidential") return; // public: PKCE is the binding
    if (
      !client.clientSecret ||
      !args.clientSecret ||
      !timingSafeEqualStr(args.clientSecret, client.clientSecret)
    ) {
      throw new AuthorizeError("invalid_client", "client authentication failed");
    }
  }

  private requireClient(clientId: string | undefined): RegisteredClient {
    const client = clientId ? this.clients.get(clientId) : undefined;
    if (!client) throw new AuthorizeError("invalid_client", "unknown client");
    return client;
  }

  private redirectAllowed(client: RegisteredClient, uri: string): boolean {
    // Exact match — the safe default.
    if (client.redirectUris?.includes(uri)) return true;
    if (!client.redirectPrefixes?.length) return false;
    // Strict-prefix — must withstand two classic bypasses: a loose-prefix sibling
    // (`/app` matching `/app-fake/evil`) and path traversal (`/app/../evil`). So
    // normalise the URL first (the URL parser resolves `..`, collapsing a traversal
    // OUT of the prefix), then require a PATH BOUNDARY after the prefix: either the
    // prefix already ends with `/`, or the next char is a separator (`/` `?` `#`)
    // or end-of-string. A plain `startsWith` has neither property.
    let normalized: string;
    try {
      normalized = new URL(uri).href;
    } catch {
      return false;
    }
    return client.redirectPrefixes.some((p) => {
      if (p.length === 0 || !normalized.startsWith(p)) return false;
      if (p.endsWith("/")) return true;
      const next = normalized[p.length];
      return next === undefined || next === "/" || next === "?" || next === "#";
    });
  }

  private grantScope(client: RegisteredClient, requested: string | undefined): string | undefined {
    if (!requested) return undefined;
    const req = requested.split(/\s+/u).filter(Boolean);
    const granted = client.scopes ? req.filter((s) => client.scopes!.includes(s)) : req;
    return granted.length > 0 ? granted.join(" ") : undefined;
  }
}
