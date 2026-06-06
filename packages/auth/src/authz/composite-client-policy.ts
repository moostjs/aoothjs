import type { ClientRedirectPolicy, ResolvedClient } from "./client-policy";

export interface CompositeClientPolicyOptions {
  /** Used when the request carries NO `client_id` (Tier-1 public/loopback CLI). */
  loopback: ClientRedirectPolicy;
  /** Used when the request carries a `client_id` (Tier-2 registered service). */
  registered: ClientRedirectPolicy;
}

/**
 * Runs Tier-1 and Tier-2 side by side, dispatching on the **presence of
 * `client_id`** (AUTH-SERVER.md §10): a request with a `client_id` is a
 * registered client, one without is a loopback CLI. The split is the safety
 * boundary — a registered client is routed only to {@link RegisteredClientPolicy}
 * (which enforces ITS redirect allowlist, so it cannot smuggle a loopback
 * redirect), and a no-`client_id` request is routed only to the loopback policy
 * (so it cannot claim to be a registered client). Each sub-policy still owns its
 * own redirect validation; this only picks which one runs.
 */
export class CompositeClientPolicy implements ClientRedirectPolicy {
  private readonly loopback: ClientRedirectPolicy;
  private readonly registered: ClientRedirectPolicy;

  constructor(opts: CompositeClientPolicyOptions) {
    this.loopback = opts.loopback;
    this.registered = opts.registered;
  }

  resolveClient(args: {
    clientId?: string;
    redirectUri: string;
    scope?: string;
  }): ResolvedClient | Promise<ResolvedClient> {
    return args.clientId ? this.registered.resolveClient(args) : this.loopback.resolveClient(args);
  }

  authenticateClient(args: { clientId?: string; clientSecret?: string }): void | Promise<void> {
    // Only registered clients authenticate at /token; a loopback client is public
    // (PKCE is its binding), so there is nothing to authenticate.
    if (args.clientId) return this.registered.authenticateClient?.(args);
  }
}
