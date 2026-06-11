import type { ClientRedirectPolicy, ResolvedClient } from "./client-policy";

export interface CompositeClientPolicyOptions {
  /** Used when the request carries NO `client_id` (Tier-1 public/loopback CLI). */
  loopback: ClientRedirectPolicy;
  /** Used when the request carries a `client_id` it recognizes (Tier-2 registered service). */
  registered?: ClientRedirectPolicy;
  /**
   * Used when the request carries a `client_id` the `registered` policy does
   * NOT recognize (RFC 7591 dynamically-registered connector clients). When
   * both `registered` and `dynamic` are set, `registered` MUST implement
   * `hasClient` — it is the dispatch probe.
   */
  dynamic?: ClientRedirectPolicy;
}

/**
 * Runs the tiers side by side, dispatching on the **presence and ownership of
 * `client_id`** (AUTH-SERVER.md §10, OAUTH.md R2): a request without a
 * `client_id` is a loopback CLI; one with a `client_id` belongs to the static
 * registry when it knows the id (`hasClient`), else to the dynamic policy. The
 * split is the safety boundary — each sub-policy still enforces ITS OWN
 * redirect allowlist (so a registered client cannot smuggle a loopback
 * redirect and a no-`client_id` request cannot claim to be registered), and
 * static-first dispatch means a dynamic registration can never shadow a static
 * client id. `authenticateClient` routes through the SAME picker: a dynamic
 * `client_id` must be authenticated by the dynamic policy (existence check,
 * PKCE binds), never rejected by the static registry that doesn't know it.
 */
export class CompositeClientPolicy implements ClientRedirectPolicy {
  private readonly loopback: ClientRedirectPolicy;
  private readonly registered?: ClientRedirectPolicy;
  private readonly dynamic?: ClientRedirectPolicy;

  constructor(opts: CompositeClientPolicyOptions) {
    if (!opts.registered && !opts.dynamic) {
      throw new Error(
        "CompositeClientPolicy requires at least one of `registered` / `dynamic` — with only loopback there is nothing to compose",
      );
    }
    // Fail loud at construction, never per-request: with both slots present the
    // dispatch depends on the registered policy's known-ness probe.
    if (opts.registered && opts.dynamic && typeof opts.registered.hasClient !== "function") {
      throw new Error(
        "CompositeClientPolicy: `registered` must implement hasClient() when composed with `dynamic`",
      );
    }
    this.loopback = opts.loopback;
    this.registered = opts.registered;
    this.dynamic = opts.dynamic;
  }

  resolveClient(args: {
    clientId?: string;
    redirectUri: string;
    scope?: string;
  }): ResolvedClient | Promise<ResolvedClient> {
    if (!args.clientId) return this.loopback.resolveClient(args);
    const picked = this.pickForClientId(args.clientId);
    return picked instanceof Promise
      ? picked.then((p) => p.resolveClient(args))
      : picked.resolveClient(args);
  }

  authenticateClient(args: { clientId?: string; clientSecret?: string }): void | Promise<void> {
    // Only identified clients authenticate at /token; a loopback client is
    // public (PKCE is its binding), so there is nothing to authenticate.
    if (!args.clientId) return;
    const picked = this.pickForClientId(args.clientId);
    return picked instanceof Promise
      ? picked.then((p) => p.authenticateClient?.(args))
      : picked.authenticateClient?.(args);
  }

  /**
   * Ownership dispatch for a presented `client_id` — static registry first
   * (when it knows the id), dynamic otherwise. Sync when the probe is sync
   * (the static registry's is), preserving the callers' sync fast path.
   */
  private pickForClientId(clientId: string): ClientRedirectPolicy | Promise<ClientRedirectPolicy> {
    if (!this.registered) return this.dynamic!;
    if (!this.dynamic) return this.registered;
    const known = this.registered.hasClient!(clientId);
    return known instanceof Promise
      ? known.then((k) => (k ? this.registered! : this.dynamic!))
      : known
        ? this.registered
        : this.dynamic;
  }
}
