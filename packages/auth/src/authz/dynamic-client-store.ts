import { randomUUID } from "node:crypto";

import { type Clock, defaultClock } from "../utils/clock";

/**
 * One dynamically-registered OAuth client (RFC 7591) — the record behind a
 * connector-style public client that self-registered at `POST /register`.
 * Everything here is **registrant-supplied** (post-validation) except
 * `clientId` and the timestamps: treat `clientName` as untrusted display text
 * and `redirectUris` as the exact-match delivery allowlist that
 * `DynamicClientPolicy` enforces at `/authorize`.
 */
export interface DynamicClient {
  /** Store-minted opaque client identifier (the DCR response `client_id`). */
  clientId: string;
  /** Sanitized display name (DCR `client_name`) — untrusted, rendered as text on consent. */
  clientName?: string;
  /** Validated redirect allowlist — https exact-match entries and/or loopback literals. */
  redirectUris: string[];
  /** v1 supports public clients only — PKCE is the binding, no secret exists. */
  tokenEndpointAuthMethod: "none";
  /** Registered grant types (narrowed to what the server supports). */
  grantTypes: string[];
  /** Registered response types (narrowed to what the server supports). */
  responseTypes: string[];
  /** Scope string from registration (space-joined) — an upper bound, not a grant. */
  scope?: string;
  createdAt: number;
  /**
   * Last time the client started an authorize request. Unset ⇒ the
   * registration was never used — the garbage-collection target of
   * {@link DynamicClientStore.deleteUnusedBefore} (anonymous `/register` spam
   * registers but never authorizes).
   */
  lastUsedAt?: number;
}

/** Input to {@link DynamicClientStore.create} — `clientId`/timestamps are store-assigned. */
export interface NewDynamicClient {
  clientName?: string;
  redirectUris: string[];
  tokenEndpointAuthMethod: "none";
  grantTypes: string[];
  responseTypes: string[];
  scope?: string;
}

/**
 * Storage seam for dynamically-registered clients (OAUTH.md R2). Long-lived
 * (unlike the pending-auth / auth-code stores): a connector caches its
 * `client_id` and reuses it across grants, so rows survive until deleted or
 * garbage-collected as never-used. An in-memory impl ships for single-process
 * apps + tests; a durable impl (atscript-db) slots under the same
 * `DYNAMIC_CLIENT_STORE_TOKEN` (from `@aooth/auth-moost`).
 */
export abstract class DynamicClientStore {
  /** Persist a validated registration; mints and returns the full record (with `clientId`). */
  abstract create(rec: NewDynamicClient): Promise<DynamicClient>;
  /** Fetch by client id, or `null` when unknown. */
  abstract get(clientId: string): Promise<DynamicClient | null>;
  /** Remove a registration. Returns `true` when a row was removed. */
  abstract delete(clientId: string): Promise<boolean>;
  /** Number of stored registrations — the `maxClients` hard-cap check. */
  abstract count(): Promise<number>;
  /** Stamp `lastUsedAt` — marks the registration as used (exempt from never-used GC). */
  abstract touch(clientId: string, at: number): Promise<void>;
  /**
   * Garbage-collect never-used registrations: delete rows with
   * `createdAt < cutoff` AND no `lastUsedAt`. Returns the number removed.
   * Used rows are NEVER evicted — a connector caches its `client_id`, and
   * evicting it strands the client (see OAUTH.md R2 abuse posture).
   */
  abstract deleteUnusedBefore(cutoff: number): Promise<number>;
}

export interface DynamicClientStoreMemoryOptions {
  /** Injectable clock for deterministic `createdAt`. Defaults to {@link defaultClock}. */
  clock?: Clock;
}

/**
 * In-memory {@link DynamicClientStore} — the reference impl for a
 * single-process app + tests. `structuredClone` on read/write isolates callers.
 */
export class DynamicClientStoreMemory extends DynamicClientStore {
  private store = new Map<string, DynamicClient>();
  private clock: Clock;

  constructor(opts?: DynamicClientStoreMemoryOptions) {
    super();
    this.clock = opts?.clock ?? defaultClock;
  }

  async create(rec: NewDynamicClient): Promise<DynamicClient> {
    const row: DynamicClient = {
      clientId: randomUUID(),
      redirectUris: [...rec.redirectUris],
      tokenEndpointAuthMethod: rec.tokenEndpointAuthMethod,
      grantTypes: [...rec.grantTypes],
      responseTypes: [...rec.responseTypes],
      createdAt: this.clock.now(),
      ...(rec.clientName !== undefined && { clientName: rec.clientName }),
      ...(rec.scope !== undefined && { scope: rec.scope }),
    };
    this.store.set(row.clientId, structuredClone(row));
    return structuredClone(row);
  }

  async get(clientId: string): Promise<DynamicClient | null> {
    const row = this.store.get(clientId);
    return row ? structuredClone(row) : null;
  }

  async delete(clientId: string): Promise<boolean> {
    return this.store.delete(clientId);
  }

  async count(): Promise<number> {
    return this.store.size;
  }

  async touch(clientId: string, at: number): Promise<void> {
    const row = this.store.get(clientId);
    if (row) row.lastUsedAt = at;
  }

  async deleteUnusedBefore(cutoff: number): Promise<number> {
    let removed = 0;
    for (const [id, row] of this.store) {
      if (row.lastUsedAt === undefined && row.createdAt < cutoff) {
        this.store.delete(id);
        removed++;
      }
    }
    return removed;
  }
}
