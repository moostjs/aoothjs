import { randomUUID } from "node:crypto";
import type { CredentialState } from "../credential/types";
import { type Clock, defaultClock } from "../utils/clock";
import type { CredentialStore } from "./store";

// Re-exported so existing import sites (`import { Clock } from '.../memory'`)
// continue to compile after the move to `utils/clock`.
export type { Clock } from "../utils/clock";

/**
 * In-memory implementation of CredentialStore using random opaque token IDs.
 *
 * - `Map<token, state>` is the primary index.
 * - `Map<userId, Set<token>>` is a secondary index for `revokeAllForUser` /
 *   `listForUser` without scanning the full primary map.
 * - Both maps are kept in sync on every mutation.
 */
export class CredentialStoreMemory<
  TPayload extends object = object,
> implements CredentialStore<TPayload> {
  private readonly states = new Map<string, CredentialState & TPayload>();
  private readonly byUser = new Map<string, Set<string>>();
  private readonly clock: Clock;

  constructor(opts?: { clock?: Clock }) {
    this.clock = opts?.clock ?? defaultClock;
  }

  async persist(state: CredentialState & TPayload, ttl?: number): Promise<string> {
    const token = randomUUID();
    const stored: CredentialState & TPayload = { ...state };
    if (typeof ttl === "number") {
      stored.expiresAt = this.clock.now() + ttl;
    }
    this.states.set(token, stored);
    this.indexAdd(stored.userId, token);
    return token;
  }

  async retrieve(token: string): Promise<(CredentialState & TPayload) | null> {
    const state = this.states.get(token);
    if (!state) return null;
    if (state.expiresAt <= this.clock.now()) {
      this.states.delete(token);
      this.indexRemove(state.userId, token);
      return null;
    }
    return { ...state };
  }

  async consume(token: string): Promise<(CredentialState & TPayload) | null> {
    const state = await this.retrieve(token);
    if (!state) return null;
    await this.revoke(token);
    return state;
  }

  async update(token: string, state: CredentialState & TPayload): Promise<string> {
    const existing = this.states.get(token);
    if (!existing) {
      // No-op for unknown tokens — `update()` is for mutating an already
      // persisted credential; resurrecting a forgotten token would silently
      // bypass revocation.
      return token;
    }
    if (existing.userId !== state.userId) {
      this.indexRemove(existing.userId, token);
      this.indexAdd(state.userId, token);
    }
    this.states.set(token, { ...state });
    return token;
  }

  async revoke(token: string): Promise<void> {
    const state = this.states.get(token);
    if (!state) return;
    this.states.delete(token);
    this.indexRemove(state.userId, token);
  }

  async touch(token: string, at: number): Promise<void> {
    const state = this.states.get(token);
    if (!state) return;
    state.lastSeenAt = at;
  }

  async revokeAllForUser(userId: string): Promise<number> {
    const tokens = this.byUser.get(userId);
    if (!tokens || tokens.size === 0) return 0;
    let count = 0;
    for (const token of tokens) {
      if (this.states.delete(token)) count++;
    }
    this.byUser.delete(userId);
    return count;
  }

  async listForUser(
    userId: string,
  ): Promise<Array<CredentialState & TPayload & { token: string }>> {
    const tokens = this.byUser.get(userId);
    if (!tokens || tokens.size === 0) return [];
    const now = this.clock.now();
    const out: Array<CredentialState & TPayload & { token: string }> = [];
    const expired: string[] = [];
    for (const token of tokens) {
      const state = this.states.get(token);
      if (!state) {
        expired.push(token);
        continue;
      }
      if (state.expiresAt <= now) {
        expired.push(token);
        continue;
      }
      out.push({ ...state, token });
    }
    for (const token of expired) {
      this.states.delete(token);
      tokens.delete(token);
    }
    if (tokens.size === 0) {
      this.byUser.delete(userId);
    }
    return out;
  }

  private indexAdd(userId: string, token: string): void {
    let set = this.byUser.get(userId);
    if (!set) {
      set = new Set();
      this.byUser.set(userId, set);
    }
    set.add(token);
  }

  private indexRemove(userId: string, token: string): void {
    const set = this.byUser.get(userId);
    if (!set) return;
    set.delete(token);
    if (set.size === 0) this.byUser.delete(userId);
  }
}
