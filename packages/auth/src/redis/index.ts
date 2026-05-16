import { randomUUID } from "node:crypto";
import type { CredentialState } from "../credential/types";
import type { CredentialStore, DenylistStore } from "../stores/store";

/**
 * Structural Redis client. Covers the exact set of commands used by
 * `CredentialStoreRedis` and `DenylistStoreRedis` — no more.
 *
 * Compatible by-shape with `ioredis`, `redis@4+`, `@redis/client`, and ad-hoc
 * test doubles. Consumers are free to wrap whatever client they ship; we
 * deliberately do not declare a peer dep on any specific package.
 *
 * Return types are widened to the union of what real clients return:
 *   - `set` returns `'OK' | string | null` (null on conditional sets that fail)
 *   - `del` / `expire` / `exists` / `sadd` / `srem` return `number`
 *   - `get` returns `string | null`
 *   - `smembers` returns `string[]`
 *
 * The `ttl` arg passed to `set` is in MILLISECONDS — we always call with
 * `PX`, never `EX`, so callers don't have to translate.
 */
export interface RedisLike {
  /** `SET key value [PX ms]` — accepts an optional ms TTL. */
  set(key: string, value: string, mode?: "PX", ttlMs?: number): Promise<string | null>;
  get(key: string): Promise<string | null>;
  del(...keys: string[]): Promise<number>;
  exists(key: string): Promise<number>;
  /** `PEXPIRE key ttlMs` — ms TTL on an existing key. */
  expire(key: string, ttlMs: number): Promise<number>;
  sadd(key: string, ...members: string[]): Promise<number>;
  srem(key: string, ...members: string[]): Promise<number>;
  smembers(key: string): Promise<string[]>;
}

interface RedisCredentialStoreOptions {
  redis: RedisLike;
  /**
   * Key prefix for every stored entry. Defaults to `aooth:cred`. Combined
   * with the token id (`<prefix>:t:<token>`) and per-user index set
   * (`<prefix>:u:<userId>`).
   */
  prefix?: string;
}

/**
 * Redis-backed `CredentialStore`. Token id is a random UUID (the same
 * scheme as `CredentialStoreMemory`) — the token is opaque to the client.
 *
 * Storage shape:
 *   - `<prefix>:t:<token>` → JSON-serialised `CredentialState`
 *   - `<prefix>:u:<userId>` → SET of tokens for that user (for
 *     `revokeAllForUser` and `listForUser`)
 *
 * TTL: when `persist(state, ttl)` is called, the state key gets a `PX` TTL
 * so Redis evicts it on expiry. The user-index set is NOT TTL-bounded — we
 * lazily prune dead members on `listForUser` and `revokeAllForUser`.
 */
export class CredentialStoreRedis<
  TClaims extends object = object,
> implements CredentialStore<TClaims> {
  private readonly redis: RedisLike;
  private readonly prefix: string;

  constructor(opts: RedisCredentialStoreOptions) {
    this.redis = opts.redis;
    this.prefix = opts.prefix ?? "aooth:cred";
  }

  private tokenKey(token: string): string {
    return `${this.prefix}:t:${token}`;
  }

  private userKey(userId: string): string {
    return `${this.prefix}:u:${userId}`;
  }

  async persist(state: CredentialState<TClaims>, ttl?: number): Promise<string> {
    const token = randomUUID();
    const stored: CredentialState<TClaims> = { ...state };
    if (typeof ttl === "number") {
      // Mirror the memory store: caller-supplied ttl overrides the state's
      // expiresAt. Always compute absolute expiry from the moment of write.
      stored.expiresAt = Date.now() + ttl;
    }
    const ttlMs = Math.max(0, stored.expiresAt - Date.now());
    if (ttlMs <= 0) {
      // Fail loud — caller asked us to persist an already-dead credential.
      // Returning a phantom token would silently corrupt downstream flows.
      throw new Error(
        "CredentialStoreRedis.persist: refusing to persist an already-expired credential",
      );
    }
    await this.redis.set(this.tokenKey(token), JSON.stringify(stored), "PX", ttlMs);
    await this.redis.sadd(this.userKey(state.userId), token);
    return token;
  }

  async retrieve(token: string): Promise<CredentialState<TClaims> | null> {
    const raw = await this.redis.get(this.tokenKey(token));
    if (raw === null) return null;
    const state = JSON.parse(raw) as CredentialState<TClaims>;
    if (state.expiresAt <= Date.now()) {
      // Redis should have expired it, but guard against clock skew.
      await this.redis.del(this.tokenKey(token));
      await this.redis.srem(this.userKey(state.userId), token);
      return null;
    }
    return state;
  }

  async consume(token: string): Promise<CredentialState<TClaims> | null> {
    const state = await this.retrieve(token);
    if (!state) return null;
    await this.revoke(token);
    return state;
  }

  async update(token: string, state: CredentialState<TClaims>): Promise<string> {
    const existingRaw = await this.redis.get(this.tokenKey(token));
    if (existingRaw === null) {
      // Mirror memory store: unknown tokens are no-ops, not resurrections.
      return token;
    }
    const existing = JSON.parse(existingRaw) as CredentialState<TClaims>;
    if (existing.userId !== state.userId) {
      await this.redis.srem(this.userKey(existing.userId), token);
      await this.redis.sadd(this.userKey(state.userId), token);
    }
    const ttlMs = Math.max(0, state.expiresAt - Date.now());
    if (ttlMs > 0) {
      await this.redis.set(this.tokenKey(token), JSON.stringify(state), "PX", ttlMs);
    } else {
      await this.revoke(token);
    }
    return token;
  }

  async revoke(token: string): Promise<void> {
    const raw = await this.redis.get(this.tokenKey(token));
    if (raw === null) return;
    const state = JSON.parse(raw) as CredentialState<TClaims>;
    await this.redis.del(this.tokenKey(token));
    await this.redis.srem(this.userKey(state.userId), token);
  }

  async revokeAllForUser(userId: string): Promise<number> {
    const setKey = this.userKey(userId);
    const tokens = await this.redis.smembers(setKey);
    if (tokens.length === 0) return 0;
    const keys = tokens.map((t) => this.tokenKey(t));
    const removed = await this.redis.del(...keys);
    // Prune just the tokens we revoked rather than `del(setKey)` — a
    // concurrent `persist` may have added a fresh token to the set between
    // `smembers` and this point, and we don't want to orphan it.
    await this.redis.srem(setKey, ...tokens);
    return removed;
  }

  async listForUser(userId: string): Promise<Array<CredentialState<TClaims> & { token: string }>> {
    const setKey = this.userKey(userId);
    const tokens = await this.redis.smembers(setKey);
    if (tokens.length === 0) return [];
    const now = Date.now();
    const out: Array<CredentialState<TClaims> & { token: string }> = [];
    const dead: string[] = [];
    for (const token of tokens) {
      const raw = await this.redis.get(this.tokenKey(token));
      if (raw === null) {
        dead.push(token);
        continue;
      }
      const state = JSON.parse(raw) as CredentialState<TClaims>;
      if (state.expiresAt <= now) {
        dead.push(token);
        continue;
      }
      out.push({ ...state, token });
    }
    if (dead.length > 0) {
      await this.redis.srem(setKey, ...dead);
    }
    return out;
  }
}

interface RedisDenylistStoreOptions {
  redis: RedisLike;
  /** Key prefix. Defaults to `aooth:dl`. Combined as `<prefix>:<jti>`. */
  prefix?: string;
}

/**
 * Redis-backed `DenylistStore`. Each `add` writes a key with a `PX` TTL set
 * to `expiresAt - now`, so Redis self-evicts the entry once the underlying
 * token would have expired anyway. `cleanup` is a no-op for that reason.
 */
export class DenylistStoreRedis implements DenylistStore {
  private readonly redis: RedisLike;
  private readonly prefix: string;

  constructor(opts: RedisDenylistStoreOptions) {
    this.redis = opts.redis;
    this.prefix = opts.prefix ?? "aooth:dl";
  }

  private key(jti: string): string {
    return `${this.prefix}:${jti}`;
  }

  async add(jti: string, expiresAt: number): Promise<void> {
    const ttlMs = expiresAt - Date.now();
    if (ttlMs <= 0) return;
    await this.redis.set(this.key(jti), "1", "PX", ttlMs);
  }

  async has(jti: string): Promise<boolean> {
    const n = await this.redis.exists(this.key(jti));
    return n > 0;
  }

  async cleanup(): Promise<number> {
    // Redis evicts expired keys automatically via PX TTL — nothing to do.
    return 0;
  }
}
