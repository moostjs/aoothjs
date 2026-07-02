import type { RedisLike } from "../index";

/**
 * In-memory `RedisLike` double. Implements the exact commands the adapters
 * use. We deliberately do NOT enforce PX-based eviction here — Redis itself
 * is responsible for that in production. Tests that need to simulate "the
 * key expired" can call `forceExpire(key)` to drop the K/V entry directly,
 * mirroring what Redis would have done.
 *
 * Every call is recorded into `ops`, so tests can assert on the exact
 * sequence (e.g. that `revokeAllForUser` calls `srem(setKey, ...tokens)`
 * rather than `del(setKey)`).
 */
export class MockRedis implements RedisLike {
  private kv = new Map<string, string>();
  private sets = new Map<string, Set<string>>();
  /** Last-seen ttl (ms) per key. Not enforced — tests use `forceExpire` instead. */
  ttls = new Map<string, number>();
  ops: Array<{ cmd: string; args: unknown[] }> = [];

  async set(key: string, value: string, mode?: "PX", ttlMs?: number): Promise<string | null> {
    this.ops.push({ cmd: "set", args: [key, value, mode, ttlMs] });
    this.kv.set(key, value);
    if (mode === "PX" && typeof ttlMs === "number") this.ttls.set(key, ttlMs);
    return "OK";
  }

  async get(key: string): Promise<string | null> {
    this.ops.push({ cmd: "get", args: [key] });
    return this.kv.get(key) ?? null;
  }

  async del(...keys: string[]): Promise<number> {
    this.ops.push({ cmd: "del", args: keys });
    let n = 0;
    for (const k of keys) {
      if (this.kv.delete(k)) n++;
      this.ttls.delete(k);
    }
    return n;
  }

  async exists(key: string): Promise<number> {
    this.ops.push({ cmd: "exists", args: [key] });
    return this.kv.has(key) ? 1 : 0;
  }

  async pexpire(key: string, ttlMs: number): Promise<number> {
    this.ops.push({ cmd: "pexpire", args: [key, ttlMs] });
    if (!this.kv.has(key)) return 0;
    this.ttls.set(key, ttlMs);
    return 1;
  }

  async incr(key: string): Promise<number> {
    this.ops.push({ cmd: "incr", args: [key] });
    const next = Number(this.kv.get(key) ?? "0") + 1;
    this.kv.set(key, String(next));
    return next;
  }

  async sadd(key: string, ...members: string[]): Promise<number> {
    this.ops.push({ cmd: "sadd", args: [key, ...members] });
    const set = this.sets.get(key) ?? new Set<string>();
    let added = 0;
    for (const m of members) {
      if (!set.has(m)) added++;
      set.add(m);
    }
    this.sets.set(key, set);
    return added;
  }

  async srem(key: string, ...members: string[]): Promise<number> {
    this.ops.push({ cmd: "srem", args: [key, ...members] });
    const set = this.sets.get(key);
    if (!set) return 0;
    let removed = 0;
    for (const m of members) {
      if (set.delete(m)) removed++;
    }
    if (set.size === 0) this.sets.delete(key);
    return removed;
  }

  async smembers(key: string): Promise<string[]> {
    this.ops.push({ cmd: "smembers", args: [key] });
    return Array.from(this.sets.get(key) ?? []);
  }

  // ---- test helpers (not part of RedisLike) -------------------------------

  /** Simulate "Redis evicted this key due to PX TTL." */
  forceExpire(key: string): void {
    this.kv.delete(key);
    this.ttls.delete(key);
  }

  /** Membership probe for assertions. */
  setMembers(key: string): string[] {
    return Array.from(this.sets.get(key) ?? []);
  }

  /** Filtered ops by command name. */
  opsOf(cmd: string): Array<{ cmd: string; args: unknown[] }> {
    return this.ops.filter((o) => o.cmd === cmd);
  }
}
