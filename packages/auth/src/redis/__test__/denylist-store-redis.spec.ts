import { describe, expect, it } from "vite-plus/test";
import { DenylistStoreRedis } from "../index";
import { MockRedis } from "./mock-redis";

describe("DenylistStoreRedis", () => {
  // Intent 8: round-trip on add/has — the denylist is the entire mechanism
  // by which stateless tokens become revocable. If add doesn't survive a
  // subsequent has(), revocation silently fails.
  it("add + has round-trips for an active jti", async () => {
    const redis = new MockRedis();
    const store = new DenylistStoreRedis({ redis });
    await store.add("abc", Date.now() + 60_000);
    expect(await store.has("abc")).toBe(true);
  });

  it("has returns false for an unknown jti", async () => {
    const store = new DenylistStoreRedis({ redis: new MockRedis() });
    expect(await store.has("never-added")).toBe(false);
  });

  it("add writes a SET ... PX <ttl> entry with the correct prefix", async () => {
    // Redis is responsible for evicting expired denylist entries — that's
    // why cleanup is a no-op. If add ever stopped passing PX, the denylist
    // would grow unbounded.
    const redis = new MockRedis();
    const store = new DenylistStoreRedis({ redis });
    const expiresAt = Date.now() + 5_000;
    await store.add("abc", expiresAt);
    const setOp = redis.opsOf("set").at(-1);
    expect(setOp).toBeDefined();
    expect(setOp?.args[0]).toBe("aooth:dl:abc");
    expect(setOp?.args[2]).toBe("PX");
    const ttl = setOp?.args[3] as number;
    // Within a small window of (expiresAt - now).
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(5_000);
  });

  it("add with already-past expiry is a no-op (no write to Redis)", async () => {
    // Negative-ttl writes would either fail or hold forever depending on
    // the Redis client — we instead refuse the write entirely.
    const redis = new MockRedis();
    const store = new DenylistStoreRedis({ redis });
    await store.add("abc", Date.now() - 1_000);
    expect(redis.opsOf("set")).toHaveLength(0);
    expect(await store.has("abc")).toBe(false);
  });

  it("cleanup is a no-op and returns 0 (Redis evicts via PX TTL)", async () => {
    const store = new DenylistStoreRedis({ redis: new MockRedis() });
    expect(await store.cleanup()).toBe(0);
  });

  it("honours a custom prefix", async () => {
    const redis = new MockRedis();
    const store = new DenylistStoreRedis({ redis, prefix: "myapp:dl" });
    await store.add("xyz", Date.now() + 1_000);
    expect(redis.opsOf("set").at(-1)?.args[0]).toBe("myapp:dl:xyz");
    expect(await store.has("xyz")).toBe(true);
  });
});
