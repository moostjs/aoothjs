import type { Redis } from "ioredis";
import { describe, expect, it } from "vite-plus/test";

import { CredentialStoreRedis, DenylistStoreRedis, RateLimitStoreRedis } from "../index";
import type { RedisLike } from "../index";

/**
 * Compile-only regression guard: a real `ioredis` client must satisfy
 * `RedisLike` — and construct every Redis-backed store — with ZERO casts.
 *
 * This function is intentionally never invoked; its body exists purely so
 * `vp check` (tsc) verifies the assignments. If ioredis's typings ever drift
 * from the seam (or the seam regresses to a shape ioredis can't match), THIS
 * FILE stops type-checking — which is the whole point.
 *
 * `import type { Redis }` is erased at build time, so this adds no runtime
 * dependency on ioredis and needs no live Redis server.
 */
function assertIoredisFitsRedisLike(client: Redis): RedisLike {
  // The exact construction a downstream consumer writes — must need no cast.
  void new CredentialStoreRedis({ redis: client });
  void new DenylistStoreRedis({ redis: client });
  void new RateLimitStoreRedis({ redis: client });
  // The core assertion: `Redis` is assignable to `RedisLike`.
  return client;
}

describe("RedisLike ↔ ioredis structural compatibility", () => {
  it("accepts a real ioredis client with no cast (enforced by tsc, not at runtime)", () => {
    // The guarantee lives in `assertIoredisFitsRedisLike`'s signature + body,
    // checked when the file is type-checked. Nothing to exercise at runtime.
    expect(assertIoredisFitsRedisLike).toBeTypeOf("function");
  });
});
