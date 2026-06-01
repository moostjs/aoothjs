import { describe, expect, it } from "vite-plus/test";
import type { CredentialState } from "../../credential/types";
import { CredentialStoreRedis } from "../index";
import { MockRedis } from "./mock-redis";

function makeState(userId: string, overrides?: Partial<CredentialState>): CredentialState {
  return {
    userId,
    issuedAt: Date.now(),
    expiresAt: Date.now() + 60_000,
    kind: "access",
    ...overrides,
  };
}

describe("CredentialStoreRedis — contract", () => {
  // Intent 1: all six CredentialStore methods work end-to-end.
  // These tests exist because the adapter has to behave indistinguishably
  // from the memory store for any downstream code wired against the
  // `CredentialStore` interface — otherwise switching adapters silently
  // changes session/token semantics.
  describe("persist + retrieve + revoke happy path", () => {
    it("persists state and retrieves it by token", async () => {
      const redis = new MockRedis();
      const store = new CredentialStoreRedis({ redis });
      const token = await store.persist(makeState("alice"));
      expect(token).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
      const state = await store.retrieve(token);
      expect(state?.userId).toBe("alice");
    });

    it("retrieve returns null for unknown token", async () => {
      const store = new CredentialStoreRedis({ redis: new MockRedis() });
      expect(await store.retrieve("nope")).toBeNull();
    });

    it("revoke removes the entry and the user-index membership", async () => {
      const redis = new MockRedis();
      const store = new CredentialStoreRedis({ redis });
      const token = await store.persist(makeState("alice"));
      await store.revoke(token);
      expect(await store.retrieve(token)).toBeNull();
      // User-index should no longer carry the token — otherwise listForUser
      // would resurrect dead tokens.
      expect(redis.setMembers("aooth:cred:u:alice")).toEqual([]);
    });

    it("revoke is idempotent for unknown tokens", async () => {
      const store = new CredentialStoreRedis({ redis: new MockRedis() });
      await expect(store.revoke("nope")).resolves.toBeUndefined();
    });
  });

  describe("consume", () => {
    it("returns the state and revokes the token in one call", async () => {
      const redis = new MockRedis();
      const store = new CredentialStoreRedis({ redis });
      const token = await store.persist(makeState("alice"));
      const consumed = await store.consume(token);
      expect(consumed?.userId).toBe("alice");
      // The whole point of consume() is single-use; a second retrieve must
      // fail or magic-link / password-reset flows become replayable.
      expect(await store.retrieve(token)).toBeNull();
    });

    it("returns null when the token does not exist", async () => {
      const store = new CredentialStoreRedis({ redis: new MockRedis() });
      expect(await store.consume("nope")).toBeNull();
    });
  });

  describe("update", () => {
    it("rewrites the row and returns the same token id", async () => {
      const redis = new MockRedis();
      const store = new CredentialStoreRedis({ redis });
      const token = await store.persist(makeState("alice"));
      const next = makeState("alice", { rotatedAt: 42 });
      const returned = await store.update(token, next);
      expect(returned).toBe(token);
      const got = await store.retrieve(token);
      expect(got?.rotatedAt).toBe(42);
    });

    it("re-indexes the user set when userId changes", async () => {
      const redis = new MockRedis();
      const store = new CredentialStoreRedis({ redis });
      const token = await store.persist(makeState("alice"));
      await store.update(token, makeState("bob"));
      expect(redis.setMembers("aooth:cred:u:alice")).toEqual([]);
      expect(redis.setMembers("aooth:cred:u:bob")).toContain(token);
    });

    it("is a no-op for unknown tokens (does not resurrect revoked entries)", async () => {
      const redis = new MockRedis();
      const store = new CredentialStoreRedis({ redis });
      const returned = await store.update("ghost", makeState("alice"));
      expect(returned).toBe("ghost");
      expect(await store.retrieve("ghost")).toBeNull();
      // No user-index leak.
      expect(redis.setMembers("aooth:cred:u:alice")).toEqual([]);
    });
  });
});

describe("CredentialStoreRedis — listForUser", () => {
  // Intent 2: listForUser must yield {...state, token} so that downstream
  // session-management UIs can present and revoke individual sessions.
  it("returns active credentials with the token attached", async () => {
    const redis = new MockRedis();
    const store = new CredentialStoreRedis({ redis });
    const t1 = await store.persist(makeState("alice", { issuedAt: 1 }));
    const t2 = await store.persist(makeState("alice", { issuedAt: 2 }));
    const list = await store.listForUser("alice");
    expect(list).toHaveLength(2);
    for (const e of list) {
      expect(e.userId).toBe("alice");
      expect(typeof e.token).toBe("string");
    }
    expect(list.map((e) => e.token).toSorted()).toEqual([t1, t2].toSorted());
  });

  it("returns an empty array for a user with no credentials", async () => {
    const store = new CredentialStoreRedis({ redis: new MockRedis() });
    expect(await store.listForUser("nobody")).toEqual([]);
  });

  it("prunes user-index members whose key Redis has already evicted", async () => {
    // listForUser must self-heal stale set members — otherwise long-lived
    // sets accumulate garbage references to tokens whose TTL fired.
    const redis = new MockRedis();
    const store = new CredentialStoreRedis({ redis });
    const ghost = await store.persist(makeState("alice"));
    const live = await store.persist(makeState("alice"));
    redis.forceExpire(`aooth:cred:t:${ghost}`);
    const list = await store.listForUser("alice");
    expect(list.map((e) => e.token)).toEqual([live]);
    expect(redis.setMembers("aooth:cred:u:alice")).toEqual([live]);
  });
});

describe("CredentialStoreRedis — revokeAllForUser", () => {
  // Intent 3: revoking all credentials for a user must clear them all and
  // return the count. This is the cascade behind "log out everywhere".
  it("revokes every credential for the user and returns the count", async () => {
    const redis = new MockRedis();
    const store = new CredentialStoreRedis({ redis });
    await store.persist(makeState("alice"));
    await store.persist(makeState("alice"));
    const removed = await store.revokeAllForUser("alice");
    expect(removed).toBe(2);
    expect(await store.listForUser("alice")).toEqual([]);
  });

  it("returns 0 when the user has nothing", async () => {
    const store = new CredentialStoreRedis({ redis: new MockRedis() });
    expect(await store.revokeAllForUser("nobody")).toBe(0);
  });

  // Intent 5: cross-user isolation. A bug here would silently log
  // unrelated users out — high blast radius.
  it("leaves other users' credentials intact", async () => {
    const redis = new MockRedis();
    const store = new CredentialStoreRedis({ redis });
    await store.persist(makeState("alice"));
    await store.persist(makeState("alice"));
    const bobToken = await store.persist(makeState("bob"));
    await store.revokeAllForUser("alice");
    const bobList = await store.listForUser("bob");
    expect(bobList).toHaveLength(1);
    expect(bobList[0].token).toBe(bobToken);
  });

  // Intent 7 — the srem fix. We previously called del(setKey), which would
  // orphan any token added concurrently between smembers and del. The new
  // implementation must call srem(setKey, ...tokens) so a concurrent persist
  // survives. Simulate the race by hooking smembers to inject a concurrent
  // persist before the prune fires.
  it("uses srem(setKey, ...tokens) so a concurrent persist is preserved", async () => {
    const redis = new MockRedis();
    const store = new CredentialStoreRedis({ redis });
    const before = await store.persist(makeState("alice"));
    void before;
    const realSmembers = redis.smembers.bind(redis);
    let injected = false;
    redis.smembers = async (key: string): Promise<string[]> => {
      const members = await realSmembers(key);
      if (!injected && key === "aooth:cred:u:alice") {
        injected = true;
        // Race: a concurrent persist lands between smembers and the prune.
        await store.persist(makeState("alice"));
      }
      return members;
    };
    const removed = await store.revokeAllForUser("alice");
    expect(removed).toBe(1);
    // The concurrent token must still be reachable via listForUser.
    const list = await store.listForUser("alice");
    expect(list).toHaveLength(1);
    // And the set must still hold it — proving srem (not del) was used.
    expect(redis.setMembers("aooth:cred:u:alice")).toHaveLength(1);
    // Sanity check on the recorded ops: a `del setKey` op would be the bug.
    const setKey = "aooth:cred:u:alice";
    const badDel = redis.opsOf("del").find((o) => o.args.length === 1 && o.args[0] === setKey);
    expect(badDel).toBeUndefined();
    // And srem(setKey, ...tokens) actually fired with the original token list.
    const srem = redis.opsOf("srem").find((o) => o.args[0] === setKey && o.args.length === 2);
    expect(srem).toBeDefined();
  });
});

describe("CredentialStoreRedis — TTL semantics", () => {
  // Intent 4: TTL expiry. Redis enforces TTL in production; here we simulate
  // by dropping the key, which mirrors what Redis would have done.
  it("retrieve returns null once Redis has evicted the key", async () => {
    const redis = new MockRedis();
    const store = new CredentialStoreRedis({ redis });
    const token = await store.persist(makeState("alice"), 50);
    redis.forceExpire(`aooth:cred:t:${token}`);
    expect(await store.retrieve(token)).toBeNull();
  });

  it("retrieve self-cleans an entry whose embedded expiresAt is in the past", async () => {
    // Clock-skew guard — even if Redis hasn't evicted yet, the adapter must
    // not hand back a state whose expiresAt has already lapsed.
    const redis = new MockRedis();
    const store = new CredentialStoreRedis({ redis });
    const token = await store.persist(makeState("alice", { expiresAt: Date.now() + 60_000 }));
    // Forge the row to be expired in-place (clock-skew simulation).
    const key = `aooth:cred:t:${token}`;
    const raw = JSON.parse((await redis.get(key)) ?? "{}");
    raw.expiresAt = Date.now() - 1;
    await redis.set(key, JSON.stringify(raw));
    expect(await store.retrieve(token)).toBeNull();
    // And the user-index must have been pruned.
    expect(redis.setMembers("aooth:cred:u:alice")).toEqual([]);
  });

  // Intent 6: fail-loud on already-expired persist. This rule exists because
  // returning a phantom token silently corrupts downstream flows — the caller
  // believes a credential is issued, then every subsequent retrieve returns
  // null and the bug surfaces far from its source.
  it("persist throws when ttl is 0", async () => {
    const store = new CredentialStoreRedis({ redis: new MockRedis() });
    await expect(store.persist(makeState("alice"), 0)).rejects.toThrow(/already-expired/i);
  });

  it("persist throws when ttl is negative", async () => {
    const store = new CredentialStoreRedis({ redis: new MockRedis() });
    await expect(store.persist(makeState("alice"), -1000)).rejects.toThrow(/already-expired/i);
  });

  it("persist throws when state.expiresAt is already in the past and no ttl override", async () => {
    const store = new CredentialStoreRedis({ redis: new MockRedis() });
    await expect(store.persist(makeState("alice", { expiresAt: Date.now() - 1 }))).rejects.toThrow(
      /already-expired/i,
    );
  });

  it("update treats a past-expiry update as a revoke (does not write a dead row)", async () => {
    // Same fail-loud rule extended to update: never leave a dead row behind.
    const redis = new MockRedis();
    const store = new CredentialStoreRedis({ redis });
    const token = await store.persist(makeState("alice"));
    await store.update(token, makeState("alice", { expiresAt: Date.now() - 1 }));
    expect(await store.retrieve(token)).toBeNull();
    expect(redis.setMembers("aooth:cred:u:alice")).toEqual([]);
  });
});

describe("CredentialStoreRedis — sessionId / lastSeenAt", () => {
  it("round-trips sessionId through persist + listForUser", async () => {
    const store = new CredentialStoreRedis({ redis: new MockRedis() });
    await store.persist(makeState("alice", { sessionId: "sess-1" }));
    const [entry] = await store.listForUser("alice");
    expect(entry.sessionId).toBe("sess-1");
  });

  it("touch sets lastSeenAt on an existing token, preserves TTL, no-op for unknown", async () => {
    const redis = new MockRedis();
    const store = new CredentialStoreRedis({ redis });
    const token = await store.persist(makeState("alice"), 60_000);
    await store.touch(token, 12_345);
    expect((await store.retrieve(token))?.lastSeenAt).toBe(12_345);
    // Unknown token is a no-op (does not throw).
    await store.touch("nope", 999);
  });
});

describe("CredentialStoreRedis — custom prefix", () => {
  it("honours the prefix option for keys and the per-user set", async () => {
    // Prefix is part of the documented surface — consumers rely on it for
    // namespacing within a shared Redis instance.
    const redis = new MockRedis();
    const store = new CredentialStoreRedis({ redis, prefix: "myapp:c" });
    const token = await store.persist(makeState("alice"));
    expect(redis.opsOf("set")[0].args[0]).toBe(`myapp:c:t:${token}`);
    expect(redis.setMembers("myapp:c:u:alice")).toContain(token);
  });
});
