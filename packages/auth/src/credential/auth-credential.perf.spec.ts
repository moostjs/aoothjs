import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vite-plus/test";
import { RateLimitStoreMemory } from "../rate-limit/store";
import { CredentialStoreRedis } from "../redis/index";
import { MockRedis } from "../redis/__test__/mock-redis";
import { DenylistStoreMemory } from "../stores/denylist-memory";
import { CredentialStoreMemory } from "../stores/memory";
import type { CredentialStore, DenylistStore } from "../stores/store";
import type { Clock } from "../utils/clock";
import { AuthCredential } from "./auth-credential";
import type { CredentialState } from "./types";

class FakeClock implements Clock {
  constructor(public time = 1_000_000) {}
  now(): number {
    return this.time;
  }
  advance(ms: number): void {
    this.time += ms;
  }
}

/** A memory store whose calls are counted. */
function countingStore(clock: Clock) {
  const store = new CredentialStoreMemory({ clock });
  const calls = { retrieve: 0, touch: [] as Array<CredentialState | undefined> };
  const retrieve = store.retrieve.bind(store);
  store.retrieve = async (token) => {
    calls.retrieve++;
    return retrieve(token);
  };
  const touch = store.touch.bind(store);
  store.touch = async (token, at, state) => {
    calls.touch.push(state);
    return touch(token, at);
  };
  return { store, calls };
}

/** A denylist answering `denied` after 20ms (a remote round trip). */
function slowDenylist(denied: boolean): DenylistStore {
  return {
    add: async () => {},
    cleanup: async () => 0,
    has: () => new Promise((r) => setTimeout(() => r(denied), 20)),
  };
}

describe("AuthCredential.validate — lookups", () => {
  it("passes the state it just read to store.touch (no re-read)", async () => {
    const clock = new FakeClock();
    const { store, calls } = countingStore(clock);
    const auth = new AuthCredential({ store, clock, trackLastSeen: "validate" });
    const { accessToken } = await auth.issue("alice");
    await auth.validate(accessToken);
    expect(calls.touch).toHaveLength(1);
    expect(calls.touch[0]).toMatchObject({ userId: "alice", kind: "access" });
  });

  it("checks the denylist and the store concurrently; a denial wins and swallows a store error", async () => {
    const clock = new FakeClock();
    const order: string[] = [];
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const denylist: DenylistStore = {
      add: async () => {},
      cleanup: async () => 0,
      has: async () => {
        order.push("has:start");
        await gate;
        order.push("has:end");
        return true;
      },
    };
    const store = new CredentialStoreMemory({ clock });
    store.retrieve = async () => {
      order.push("retrieve");
      throw new Error("store down");
    };
    const auth = new AuthCredential({ store, clock, denylist });
    const pending = auth.validate("tok");
    await Promise.resolve();
    expect(order).toEqual(["retrieve", "has:start"]);
    release();
    expect(await pending).toBeNull();
  });

  it("a store failure settling while the denylist is awaited is never an unhandled rejection", async () => {
    const clock = new FakeClock();
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);
    process.on("unhandledRejection", onUnhandled);
    try {
      const store = new CredentialStoreMemory({ clock });
      store.retrieve = async () => {
        throw new Error("store down");
      };
      const denying = new AuthCredential({ store, clock, denylist: slowDenylist(true) });
      expect(await denying.validate("tok")).toBeNull();
      const allowing = new AuthCredential({ store, clock, denylist: slowDenylist(false) });
      await expect(allowing.validate("tok")).rejects.toThrow("store down");
      await new Promise((r) => setTimeout(r, 20));
      expect(unhandled).toEqual([]);
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }
  });

  it("not denied: the store's answer (and its error) stands; a denylist error propagates", async () => {
    const clock = new FakeClock();
    const store = new CredentialStoreMemory({ clock });
    const denylist = new DenylistStoreMemory({ clock });
    const auth = new AuthCredential({ store, clock, denylist });
    const { accessToken } = await auth.issue("alice");
    expect((await auth.validate(accessToken))?.userId).toBe("alice");
    await denylist.add(accessToken, clock.now() + 60_000);
    expect(await auth.validate(accessToken)).toBeNull();
    const failing = new AuthCredential({
      store,
      clock,
      denylist: {
        add: async () => {},
        cleanup: async () => 0,
        has: async () => Promise.reject(new Error("dl down")),
      },
    });
    await expect(failing.validate(accessToken)).rejects.toThrow("dl down");
  });

  it("credentialId is the token's SHA-256, computed on read, writable, enumerable, in place", async () => {
    const clock = new FakeClock();
    const auth = new AuthCredential({ store: new CredentialStoreMemory({ clock }), clock });
    const { accessToken } = await auth.issue("alice");
    const ctx = (await auth.validate(accessToken))!;
    const expected = createHash("sha256").update(accessToken).digest("hex");
    expect(ctx.credentialId).toBe(expected);
    expect(Object.keys(ctx)).toEqual([
      "userId",
      "method",
      "credentialId",
      "sessionId",
      "expiresAt",
    ]);
    expect(JSON.parse(JSON.stringify(ctx)).credentialId).toBe(expected);
    expect({ ...ctx }.credentialId).toBe(expected);
    ctx.credentialId = "x";
    expect(ctx.credentialId).toBe("x");
  });
});

describe("AuthCredential validateCache (opt-in)", () => {
  function setup(opts: { ttlMs?: number; max?: number } = {}) {
    const clock = new FakeClock();
    const { store, calls } = countingStore(clock);
    const auth = new AuthCredential({
      store,
      clock,
      refresh: { ttl: 600_000 },
      validateCache: { ttlMs: opts.ttlMs ?? 5000, max: opts.max },
    });
    return { auth, store, calls, clock };
  }

  it("is off by default: every validate reads the store", async () => {
    const clock = new FakeClock();
    const { store, calls } = countingStore(clock);
    const auth = new AuthCredential({ store, clock });
    const { accessToken } = await auth.issue("alice");
    await auth.validate(accessToken);
    await auth.validate(accessToken);
    expect(calls.retrieve).toBe(2);
  });

  it("reuses a validated state for ttlMs; re-reads after it", async () => {
    const { auth, calls, clock } = setup();
    const { accessToken } = await auth.issue("alice");
    const a = await auth.validate(accessToken);
    const b = await auth.validate(accessToken);
    expect(b).toEqual(a);
    expect(calls.retrieve).toBe(1);
    clock.advance(5000);
    await auth.validate(accessToken);
    expect(calls.retrieve).toBe(2);
  });

  it("re-checks expiry on a hit", async () => {
    const clock = new FakeClock();
    const auth = new AuthCredential({
      store: new CredentialStoreMemory({ clock }),
      clock,
      accessTtl: 1000,
      validateCache: { ttlMs: 60_000 },
    });
    const { accessToken } = await auth.issue("alice");
    expect(await auth.validate(accessToken)).not.toBeNull();
    clock.advance(1000);
    expect(await auth.validate(accessToken)).toBeNull();
  });

  it("revoke / revokeAllForUser / revokeSession / revokeOtherSessions evict at once", async () => {
    const { auth } = setup({ ttlMs: 60_000 });
    const one = await auth.issue("alice");
    expect(await auth.validate(one.accessToken)).not.toBeNull();
    await auth.revoke(one.accessToken);
    expect(await auth.validate(one.accessToken)).toBeNull();

    const two = await auth.issue("alice");
    const bob = await auth.issue("bob");
    await auth.validate(two.accessToken);
    await auth.validate(bob.accessToken);
    await auth.revokeAllForUser("alice");
    expect(await auth.validate(two.accessToken)).toBeNull();
    expect(await auth.validate(bob.accessToken)).not.toBeNull();

    const s1 = await auth.issue("carol");
    const s2 = await auth.issue("carol");
    const c1 = (await auth.validate(s1.accessToken))!;
    await auth.validate(s2.accessToken);
    await auth.revokeOtherSessions("carol", c1.sessionId!);
    expect(await auth.validate(s2.accessToken)).toBeNull();
    expect(await auth.validate(s1.accessToken)).not.toBeNull();
    await auth.revokeSession("carol", c1.sessionId!);
    expect(await auth.validate(s1.accessToken)).toBeNull();
  });

  it("never caches a refresh token or a miss; a revocation racing a validation is not re-cached", async () => {
    const { auth, store, calls } = setup({ ttlMs: 60_000 });
    const { accessToken, refreshToken } = await auth.issue("alice");
    expect(await auth.validate(refreshToken!)).toBeNull();
    expect(await auth.validate(refreshToken!)).toBeNull();
    expect(await auth.validate("nope")).toBeNull();
    expect(await auth.validate("nope")).toBeNull();
    expect(calls.retrieve).toBe(4);
    // A revoke landing while validate awaits the store must not leave a cached entry.
    const retrieve = store.retrieve.bind(store);
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    store.retrieve = async (t) => {
      const s = await retrieve(t);
      await gate;
      return s;
    };
    const pending = auth.validate(accessToken);
    await Promise.resolve();
    await auth.revoke(accessToken);
    release();
    await pending;
    store.retrieve = retrieve;
    expect(await auth.validate(accessToken)).toBeNull();
  });

  it("a validation starting while a revoke's store write is in flight is not cached", async () => {
    const { auth, store } = setup({ ttlMs: 60_000 });
    const { accessToken } = await auth.issue("alice");
    const second = await auth.issue("alice");
    for (const revokeAll of [false, true]) {
      const token = revokeAll ? second.accessToken : accessToken;
      // The store write lags (a remote store): a read before it lands still sees the token.
      const revoke = store.revoke.bind(store);
      const revokeAllForUser = store.revokeAllForUser.bind(store);
      let release!: () => void;
      const gate = new Promise<void>((r) => (release = r));
      store.revoke = async (t) => {
        await gate;
        return revoke(t);
      };
      store.revokeAllForUser = async (u) => {
        await gate;
        return revokeAllForUser(u);
      };
      const revoking = revokeAll ? auth.revokeAllForUser("alice") : auth.revoke(token);
      expect(await auth.validate(token)).not.toBeNull(); // read before the write landed
      release();
      await revoking;
      store.revoke = revoke;
      store.revokeAllForUser = revokeAllForUser;
      expect(await auth.validate(token)).toBeNull();
    }
  });

  it("hands touch only a state it just read — never a cached one (no stale write-back)", async () => {
    const clock = new FakeClock();
    const { store, calls } = countingStore(clock);
    const auth = new AuthCredential({
      store,
      clock,
      trackLastSeen: "validate",
      validateCache: { ttlMs: 60_000 },
    });
    const { accessToken } = await auth.issue("alice");
    await auth.validate(accessToken);
    await auth.validate(accessToken);
    expect(calls.retrieve).toBe(1);
    expect(calls.touch).toHaveLength(2);
    expect(calls.touch[0]).toMatchObject({ userId: "alice" });
    expect(calls.touch[1]).toBeUndefined();
  });

  it("Redis: a cache hit after a revocation elsewhere never resurrects the token", async () => {
    const redis = new MockRedis();
    const clock = new FakeClock(Date.now());
    const nodeA = new AuthCredential({
      store: new CredentialStoreRedis({ redis }),
      clock,
      trackLastSeen: "validate",
      validateCache: { ttlMs: 60_000 },
    });
    const nodeB = new AuthCredential({ store: new CredentialStoreRedis({ redis }), clock });
    const { accessToken } = await nodeA.issue("alice");
    expect(await nodeA.validate(accessToken)).not.toBeNull();
    await nodeB.revoke(accessToken);
    // Node A serves its cached entry until ttlMs (documented cross-node lag)…
    expect(await nodeA.validate(accessToken)).not.toBeNull();
    // …but its activity stamp must not write the revoked token back.
    expect(await nodeB.validate(accessToken)).toBeNull();
  });

  it("is bounded (oldest first) and rejects a non-positive ttl", async () => {
    const { auth, calls } = setup({ max: 2 });
    const tokens = await Promise.all(["a", "b", "c"].map((u) => auth.issue(u)));
    for (const t of tokens) await auth.validate(t.accessToken);
    expect(calls.retrieve).toBe(3);
    await auth.validate(tokens[0].accessToken); // evicted by c
    expect(calls.retrieve).toBe(4);
    await auth.validate(tokens[2].accessToken);
    expect(calls.retrieve).toBe(4);
    expect(
      () =>
        new AuthCredential({
          store: new CredentialStoreMemory(),
          validateCache: { ttlMs: 0 },
        }),
    ).toThrow(/validateCache\.ttlMs/);
  });
});

describe("amortized sweeps of in-memory bookkeeping", () => {
  it("RateLimitStoreMemory drops dead window counters as it grows", async () => {
    const clock = new FakeClock();
    const rl = new RateLimitStoreMemory({ clock });
    const size = () => (rl as unknown as { entries: Map<string, unknown> }).entries.size;
    for (let i = 0; i < 1024; i++) await rl.hit(`k:${i}`, 1000);
    clock.advance(1000);
    for (let i = 0; i < 1100; i++) await rl.hit(`w2:${i}`, 1000);
    expect(size()).toBe(1100);
    expect(await rl.hit("w2:0", 1000)).toBe(2); // live counters kept
  });

  it("DenylistStoreMemory drops expired ids as it grows", async () => {
    const clock = new FakeClock();
    const dl = new DenylistStoreMemory({ clock });
    const size = () => (dl as unknown as { entries: Map<string, unknown> }).entries.size;
    for (let i = 0; i < 1024; i++) await dl.add(`old:${i}`, clock.now() + 10);
    clock.advance(10);
    await dl.add("live", clock.now() + 1000);
    expect(size()).toBe(1);
    expect(await dl.has("live")).toBe(true);
  });

  it("consumed-refresh records are swept once expired (stateless store)", async () => {
    const clock = new FakeClock();
    const store: CredentialStore = new CredentialStoreMemory({ clock });
    // A store without `listForUser` takes the stateless single-use path.
    const stateless = Object.assign(Object.create(store) as CredentialStore, {
      listForUser: undefined,
    });
    const auth = new AuthCredential({
      store: stateless,
      clock,
      refresh: { ttl: 1000, rotation: "always" },
    });
    const consumed = () =>
      (auth as unknown as { consumedRefreshes: Map<string, unknown> }).consumedRefreshes;
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    for (let i = 0; i < 1024; i++) {
      const { refreshToken } = await auth.issue(`u${i}`);
      await auth.refresh(refreshToken!);
    }
    expect(consumed().size).toBe(1024);
    clock.advance(1000);
    const { refreshToken } = await auth.issue("late");
    await auth.refresh(refreshToken!);
    expect(consumed().size).toBe(1);
    spy.mockRestore();
  });
});
