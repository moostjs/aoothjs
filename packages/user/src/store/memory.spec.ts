import { describe, expect, it } from "vite-plus/test";
import { UserAuthError } from "../errors";
import type { UserCredentials } from "../types";
import { UserStoreMemory } from "./memory";

function makeUser(username: string, overrides?: Partial<UserCredentials>): UserCredentials {
  return {
    id: `id-${username}`,
    username,
    password: { hash: "hash", history: [], lastChanged: 0, isInitial: false },
    account: {
      active: false,
      locked: false,
      lockReason: "",
      lockEnds: 0,
      failedLoginAttempts: 0,
      lastLogin: 0,
    },
    mfa: { methods: [], defaultMethod: "", autoSend: false },
    ...overrides,
  };
}

describe("UserStoreMemory", () => {
  describe("exists", () => {
    it("should return false for unknown user", async () => {
      const store = new UserStoreMemory();
      expect(await store.exists("unknown")).toBe(false);
    });

    it("should return true after create", async () => {
      const store = new UserStoreMemory();
      await store.create(makeUser("alice"));
      expect(await store.exists("alice")).toBe(true);
    });
  });

  describe("findByHandle", () => {
    it("should return null for unknown user", async () => {
      const store = new UserStoreMemory();
      expect(await store.findByHandle("unknown")).toBeNull();
    });

    it("should return cloned data", async () => {
      const store = new UserStoreMemory();
      await store.create(makeUser("alice"));
      const a = await store.findByHandle("alice");
      const b = await store.findByHandle("alice");
      expect(a).toEqual(b);
      expect(a).not.toBe(b);
    });
  });

  describe("findById", () => {
    it("should return null for unknown id", async () => {
      const store = new UserStoreMemory();
      expect(await store.findById("unknown")).toBeNull();
    });

    it("should read by the stable surrogate id", async () => {
      const store = new UserStoreMemory();
      await store.create(makeUser("alice"));
      const user = await store.findById("id-alice");
      expect(user!.username).toBe("alice");
    });
  });

  describe("create", () => {
    it("should store a user", async () => {
      const store = new UserStoreMemory();
      await store.create(makeUser("alice"));
      const user = await store.findByHandle("alice");
      expect(user!.username).toBe("alice");
    });

    it("should throw ALREADY_EXISTS for duplicate", async () => {
      const store = new UserStoreMemory();
      await store.create(makeUser("alice"));
      await expect(store.create(makeUser("alice"))).rejects.toThrow(UserAuthError);
      try {
        await store.create(makeUser("alice"));
      } catch (e) {
        expect((e as UserAuthError).type).toBe("ALREADY_EXISTS");
      }
    });
  });

  describe("update", () => {
    it("should return false for unknown user", async () => {
      const store = new UserStoreMemory();
      expect(await store.update("unknown", { set: { account: { active: true } } as any })).toBe(
        false,
      );
    });

    it("should deep merge set fields", async () => {
      const store = new UserStoreMemory();
      await store.create(makeUser("alice"));
      await store.update("id-alice", { set: { account: { active: true } } as any });
      const user = await store.findByHandle("alice");
      expect(user!.account.active).toBe(true);
      expect(user!.account.locked).toBe(false); // unchanged
    });

    it("should atomically increment with inc", async () => {
      const store = new UserStoreMemory();
      await store.create(makeUser("alice"));
      await store.update("id-alice", { inc: { "account.failedLoginAttempts": 1 } });
      await store.update("id-alice", { inc: { "account.failedLoginAttempts": 1 } });
      const user = await store.findByHandle("alice");
      expect(user!.account.failedLoginAttempts).toBe(2);
    });

    it("should handle combined set and inc", async () => {
      const store = new UserStoreMemory();
      await store.create(makeUser("alice"));
      await store.update("id-alice", {
        set: { account: { locked: true } } as any,
        inc: { "account.failedLoginAttempts": 3 },
      });
      const user = await store.findByHandle("alice");
      expect(user!.account.locked).toBe(true);
      expect(user!.account.failedLoginAttempts).toBe(3);
    });

    it("should return true for successful update", async () => {
      const store = new UserStoreMemory();
      await store.create(makeUser("alice"));
      expect(await store.update("id-alice", { set: { account: { active: true } } as any })).toBe(
        true,
      );
    });
  });

  describe("seed constructor", () => {
    it("should initialize with seeded data", async () => {
      const store = new UserStoreMemory({ alice: makeUser("alice") });
      expect(await store.exists("alice")).toBe(true);
    });
  });

  describe("withCas", () => {
    it("applies the patch on the first attempt when uncontended", async () => {
      const store = new UserStoreMemory();
      await store.create(makeUser("alice"));
      let calls = 0;
      await store.withCas("id-alice", (user) => {
        calls++;
        expect(user.username).toBe("alice");
        return { set: { account: { active: true } } as any };
      });
      expect(calls).toBe(1);
      const after = await store.findByHandle("alice");
      expect(after!.account.active).toBe(true);
      expect(after!.version).toBe(1);
    });

    it("mutator returning null exits cleanly without writing or bumping version", async () => {
      const store = new UserStoreMemory();
      await store.create(makeUser("alice"));
      await store.withCas("id-alice", () => null);
      const after = await store.findByHandle("alice");
      expect(after!.version).toBe(0);
    });

    it("throws NOT_FOUND when the user does not exist", async () => {
      const store = new UserStoreMemory();
      try {
        await store.withCas("ghost", () => ({ set: { account: { active: true } } as any }));
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("NOT_FOUND");
      }
    });

    it("throws CAS_EXHAUSTED after maxAttempts retries when every attempt loses to contention", async () => {
      // The default budget is 2 (one initial attempt + one retry). To force
      // exhaustion we inject a competing write inside the mutator: memory
      // store's `update` body is synchronous, so the void update lands
      // BEFORE withCas reaches its CAS check, guaranteeing the version is
      // stale every time. Two such losses → CAS_EXHAUSTED.
      const store = new UserStoreMemory();
      await store.create(makeUser("alice"));
      let calls = 0;
      try {
        await store.withCas("id-alice", () => {
          calls++;
          // Sneak a competing write in between this attempt's read and its CAS.
          void store.update("id-alice", { set: { account: { lastLogin: calls } } as any });
          // We don't care about the patch contents — it'll never apply.
          return { set: { account: { failedLoginAttempts: calls } } as any };
        });
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("CAS_EXHAUSTED");
      }
      // Mutator ran exactly maxAttempts (2) times: 1 initial + 1 retry.
      expect(calls).toBe(2);
      // The competing writes DID land (they don't use expectedVersion), so
      // version is bumped twice — once per failed attempt's sneaked update.
      const after = await store.findByHandle("alice");
      expect(after!.version).toBe(2);
      // The withCas patches (failedLoginAttempts) never landed.
      expect(after!.account.failedLoginAttempts).toBe(0);
    });

    it("honors a custom maxAttempts — succeeds when budget covers the contention", async () => {
      // Same contention pattern as above, but with maxAttempts=5 we give the
      // writer enough budget that on the 5th attempt the competing-write
      // counter has stopped firing (we only sneak a write on the first 4).
      const store = new UserStoreMemory();
      await store.create(makeUser("alice"));
      let calls = 0;
      await store.withCas(
        "id-alice",
        () => {
          calls++;
          if (calls <= 4) {
            // Compete for the first 4 attempts; let the 5th win.
            void store.update("id-alice", { set: { account: { lastLogin: calls } } as any });
          }
          return { set: { account: { failedLoginAttempts: calls } } as any };
        },
        { maxAttempts: 5 },
      );
      expect(calls).toBe(5);
      const after = await store.findByHandle("alice");
      // 4 competing writes bumped the version, then attempt 5 succeeded
      // (its own +1). Total bumps = 5.
      expect(after!.version).toBe(5);
      expect(after!.account.failedLoginAttempts).toBe(5);
    });
  });
});
