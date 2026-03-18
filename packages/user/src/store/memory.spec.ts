import { describe, expect, it } from "vite-plus/test";
import { UserAuthError } from "../errors";
import type { UserCredentials } from "../types";
import { UserStoreMemory } from "./memory";

function makeUser(username: string, overrides?: Partial<UserCredentials>): UserCredentials {
  return {
    id: "",
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

  describe("findByUsername", () => {
    it("should return null for unknown user", async () => {
      const store = new UserStoreMemory();
      expect(await store.findByUsername("unknown")).toBeNull();
    });

    it("should return cloned data", async () => {
      const store = new UserStoreMemory();
      await store.create(makeUser("alice"));
      const a = await store.findByUsername("alice");
      const b = await store.findByUsername("alice");
      expect(a).toEqual(b);
      expect(a).not.toBe(b);
    });
  });

  describe("create", () => {
    it("should store a user", async () => {
      const store = new UserStoreMemory();
      await store.create(makeUser("alice"));
      const user = await store.findByUsername("alice");
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
      await store.update("alice", { set: { account: { active: true } } as any });
      const user = await store.findByUsername("alice");
      expect(user!.account.active).toBe(true);
      expect(user!.account.locked).toBe(false); // unchanged
    });

    it("should atomically increment with inc", async () => {
      const store = new UserStoreMemory();
      await store.create(makeUser("alice"));
      await store.update("alice", { inc: { "account.failedLoginAttempts": 1 } });
      await store.update("alice", { inc: { "account.failedLoginAttempts": 1 } });
      const user = await store.findByUsername("alice");
      expect(user!.account.failedLoginAttempts).toBe(2);
    });

    it("should handle combined set and inc", async () => {
      const store = new UserStoreMemory();
      await store.create(makeUser("alice"));
      await store.update("alice", {
        set: { account: { locked: true } } as any,
        inc: { "account.failedLoginAttempts": 3 },
      });
      const user = await store.findByUsername("alice");
      expect(user!.account.locked).toBe(true);
      expect(user!.account.failedLoginAttempts).toBe(3);
    });

    it("should return true for successful update", async () => {
      const store = new UserStoreMemory();
      await store.create(makeUser("alice"));
      expect(await store.update("alice", { set: { account: { active: true } } as any })).toBe(true);
    });
  });

  describe("seed constructor", () => {
    it("should initialize with seeded data", async () => {
      const store = new UserStoreMemory({ alice: makeUser("alice") });
      expect(await store.exists("alice")).toBe(true);
    });
  });
});
