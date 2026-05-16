import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vite-plus/test";
import { AtscriptDbTable } from "@atscript/db";
import { SqliteAdapter, BetterSqlite3Driver } from "@atscript/db-sqlite";
import { UserAuthError, UserService } from "../../index";
import type { UserCredentials } from "../../index";

import { type AuthUserTable, UsersStoreAtscriptDb } from "../index";
import { prepareFixtures } from "./test-utils";

let AoothUserCredentials: any;

function makeUserData(overrides?: Partial<UserCredentials>): UserCredentials {
  return {
    id: "test-id-1",
    username: "alice",
    password: {
      hash: "$scrypt$N=1024,r=1,p=1,l=32$dGVzdHNhbHQ$dGVzdGhhc2g",
      history: [],
      lastChanged: 1000,
      isInitial: true,
    },
    account: {
      active: false,
      locked: false,
      lockReason: "",
      lockEnds: 0,
      failedLoginAttempts: 0,
      lastLogin: 0,
    },
    mfa: {
      methods: [],
      defaultMethod: "",
      autoSend: false,
    },
    ...overrides,
  };
}

describe("UsersStoreAtscriptDb", () => {
  let driver: BetterSqlite3Driver;
  let adapter: SqliteAdapter;
  let table: AtscriptDbTable;
  let store: UsersStoreAtscriptDb;

  beforeAll(async () => {
    await prepareFixtures();
    const fixtures = await import("./fixtures/test-user.as");
    AoothUserCredentials = fixtures.AoothUserCredentials;
  });

  beforeEach(async () => {
    driver = new BetterSqlite3Driver(":memory:");
    adapter = new SqliteAdapter(driver);
    table = new AtscriptDbTable(AoothUserCredentials, adapter);
    await table.ensureTable();
    await table.syncIndexes();
    // `AtscriptDbTable` returns `Record<string, unknown>` from its
    // structural reads, so the typed `AuthUserTable<UserCredentialsRow>`
    // surface needs a cast at the wiring seam — same pattern e2e-demo's
    // `wf-store.ts` uses.
    store = new UsersStoreAtscriptDb({ table: table as unknown as AuthUserTable });
  });

  afterEach(() => {
    driver.close();
  });

  describe("exists", () => {
    it("returns false for unknown user", async () => {
      expect(await store.exists("alice")).toBe(false);
    });

    it("returns true after create", async () => {
      await store.create(makeUserData());
      expect(await store.exists("alice")).toBe(true);
    });
  });

  describe("create", () => {
    it("stores a record", async () => {
      await store.create(makeUserData());
      const data = await store.findByUsername("alice");
      expect(data).not.toBeNull();
      expect(data!.username).toBe("alice");
      expect(data!.password.hash).toContain("$scrypt$");
      expect(data!.account.active).toBe(false);
    });

    it("throws ALREADY_EXISTS on duplicate username", async () => {
      await store.create(makeUserData());
      try {
        await store.create(makeUserData());
        expect.unreachable();
      } catch (e) {
        expect(e).toBeInstanceOf(UserAuthError);
        expect((e as UserAuthError).type).toBe("ALREADY_EXISTS");
      }
    });
  });

  describe("findByUsername", () => {
    it("returns full record", async () => {
      await store.create(makeUserData());
      const data = await store.findByUsername("alice");
      expect(data).not.toBeNull();
      expect(data!.id).toBe("test-id-1");
      expect(data!.username).toBe("alice");
      expect(data!.password.history).toEqual([]);
      expect(data!.password.lastChanged).toBe(1000);
      expect(data!.password.isInitial).toBe(true);
      expect(data!.account.failedLoginAttempts).toBe(0);
      expect(data!.mfa.methods).toEqual([]);
      expect(data!.mfa.defaultMethod).toBe("");
    });

    it("returns null for unknown user", async () => {
      expect(await store.findByUsername("nobody")).toBeNull();
    });
  });

  describe("update", () => {
    beforeEach(async () => {
      await store.create(makeUserData());
    });

    it("applies set operation", async () => {
      await store.update("alice", {
        set: { account: { active: true } } as any,
      });
      const data = await store.findByUsername("alice");
      expect(data!.account.active).toBe(true);
    });

    it("applies multiple set operations", async () => {
      await store.update("alice", {
        set: {
          account: { locked: true, lockReason: "too many attempts", lockEnds: 9999 },
        } as any,
      });
      const data = await store.findByUsername("alice");
      expect(data!.account.locked).toBe(true);
      expect(data!.account.lockReason).toBe("too many attempts");
      expect(data!.account.lockEnds).toBe(9999);
    });

    it("applies inc operation", async () => {
      await store.update("alice", {
        inc: { "account.failedLoginAttempts": 1 },
      });
      const data1 = await store.findByUsername("alice");
      expect(data1!.account.failedLoginAttempts).toBe(1);

      await store.update("alice", {
        inc: { "account.failedLoginAttempts": 1 },
      });
      const data2 = await store.findByUsername("alice");
      expect(data2!.account.failedLoginAttempts).toBe(2);
    });

    it("applies mixed set and inc operations", async () => {
      await store.update("alice", {
        set: { account: { locked: true } } as any,
        inc: { "account.failedLoginAttempts": 3 },
      });
      const data = await store.findByUsername("alice");
      expect(data!.account.locked).toBe(true);
      expect(data!.account.failedLoginAttempts).toBe(3);
    });

    it("applies set on password history (JSON field)", async () => {
      const newHistory = ["$scrypt$N=1024,r=1,p=1,l=32$oldsalt$oldhash"];
      await store.update("alice", {
        set: { password: { history: newHistory } } as any,
      });
      const data = await store.findByUsername("alice");
      expect(data!.password.history).toEqual(newHistory);
    });

    it("no-ops for empty update", async () => {
      const result = await store.update("alice", {});
      expect(result).toBe(true);
      const data = await store.findByUsername("alice");
      expect(data!.username).toBe("alice");
    });

    it("returns false for unknown user", async () => {
      const result = await store.update("nobody", {
        set: { account: { active: true } } as any,
      });
      expect(result).toBe(false);
    });
  });

  describe("UserService integration", () => {
    it("works as a drop-in UserStore for UserService", async () => {
      const svc = new UserService(store, {
        password: { scryptN: 1024, scryptR: 1, scryptP: 1, keyLength: 32 },
      });

      // Create user
      const user = await svc.createUser("bob", "Secret1!");
      expect(user.username).toBe("bob");
      expect(user.password.hash).toContain("$scrypt$");
      expect(user.password.isInitial).toBe(false);

      // Read back
      const readUser = await svc.getUser("bob");
      expect(readUser.username).toBe("bob");
      expect(readUser.password.hash).toBe(user.password.hash);

      // Activate account
      await svc.activateAccount("bob");
      const activated = await svc.getUser("bob");
      expect(activated.account.active).toBe(true);

      // Login
      const result = await svc.login("bob", "Secret1!");
      expect(result.user.username).toBe("bob");
      expect(result.user.account.lastLogin).toBeGreaterThan(0);

      // Duplicate throws
      try {
        await svc.createUser("bob");
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("ALREADY_EXISTS");
      }
    });

    it("validates password through the store", async () => {
      const svc = new UserService(store, {
        password: { scryptN: 1024, scryptR: 1, scryptP: 1, keyLength: 32 },
      });
      await svc.createUser("carol", "Secret1!");

      expect(await svc.verifyPassword("carol", "Secret1!")).toBe(true);
      expect(await svc.verifyPassword("carol", "wrong")).toBe(false);
    });
  });
});
