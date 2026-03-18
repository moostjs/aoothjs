import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vite-plus/test";
import { AtscriptDbTable } from "@atscript/db";
import { SqliteAdapter, BetterSqlite3Driver } from "@atscript/db-sqlite";
import { Aooth } from "@aoothjs/user";
import type { TAoothUserCredentials } from "@aoothjs/user";

import { UsersStoreAs } from "../users-store-as";
import { prepareFixtures } from "./test-utils";

let AoothUserCredentials: any;

function makeUserData(overrides?: Partial<TAoothUserCredentials>): TAoothUserCredentials {
  return {
    id: "test-id-1",
    username: "alice",
    password: {
      hash: "abc123",
      salt: "salt1",
      algorithm: "sha3-224",
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
      email: { address: "", confirmed: false },
      sms: { confirmed: false, number: "" },
      totp: { secretKey: "" },
      default: "",
      autoSend: false,
    },
    ...overrides,
  };
}

describe("UsersStoreAs", () => {
  let driver: BetterSqlite3Driver;
  let adapter: SqliteAdapter;
  let table: AtscriptDbTable;
  let store: UsersStoreAs;

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
    store = new UsersStoreAs(table);
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
      const data = await store.read("alice");
      expect(data.username).toBe("alice");
      expect(data.password.hash).toBe("abc123");
      expect(data.account.active).toBe(false);
    });

    it("throws on duplicate username", async () => {
      await store.create(makeUserData());
      await expect(store.create(makeUserData())).rejects.toThrow(
        'User with id "alice" already exists.',
      );
    });
  });

  describe("read", () => {
    it("returns full record", async () => {
      await store.create(makeUserData());
      const data = await store.read("alice");
      expect(data.id).toBe("test-id-1");
      expect(data.username).toBe("alice");
      expect(data.password.salt).toBe("salt1");
      expect(data.password.algorithm).toBe("sha3-224");
      expect(data.password.history).toEqual([]);
      expect(data.password.lastChanged).toBe(1000);
      expect(data.password.isInitial).toBe(true);
      expect(data.account.failedLoginAttempts).toBe(0);
      expect(data.mfa.email.address).toBe("");
      expect(data.mfa.default).toBe("");
    });

    it("throws Not found for unknown user", async () => {
      await expect(store.read("nobody")).rejects.toThrow("Not found");
    });
  });

  describe("change", () => {
    beforeEach(async () => {
      await store.create(makeUserData());
    });

    it("applies set operation", async () => {
      await store.change("alice", {
        "account.active": { oldValue: false, value: true, op: "set" },
      });
      const data = await store.read("alice");
      expect(data.account.active).toBe(true);
    });

    it("applies multiple set operations", async () => {
      await store.change("alice", {
        "account.locked": { oldValue: false, value: true, op: "set" },
        "account.lockReason": { oldValue: "", value: "too many attempts", op: "set" },
        "account.lockEnds": { oldValue: 0, value: 9999, op: "set" },
      });
      const data = await store.read("alice");
      expect(data.account.locked).toBe(true);
      expect(data.account.lockReason).toBe("too many attempts");
      expect(data.account.lockEnds).toBe(9999);
    });

    it("applies deeply nested set", async () => {
      await store.change("alice", {
        "mfa.email.address": { oldValue: "", value: "alice@test.com", op: "set" },
        "mfa.email.confirmed": { oldValue: false, value: true, op: "set" },
      });
      const data = await store.read("alice");
      expect(data.mfa.email.address).toBe("alice@test.com");
      expect(data.mfa.email.confirmed).toBe(true);
    });

    it("applies inc operation", async () => {
      await store.change("alice", {
        "account.failedLoginAttempts": { oldValue: 0, value: 1, op: "inc" },
      });
      const data = await store.read("alice");
      expect(data.account.failedLoginAttempts).toBe(1);

      // increment again
      await store.change("alice", {
        "account.failedLoginAttempts": { oldValue: 1, value: 1, op: "inc" },
      });
      const data2 = await store.read("alice");
      expect(data2.account.failedLoginAttempts).toBe(2);
    });

    it("applies mixed set and inc operations", async () => {
      await store.change("alice", {
        "account.locked": { oldValue: false, value: true, op: "set" },
        "account.failedLoginAttempts": { oldValue: 0, value: 1, op: "inc" },
      });
      const data = await store.read("alice");
      expect(data.account.locked).toBe(true);
      expect(data.account.failedLoginAttempts).toBe(1);
    });

    it("applies set on password history (JSON field)", async () => {
      const newHistory = [{ algorithm: "sha3-224", hash: "oldhash" }];
      await store.change("alice", {
        "password.history": { oldValue: [], value: newHistory, op: "set" },
      });
      const data = await store.read("alice");
      expect(data.password.history).toEqual(newHistory);
    });

    it("no-ops for empty changes", async () => {
      await store.change("alice", {});
      const data = await store.read("alice");
      expect(data.username).toBe("alice");
    });

    it("throws Not found for unknown user", async () => {
      await expect(
        store.change("nobody", {
          "account.active": { oldValue: false, value: true, op: "set" },
        }),
      ).rejects.toThrow("Not found");
    });
  });

  describe("Aooth integration", () => {
    it("works as a drop-in replacement for UsersStoreMemory", async () => {
      const aooth = new Aooth(store);

      // Create user
      const user = await aooth.createUser("bob");
      const data = user.getData();
      expect(data.username).toBe("bob");
      expect(data.password.hash).toBeTruthy();
      expect(data.password.isInitial).toBe(true);
      expect(data.account.active).toBe(false);

      // Read back
      const readData = await aooth.getUserData("bob");
      expect(readData.username).toBe("bob");
      expect(readData.password.hash).toBe(data.password.hash);

      // Activate account
      const u = aooth.user("bob");
      await u.read();
      u.activateAccount();
      await u.save();
      const activated = await aooth.getUserData("bob");
      expect(activated.account.active).toBe(true);

      // Duplicate throws
      await expect(aooth.createUser("bob")).rejects.toThrow('User with id "bob" already exists');
    });

    it("validates password through the store", async () => {
      const aooth = new Aooth(store);
      await aooth.createUser("carol");

      // Set a known password
      const u = aooth.user("carol");
      await u.read();
      const cfg = aooth.getConfig().password;
      u.changePassword(cfg, "Secret1!", "Secret1!");
      await u.save();

      // Validate
      expect(await aooth.validatePassword("carol", "Secret1!")).toBe(true);
      expect(await aooth.validatePassword("carol", "wrong")).toBe(false);
    });
  });
});
