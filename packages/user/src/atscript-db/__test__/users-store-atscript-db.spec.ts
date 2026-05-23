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

  describe("OCC / withCas", () => {
    it("expectedVersion threads to $cas: SQL-layer rejects stale writes", async () => {
      // Proves the adapter's `if (expectedVersion !== undefined) patch.$cas`
      // wiring actually reaches the atscript-db UPDATE generator and the
      // version predicate fires in SQL. Without this, withCas would silently
      // degrade to last-write-wins on this backend.
      await store.create(makeUserData());
      const initial = await store.findByUsername("alice");
      expect(initial!.version).toBe(0);

      // Winner: CAS with expectedVersion=0 applies, version auto-bumps to 1.
      expect(
        await store.update("alice", {
          set: { account: { active: true } } as any,
          expectedVersion: 0,
        }),
      ).toBe(true);
      const afterWinner = await store.findByUsername("alice");
      expect(afterWinner!.version).toBe(1);
      expect(afterWinner!.account.active).toBe(true);

      // Stale writer: expectedVersion=0 ≠ stored 1 → rejected, no mutation.
      expect(
        await store.update("alice", {
          set: { account: { lastLogin: 999 } } as any,
          expectedVersion: 0,
        }),
      ).toBe(false);
      const afterStale = await store.findByUsername("alice");
      expect(afterStale!.account.lastLogin).toBe(0);
      expect(afterStale!.version).toBe(1);

      // Same patch without expectedVersion goes through (no CAS predicate).
      expect(
        await store.update("alice", {
          set: { account: { lastLogin: 999 } } as any,
        }),
      ).toBe(true);
      const afterUnchecked = await store.findByUsername("alice");
      expect(afterUnchecked!.account.lastLogin).toBe(999);
      expect(afterUnchecked!.version).toBe(2);
    });

    it("withCas: applies the patch and auto-bumps version when uncontended", async () => {
      await store.create(makeUserData());
      let calls = 0;
      await store.withCas("alice", (user) => {
        calls++;
        expect(user.version).toBe(0);
        return { set: { account: { active: true } } as any };
      });
      expect(calls).toBe(1);
      const after = await store.findByUsername("alice");
      expect(after!.account.active).toBe(true);
      expect(after!.version).toBe(1);
    });

    it("withCas: mutator returning null exits without writing or bumping version", async () => {
      await store.create(makeUserData());
      await store.withCas("alice", () => null);
      const after = await store.findByUsername("alice");
      expect(after!.version).toBe(0);
    });

    it("withCas: throws NOT_FOUND when the user does not exist", async () => {
      try {
        await store.withCas("ghost", () => ({ set: { account: { active: true } } as any }));
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("NOT_FOUND");
      }
    });

    it("withCas: throws CAS_EXHAUSTED when CAS checks repeatedly miss", async () => {
      // Forcing a real race on better-sqlite3 isn't workable here: it
      // serializes all writes through a single connection and rejects nested
      // transactions, so the in-memory "void competing update" trick blows up
      // with "cannot start a transaction within a transaction". Instead we
      // simulate CAS misses by overriding `update` to return false whenever an
      // expectedVersion is supplied. This exercises the EXACT same loop +
      // throw machinery (the abstract loop in UsersStoreAtscriptDb.withCas)
      // running against real SQLite reads — only the write side is stubbed.
      class FailingStore extends UsersStoreAtscriptDb {
        public missesInjected = 0;
        override async update(username: string, update: any): Promise<boolean> {
          if (update.expectedVersion !== undefined) {
            this.missesInjected++;
            return false;
          }
          return super.update(username, update);
        }
      }
      const failStore = new FailingStore({ table: table as unknown as AuthUserTable });
      await failStore.create(makeUserData());

      let calls = 0;
      try {
        await failStore.withCas("alice", () => {
          calls++;
          return { set: { account: { active: true } } as any };
        });
        expect.unreachable();
      } catch (e) {
        expect((e as UserAuthError).type).toBe("CAS_EXHAUSTED");
      }
      expect(calls).toBe(2); // 1 initial + 1 retry, both rejected
      expect(failStore.missesInjected).toBe(2);
    });

    it("withCas: addMfaMethod through UserService composes sequential writes (end-to-end on real SQLite)", async () => {
      // Sequential rather than Promise.all because better-sqlite3 serializes
      // a single connection and rejects nested transactions ("cannot start a
      // transaction within a transaction"). True concurrent writes against
      // the same SQLite connection aren't a useful test target — in
      // production, concurrent HTTP requests serialize at the SQL layer
      // anyway. What we DO verify here: the addMfaMethod flow's
      // service-layer mutator + store-layer withCas + atscript-db $cas all
      // compose correctly against real SQL — both methods land, the
      // mfa.methods array patch survives the round-trip through
      // @db.patch.strategy 'merge', and version auto-bumps once per call.
      const svc = new UserService(store, {
        password: { scryptN: 1024, scryptR: 1, scryptP: 1, keyLength: 32 },
      });
      await svc.createUser("dave", "Secret1!");
      await svc.activateAccount("dave");

      await svc.addMfaMethod("dave", { name: "email", confirmed: false, value: "d@x.test" });
      await svc.addMfaMethod("dave", { name: "totp", confirmed: false, value: "SECRET" });

      const persisted = await store.findByUsername("dave");
      const names = persisted!.mfa.methods.map((m) => m.name);
      expect(names).toContain("email");
      expect(names).toContain("totp");
      // Version bumped once per addMfaMethod call (plus 1 from activateAccount).
      expect(persisted!.version).toBe(3);
    });
  });
});
