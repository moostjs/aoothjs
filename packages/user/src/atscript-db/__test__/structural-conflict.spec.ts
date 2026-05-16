import { describe, it, expect } from "vite-plus/test";

import { UserAuthError } from "../../index";
import type { UserCredentials } from "../../index";
import { type AuthUserTable, UsersStoreAtscriptDb } from "../index";
import { MockTable } from "./mock-table";

/**
 * Smoke spec for the `@aoothjs/user/atscript-db` subpath that does NOT depend
 * on `@atscript/db` or SQLite. Two things this proves that the SQLite-backed
 * spec cannot prove on its own:
 *
 *   1. The subpath import (`@aoothjs/user/atscript-db`) wires up a working
 *      constructor — i.e. the package.json `exports` map is honored at the
 *      source layer the same way it is at the published layer.
 *   2. Conflict detection is structural (`code === "CONFLICT"`) not nominal
 *      (`instanceof DbError`). If anyone reverts that, this test fails — the
 *      thrown sentinel here is a plain `Error` with a `code` property, which
 *      a nominal check would miss.
 */

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

describe("UsersStoreAtscriptDb (structural surface, no @atscript/db)", () => {
  it("constructs from a structural AuthUserTable and supports the basic CRUD path", async () => {
    const table = new MockTable();
    const store = new UsersStoreAtscriptDb({ table: table as AuthUserTable });

    expect(await store.exists("alice")).toBe(false);
    await store.create(makeUserData());
    expect(await store.exists("alice")).toBe(true);

    const data = await store.findByUsername("alice");
    expect(data).not.toBeNull();
    expect(data!.username).toBe("alice");
  });

  it("treats a non-DbError throw with `code === 'CONFLICT'` as ALREADY_EXISTS", async () => {
    // Custom table that throws a plain Error carrying the structural code —
    // proves the adapter does NOT rely on `instanceof DbError`.
    const table: AuthUserTable = {
      async count() {
        return 0;
      },
      async findOne() {
        return null;
      },
      async insertOne() {
        throw Object.assign(new Error("duplicate"), { code: "CONFLICT" });
      },
      async updateOne() {
        return { matchedCount: 0, modifiedCount: 0 };
      },
      async deleteMany() {
        return { deletedCount: 0 };
      },
    };
    const store = new UsersStoreAtscriptDb({ table });

    try {
      await store.create(makeUserData());
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(UserAuthError);
      expect((e as UserAuthError).type).toBe("ALREADY_EXISTS");
    }
  });

  it("re-throws unrelated errors verbatim (no broad catch)", async () => {
    const sentinel = new Error("disk full");
    const table: AuthUserTable = {
      async count() {
        return 0;
      },
      async findOne() {
        return null;
      },
      async insertOne() {
        throw sentinel;
      },
      async updateOne() {
        return { matchedCount: 0, modifiedCount: 0 };
      },
      async deleteMany() {
        return { deletedCount: 0 };
      },
    };
    const store = new UsersStoreAtscriptDb({ table });

    await expect(store.create(makeUserData())).rejects.toBe(sentinel);
  });

  it("short-circuits an empty update without hitting the table", async () => {
    const table = new MockTable();
    const store = new UsersStoreAtscriptDb({ table: table as AuthUserTable });
    await store.create(makeUserData());

    table.ops.length = 0;
    const result = await store.update("alice", {});

    expect(result).toBe(true);
    expect(table.opsOf("updateOne")).toHaveLength(0);
  });
});
