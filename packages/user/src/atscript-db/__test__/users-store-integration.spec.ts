import { AtscriptDbTable } from "@atscript/db";
import { BetterSqlite3Driver, SqliteAdapter } from "@atscript/db-sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vite-plus/test";

import { UserService } from "../../user-service";
import { UsersStoreAtscriptDb } from "../index";
// The SHIPPED model (not a fixture copy): its optional `account.*` leaves are
// nullable columns, which SQLite reads back as `null` when unset.
import { AoothUserCredentials } from "../user-credentials.as";

/**
 * SQL engines read an unset column back as `null` (Mongo omits the key). The
 * store drops `null` from aooth's optional paths, so a pre-0.2 pending invite
 * (no `account.inviteNonce`) reads as "no marker", not as a different one.
 */
describe("UsersStoreAtscriptDb — integration against real SQLite", () => {
  let driver: BetterSqlite3Driver;
  let store: UsersStoreAtscriptDb;
  let users: UserService;

  beforeEach(async () => {
    driver = new BetterSqlite3Driver(":memory:");
    const table = new AtscriptDbTable(AoothUserCredentials, new SqliteAdapter(driver));
    await table.ensureTable();
    await table.syncIndexes();
    store = new UsersStoreAtscriptDb({ table });
    users = new UserService(store);
  });

  afterEach(() => {
    driver.close();
  });

  /** A pending invite as written before 0.2 — no `inviteNonce` on the row. */
  async function legacyInvite(username: string): Promise<string> {
    const created = await users.createUser(username);
    await store.update(created.id, { set: { account: { pendingInvitation: true } } });
    return created.id;
  }

  it("reads unset optional paths back as absent, not null", async () => {
    const id = await legacyInvite("legacy@x.test");
    for (const user of [
      await store.findById(id),
      await store.findByHandle("legacy@x.test"),
      await store.findByIdentifier(id),
    ]) {
      expect(user?.account.pendingInvitation).toBe(true);
      for (const field of ["invitedBy", "inviteNonce", "verifiedEmail"]) {
        expect(user?.account).not.toHaveProperty(field);
      }
      expect(user).not.toHaveProperty("trustedDevices");
      expect(user).not.toHaveProperty("seenDevices");
    }
  });

  it("a pre-0.2 pending invite (NULL inviteNonce) accepts from a run without a marker", async () => {
    const id = await legacyInvite("legacy@x.test");
    expect(await users.acceptInvitation(id, undefined)).toBe(true);
    expect((await store.findById(id))?.account.pendingInvitation).toBe(false);
  });

  it("a re-invite (a real marker) still refuses an older or unmarked link", async () => {
    const id = await legacyInvite("legacy@x.test");
    await store.update(id, { set: { account: { inviteNonce: "newer" } } });
    expect(await users.acceptInvitation(id, undefined)).toBe(false);
    expect(await users.acceptInvitation(id, "older")).toBe(false);
    expect(await users.acceptInvitation(id, "newer")).toBe(true);
  });
});
