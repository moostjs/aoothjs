import { AtscriptDbTable } from "@atscript/db";
import { BetterSqlite3Driver, SqliteAdapter } from "@atscript/db-sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vite-plus/test";

import { FederatedIdentityStoreAtscriptDb, type FederatedIdentityTable } from "../index";
// The SHIPPED model itself (not a fixture copy) — so a typo / divergence in the
// `provider_subject_idx` index-name declaration that silently degrades the
// compound-unique index into two single-column indexes makes THIS spec fail.
import { AoothFederatedIdentity } from "../federated-identity.as";

/**
 * The mock-table spec proves the adapter's `CONFLICT → ALREADY_EXISTS` mapping
 * and op routing, but the mock fakes `(provider, subject)` uniqueness in JS —
 * independent of the `.as` schema. This spec boots a real `@atscript/db` +
 * SQLite table from the shipped model so the load-bearing anti-takeover
 * guarantee — the SAME index name on `provider` and `subject` collapsing into
 * ONE compound-unique index (RFC IDP.md §1 note #4, §4) — is actually
 * enforced by the engine.
 */
describe("FederatedIdentityStoreAtscriptDb — integration against real SQLite", () => {
  let driver: BetterSqlite3Driver;
  let adapter: SqliteAdapter;
  let table: AtscriptDbTable;
  let store: FederatedIdentityStoreAtscriptDb;
  let now = 1_000;

  beforeEach(async () => {
    now = 1_000;
    driver = new BetterSqlite3Driver(":memory:");
    adapter = new SqliteAdapter(driver);
    table = new AtscriptDbTable(AoothFederatedIdentity, adapter);
    await table.ensureTable();
    await table.syncIndexes();
    store = new FederatedIdentityStoreAtscriptDb({
      table: table as unknown as FederatedIdentityTable,
      clock: () => now,
    });
  });

  afterEach(() => {
    driver.close();
  });

  it("link + find round-trips through SQLite (id minted, linkedAt from clock, snapshot persisted)", async () => {
    now = 7_000;
    const linked = await store.link({
      provider: "google",
      subject: "sub-1",
      userId: "u1",
      email: "a@example.com",
      emailVerified: true,
      displayName: "Alice",
    });
    expect(linked.id).toBeTruthy();
    expect(linked.linkedAt).toBe(7_000);

    const found = await store.find("google", "sub-1");
    expect(found).toMatchObject({
      id: linked.id,
      userId: "u1",
      email: "a@example.com",
      emailVerified: true,
      displayName: "Alice",
    });
  });

  // THE load-bearing assertion: a real UNIQUE index must reject a second link of
  // the same provider account — even to a different user. This is what an
  // index-name typo (→ two single-column indexes) would silently break.
  it("compound-unique fires: re-linking the same (provider, subject) to a different user → ALREADY_EXISTS", async () => {
    await store.link({ provider: "google", subject: "sub-1", userId: "u1" });
    await expect(
      store.link({ provider: "google", subject: "sub-1", userId: "u2" }),
    ).rejects.toMatchObject({ name: "UserAuthError", type: "ALREADY_EXISTS" });
    expect((await store.find("google", "sub-1"))?.userId).toBe("u1");
  });

  // Proves the index is COMPOUND on (provider, subject), not a single-column
  // unique on either field alone — both of these would FAIL if the two
  // `@db.index.unique` names had diverged into separate single-field indexes.
  it("index is compound: same subject under a different provider, and same provider under a different subject, both succeed", async () => {
    await store.link({ provider: "google", subject: "shared-sub", userId: "u1" });
    await expect(
      store.link({ provider: "github", subject: "shared-sub", userId: "u1" }),
    ).resolves.toMatchObject({ provider: "github" });
    await expect(
      store.link({ provider: "google", subject: "other-sub", userId: "u1" }),
    ).resolves.toMatchObject({ subject: "other-sub" });
  });

  it("listForUser + deleteAllForUser scan the plain userId column", async () => {
    await store.link({ provider: "google", subject: "g", userId: "u1" });
    now += 500;
    await store.link({ provider: "github", subject: "h", userId: "u1" });
    await store.link({ provider: "google", subject: "k", userId: "u2" });

    const list = await store.listForUser("u1");
    expect(list.map((r) => r.provider)).toEqual(["google", "github"]);

    expect(await store.deleteAllForUser("u1")).toBe(2);
    expect(await store.listForUser("u1")).toEqual([]);
    expect((await store.find("google", "k"))?.userId).toBe("u2");
  });

  it("touchLogin round-trips lastLoginAt + merged profile through replaceOne", async () => {
    await store.link({ provider: "google", subject: "g", userId: "u1", displayName: "Old" });
    now = 9_000;
    await store.touchLogin("google", "g", { displayName: "New", avatarUrl: "http://x/a.png" });

    const row = await store.find("google", "g");
    expect(row?.lastLoginAt).toBe(9_000);
    expect(row?.displayName).toBe("New");
    expect(row?.avatarUrl).toBe("http://x/a.png");
  });
});
