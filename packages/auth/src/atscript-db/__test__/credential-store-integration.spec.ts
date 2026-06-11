import { AtscriptDbTable } from "@atscript/db";
import { BetterSqlite3Driver, SqliteAdapter } from "@atscript/db-sqlite";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import type { CredentialState } from "../../credential/types";
import { type AuthCredentialTable, CredentialStoreAtscriptDb } from "../index";
import { prepareFixtures } from "./test-utils";

// Late-binds the compiled fixture class — populated in beforeAll once
// `prepareFixtures()` has written `auth-credential.as.js` to disk.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let AoothAuthCredential: any;

// Typed credential payload — the flat root fields a consumer adds when they
// `extends AoothAuthCredential`. Mirrors the fixture model's payload columns:
// a scalar (`scope`) and a structured `@db.json` column (`grants`). Optional,
// since a normal token carries none. Replaces the dropped free-form `claims`.
interface DemoClaims {
  scope?: string;
  grants?: { roles?: string[]; tenantId?: string };
}

function makeState(
  userId: string,
  overrides?: Partial<CredentialState & DemoClaims>,
): CredentialState & DemoClaims {
  return {
    userId,
    issuedAt: Date.now(),
    expiresAt: Date.now() + 60_000,
    kind: "refresh",
    ...overrides,
  };
}

// Intent: the shipped `AoothAuthCredential` .as model + the runtime
// `CredentialStoreAtscriptDb` adapter must work together against a real
// `@atscript/db` table. The mock-table spec covers adapter logic; this
// spec proves the .as schema compiles, the JSON columns round-trip
// through SQLite, and the wiring seam (`table as unknown as
// AuthCredentialTable<…>`) holds up — none of which the mock can
// validate.
describe("CredentialStoreAtscriptDb — integration against real SQLite", () => {
  let driver: BetterSqlite3Driver;
  let adapter: SqliteAdapter;
  let table: AtscriptDbTable;
  let store: CredentialStoreAtscriptDb<DemoClaims>;

  beforeAll(async () => {
    await prepareFixtures();
    const fixtures = await import("./fixtures/auth-credential.as");
    AoothAuthCredential = fixtures.AoothAuthCredential;
  });

  beforeEach(async () => {
    driver = new BetterSqlite3Driver(":memory:");
    adapter = new SqliteAdapter(driver);
    table = new AtscriptDbTable(AoothAuthCredential, adapter);
    await table.ensureTable();
    await table.syncIndexes();
    // Same wiring-seam cast pattern as e2e-demo's `wf-store.ts` and
    // user's spec: AtscriptDbTable returns Record<string, unknown> from
    // structural reads; the adapter's typed surface needs an explicit
    // cast at the boundary.
    // `metadataField` maps the envelope's `metadata` through the fixture's
    // consumer-declared `@db.json metadata` column (the shipped model has no
    // metadata column anymore). Real apps resolve the name at boot via
    // `getAoothCredentialMetadataSpec` (`@aooth/arbac-moost/atscript`).
    store = new CredentialStoreAtscriptDb<DemoClaims>({
      table: table as unknown as AuthCredentialTable<DemoClaims>,
      metadataField: "metadata",
    });
  });

  afterEach(() => {
    driver.close();
  });

  it("persist + retrieve round-trips userId/kind/expiresAt through SQLite", async () => {
    const token = await store.persist(makeState("alice"));
    expect(token).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
    const got = await store.retrieve(token);
    expect(got?.userId).toBe("alice");
    expect(got?.kind).toBe("refresh");
  });

  // The load-bearing assertion. A consumer's typed payload fields persist as
  // REAL columns — a scalar (`scope`) and a `@db.json` structured column
  // (`grants`) — alongside the `@db.json` `metadata`. If `@db.json` is ever
  // dropped from a structured column, this fails at table.ensureTable() OR
  // returns junk on retrieve.
  it("typed payload columns + metadata round-trip through SQLite", async () => {
    const metadata = {
      ip: "10.0.0.1",
      userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
      fingerprint: "fp-abc-123",
      label: "MacBook Pro",
    };
    const token = await store.persist(
      makeState("alice", { scope: "read:tasks write:tasks", metadata }),
    );
    const got = await store.retrieve(token);
    expect(got?.scope).toBe("read:tasks write:tasks");
    expect(got?.metadata).toEqual(metadata);
  });

  // STRUCTURED typed payload round-trip — a payload field can be a structured
  // object (e.g. the `grants` column), not just a scalar, and the `@db.json`
  // column must load it back IDENTICALLY (not flatten/null it). This is the
  // typed-field replacement for the old free-form nested-claims test.
  it("@db.json round-trips a STRUCTURED typed payload column through SQLite", async () => {
    const grants = { roles: ["doc-reader"], tenantId: "t1" };
    const token = await store.persist(makeState("alice", { grants }));
    const got = await store.retrieve(token);
    expect(got?.grants).toEqual(grants);
    expect(got?.grants?.roles).toEqual(["doc-reader"]);
    expect(got?.grants?.tenantId).toBe("t1");
  });

  it("listForUser returns the persisted rows with tokens attached", async () => {
    const t1 = await store.persist(makeState("alice", { issuedAt: 1 }));
    const t2 = await store.persist(makeState("alice", { issuedAt: 2 }));
    await store.persist(makeState("bob"));
    const list = await store.listForUser("alice");
    expect(list).toHaveLength(2);
    expect(list.map((e) => e.token).toSorted()).toEqual([t1, t2].toSorted());
    for (const e of list) expect(e.userId).toBe("alice");
  });

  it("revoke deletes the row by its PK and retrieve returns null after", async () => {
    const token = await store.persist(makeState("alice"));
    await store.revoke(token);
    expect(await store.retrieve(token)).toBeNull();
  });

  it("revokeAllForUser deletes every row for the user and leaves others intact", async () => {
    await store.persist(makeState("alice"));
    await store.persist(makeState("alice"));
    const bobToken = await store.persist(makeState("bob"));
    const count = await store.revokeAllForUser("alice");
    expect(count).toBe(2);
    expect(await store.listForUser("alice")).toEqual([]);
    expect((await store.listForUser("bob")).map((e) => e.token)).toEqual([bobToken]);
  });

  it("retrieve evicts a row whose expiresAt is past (lazy GC contract)", async () => {
    // Mirrors the mock-table contract test — exercising it against real
    // SQLite proves the delete-on-read path actually fires the DELETE.
    const token = await store.persist(makeState("alice", { expiresAt: Date.now() + 50 }));
    await new Promise((r) => setTimeout(r, 80));
    expect(await store.retrieve(token)).toBeNull();
    // Probe the table directly — the row must be gone, not just hidden.
    const raw = await table.findOne({ filter: { token } });
    expect(raw).toBeNull();
  });
});
