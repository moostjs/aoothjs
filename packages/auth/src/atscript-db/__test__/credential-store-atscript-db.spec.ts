import { describe, expect, it } from "vite-plus/test";
import type { CredentialState } from "../../credential/types";
import { CredentialStoreAtscriptDb } from "../index";
import { MockTable } from "./mock-table";

function makeState(userId: string, overrides?: Partial<CredentialState>): CredentialState {
  return {
    userId,
    issuedAt: Date.now(),
    expiresAt: Date.now() + 60_000,
    kind: "access",
    ...overrides,
  };
}

describe("CredentialStoreAtscriptDb — contract", () => {
  // Intent 1: every CredentialStore method must behave the same as the
  // in-memory store. Without this parity, downstream auth flows would
  // diverge depending on adapter — exactly the bug an interface is meant
  // to prevent.
  describe("persist + retrieve + revoke", () => {
    it("persists a row keyed on a UUID token and retrieves it", async () => {
      const table = new MockTable();
      const store = new CredentialStoreAtscriptDb({ table });
      const token = await store.persist(makeState("alice"));
      expect(token).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
      const state = await store.retrieve(token);
      expect(state?.userId).toBe("alice");
    });

    it("retrieve returns null for unknown tokens", async () => {
      const store = new CredentialStoreAtscriptDb({ table: new MockTable() });
      expect(await store.retrieve("nope")).toBeNull();
    });

    it("revoke deletes the row by its primary key", async () => {
      const table = new MockTable();
      const store = new CredentialStoreAtscriptDb({ table });
      const token = await store.persist(makeState("alice"));
      await store.revoke(token);
      expect(await store.retrieve(token)).toBeNull();
      // deleteOne must be called with the token itself (PK on the .as model).
      const last = table.opsOf("deleteOne").at(-1);
      expect(last?.args[0]).toBe(token);
    });

    it("revoke is idempotent on unknown tokens (no throw)", async () => {
      const store = new CredentialStoreAtscriptDb({ table: new MockTable() });
      await expect(store.revoke("nope")).resolves.toBeUndefined();
    });
  });

  describe("consume", () => {
    it("returns the state and deletes the row in one call", async () => {
      const table = new MockTable();
      const store = new CredentialStoreAtscriptDb({ table });
      const token = await store.persist(makeState("alice"));
      const consumed = await store.consume(token);
      expect(consumed?.userId).toBe("alice");
      expect(await store.retrieve(token)).toBeNull();
    });

    it("returns null when the token is not found", async () => {
      const store = new CredentialStoreAtscriptDb({ table: new MockTable() });
      expect(await store.consume("nope")).toBeNull();
    });
  });

  describe("update", () => {
    it("replaces the row in place and returns the same token", async () => {
      const table = new MockTable();
      const store = new CredentialStoreAtscriptDb({ table });
      const token = await store.persist(makeState("alice"));
      const returned = await store.update(token, makeState("alice", { rotatedAt: 7 }));
      expect(returned).toBe(token);
      expect((await store.retrieve(token))?.rotatedAt).toBe(7);
    });

    it("is a no-op for unknown tokens (does not insert a resurrected row)", async () => {
      const table = new MockTable();
      const store = new CredentialStoreAtscriptDb({ table });
      const returned = await store.update("ghost", makeState("alice"));
      expect(returned).toBe("ghost");
      expect(await store.retrieve("ghost")).toBeNull();
      expect(table.opsOf("replaceOne")).toHaveLength(0);
    });

    // Intent 9: update with a past-expiry state calls deleteOne, NOT
    // replaceOne. This exists for parity with the Redis adapter's
    // fail-loud rule — a dead row in the table would silently flip to
    // "unknown" on the next retrieve and confuse downstream debugging.
    it("calls deleteOne (revoke) — not replaceOne — when state.expiresAt is past", async () => {
      const table = new MockTable();
      const store = new CredentialStoreAtscriptDb({ table });
      const token = await store.persist(makeState("alice"));
      const replaceCountBefore = table.opsOf("replaceOne").length;
      await store.update(token, makeState("alice", { expiresAt: Date.now() - 1 }));
      // No new replaceOne since the persist.
      expect(table.opsOf("replaceOne")).toHaveLength(replaceCountBefore);
      // The row was deleted by token id.
      const lastDelete = table.opsOf("deleteOne").at(-1);
      expect(lastDelete?.args[0]).toBe(token);
      expect(await store.retrieve(token)).toBeNull();
    });
  });
});

describe("CredentialStoreAtscriptDb — sessionId / lastSeenAt", () => {
  it("round-trips sessionId through persist + retrieve + listForUser", async () => {
    const store = new CredentialStoreAtscriptDb({ table: new MockTable() });
    const token = await store.persist(makeState("alice", { sessionId: "sess-1" }));
    expect((await store.retrieve(token))?.sessionId).toBe("sess-1");
    const [entry] = await store.listForUser("alice");
    expect(entry.sessionId).toBe("sess-1");
  });

  it("touch writes lastSeenAt via replaceOne on an existing token; no-op for unknown", async () => {
    const table = new MockTable();
    const store = new CredentialStoreAtscriptDb({ table });
    const token = await store.persist(makeState("alice"));
    await store.touch(token, 4242);
    expect((await store.retrieve(token))?.lastSeenAt).toBe(4242);
    const replaceCountBefore = table.opsOf("replaceOne").length;
    // Unknown token is a no-op — does not throw, does not write.
    await store.touch("nope", 1);
    expect(table.opsOf("replaceOne")).toHaveLength(replaceCountBefore);
  });
});

describe("CredentialStoreAtscriptDb — typed payload + metadata round-trip", () => {
  // Intent: a consumer's typed payload (the flat root fields added to their
  // `extends AoothAuthCredential` model) and metadata persist as real columns.
  // The adapter must round-trip them byte-for-byte through persist → retrieve;
  // a regression here means per-token data silently drops on the wire.
  it("persists typed payload + metadata and returns them on retrieve", async () => {
    const table = new MockTable<{ scope: string; roles: string[] }>();
    const store = new CredentialStoreAtscriptDb<{ scope: string; roles: string[] }>({ table });
    const metadata = {
      ip: "10.0.0.1",
      userAgent: "Mozilla/5.0",
      fingerprint: "fp-1",
      label: "iPhone",
    };
    const token = await store.persist({
      userId: "alice",
      issuedAt: Date.now(),
      expiresAt: Date.now() + 60_000,
      kind: "refresh",
      scope: "read:tasks",
      roles: ["admin", "user"],
      metadata,
    });
    const got = await store.retrieve(token);
    expect(got?.scope).toBe("read:tasks");
    expect(got?.roles).toEqual(["admin", "user"]);
    expect(got?.metadata).toEqual(metadata);
  });

  it("does not surface payload/metadata when none were persisted (no synthetic fields)", async () => {
    // Surface contract: omitting a field on persist must NOT synthesize it on
    // retrieve — the adapter returns only the envelope fields actually written.
    const table = new MockTable();
    const store = new CredentialStoreAtscriptDb({ table });
    const token = await store.persist(makeState("alice"));
    const got = await store.retrieve(token);
    expect(got?.metadata).toBeUndefined();
    expect(Object.keys(got ?? {}).toSorted()).toEqual(["expiresAt", "issuedAt", "kind", "userId"]);
  });

  it("update replaces typed payload + metadata wholesale (no merge)", async () => {
    // Adapter contract: update is replace-semantic, not patch-semantic. The
    // refresh-token rotation path relies on this — a stale fingerprint or an
    // old payload value MUST NOT survive a rotation.
    const table = new MockTable<{ scope: string }>();
    const store = new CredentialStoreAtscriptDb<{ scope: string }>({ table });
    const token = await store.persist({
      userId: "alice",
      issuedAt: Date.now(),
      expiresAt: Date.now() + 60_000,
      scope: "read:tasks",
      metadata: { ip: "10.0.0.1" },
    });
    await store.update(token, {
      userId: "alice",
      issuedAt: Date.now(),
      expiresAt: Date.now() + 120_000,
      scope: "write:tasks",
      metadata: { ip: "10.0.0.2" },
    });
    const got = await store.retrieve(token);
    expect(got?.scope).toBe("write:tasks");
    expect(got?.metadata).toEqual({ ip: "10.0.0.2" });
  });
});

describe("CredentialStoreAtscriptDb — listForUser", () => {
  // Intent 2: listForUser must yield {...state, token} so UIs can show
  // and manage individual sessions/refresh tokens.
  it("returns active rows with the token attached", async () => {
    const table = new MockTable();
    const store = new CredentialStoreAtscriptDb({ table });
    const t1 = await store.persist(makeState("alice", { issuedAt: 1 }));
    const t2 = await store.persist(makeState("alice", { issuedAt: 2 }));
    const list = await store.listForUser("alice");
    expect(list).toHaveLength(2);
    for (const e of list) {
      expect(e.userId).toBe("alice");
      expect(typeof e.token).toBe("string");
    }
    expect(list.map((e) => e.token).toSorted()).toEqual([t1, t2].toSorted());
  });

  it("returns an empty array when the user has nothing", async () => {
    const store = new CredentialStoreAtscriptDb({ table: new MockTable() });
    expect(await store.listForUser("nobody")).toEqual([]);
  });

  it("filters out expired rows and prunes them in the background", async () => {
    // Lazy GC on read keeps the table tidy without a separate cron — the
    // dead rows would otherwise accumulate forever.
    const table = new MockTable();
    const store = new CredentialStoreAtscriptDb({ table });
    const liveToken = await store.persist(makeState("alice"));
    // Inject a row directly with an expired timestamp.
    await table.insertOne({
      token: "dead-token",
      userId: "alice",
      issuedAt: Date.now() - 10_000,
      expiresAt: Date.now() - 1,
      kind: "access",
    });
    const list = await store.listForUser("alice");
    expect(list.map((e) => e.token)).toEqual([liveToken]);
    expect(table.rows.has("dead-token")).toBe(false);
  });
});

describe("CredentialStoreAtscriptDb — revokeAllForUser", () => {
  // Intent 3 + 5: cascade revoke for a user; other users untouched.
  it("deletes every row for the user and returns the count", async () => {
    const table = new MockTable();
    const store = new CredentialStoreAtscriptDb({ table });
    await store.persist(makeState("alice"));
    await store.persist(makeState("alice"));
    const count = await store.revokeAllForUser("alice");
    expect(count).toBe(2);
    expect(await store.listForUser("alice")).toEqual([]);
  });

  it("returns 0 when the user has nothing", async () => {
    const store = new CredentialStoreAtscriptDb({ table: new MockTable() });
    expect(await store.revokeAllForUser("nobody")).toBe(0);
  });

  it("leaves other users' credentials intact", async () => {
    const table = new MockTable();
    const store = new CredentialStoreAtscriptDb({ table });
    await store.persist(makeState("alice"));
    await store.persist(makeState("alice"));
    const bobToken = await store.persist(makeState("bob"));
    await store.revokeAllForUser("alice");
    const bobList = await store.listForUser("bob");
    expect(bobList).toHaveLength(1);
    expect(bobList[0].token).toBe(bobToken);
  });

  it("uses a single deleteMany call (one round trip)", async () => {
    // The whole point of choosing deleteMany over read-then-deleteOne is
    // performance — if a future refactor regresses this we want to know.
    const table = new MockTable();
    const store = new CredentialStoreAtscriptDb({ table });
    await store.persist(makeState("alice"));
    await store.persist(makeState("alice"));
    const deleteManyBefore = table.opsOf("deleteMany").length;
    await store.revokeAllForUser("alice");
    expect(table.opsOf("deleteMany").length - deleteManyBefore).toBe(1);
  });
});

describe("CredentialStoreAtscriptDb — TTL expiry", () => {
  // Intent 4: retrieve must reject and delete a row whose expiresAt has
  // passed, even if no separate eviction job has run.
  it("retrieve returns null and deletes the row when expiresAt is past", async () => {
    const table = new MockTable();
    const store = new CredentialStoreAtscriptDb({ table });
    const token = await store.persist(makeState("alice"));
    // Push the row into the past in-place to simulate clock-skew / no GC.
    const row = table.rows.get(token);
    if (!row) throw new Error("row missing");
    row.expiresAt = Date.now() - 1;
    expect(await store.retrieve(token)).toBeNull();
    expect(table.rows.has(token)).toBe(false);
  });
});
